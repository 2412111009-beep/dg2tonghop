import os, secrets, hashlib, smtplib, sqlite3, uuid
from datetime import datetime, timedelta, date
from email.message import EmailMessage
from functools import wraps

from flask import (Flask, jsonify, render_template, request, redirect, url_for, session,
                   flash, g, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from db import get_db, init_db, DATA_DIR

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    p = os.path.join(DATA_DIR, ".secret_key")
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(secrets.token_hex(32))
    return open(p).read()


app = Flask(__name__)
app.secret_key = _secret()
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"   # bật khi chạy sau HTTPS

ROLE_LABEL = {"admin": "Quản trị", "lecturer": "Giảng viên", "student": "Sinh viên"}
STATUS_LABEL = {"pending": "Chờ duyệt", "approved": "Đã duyệt", "rejected": "Từ chối",
                "cancelled": "Đã hủy", "bumped": "Bị thay thế", "done": "Hoàn tất"}
COND_LABEL = {"good": "Tốt", "damaged": "Hỏng", "lost": "Mất"}
OPEN_H, CLOSE_H = 7, 21          # giờ mở cửa phòng lab
WEEKDAYS = ["Thứ 2", "Thứ 3", "Thứ 4", "Thứ 5", "Thứ 6", "Thứ 7", "CN"]


# ---------------------------------------------------------------- tiện ích
def db():
    if "db" not in g:
        g.db = get_db()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def q(sql, args=()):
    return db().execute(sql, args).fetchall()


def one(sql, args=()):
    return db().execute(sql, args).fetchone()


@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        u = one("SELECT * FROM users WHERE id=? AND is_active=1", (uid,))
        if u:
            g.user = u
        else:
            session.clear()


@app.before_request
def csrf_protect():
    if request.method == "POST" and not request.path.startswith("/api/"):   # API dùng Bearer token
        sent, real = request.form.get("csrf", ""), session.get("csrf", "")
        if not real or not secrets.compare_digest(real, sent):
            abort(400, "CSRF token không hợp lệ. Hãy tải lại trang và thử lại.")


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return dict(csrf=session["csrf"], ROLE_LABEL=ROLE_LABEL, STATUS_LABEL=STATUS_LABEL,
                COND_LABEL=COND_LABEL, me=g.get("user"), WEEKDAYS=WEEKDAYS)


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            flash("Vui lòng đăng nhập.", "warn")
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


def roles(*allowed):
    def deco(f):
        @wraps(f)
        @login_required
        def w(*a, **k):
            if g.user["role"] not in allowed:
                abort(403)
            return f(*a, **k)
        return w
    return deco


def parse_dt(d, t):
    return datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M")


def monday_of(d):
    return d - timedelta(days=d.weekday())


# ---------------------------------------------------------------- xác thực
@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        u = one("SELECT * FROM users WHERE email=?", (email,))
        if not u or not check_password_hash(u["password_hash"], request.form["password"]):
            flash("Email hoặc mật khẩu không đúng.", "err")
        elif not u["is_active"]:
            flash("Tài khoản đang chờ quản trị viên kích hoạt.", "warn")
        else:
            session.clear()
            session["uid"] = u["id"]
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        f = request.form
        email, name = f["email"].strip().lower(), f["full_name"].strip()
        role = f.get("role", "student")
        if role not in ("student", "lecturer"):
            role = "student"
        if not email or not name:
            flash("Hãy nhập đủ họ tên và email.", "err")
        elif len(f["password"]) < 6:
            flash("Mật khẩu cần tối thiểu 6 ký tự.", "err")
        elif f["password"] != f["password2"]:
            flash("Hai mật khẩu chưa khớp.", "err")
        elif one("SELECT 1 FROM users WHERE email=?", (email,)):
            flash("Email này đã được đăng ký.", "err")
        else:
            active = 1 if role == "student" else 0   # giảng viên phải được admin duyệt
            db().execute(
                "INSERT INTO users(email,password_hash,full_name,phone,role,group_name,is_active) VALUES (?,?,?,?,?,?,?)",
                (email, generate_password_hash(f["password"]), name, f.get("phone", "").strip(),
                 role, f.get("group_name", "").strip() or None, active))
            db().commit()
            flash("Đăng ký thành công. " + ("Bạn có thể đăng nhập ngay." if active else
                  "Tài khoản giảng viên sẽ dùng được sau khi quản trị viên kích hoạt."), "ok")
            return redirect(url_for("login"))
    return render_template("register.html")


def send_reset_mail(to, link):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = "Đặt lại mật khẩu LabBook", os.environ.get("SMTP_FROM", "noreply@lab.local"), to
    msg.set_content(f"Mở liên kết sau trong 30 phút để đặt lại mật khẩu:\n{link}")
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587))) as s:
        s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
        s.send_message(msg)
    return True


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    dev_link = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        u = one("SELECT * FROM users WHERE email=? AND is_active=1", (email,))
        if u:
            token = secrets.token_urlsafe(32)
            exp = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            db().execute("INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES (?,?,?)",
                         (u["id"], hashlib.sha256(token.encode()).hexdigest(), exp))
            db().commit()
            link = url_for("reset", token=token, _external=True)
            try:
                sent = send_reset_mail(email, link)
            except Exception as e:      # lỗi SMTP không được lộ việc email có tồn tại hay không
                app.logger.error("SMTP lỗi: %s", e)
                sent = False
            if not sent:                # chưa cấu hình SMTP -> chế độ phát triển
                print(f"[DEV] Link đặt lại mật khẩu cho {email}: {link}")
                dev_link = link
        flash("Nếu email tồn tại trong hệ thống, liên kết đặt lại mật khẩu đã được gửi.", "ok")
    return render_template("forgot.html", dev_link=dev_link)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    h = hashlib.sha256(token.encode()).hexdigest()
    r = one("SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?",
            (h, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    if not r:
        flash("Liên kết không hợp lệ hoặc đã hết hạn.", "err")
        return redirect(url_for("forgot"))
    if request.method == "POST":
        if len(request.form["password"]) < 6:
            flash("Mật khẩu cần tối thiểu 6 ký tự.", "err")
        elif request.form["password"] != request.form["password2"]:
            flash("Hai mật khẩu chưa khớp.", "err")
        else:
            db().execute("UPDATE users SET password_hash=? WHERE id=?",
                         (generate_password_hash(request.form["password"]), r["user_id"]))
            db().execute("UPDATE password_resets SET used=1 WHERE user_id=?", (r["user_id"],))
            db().commit()
            flash("Đã đổi mật khẩu. Hãy đăng nhập lại.", "ok")
            return redirect(url_for("login"))
    return render_template("reset.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        f = request.form
        if f.get("new_password"):
            if not check_password_hash(g.user["password_hash"], f["old_password"]):
                flash("Mật khẩu hiện tại chưa đúng.", "err")
                return redirect(url_for("profile"))
            if len(f["new_password"]) < 6:
                flash("Mật khẩu mới cần tối thiểu 6 ký tự.", "err")
                return redirect(url_for("profile"))
            db().execute("UPDATE users SET password_hash=? WHERE id=?",
                         (generate_password_hash(f["new_password"]), g.user["id"]))
        db().execute("UPDATE users SET full_name=?, phone=?, group_name=? WHERE id=?",
                     (f["full_name"].strip() or g.user["full_name"], f.get("phone", ""),
                      f.get("group_name") or None, g.user["id"]))
        db().commit()
        flash("Đã lưu hồ sơ.", "ok")
        return redirect(url_for("profile"))
    return render_template("profile.html")


# ---------------------------------------------------------------- bảng điều khiển theo vai trò
@app.route("/dashboard")
@login_required
def dashboard():
    role = g.user["role"]
    if role == "admin":
        stats = dict(
            pending=one("SELECT COUNT(*) c FROM bookings WHERE status='pending'")["c"],
            today=one("SELECT COUNT(*) c FROM bookings WHERE status='approved' AND date(start_time)=date('now','localtime')")["c"],
            out=one("SELECT COUNT(*) c FROM loans WHERE returned_at IS NULL")["c"],
            dmg=one("SELECT COUNT(*) c FROM damage_reports WHERE status='open'")["c"],
            inactive=one("SELECT COUNT(*) c FROM users WHERE is_active=0")["c"])
        pend = q("""SELECT b.*, u.full_name, u.role, r.name room FROM bookings b
                    JOIN users u ON u.id=b.user_id LEFT JOIN rooms r ON r.id=b.room_id
                    WHERE b.status='pending' ORDER BY (u.role='lecturer') DESC, b.start_time LIMIT 8""")
        return render_template("dash_admin.html", s=stats, pend=pend)
    mine = q("""SELECT b.*, r.name room FROM bookings b LEFT JOIN rooms r ON r.id=b.room_id
                WHERE b.user_id=? AND b.end_time>=datetime('now','localtime') AND b.status IN ('pending','approved','bumped')
                ORDER BY b.start_time LIMIT 6""", (g.user["id"],))
    bumped = q("SELECT COUNT(*) c FROM bookings WHERE user_id=? AND status='bumped'", (g.user["id"],))[0]["c"]
    return render_template("dash_lecturer.html" if role == "lecturer" else "dash_student.html",
                           mine=mine, bumped=bumped)


# ---------------------------------------------------------------- lịch tuần
def build_week(kind, obj_id, monday):
    start = monday.strftime("%Y-%m-%d 00:00")
    end = (monday + timedelta(days=7)).strftime("%Y-%m-%d 00:00")
    if kind == "room":
        rows = q("""SELECT b.*, u.full_name, u.role, NULL qty FROM bookings b JOIN users u ON u.id=b.user_id
                    WHERE b.room_id=? AND b.status IN ('pending','approved') AND b.start_time<? AND b.end_time>?""",
                 (obj_id, end, start))
    else:
        rows = q("""SELECT b.*, u.full_name, u.role, be.quantity qty FROM bookings b
                    JOIN booking_equipment be ON be.booking_id=b.id JOIN users u ON u.id=b.user_id
                    WHERE be.equipment_id=? AND b.status IN ('pending','approved') AND b.start_time<? AND b.end_time>?""",
                 (obj_id, end, start))
    grid = {}
    for d in range(7):
        day = monday + timedelta(days=d)
        for h in range(OPEN_H, CLOSE_H):
            s = datetime(day.year, day.month, day.day, h)
            e = s + timedelta(hours=1)
            cell = [b for b in rows
                    if datetime.strptime(b["start_time"], "%Y-%m-%d %H:%M") < e
                    and datetime.strptime(b["end_time"], "%Y-%m-%d %H:%M") > s]
            grid[(d, h)] = cell
    return grid


@app.route("/schedule")
@login_required
def schedule():
    kind = "equip" if request.args.get("kind") == "equip" else "room"
    rooms = q("SELECT * FROM rooms WHERE is_active=1 ORDER BY name")
    equips = q("SELECT * FROM equipment WHERE is_active=1 ORDER BY name")
    items = rooms if kind == "room" else equips
    try:
        obj_id = int(request.args.get("id", items[0]["id"] if items else 0))
    except ValueError:
        obj_id = 0
    try:
        monday = monday_of(datetime.strptime(request.args.get("week", ""), "%Y-%m-%d").date())
    except ValueError:
        monday = monday_of(date.today())
    obj = next((i for i in items if i["id"] == obj_id), None)
    grid = build_week(kind, obj_id, monday) if obj else {}
    return render_template("schedule.html", kind=kind, items=items, obj=obj, grid=grid,
                           monday=monday, prev=monday - timedelta(days=7), nxt=monday + timedelta(days=7),
                           hours=range(OPEN_H, CLOSE_H), days=[monday + timedelta(days=i) for i in range(7)],
                           today=date.today(), now_str=datetime.now().strftime("%Y-%m-%d %H:%M"))


# ---------------------------------------------------------------- đặt lịch
def create_booking(user, room_id, start, end, purpose, equip):
    """Tạo yêu cầu. Việc chặn trùng do trigger CSDL đảm nhiệm;
    nếu người đặt là giảng viên, thử thay thế các yêu cầu CHƯA DUYỆT của sinh viên rồi chèn lại."""
    d = db()
    bumped = []
    is_lect = user["role"] == "lecturer"

    def bump(where_sql, args):
        victims = d.execute(f"""SELECT b.id FROM bookings b JOIN users u ON u.id=b.user_id
            WHERE b.status='pending' AND u.role='student' AND b.start_time<? AND b.end_time>? AND {where_sql}
            ORDER BY b.created_at DESC""", (end, start, *args)).fetchall()
        for v in victims:
            d.execute("UPDATE bookings SET status='bumped', admin_note=? WHERE id=?",
                      ("Bị thay thế bởi yêu cầu ưu tiên của giảng viên " + user["full_name"], v["id"]))
            bumped.append(v["id"])
        return len(victims)

    try:
        for attempt in range(2):
            try:
                cur = d.execute("INSERT INTO bookings(user_id,room_id,start_time,end_time,purpose) VALUES (?,?,?,?,?)",
                                (user["id"], room_id, start, end, purpose))
                break
            except sqlite3.IntegrityError as e:
                if "ROOM_CONFLICT" in str(e) and is_lect and attempt == 0 and bump("b.room_id=?", (room_id,)):
                    continue
                raise
        bid = cur.lastrowid
        for eid, qty in equip:
            while True:
                try:
                    d.execute("INSERT INTO booking_equipment(booking_id,equipment_id,quantity) VALUES (?,?,?)",
                              (bid, eid, qty))
                    break
                except sqlite3.IntegrityError as e:
                    if "EQUIP_CONFLICT" in str(e) and is_lect:
                        one_victim = d.execute("""SELECT b.id FROM bookings b JOIN users u ON u.id=b.user_id
                            JOIN booking_equipment be ON be.booking_id=b.id
                            WHERE b.status='pending' AND u.role='student' AND be.equipment_id=?
                              AND b.start_time<? AND b.end_time>? ORDER BY b.created_at DESC LIMIT 1""",
                                               (eid, end, start)).fetchone()
                        if one_victim:
                            d.execute("UPDATE bookings SET status='bumped', admin_note=? WHERE id=?",
                                      ("Bị thay thế bởi yêu cầu ưu tiên của giảng viên " + user["full_name"], one_victim["id"]))
                            bumped.append(one_victim["id"])
                            continue
                    raise
        d.commit()
        return bid, bumped
    except Exception:
        d.rollback()
        raise


@app.route("/booking/new", methods=["GET", "POST"])
@roles("student", "lecturer")
def booking_new():
    rooms = q("SELECT * FROM rooms WHERE is_active=1 ORDER BY name")
    equips = q("SELECT *, quantity-broken_qty AS avail FROM equipment WHERE is_active=1 ORDER BY name")
    if request.method == "POST":
        f = request.form
        try:
            room_id = int(f["room_id"]) if f.get("room_id") else None
            start, end = parse_dt(f["date"], f["start"]), parse_dt(f["date"], f["end"])
            equip = []
            for e in equips:
                n = int(f.get(f"eq_{e['id']}") or 0)
                if n > 0:
                    equip.append((e["id"], n))
        except (ValueError, KeyError):
            flash("Dữ liệu chưa hợp lệ, hãy kiểm tra lại ngày giờ và số lượng.", "err")
            return render_template("booking_new.html", rooms=rooms, equips=equips, f=f)
        err = None
        if not room_id and not equip:
            err = "Hãy chọn ít nhất một phòng hoặc một thiết bị."
        elif start >= end:
            err = "Giờ kết thúc phải sau giờ bắt đầu."
        elif start < datetime.now():
            err = "Không thể đặt vào thời điểm đã qua."
        elif start.hour < OPEN_H or end > end.replace(hour=CLOSE_H, minute=0) or end.hour < OPEN_H:
            err = f"Phòng lab mở từ {OPEN_H}:00 đến {CLOSE_H}:00."
        if err:
            flash(err, "err")
            return render_template("booking_new.html", rooms=rooms, equips=equips, f=f)
        try:
            bid, bumped = create_booking(g.user, room_id, start.strftime("%Y-%m-%d %H:%M"),
                                         end.strftime("%Y-%m-%d %H:%M"), f.get("purpose", "").strip(), equip)
        except sqlite3.IntegrityError as e:
            msg = str(e)
            if "ROOM_CONFLICT" in msg:
                flash("Phòng đã có yêu cầu khác trong khung giờ này. Xem lịch tuần để chọn giờ trống.", "err")
            elif "EQUIP_CONFLICT" in msg:
                flash("Một thiết bị không đủ số lượng trong khung giờ này.", "err")
            else:
                flash("Không thể lưu yêu cầu: " + msg, "err")
            return render_template("booking_new.html", rooms=rooms, equips=equips, f=f)
        flash("Đã gửi yêu cầu, đang chờ cán bộ duyệt." +
              (f" Đã thay thế {len(bumped)} yêu cầu chưa duyệt của sinh viên." if bumped else ""), "ok")
        return redirect(url_for("my_bookings"))
    return render_template("booking_new.html", rooms=rooms, equips=equips, f=request.args)


@app.route("/my/bookings")
@roles("student", "lecturer")
def my_bookings():
    rows = q("""SELECT b.*, r.name room,
                (SELECT group_concat(e.name||' ×'||be.quantity, ', ') FROM booking_equipment be
                   JOIN equipment e ON e.id=be.equipment_id WHERE be.booking_id=b.id) equip
                FROM bookings b LEFT JOIN rooms r ON r.id=b.room_id
                WHERE b.user_id=? ORDER BY b.start_time DESC""", (g.user["id"],))
    return render_template("my_bookings.html", rows=rows)


@app.route("/booking/<int:bid>/cancel", methods=["POST"])
@roles("student", "lecturer")
def booking_cancel(bid):
    b = one("SELECT * FROM bookings WHERE id=? AND user_id=?", (bid, g.user["id"]))
    if not b or b["status"] not in ("pending", "approved"):
        abort(404)
    if one("SELECT 1 FROM loans WHERE booking_id=? AND returned_at IS NULL", (bid,)):
        flash("Thiết bị của yêu cầu này đang được mượn, hãy trả trước khi hủy.", "err")
    else:
        db().execute("UPDATE bookings SET status='cancelled' WHERE id=?", (bid,))
        db().commit()
        flash("Đã hủy yêu cầu.", "ok")
    return redirect(url_for("my_bookings"))


# ---------------------------------------------------------------- quản trị: duyệt yêu cầu
@app.route("/admin/bookings")
@roles("admin")
def admin_bookings():
    status = request.args.get("status", "pending")
    sql = """SELECT b.*, u.full_name, u.role, u.group_name, r.name room,
             (SELECT group_concat(e.name||' ×'||be.quantity, ', ') FROM booking_equipment be
                JOIN equipment e ON e.id=be.equipment_id WHERE be.booking_id=b.id) equip
             FROM bookings b JOIN users u ON u.id=b.user_id LEFT JOIN rooms r ON r.id=b.room_id"""
    if status in STATUS_LABEL:
        rows = q(sql + " WHERE b.status=? ORDER BY (u.role='lecturer') DESC, b.start_time", (status,))
    else:
        rows = q(sql + " ORDER BY b.start_time DESC LIMIT 200")
    return render_template("admin_bookings.html", rows=rows, status=status)


@app.route("/admin/booking/<int:bid>/<action>", methods=["POST"])
@roles("admin")
def admin_booking_action(bid, action):
    b = one("SELECT * FROM bookings WHERE id=?", (bid,))
    if not b:
        abort(404)
    new = {"approve": "approved", "reject": "rejected", "done": "done"}.get(action)
    allowed = {"approved": ("pending",), "rejected": ("pending", "approved"), "done": ("approved",)}
    if not new or b["status"] not in allowed[new]:
        flash("Thao tác không áp dụng được với trạng thái hiện tại.", "err")
    else:
        if new == "done" and one("SELECT 1 FROM loans WHERE booking_id=? AND returned_at IS NULL", (bid,)):
            flash("Còn thiết bị chưa trả, chưa thể hoàn tất.", "err")
            return redirect(request.referrer or url_for("admin_bookings"))
        db().execute("UPDATE bookings SET status=?, admin_note=? WHERE id=?",
                     (new, request.form.get("note") or b["admin_note"], bid))
        db().commit()
        flash(f"Đã chuyển yêu cầu #{bid} sang “{STATUS_LABEL[new]}”.", "ok")
    return redirect(request.referrer or url_for("admin_bookings"))


# ---------------------------------------------------------------- mượn - trả
@app.route("/admin/loans")
@roles("admin")
def admin_loans():
    to_issue = q("""SELECT b.id bid, b.start_time, b.end_time, u.full_name, be.equipment_id, be.quantity, e.name ename,
                    be.quantity - COALESCE((SELECT SUM(l.quantity) FROM loans l WHERE l.booking_id=b.id AND l.equipment_id=be.equipment_id),0) AS remain
                    FROM bookings b JOIN users u ON u.id=b.user_id
                    JOIN booking_equipment be ON be.booking_id=b.id JOIN equipment e ON e.id=be.equipment_id
                    WHERE b.status='approved' AND b.end_time>=datetime('now','localtime','-1 day')
                    ORDER BY b.start_time""")
    to_issue = [r for r in to_issue if r["remain"] > 0]
    out = q("""SELECT l.*, e.name ename, u.full_name FROM loans l JOIN equipment e ON e.id=l.equipment_id
               JOIN bookings b ON b.id=l.booking_id JOIN users u ON u.id=b.user_id
               WHERE l.returned_at IS NULL ORDER BY l.borrowed_at""")
    history = q("""SELECT l.*, e.name ename, u.full_name FROM loans l JOIN equipment e ON e.id=l.equipment_id
               JOIN bookings b ON b.id=l.booking_id JOIN users u ON u.id=b.user_id
               WHERE l.returned_at IS NOT NULL ORDER BY l.returned_at DESC LIMIT 30""")
    return render_template("admin_loans.html", to_issue=to_issue, out=out, history=history)


@app.route("/admin/loan/issue", methods=["POST"])
@roles("admin")
def loan_issue():
    bid, eid = int(request.form["booking_id"]), int(request.form["equipment_id"])
    be = one("SELECT * FROM booking_equipment WHERE booking_id=? AND equipment_id=?", (bid, eid))
    if not be:
        abort(404)
    db().execute("INSERT INTO loans(booking_id,equipment_id,quantity,handled_by) VALUES (?,?,?,?)",
                 (bid, eid, be["quantity"], g.user["id"]))
    db().commit()
    flash("Đã ghi nhận giao thiết bị.", "ok")
    return redirect(url_for("admin_loans"))


@app.route("/admin/loan/<int:lid>/return", methods=["POST"])
@roles("admin")
def loan_return(lid):
    l = one("SELECT * FROM loans WHERE id=? AND returned_at IS NULL", (lid,))
    if not l:
        abort(404)
    cond = request.form.get("condition", "good")
    if cond not in COND_LABEL:
        abort(400)
    note = request.form.get("note", "").strip()
    d = db()
    d.execute("UPDATE loans SET returned_at=datetime('now','localtime'), return_condition=?, return_note=? WHERE id=?",
              (cond, note, lid))
    if cond in ("damaged", "lost"):
        d.execute("UPDATE equipment SET broken_qty=MIN(quantity, broken_qty+?) WHERE id=?", (l["quantity"], l["equipment_id"]))
        d.execute("INSERT INTO damage_reports(reporter_id,equipment_id,loan_id,description) VALUES (?,?,?,?)",
                  (g.user["id"], l["equipment_id"], lid, f"[Phát hiện khi trả – {COND_LABEL[cond]}] {note}"))
    d.commit()
    flash("Đã ghi nhận trả thiết bị.", "ok")
    return redirect(url_for("admin_loans"))


# ---------------------------------------------------------------- báo hỏng kèm ảnh
def save_photo(file):
    if not file or not file.filename:
        return None
    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
        raise ValueError("Chỉ nhận ảnh PNG, JPG, GIF hoặc WEBP.")
    name = uuid.uuid4().hex + ext
    file.save(os.path.join(UPLOAD_DIR, name))
    return name


@app.route("/damage/new", methods=["GET", "POST"])
@login_required
def damage_new():
    rooms = q("SELECT * FROM rooms ORDER BY name")
    equips = q("SELECT * FROM equipment ORDER BY name")
    if request.method == "POST":
        f = request.form
        if not f.get("description", "").strip():
            flash("Hãy mô tả tình trạng hỏng.", "err")
        elif not f.get("equipment_id") and not f.get("room_id"):
            flash("Hãy chọn thiết bị hoặc phòng bị hỏng.", "err")
        else:
            try:
                photo = save_photo(request.files.get("photo"))
            except ValueError as e:
                flash(str(e), "err")
                return render_template("damage_new.html", rooms=rooms, equips=equips)
            db().execute("INSERT INTO damage_reports(reporter_id,equipment_id,room_id,description,photo) VALUES (?,?,?,?,?)",
                         (g.user["id"], f.get("equipment_id") or None, f.get("room_id") or None,
                          f["description"].strip(), photo))
            db().commit()
            flash("Đã gửi báo hỏng.", "ok")
            return redirect(url_for("damage_list"))
    return render_template("damage_new.html", rooms=rooms, equips=equips)


@app.route("/damage")
@login_required
def damage_list():
    sql = """SELECT d.*, u.full_name, e.name ename, r.name rname FROM damage_reports d
             JOIN users u ON u.id=d.reporter_id LEFT JOIN equipment e ON e.id=d.equipment_id
             LEFT JOIN rooms r ON r.id=d.room_id"""
    if g.user["role"] == "admin":
        rows = q(sql + " ORDER BY (d.status='open') DESC, d.created_at DESC")
    else:
        rows = q(sql + " WHERE d.reporter_id=? ORDER BY d.created_at DESC", (g.user["id"],))
    return render_template("damage_list.html", rows=rows)


@app.route("/admin/damage/<int:did>/resolve", methods=["POST"])
@roles("admin")
def damage_resolve(did):
    d = one("SELECT * FROM damage_reports WHERE id=?", (did,))
    if not d:
        abort(404)
    db().execute("UPDATE damage_reports SET status='resolved' WHERE id=?", (did,))
    if d["equipment_id"] and request.form.get("restock"):   # thiết bị đã sửa xong -> trả về kho dùng được
        db().execute("UPDATE equipment SET broken_qty=MAX(0, broken_qty-1) WHERE id=?", (d["equipment_id"],))
    db().commit()
    flash("Đã đánh dấu xử lý xong.", "ok")
    return redirect(url_for("damage_list"))


@app.route("/uploads/<path:name>")
@login_required
def uploads(name):
    return send_from_directory(UPLOAD_DIR, name)


# ---------------------------------------------------------------- quản trị: phòng, thiết bị, người dùng
@app.route("/admin/rooms", methods=["GET", "POST"])
@roles("admin")
def admin_rooms():
    if request.method == "POST":
        f = request.form
        try:
            if f["op"] == "add":
                db().execute("INSERT INTO rooms(name,location,capacity,description) VALUES (?,?,?,?)",
                             (f["name"].strip(), f["location"].strip(), int(f.get("capacity") or 0) or None, f.get("description")))
            elif f["op"] == "toggle":
                db().execute("UPDATE rooms SET is_active=1-is_active WHERE id=?", (int(f["id"]),))
            db().commit()
            flash("Đã lưu.", "ok")
        except (sqlite3.IntegrityError, ValueError):
            flash("Không lưu được (tên phòng đã tồn tại hoặc dữ liệu sai).", "err")
        return redirect(url_for("admin_rooms"))
    return render_template("admin_rooms.html", rows=q("SELECT * FROM rooms ORDER BY name"))


@app.route("/admin/equipment", methods=["GET", "POST"])
@roles("admin")
def admin_equipment():
    if request.method == "POST":
        f = request.form
        try:
            if f["op"] == "add":
                db().execute("INSERT INTO equipment(name,category,quantity,description) VALUES (?,?,?,?)",
                             (f["name"].strip(), f["category"].strip(), int(f["quantity"]), f.get("description")))
            elif f["op"] == "toggle":
                db().execute("UPDATE equipment SET is_active=1-is_active WHERE id=?", (int(f["id"]),))
            elif f["op"] == "qty":
                db().execute("UPDATE equipment SET quantity=?, broken_qty=MIN(broken_qty, ?) WHERE id=?",
                             (int(f["quantity"]), int(f["quantity"]), int(f["id"])))
            db().commit()
            flash("Đã lưu.", "ok")
        except (sqlite3.IntegrityError, ValueError):
            flash("Không lưu được (tên đã tồn tại hoặc số lượng sai).", "err")
        return redirect(url_for("admin_equipment"))
    return render_template("admin_equipment.html", rows=q("SELECT * FROM equipment ORDER BY name"))


@app.route("/admin/users", methods=["GET", "POST"])
@roles("admin")
def admin_users():
    if request.method == "POST":
        uid = int(request.form["id"])
        if uid == g.user["id"]:
            flash("Không thể tự thay đổi tài khoản của chính mình tại đây.", "err")
        else:
            op = request.form["op"]
            if op == "toggle":
                db().execute("UPDATE users SET is_active=1-is_active WHERE id=?", (uid,))
            elif op == "role" and request.form["role"] in ROLE_LABEL:
                db().execute("UPDATE users SET role=? WHERE id=?", (request.form["role"], uid))
            db().commit()
            flash("Đã cập nhật tài khoản.", "ok")
        return redirect(url_for("admin_users"))
    return render_template("admin_users.html", rows=q("SELECT * FROM users ORDER BY is_active, role, full_name"))


# ---------------------------------------------------------------- thống kê
@app.route("/admin/stats")
@roles("admin")
def admin_stats():
    try:
        d_to = datetime.strptime(request.args["to"], "%Y-%m-%d").date()
        d_from = datetime.strptime(request.args["from"], "%Y-%m-%d").date()
    except (KeyError, ValueError):
        d_to, d_from = date.today(), date.today() - timedelta(days=29)
    a, b = d_from.strftime("%Y-%m-%d 00:00"), (d_to + timedelta(days=1)).strftime("%Y-%m-%d 00:00")
    rooms = q("""SELECT r.name, COUNT(b.id) cnt,
                 ROUND(COALESCE(SUM((julianday(b.end_time)-julianday(b.start_time))*24),0),1) hours
                 FROM rooms r LEFT JOIN bookings b ON b.room_id=r.id AND b.status IN ('approved','done')
                   AND b.start_time>=? AND b.start_time<? GROUP BY r.id ORDER BY cnt DESC, r.name""", (a, b))
    equips = q("""SELECT e.name, COUNT(b.id) cnt, COALESCE(SUM(be.quantity),0) qty
                  FROM equipment e LEFT JOIN booking_equipment be ON be.equipment_id=e.id
                  LEFT JOIN bookings b ON b.id=be.booking_id AND b.status IN ('approved','done')
                    AND b.start_time>=? AND b.start_time<?
                  GROUP BY e.id ORDER BY cnt DESC, e.name""", (a, b))
    wd = {int(r["w"]): r["c"] for r in q("""SELECT strftime('%w',start_time) w, COUNT(*) c FROM bookings
                 WHERE status IN ('approved','done') AND start_time>=? AND start_time<? GROUP BY w""", (a, b))}
    by_day = [(WEEKDAYS[(i - 1) % 7], wd.get(i % 7, 0)) for i in range(1, 8)]   # Thứ 2 .. CN
    return render_template("admin_stats.html", rooms=rooms, equips=equips, by_day=by_day,
                           d_from=d_from, d_to=d_to,
                           max_room=max([r["cnt"] for r in rooms] + [1]),
                           max_eq=max([e["cnt"] for e in equips] + [1]),
                           max_day=max([c for _, c in by_day] + [1]))


@app.errorhandler(403)
def e403(_):
    if request.path.startswith("/api/"):
        return jsonify(error="forbidden", message="Không có quyền."), 403
    return render_template("error.html", code=403, msg="Bạn không có quyền vào trang này."), 403


@app.errorhandler(404)
def e404(_):
    if request.path.startswith("/api/"):
        return jsonify(error="not_found", message="Không tìm thấy."), 404
    return render_template("error.html", code=404, msg="Không tìm thấy trang hoặc dữ liệu."), 404


@app.errorhandler(400)
def e400(e):
    if request.path.startswith("/api/"):
        return jsonify(error="bad_request", message=str(getattr(e, "description", "Yêu cầu không hợp lệ."))), 400
    return render_template("error.html", code=400, msg=getattr(e, "description", "Yêu cầu không hợp lệ.")), 400


@app.errorhandler(405)
def e405(_):
    if request.path.startswith("/api/"):
        return jsonify(error="method_not_allowed", message="Phương thức không được hỗ trợ."), 405
    return render_template("error.html", code=405, msg="Phương thức không được hỗ trợ."), 405


# ---------------------------------------------------------------- API (xem api.py, docs/API.md)
import api  # noqa: E402

api.init(q=q, one=one, conn=db, parse_dt=parse_dt, monday_of=monday_of, create_booking=create_booking,
         STATUS_LABEL=STATUS_LABEL, OPEN_H=OPEN_H, CLOSE_H=CLOSE_H)
app.register_blueprint(api.bp)

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host=os.environ.get("HOST", "127.0.0.1"), port=5000)

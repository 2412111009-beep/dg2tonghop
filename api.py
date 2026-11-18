"""REST API (JSON) cho LabBook – xác thực bằng Bearer token.
Tài liệu: /api/docs  ·  Đặc tả: /api/v1/openapi.json  ·  Biện pháp bảo mật: docs/API.md (mục Bảo mật)

Tự tạo bảng api_tokens và api_audit (không sửa db.py). Dùng lại create_booking của app.py nên quy tắc
chống trùng lịch và ưu tiên giảng viên giống hệt giao diện web. Được nối vào app ở cuối app.py."""
import hashlib, os, secrets, sqlite3, time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, render_template_string, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db

bp = Blueprint("api", __name__)

# Các hàm dùng chung được app.py truyền vào (tránh import vòng khi chạy `python app.py`)
q = one = conn = parse_dt = monday_of = create_booking = None
STATUS_LABEL = {}
OPEN_H, CLOSE_H = 7, 21


def init(**deps):
    globals().update(deps)


V1 = "/api/v1"
# ---- cấu hình bảo mật ----------------------------------------------------------------------
TOKEN_HOURS = 12          # tuổi thọ tối đa của token
IDLE_MINUTES = 120        # không dùng quá thời gian này thì token tự hết hạn
MAX_TOKENS_PER_USER = 5   # mỗi tài khoản giữ tối đa 5 token, token cũ nhất bị thu hồi
FAIL_PER_PAIR = 5         # đăng nhập sai tối đa / (IP, email) / 15 phút
FAIL_PER_IP = 30          # đăng nhập sai tối đa / IP / 15 phút (chặn dò nhiều email)
FAIL_WINDOW = 900
RATE_PER_MIN = 120        # số lời gọi / phút / token
MAX_BODY = 64 * 1024      # kích thước JSON tối đa
MAX_TEXT = 500            # độ dài tối đa của mục đích, ghi chú
MAX_EQUIP_ITEMS = 20
MAX_QTY = 1000

# ---- bảng token (băm SHA-256) và nhật ký an ninh -------------------------------------------
_c = get_db()
if "pw_fp" not in [r[1] for r in _c.execute("PRAGMA table_info(api_tokens)")]:
    _c.execute("DROP TABLE IF EXISTS api_tokens")           # bản cũ thiếu cột bảo mật: buộc đăng nhập lại
_c.execute("""CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE,
  pw_fp TEXT NOT NULL,                  -- dấu vân tay mật khẩu lúc cấp: đổi mật khẩu thì token cũ vô hiệu
  expires_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')))""")
_c.execute("""CREATE TABLE IF NOT EXISTS api_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  user_id INTEGER, email TEXT, ip TEXT, event TEXT NOT NULL, detail TEXT)""")
_c.commit()
_c.close()

DUMMY_HASH = generate_password_hash("mat-khau-gia-de-chong-do-thoi-gian")   # cân bằng thời gian khi email không tồn tại

# ---- giới hạn tốc độ (bộ nhớ, 1 tiến trình) ------------------------------------------------
_HITS = defaultdict(deque)


def _prune(dq, now, window):
    while dq and now - dq[0] > window:
        dq.popleft()


def rate_hit(key, limit, window):
    """Ghi một lượt gọi. Trả (được_phép, số_giây_phải_chờ)."""
    now = time.time()
    if len(_HITS) > 5000:                                        # dọn khóa cũ để không phình bộ nhớ
        for k in [k for k, d in _HITS.items() if not d or now - d[-1] > 900]:
            _HITS.pop(k, None)
    dq = _HITS[key]
    _prune(dq, now, window)
    if len(dq) >= limit:
        return False, max(1, int(window - (now - dq[0])) + 1)
    dq.append(now)
    return True, 0


def rate_count(key, window):
    dq = _HITS.get(key)
    if not dq:
        return 0, 0
    now = time.time()
    _prune(dq, now, window)
    return len(dq), (max(1, int(window - (now - dq[0])) + 1) if dq else 0)


# ---- tiện ích -----------------------------------------------------------------------------
def err(status, code, message, retry=None):
    r = jsonify(error=code, message=message)
    r.status_code = status
    if retry:
        r.headers["Retry-After"] = str(retry)
    return r


def body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def now_s():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _fp(password_hash):
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def to_int(v):
    if isinstance(v, bool) or (isinstance(v, float) and not v.is_integer()):
        raise ValueError("không phải số nguyên")
    return int(v)


def audit(event, user_id=None, email=None, detail=None):
    try:
        conn().execute("INSERT INTO api_audit(user_id,email,ip,event,detail) VALUES (?,?,?,?,?)",
                       (user_id, email, request.remote_addr, event, (detail or "")[:200]))
        conn().commit()
    except Exception:
        current_app.logger.exception("Không ghi được nhật ký an ninh")


@bp.before_request
def guard():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            request.max_content_length = MAX_BODY              # chặn cả body không khai Content-Length
        except Exception:
            pass
        cl = request.content_length
        if cl and cl > MAX_BODY:
            return err(413, "payload_too_large", "Nội dung quá lớn (tối đa 64 KB).")
        if cl and not request.is_json:
            return err(415, "unsupported_media_type", "Hãy gửi JSON kèm Content-Type: application/json.")


@bp.after_app_request
def secure_headers(resp):
    if request.path.startswith("/api/"):
        h = resp.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
        h["Referrer-Policy"] = "no-referrer"
        h["X-Frame-Options"] = "DENY"
        h["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'" if request.path != "/api/docs" else
            "default-src 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; base-uri 'none'; frame-ancestors 'none'")
        if os.environ.get("COOKIE_SECURE") == "1":                # chạy sau HTTPS
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@bp.errorhandler(Exception)
def api_error(e):
    if isinstance(e, HTTPException):
        return err(e.code or 500, (e.name or "error").lower().replace(" ", "_"), e.description or "")
    current_app.logger.exception("Lỗi API không xử lý được")        # chi tiết chỉ ghi log, không trả cho client
    try:
        conn().rollback()
    except Exception:
        pass
    return err(500, "server_error", "Lỗi máy chủ, vui lòng thử lại sau.")


def api_auth(*allowed):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer ") or len(h) > 200:
                return err(401, "unauthorized", "Thiếu header Authorization: Bearer <token>.")
            row = one("""SELECT u.*, t.id AS tid, t.pw_fp AS tfp, t.last_used_at AS tlast
                         FROM api_tokens t JOIN users u ON u.id=t.user_id
                         WHERE t.token_hash=? AND t.expires_at>? AND u.is_active=1""",
                      (_hash(h[7:].strip()), now_s()))
            bad = row is None
            if row is not None:
                idle = datetime.now() - datetime.strptime(row["tlast"], "%Y-%m-%d %H:%M:%S")
                bad = row["tfp"] != _fp(row["password_hash"]) or idle > timedelta(minutes=IDLE_MINUTES)
                if bad:                                              # đổi mật khẩu hoặc để quá lâu: thu hồi luôn
                    conn().execute("DELETE FROM api_tokens WHERE id=?", (row["tid"],))
                    conn().commit()
            if bad:
                current_app.logger.warning("API: token không hợp lệ từ %s", request.remote_addr)
                return err(401, "invalid_token", "Token không hợp lệ hoặc đã hết hạn.")
            ok, wait = rate_hit(("tok", row["tid"]), RATE_PER_MIN, 60)
            if not ok:
                return err(429, "rate_limited", "Gọi quá nhanh, hãy thử lại sau ít giây.", retry=wait)
            if idle > timedelta(seconds=60):                         # chỉ ghi lại tối đa 1 lần/phút
                conn().execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (now_s(), row["tid"]))
                conn().commit()
            g.user, g.token_id = row, row["tid"]                     # API chỉ tin token, không tin cookie phiên
            if allowed and row["role"] not in allowed:
                audit("forbidden", row["id"], row["email"], request.method + " " + request.path)
                return err(403, "forbidden", "Vai trò của bạn không được dùng chức năng này.")
            return f(*a, **k)
        return w
    return deco


def user_json(u):
    return dict(id=u["id"], email=u["email"], full_name=u["full_name"], role=u["role"],
                group_name=u["group_name"], phone=u["phone"])


def page_args():
    try:
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        limit, offset = 50, 0
    return limit, offset


def booking_json(rows):
    ids = [r["id"] for r in rows]
    eq = {}
    if ids:
        for e in q(f"""SELECT be.booking_id, e.id, e.name, be.quantity FROM booking_equipment be
                       JOIN equipment e ON e.id=be.equipment_id
                       WHERE be.booking_id IN ({','.join('?' * len(ids))})""", ids):
            eq.setdefault(e["booking_id"], []).append(dict(id=e["id"], name=e["name"], quantity=e["quantity"]))
    return [dict(id=r["id"], status=r["status"], status_label=STATUS_LABEL[r["status"]],
                 user=dict(id=r["user_id"], full_name=r["uname"], role=r["urole"]),
                 room=dict(id=r["room_id"], name=r["rname"]) if r["room_id"] else None,
                 start=r["start_time"], end=r["end_time"], purpose=r["purpose"],
                 admin_note=r["admin_note"], equipment=eq.get(r["id"], []), created_at=r["created_at"])
            for r in rows]


BOOKING_SQL = """SELECT b.*, u.full_name uname, u.role urole, r.name rname FROM bookings b
                 JOIN users u ON u.id=b.user_id LEFT JOIN rooms r ON r.id=b.room_id"""


def get_booking(bid):
    rows = q(BOOKING_SQL + " WHERE b.id=?", (bid,))
    if not rows or (g.user["role"] != "admin" and rows[0]["user_id"] != g.user["id"]):
        return None                                   # người khác không biết yêu cầu có tồn tại
    return rows[0]


# ---- xác thực ------------------------------------------------------------------------------
@bp.route(f"{V1}/auth/login", methods=["POST"])
def api_login():
    d = body()
    email = str(d.get("email", ""))[:254].strip().lower()
    pw = str(d.get("password", ""))[:256]
    ip = request.remote_addr or "?"
    n1, w1 = rate_count(("fail", ip, email), FAIL_WINDOW)
    n2, w2 = rate_count(("failip", ip), FAIL_WINDOW)
    if n1 >= FAIL_PER_PAIR or n2 >= FAIL_PER_IP:
        audit("login_locked", None, email)
        return err(429, "too_many_attempts", "Sai quá nhiều lần, hãy thử lại sau ít phút.", retry=max(w1, w2))
    u = one("SELECT * FROM users WHERE email=?", (email,))
    good = check_password_hash(u["password_hash"] if u else DUMMY_HASH, pw)    # luôn tốn cùng một lượng thời gian
    if not u or not good:
        rate_hit(("fail", ip, email), 10**6, FAIL_WINDOW)
        rate_hit(("failip", ip), 10**6, FAIL_WINDOW)
        audit("login_failed", u["id"] if u else None, email)
        return err(401, "bad_credentials", "Email hoặc mật khẩu không đúng.")
    if not u["is_active"]:
        audit("login_inactive", u["id"], email)
        return err(403, "inactive", "Tài khoản đang chờ quản trị viên kích hoạt.")
    token = "lb_" + secrets.token_urlsafe(32)
    exp = (datetime.now() + timedelta(hours=TOKEN_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    c = conn()
    c.execute("DELETE FROM api_tokens WHERE expires_at<?", (now_s(),))
    old = c.execute("SELECT id FROM api_tokens WHERE user_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    for r in old[MAX_TOKENS_PER_USER - 1:]:                                   # giữ tối đa N token mỗi tài khoản
        c.execute("DELETE FROM api_tokens WHERE id=?", (r["id"],))
    c.execute("INSERT INTO api_tokens(user_id,token_hash,pw_fp,expires_at,last_used_at,ip) VALUES (?,?,?,?,?,?)",
              (u["id"], _hash(token), _fp(u["password_hash"]), exp, now_s(), ip))
    c.commit()
    _HITS.pop(("fail", ip, email), None)
    audit("login_ok", u["id"], email)
    return jsonify(token=token, token_type="Bearer", expires_at=exp, user=user_json(u))


@bp.route(f"{V1}/auth/logout", methods=["POST"])
@api_auth()
def api_logout():
    conn().execute("DELETE FROM api_tokens WHERE id=?", (g.token_id,))
    conn().commit()
    audit("logout", g.user["id"], g.user["email"])
    return jsonify(ok=True)


@bp.route(f"{V1}/auth/logout-all", methods=["POST"])
@api_auth()
def api_logout_all():
    cur = conn().execute("DELETE FROM api_tokens WHERE user_id=?", (g.user["id"],))
    conn().commit()
    audit("logout_all", g.user["id"], g.user["email"], f"{cur.rowcount} token")
    return jsonify(ok=True, revoked=cur.rowcount)


@bp.route(f"{V1}/me")
@api_auth()
def api_me():
    return jsonify(user_json(g.user))


# ---- danh mục ------------------------------------------------------------------------------
@bp.route(f"{V1}/rooms")
@api_auth()
def api_rooms():
    rows = q("SELECT * FROM rooms" + ("" if g.user["role"] == "admin" else " WHERE is_active=1") + " ORDER BY name")
    return jsonify(items=[dict(id=r["id"], name=r["name"], location=r["location"], capacity=r["capacity"],
                               is_active=bool(r["is_active"])) for r in rows])


@bp.route(f"{V1}/equipment")
@api_auth()
def api_equipment():
    rows = q("SELECT * FROM equipment" + ("" if g.user["role"] == "admin" else " WHERE is_active=1") + " ORDER BY name")
    return jsonify(items=[dict(id=r["id"], name=r["name"], category=r["category"], total=r["quantity"],
                               broken=r["broken_qty"], available=r["quantity"] - r["broken_qty"],
                               is_active=bool(r["is_active"])) for r in rows])


# ---- lịch tuần -----------------------------------------------------------------------------
@bp.route(f"{V1}/schedule")
@api_auth()
def api_schedule():
    kind = "equip" if request.args.get("kind") == "equip" else "room"
    try:
        oid = int(request.args.get("id", ""))
        monday = monday_of(datetime.strptime(request.args.get("week", ""), "%Y-%m-%d").date()) \
            if request.args.get("week") else monday_of(datetime.now().date())
    except ValueError:
        return err(400, "invalid_input", "id phải là số, week có dạng YYYY-MM-DD.")
    obj = one("SELECT id, name FROM rooms WHERE id=?" if kind == "room" else "SELECT id, name FROM equipment WHERE id=?", (oid,))
    if not obj:
        return err(404, "not_found", "Không tìm thấy phòng/thiết bị.")
    a, b = monday.strftime("%Y-%m-%d 00:00"), (monday + timedelta(days=7)).strftime("%Y-%m-%d 00:00")
    if kind == "room":
        rows = q("""SELECT b.*, u.full_name, u.role, NULL qty FROM bookings b JOIN users u ON u.id=b.user_id
                    WHERE b.room_id=? AND b.status IN ('pending','approved') AND b.start_time<? AND b.end_time>?
                    ORDER BY b.start_time""", (oid, b, a))
    else:
        rows = q("""SELECT b.*, u.full_name, u.role, be.quantity qty FROM bookings b
                    JOIN booking_equipment be ON be.booking_id=b.id JOIN users u ON u.id=b.user_id
                    WHERE be.equipment_id=? AND b.status IN ('pending','approved') AND b.start_time<? AND b.end_time>?
                    ORDER BY b.start_time""", (oid, b, a))
    me = g.user
    slots = [dict(booking_id=r["id"], start=r["start_time"], end=r["end_time"], status=r["status"], quantity=r["qty"],
                  by_role=r["role"],
                  by=r["full_name"] if me["role"] == "admin" or r["user_id"] == me["id"] else None) for r in rows]
    return jsonify(kind=kind, id=obj["id"], name=obj["name"], week_start=monday.isoformat(),
                   week_end=(monday + timedelta(days=6)).isoformat(), open_hour=OPEN_H, close_hour=CLOSE_H, slots=slots)


# ---- yêu cầu đặt ---------------------------------------------------------------------------
@bp.route(f"{V1}/bookings", methods=["GET"])
@api_auth()
def api_bookings():
    limit, offset = page_args()
    where, args = [], []
    if g.user["role"] != "admin":
        where.append("b.user_id=?"); args.append(g.user["id"])
    st = request.args.get("status")
    if st:
        if st not in STATUS_LABEL:
            return err(400, "invalid_input", "status phải là một trong: " + ", ".join(STATUS_LABEL))
        where.append("b.status=?"); args.append(st)
    cond = (" WHERE " + " AND ".join(where)) if where else ""
    total = one("SELECT COUNT(*) c FROM bookings b" + cond, args)["c"]
    rows = q(BOOKING_SQL + cond + " ORDER BY b.start_time DESC LIMIT ? OFFSET ?", (*args, limit, offset))
    return jsonify(total=total, limit=limit, offset=offset, items=booking_json(rows))


@bp.route(f"{V1}/bookings/<int:bid>", methods=["GET"])
@api_auth()
def api_booking_detail(bid):
    r = get_booking(bid)
    return jsonify(booking_json([r])[0]) if r else err(404, "not_found", "Không tìm thấy yêu cầu.")


@bp.route(f"{V1}/bookings", methods=["POST"])
@api_auth("student", "lecturer")
def api_booking_create():
    if create_booking is None:
        return err(501, "not_available", "Chức năng đặt lịch chưa sẵn sàng.")
    d = body()
    try:
        room_id = d.get("room_id")
        room_id = to_int(room_id) if room_id not in (None, "") else None
        start, end = parse_dt(str(d["date"]), str(d["start"])), parse_dt(str(d["date"]), str(d["end"]))
        items = d.get("equipment") or []
        purpose = d.get("purpose", "")
        if not isinstance(items, list) or not isinstance(purpose, str):
            raise ValueError("sai kiểu dữ liệu")
    except (ValueError, TypeError, KeyError):
        return err(400, "invalid_input", "Cần date (YYYY-MM-DD), start, end (HH:MM); equipment là danh sách {id, quantity}.")
    if len(items) > MAX_EQUIP_ITEMS or len(purpose) > MAX_TEXT:
        return err(422, "invalid_input", f"Tối đa {MAX_EQUIP_ITEMS} thiết bị và mục đích tối đa {MAX_TEXT} ký tự.")
    want = {}
    try:
        for x in items:
            eid, qty = to_int(x["id"]), to_int(x["quantity"])
            want[eid] = want.get(eid, 0) + qty
    except (ValueError, TypeError, KeyError):
        return err(400, "invalid_input", "Mỗi thiết bị cần id và quantity là số nguyên.")
    if not room_id and not want:
        return err(422, "invalid_input", "Hãy chọn ít nhất một phòng hoặc một thiết bị.")
    if start >= end:
        return err(422, "invalid_time", "Giờ kết thúc phải sau giờ bắt đầu.")
    if start < datetime.now():
        return err(422, "invalid_time", "Không thể đặt vào thời điểm đã qua.")
    if start.hour < OPEN_H or end > end.replace(hour=CLOSE_H, minute=0):
        return err(422, "invalid_time", f"Phòng lab mở từ {OPEN_H}:00 đến {CLOSE_H}:00.")
    if room_id and not one("SELECT 1 FROM rooms WHERE id=? AND is_active=1", (room_id,)):
        return err(404, "not_found", "Phòng không tồn tại hoặc đang tạm ngưng.")
    for eid, qty in want.items():
        if qty <= 0 or qty > MAX_QTY or not one("SELECT 1 FROM equipment WHERE id=? AND is_active=1", (eid,)):
            return err(422, "invalid_input", f"Thiết bị {eid} không tồn tại hoặc số lượng không hợp lệ.")
    try:
        bid, bumped = create_booking(g.user, room_id, start.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M"),
                                     purpose.strip(), list(want.items()))
    except sqlite3.IntegrityError as e:
        m = str(e)
        if "ROOM_CONFLICT" in m:
            return err(409, "room_conflict", "Phòng đã có yêu cầu khác trong khung giờ này.")
        if "EQUIP_CONFLICT" in m:
            return err(409, "equipment_conflict", "Một thiết bị không đủ số lượng trong khung giờ này.")
        current_app.logger.warning("API đặt lịch lỗi CSDL: %s", m)
        return err(400, "db_error", "Không lưu được yêu cầu.")
    resp = booking_json([get_booking(bid)])[0]
    resp["replaced_booking_ids"] = bumped
    r = jsonify(resp)
    r.status_code = 201
    return r


@bp.route(f"{V1}/bookings/<int:bid>/cancel", methods=["POST"])
@api_auth("student", "lecturer")
def api_booking_cancel(bid):
    b = one("SELECT * FROM bookings WHERE id=? AND user_id=?", (bid, g.user["id"]))
    if not b:
        return err(404, "not_found", "Không tìm thấy yêu cầu.")
    if b["status"] not in ("pending", "approved"):
        return err(409, "invalid_state", "Chỉ hủy được yêu cầu đang chờ duyệt hoặc đã duyệt.")
    if one("SELECT 1 FROM loans WHERE booking_id=? AND returned_at IS NULL", (bid,)):
        return err(409, "loan_open", "Thiết bị đang được mượn, hãy trả trước khi hủy.")
    conn().execute("UPDATE bookings SET status='cancelled' WHERE id=?", (bid,))
    conn().commit()
    return jsonify(booking_json([get_booking(bid)])[0])


@bp.route(f"{V1}/admin/bookings/<int:bid>/<action>", methods=["POST"])
@api_auth("admin")
def api_admin_booking_action(bid, action):
    b = one("SELECT * FROM bookings WHERE id=?", (bid,))
    if not b:
        return err(404, "not_found", "Không tìm thấy yêu cầu.")
    new = {"approve": "approved", "reject": "rejected", "done": "done"}.get(action)
    allowed = {"approved": ("pending",), "rejected": ("pending", "approved"), "done": ("approved",)}
    if not new:
        return err(404, "not_found", "action phải là approve, reject hoặc done.")
    if b["status"] not in allowed[new]:
        return err(409, "invalid_state", f"Không thể chuyển từ “{b['status']}” sang “{new}”.")
    if new == "done" and one("SELECT 1 FROM loans WHERE booking_id=? AND returned_at IS NULL", (bid,)):
        return err(409, "loan_open", "Còn thiết bị chưa trả, chưa thể hoàn tất.")
    note = body().get("note", "")
    if not isinstance(note, str) or len(note) > MAX_TEXT:
        return err(422, "invalid_input", f"note phải là chuỗi tối đa {MAX_TEXT} ký tự.")
    conn().execute("UPDATE bookings SET status=?, admin_note=? WHERE id=?", (new, note.strip() or b["admin_note"], bid))
    conn().commit()
    audit("booking_" + action, g.user["id"], g.user["email"], f"#{bid}")
    return jsonify(booking_json([get_booking(bid)])[0])


# ---- thống kê ------------------------------------------------------------------------------
@bp.route(f"{V1}/admin/stats/usage")
@api_auth("admin")
def api_stats():
    try:
        d_to = datetime.strptime(request.args["to"], "%Y-%m-%d").date()
        d_from = datetime.strptime(request.args["from"], "%Y-%m-%d").date()
    except KeyError:
        d_to = datetime.now().date(); d_from = d_to - timedelta(days=29)
    except ValueError:
        return err(400, "invalid_input", "from và to có dạng YYYY-MM-DD.")
    a, b = d_from.strftime("%Y-%m-%d 00:00"), (d_to + timedelta(days=1)).strftime("%Y-%m-%d 00:00")
    rooms = q("""SELECT r.id, r.name, COUNT(b.id) bookings,
                 ROUND(COALESCE(SUM((julianday(b.end_time)-julianday(b.start_time))*24),0),1) hours
                 FROM rooms r LEFT JOIN bookings b ON b.room_id=r.id AND b.status IN ('approved','done')
                   AND b.start_time>=? AND b.start_time<? GROUP BY r.id ORDER BY bookings DESC, r.name""", (a, b))
    equips = q("""SELECT e.id, e.name, COUNT(b.id) bookings, COALESCE(SUM(be.quantity),0) units
                  FROM equipment e LEFT JOIN booking_equipment be ON be.equipment_id=e.id
                  LEFT JOIN bookings b ON b.id=be.booking_id AND b.status IN ('approved','done')
                    AND b.start_time>=? AND b.start_time<? GROUP BY e.id ORDER BY bookings DESC, e.name""", (a, b))
    return jsonify(**{"from": d_from.isoformat(), "to": d_to.isoformat()},
                   rooms=[dict(r) for r in rooms], equipment=[dict(e) for e in equips])


@bp.route(f"{V1}/admin/audit")
@api_auth("admin")
def api_audit():
    limit, offset = page_args()
    ev = request.args.get("event")
    cond, args = ("WHERE event=?", [ev]) if ev else ("", [])
    total = one("SELECT COUNT(*) c FROM api_audit " + cond, args)["c"]
    rows = q("SELECT * FROM api_audit " + cond + " ORDER BY id DESC LIMIT ? OFFSET ?", (*args, limit, offset))
    return jsonify(total=total, limit=limit, offset=offset, items=[dict(r) for r in rows])


# ---- tài liệu ------------------------------------------------------------------------------
ENDPOINTS = [
    ("POST", "/auth/login", "—", "Đăng nhập, nhận token (hiệu lực tối đa 12 giờ, hết hạn nếu 2 giờ không dùng). Sai nhiều lần bị khóa tạm.",
     '{"email": "sv@lab.local", "password": "sv123456"}'),
    ("POST", "/auth/logout", "đã đăng nhập", "Hủy token hiện tại.", None),
    ("POST", "/auth/logout-all", "đã đăng nhập", "Hủy mọi token của tài khoản (dùng khi nghi lộ token).", None),
    ("GET", "/me", "đã đăng nhập", "Thông tin tài khoản đang dùng token.", None),
    ("GET", "/rooms", "đã đăng nhập", "Danh sách phòng.", None),
    ("GET", "/equipment", "đã đăng nhập", "Danh sách thiết bị kèm số lượng khả dụng.", None),
    ("GET", "/schedule?kind=room|equip&id=1&week=2026-11-16", "đã đăng nhập",
     "Các khung giờ đã đặt trong tuần của một phòng/thiết bị. Tên người đặt chỉ hiện với quản trị hoặc chính chủ.", None),
    ("GET", "/bookings?status=&limit=50&offset=0", "đã đăng nhập", "Yêu cầu của tôi (quản trị thấy tất cả).", None),
    ("GET", "/bookings/<int:bid>", "đã đăng nhập", "Chi tiết một yêu cầu.", None),
    ("POST", "/bookings", "giảng viên, sinh viên",
     "Tạo yêu cầu. Trùng giờ trả 409. Giảng viên có thể thay thế yêu cầu chưa duyệt của sinh viên (xem replaced_booking_ids).",
     '{"room_id": 1, "date": "2026-11-25", "start": "09:00", "end": "11:00", "purpose": "Đồ án IoT", "equipment": [{"id": 2, "quantity": 2}]}'),
    ("POST", "/bookings/<int:bid>/cancel", "giảng viên, sinh viên", "Hủy yêu cầu của mình.", None),
    ("POST", "/admin/bookings/<int:bid>/<action>", "quản trị", "action = approve | reject | done. Có thể kèm note.", '{"note": "Lý do (tùy chọn)"}'),
    ("GET", "/admin/stats/usage?from=2026-11-01&to=2026-11-30", "quản trị", "Tần suất sử dụng phòng và thiết bị.", None),
    ("GET", "/admin/audit?event=&limit=50&offset=0", "quản trị", "Nhật ký an ninh: đăng nhập thành công/sai/bị khóa, truy cập trái quyền, duyệt yêu cầu.", None),
]


@bp.route(f"{V1}/openapi.json")
def api_openapi():
    paths = {}
    for method, path, auth, desc, example in ENDPOINTS:
        clean = path.split("?")[0].replace("<int:bid>", "{bid}").replace("<action>", "{action}")
        op = {"summary": desc, "responses": {"200": {"description": "Thành công"}}}
        if auth != "—":
            op["security"] = [{"bearer": []}]
        paths.setdefault(clean, {})[method.lower()] = op
    return jsonify(openapi="3.0.3", info={"title": "LabBook API", "version": "1.1"}, servers=[{"url": V1}],
                   components={"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}, paths=paths)


@bp.route("/api/docs")
def api_docs():
    return render_template_string(DOCS_HTML, endpoints=ENDPOINTS, v1=V1)


DOCS_HTML = """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tài liệu API · LabBook</title><link rel="stylesheet" href="/static/style.css">
<style>pre{background:#17262A;color:#E6F0EE;padding:.9rem 1rem;border-radius:6px;overflow-x:auto;font-size:.85rem;margin:.4rem 0}
code{font-family:Consolas,monospace;font-size:.88rem}.m{font-weight:700;display:inline-block;min-width:3.6rem}.GET{color:#2F7D4F}.POST{color:#B7791F}</style></head>
<body class="role-student"><main class="main" style="margin:auto">
<h1>LabBook API</h1><p class="sub">Địa chỉ gốc <code>{{ v1 }}</code> · dữ liệu JSON · đặc tả: <a href="{{ v1 }}/openapi.json">openapi.json</a></p>
<div class="card"><h2>Cách dùng</h2>
<p>1. Gọi <code>POST {{ v1 }}/auth/login</code> để lấy <code>token</code>. 2. Gửi kèm mọi yêu cầu sau đó header <code>Authorization: Bearer &lt;token&gt;</code>.</p>
<pre>curl -X POST http://localhost:5000{{ v1 }}/auth/login -H "Content-Type: application/json" -d "{\"email\":\"sv@lab.local\",\"password\":\"sv123456\"}"
curl http://localhost:5000{{ v1 }}/rooms -H "Authorization: Bearer &lt;token&gt;"</pre>
<p class="muted">Lỗi trả về dạng <code>{"error": "mã", "message": "giải thích"}</code> kèm mã HTTP 400, 401, 403, 404, 409, 422 hoặc 429.</p></div>
<div class="card"><h2>Bảo mật</h2><ul style="margin:0;padding-left:1.2rem;line-height:1.7">
<li>Token ngẫu nhiên 256 bit, chỉ lưu <b>băm SHA-256</b>; hiệu lực tối đa 12 giờ, tự hết hạn nếu 2 giờ không dùng; tối đa 5 token mỗi tài khoản.</li>
<li><b>Đổi mật khẩu hoặc khóa tài khoản thì mọi token cũ mất hiệu lực ngay.</b> Có <code>/auth/logout-all</code> khi nghi lộ token.</li>
<li>Chống dò mật khẩu: sai 5 lần/15 phút với một email, hoặc 30 lần/IP, sẽ bị khóa tạm (429 kèm <code>Retry-After</code>). Đăng nhập tốn thời gian như nhau dù email có tồn tại hay không.</li>
<li>Giới hạn 120 lời gọi/phút/token; JSON tối đa 64 KB và bắt buộc <code>Content-Type: application/json</code>; kiểm tra kiểu và độ dài mọi trường.</li>
<li>Phân quyền theo vai trò và theo chủ sở hữu (không xem được yêu cầu của người khác); phản hồi lỗi không lộ chi tiết nội bộ.</li>
<li>Header an toàn (<code>nosniff</code>, <code>no-store</code>, CSP, <code>X-Frame-Options</code>, HSTS khi chạy HTTPS) và nhật ký an ninh cho quản trị.</li>
<li><b>Chỉ dùng qua HTTPS khi triển khai thật</b>, vì token đi trong header.</li></ul></div>
<div class="card tw"><table><tr><th>Phương thức</th><th>Đường dẫn</th><th>Quyền</th><th>Mô tả</th></tr>
{% for m, p, a, d, ex in endpoints %}<tr><td><span class="m {{ m }}">{{ m }}</span></td><td><code>{{ v1 }}{{ p }}</code></td><td>{{ a }}</td>
<td>{{ d }}{% if ex %}<pre>{{ ex }}</pre>{% endif %}</td></tr>{% endfor %}</table></div>
</main></body></html>
"""

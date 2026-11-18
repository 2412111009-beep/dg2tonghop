"""Kiểm thử API. Chạy:  python tests/test_api.py   (dùng CSDL tạm, không đụng dữ liệu thật)"""
import os, sys, tempfile
os.environ["LABBOOK_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from datetime import date, timedelta
from werkzeug.security import generate_password_hash
import app as A

c = A.app.test_client()
V = "/api/v1"
DAY = (date.today() + timedelta(days=3)).isoformat()
ok = 0


def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    ok += 1


def login(email, pw):
    r = c.post(f"{V}/auth/login", json={"email": email, "password": pw})
    return r, (r.get_json() or {}).get("token")


def H(t):
    return {"Authorization": f"Bearer {t}"}


cn = A.get_db()
cn.execute("INSERT INTO users(email,password_hash,full_name,role) VALUES ('sv2@lab.local',?, 'Sinh viên 2','student')",
           (generate_password_hash("sv2pass"),))
cn.commit(); cn.close()

check("không token -> 401", c.get(f"{V}/me").status_code == 401)
check("token sai -> 401", c.get(f"{V}/me", headers=H("lb_sai")).status_code == 401)
r, _ = login("sv@lab.local", "sai")
check("sai mật khẩu -> 401", r.status_code == 401)
r, sv = login("sv@lab.local", "sv123456")
check("đăng nhập -> có token", r.status_code == 200 and sv.startswith("lb_"))
check("token lưu dạng băm", A.get_db().execute("SELECT COUNT(*) FROM api_tokens WHERE token_hash=?", (sv,)).fetchone()[0] == 0)
_, gv = login("gv@lab.local", "gv123456")
_, ad = login("admin@lab.local", "admin123")
_, sv2 = login("sv2@lab.local", "sv2pass")

check("/me", c.get(f"{V}/me", headers=H(sv)).get_json()["role"] == "student")
check("rooms", len(c.get(f"{V}/rooms", headers=H(sv)).get_json()["items"]) == 3)
eq = c.get(f"{V}/equipment", headers=H(sv)).get_json()["items"]
check("equipment có available", eq[0]["available"] == eq[0]["total"])
check("POST không cần CSRF (JSON)", c.post(f"{V}/auth/login", json={}).status_code == 401)

body = dict(room_id=1, date=DAY, start="09:00", end="11:00", purpose="Đồ án", equipment=[{"id": 2, "quantity": 2}])
r = c.post(f"{V}/bookings", json=body, headers=H(sv))
check("sinh viên đặt -> 201", r.status_code == 201 and r.get_json()["status"] == "pending")
b1 = r.get_json()["id"]
r = c.post(f"{V}/bookings", json=dict(body, start="10:00", end="12:00", equipment=[]), headers=H(sv2))
check("trùng phòng -> 409", r.status_code == 409 and r.get_json()["error"] == "room_conflict")
r = c.post(f"{V}/bookings", json=dict(date=DAY, start="09:30", end="10:30", equipment=[{"id": 2, "quantity": 9}]), headers=H(sv2))
check("thiết bị vượt số lượng -> 409", r.status_code == 409 and r.get_json()["error"] == "equipment_conflict")
check("giờ ngược -> 422", c.post(f"{V}/bookings", json=dict(body, start="12:00", end="10:00"), headers=H(sv2)).status_code == 422)
check("thiếu trường -> 400", c.post(f"{V}/bookings", json={"room_id": 1}, headers=H(sv2)).status_code == 400)
check("quản trị không được đặt -> 403", c.post(f"{V}/bookings", json=body, headers=H(ad)).status_code == 403)

r = c.post(f"{V}/bookings", json=dict(body, equipment=[{"id": 2, "quantity": 10}]), headers=H(gv))
check("giảng viên thay thế yêu cầu chưa duyệt", r.status_code == 201 and r.get_json()["replaced_booking_ids"] == [b1])
b2 = r.get_json()["id"]
check("yêu cầu cũ thành bumped", c.get(f"{V}/bookings/{b1}", headers=H(sv)).get_json()["status"] == "bumped")
check("người khác không xem được -> 404", c.get(f"{V}/bookings/{b2}", headers=H(sv)).status_code == 404)
check("danh sách chỉ của mình", c.get(f"{V}/bookings", headers=H(sv)).get_json()["total"] == 1)
check("quản trị thấy tất cả", c.get(f"{V}/bookings", headers=H(ad)).get_json()["total"] == 2)
check("lọc theo status", c.get(f"{V}/bookings?status=pending", headers=H(ad)).get_json()["total"] == 1)
check("status sai -> 400", c.get(f"{V}/bookings?status=abc", headers=H(ad)).status_code == 400)

check("sinh viên gọi API admin -> 403", c.post(f"{V}/admin/bookings/{b2}/approve", headers=H(sv)).status_code == 403)
r = c.post(f"{V}/admin/bookings/{b2}/approve", json={"note": "ok"}, headers=H(ad))
check("admin duyệt", r.status_code == 200 and r.get_json()["status"] == "approved")
check("duyệt lại -> 409", c.post(f"{V}/admin/bookings/{b2}/approve", headers=H(ad)).status_code == 409)
r = c.post(f"{V}/bookings", json=dict(body, equipment=[]), headers=H(sv))
check("trùng yêu cầu đã duyệt -> 409", r.status_code == 409)

s = c.get(f"{V}/schedule?kind=room&id=1&week={DAY}", headers=H(sv)).get_json()
check("lịch tuần có khung giờ", len(s["slots"]) == 1 and s["slots"][0]["by"] is None)
check("quản trị thấy tên người đặt", c.get(f"{V}/schedule?kind=room&id=1&week={DAY}", headers=H(ad)).get_json()["slots"][0]["by"] == "Đỗ Văn Tuyên")
check("lịch thiết bị", c.get(f"{V}/schedule?kind=equip&id=2&week={DAY}", headers=H(ad)).get_json()["slots"][0]["quantity"] == 10)
check("lịch id sai -> 404", c.get(f"{V}/schedule?kind=room&id=99", headers=H(sv)).status_code == 404)

r = c.post(f"{V}/bookings", json=dict(date=DAY, start="14:00", end="15:00", room_id=2), headers=H(sv))
b3 = r.get_json()["id"]
r = c.post(f"{V}/bookings/{b3}/cancel", headers=H(sv))
check("hủy yêu cầu của mình", r.status_code == 200 and r.get_json()["status"] == "cancelled")
check("hủy yêu cầu của người khác -> 404", c.post(f"{V}/bookings/{b2}/cancel", headers=H(sv)).status_code == 404)

END = (date.today() + timedelta(days=10)).isoformat()
st = c.get(f"{V}/admin/stats/usage?from={date.today().isoformat()}&to={END}", headers=H(ad)).get_json()
check("thống kê", st["rooms"][0]["bookings"] == 1 and "from" in st)
check("thống kê chặn sinh viên", c.get(f"{V}/admin/stats/usage", headers=H(sv)).status_code == 403)

check("openapi.json", c.get(f"{V}/openapi.json").get_json()["openapi"].startswith("3."))
check("trang /api/docs", c.get("/api/docs").status_code == 200)
check("404 trả JSON", c.get(f"{V}/khong-co", headers=H(sv)).get_json()["error"] == "not_found")
check("405 trả JSON", c.put(f"{V}/rooms", headers=H(sv)).get_json()["error"] == "method_not_allowed")

check("đăng xuất", c.post(f"{V}/auth/logout", headers=H(sv)).status_code == 200)
check("token sau đăng xuất mất hiệu lực", c.get(f"{V}/me", headers=H(sv)).status_code == 401)
for _ in range(5):
    login("sv2@lab.local", "sai")
check("sai quá 5 lần -> 429", login("sv2@lab.local", "sv2pass")[0].status_code == 429)
# ======================== BẢO MẬT ========================
import hashlib
import api as API
r = c.get(f"{V}/rooms", headers=H(ad))
check("header an toàn", r.headers["X-Content-Type-Options"] == "nosniff" and "no-store" in r.headers["Cache-Control"]
      and "default-src 'none'" in r.headers["Content-Security-Policy"] and r.headers["X-Frame-Options"] == "DENY")
check("không có HSTS khi chưa bật HTTPS", "Strict-Transport-Security" not in r.headers)
os.environ["COOKIE_SECURE"] = "1"
check("có HSTS khi chạy HTTPS", "Strict-Transport-Security" in c.get(f"{V}/rooms", headers=H(ad)).headers)
os.environ.pop("COOKIE_SECURE")

a1 = c.post(f"{V}/auth/login", json={"email": "khong-ton-tai@lab.local", "password": "x"})
a2 = c.post(f"{V}/auth/login", json={"email": "gv@lab.local", "password": "x"})
check("không lộ email có tồn tại hay không", a1.status_code == a2.status_code == 401 and a1.get_json() == a2.get_json())
check("form-encoded -> 415", c.post(f"{V}/auth/login", data="email=a&password=b",
      content_type="application/x-www-form-urlencoded").status_code == 415)
check("body quá lớn -> 413", c.post(f"{V}/auth/login", data="x" * 70000, content_type="application/json").status_code == 413)

check("id kiểu bool -> 400", c.post(f"{V}/bookings", json=dict(date=DAY, start="14:00", end="15:00", equipment=[{"id": True, "quantity": 1}]), headers=H(gv)).status_code == 400)
check("mục đích quá dài -> 422", c.post(f"{V}/bookings", json=dict(body, purpose="x" * 501), headers=H(gv)).status_code == 422)
check("quá 20 thiết bị -> 422", c.post(f"{V}/bookings", json=dict(body, equipment=[{"id": 1, "quantity": 1}] * 21), headers=H(gv)).status_code == 422)
check("số lượng 1001 -> 422", c.post(f"{V}/bookings", json=dict(date=DAY, start="16:00", end="17:00", equipment=[{"id": 1, "quantity": 1001}]), headers=H(gv)).status_code == 422)

cn = A.get_db()
cn.execute("INSERT INTO users(email,password_hash,full_name,role) VALUES ('sec@lab.local',?, 'Người kiểm thử','student')",
           (generate_password_hash("secpass1"),))
cn.commit(); cn.close()

toks = [login("sec@lab.local", "secpass1")[1] for _ in range(6)]
check("tối đa 5 token: token cũ nhất bị thu hồi", c.get(f"{V}/me", headers=H(toks[0])).status_code == 401
      and c.get(f"{V}/me", headers=H(toks[5])).status_code == 200)
cn = A.get_db()
check("DB chỉ có 5 token", cn.execute("SELECT COUNT(*) FROM api_tokens WHERE user_id=(SELECT id FROM users WHERE email='sec@lab.local')").fetchone()[0] == 5)
cn.close()
r = c.post(f"{V}/auth/logout-all", headers=H(toks[5]))
check("logout-all thu hồi mọi token", r.get_json()["revoked"] == 5 and c.get(f"{V}/me", headers=H(toks[4])).status_code == 401)

_, t = login("sec@lab.local", "secpass1")
cn = A.get_db()
cn.execute("UPDATE users SET password_hash=? WHERE email='sec@lab.local'", (generate_password_hash("matkhaumoi1"),))
cn.commit(); cn.close()
check("đổi mật khẩu -> token cũ vô hiệu", c.get(f"{V}/me", headers=H(t)).status_code == 401)

_, t = login("sec@lab.local", "matkhaumoi1")
cn = A.get_db()
cn.execute("UPDATE api_tokens SET last_used_at='2000-01-01 00:00:00' WHERE token_hash=?", (hashlib.sha256(t.encode()).hexdigest(),))
cn.commit(); cn.close()
check("không dùng quá lâu -> token hết hạn", c.get(f"{V}/me", headers=H(t)).status_code == 401)

_, t = login("sec@lab.local", "matkhaumoi1")
cn = A.get_db()
cn.execute("UPDATE users SET is_active=0 WHERE email='sec@lab.local'"); cn.commit(); cn.close()
check("khóa tài khoản -> token vô hiệu", c.get(f"{V}/me", headers=H(t)).status_code == 401)
cn = A.get_db()
cn.execute("UPDATE users SET is_active=1 WHERE email='sec@lab.local'"); cn.commit(); cn.close()

_, t = login("sec@lab.local", "matkhaumoi1")
codes = [c.get(f"{V}/me", headers=H(t)).status_code for _ in range(121)]
r = c.get(f"{V}/me", headers=H(t))
check("giới hạn 120 lời gọi/phút/token", codes[:120] == [200] * 120 and codes[120] == 429 and "Retry-After" in r.headers)

_, t2 = login("sec@lab.local", "matkhaumoi1")
check("sinh viên gọi nhật ký an ninh -> 403", c.get(f"{V}/admin/audit", headers=H(t2)).status_code == 403)
au = c.get(f"{V}/admin/audit?limit=200", headers=H(ad)).get_json()
ev = {i["event"] for i in au["items"]}
check("nhật ký ghi đủ sự kiện", {"login_ok", "login_failed", "forbidden", "login_locked"} <= ev)
check("nhật ký không chứa mật khẩu/token", not any("secpass1" in str(i) or "lb_" in str(i) for i in au["items"]))
check("lọc nhật ký theo event", all(i["event"] == "forbidden" for i in c.get(f"{V}/admin/audit?event=forbidden", headers=H(ad)).get_json()["items"]))

orig = API.q
API.q = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bi-mat-noi-bo-xyz"))
r = c.get(f"{V}/rooms", headers=H(ad))
API.q = orig
check("lỗi nội bộ -> 500 JSON, không lộ chi tiết", r.status_code == 500 and r.get_json()["error"] == "server_error" and "bi-mat" not in r.get_data(as_text=True))

for i in range(30):
    login(f"doman{i}@x.vn", "sai")
r, _ = login("admin@lab.local", "admin123")
check("dò nhiều email từ một IP -> 429", r.status_code == 429 and "Retry-After" in r.headers)
print(f"\n{ok} kiểm thử đạt")

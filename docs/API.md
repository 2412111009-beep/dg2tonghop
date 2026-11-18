# LabBook API (v1)

Địa chỉ gốc: `http://localhost:5000/api/v1` · dữ liệu JSON · xem nhanh tại **http://localhost:5000/api/docs**
Đặc tả OpenAPI: `/api/v1/openapi.json` (nhập được vào Postman hoặc Swagger Editor).

## Xác thực
1. `POST /auth/login` với email và mật khẩu, nhận `token` (tối đa 12 giờ).
2. Mọi yêu cầu sau gửi kèm header `Authorization: Bearer <token>`. Không bao giờ đưa token vào URL.
3. Hết việc thì `POST /auth/logout`; nghi lộ token thì `POST /auth/logout-all`.

## Danh sách
| Phương thức | Đường dẫn | Quyền |
|---|---|---|
| POST | `/auth/login` | — |
| POST | `/auth/logout`, `/auth/logout-all` | đã đăng nhập |
| GET | `/me` | đã đăng nhập |
| GET | `/rooms`, `/equipment` | đã đăng nhập |
| GET | `/schedule?kind=room\|equip&id=&week=YYYY-MM-DD` | đã đăng nhập |
| GET | `/bookings?status=&limit=&offset=` | đã đăng nhập (quản trị thấy tất cả) |
| GET | `/bookings/<id>` | chủ yêu cầu hoặc quản trị |
| POST | `/bookings` | giảng viên, sinh viên |
| POST | `/bookings/<id>/cancel` | giảng viên, sinh viên |
| POST | `/admin/bookings/<id>/approve\|reject\|done` | quản trị |
| GET | `/admin/stats/usage?from=&to=` | quản trị |
| GET | `/admin/audit?event=&limit=&offset=` | quản trị (nhật ký an ninh) |

## Mã lỗi
`{"error": "mã_máy", "message": "giải thích tiếng Việt"}` với: 400 dữ liệu sai · 401 chưa/sai token · 403 không đủ quyền ·
404 không tìm thấy · 409 trùng giờ hoặc sai trạng thái (`room_conflict`, `equipment_conflict`, `invalid_state`) ·
413 nội dung quá 64 KB · 415 không phải JSON · 422 giờ hoặc dữ liệu không hợp lệ · 429 đăng nhập sai nhiều hoặc gọi quá nhanh (có header `Retry-After`) · 500 lỗi máy chủ (không lộ chi tiết).

## Ví dụ
### Windows PowerShell
```powershell
$r = Invoke-RestMethod -Method Post http://localhost:5000/api/v1/auth/login -ContentType application/json `
     -Body '{"email":"sv@lab.local","password":"sv123456"}'
$h = @{ Authorization = "Bearer $($r.token)" }
Invoke-RestMethod http://localhost:5000/api/v1/rooms -Headers $h
Invoke-RestMethod -Method Post http://localhost:5000/api/v1/bookings -Headers $h -ContentType application/json `
     -Body '{"room_id":1,"date":"2026-11-25","start":"09:00","end":"11:00","purpose":"Đồ án","equipment":[{"id":2,"quantity":2}]}'
```
### curl (macOS, Linux, Git Bash)
```bash
TOKEN=$(curl -s -X POST localhost:5000/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"sv@lab.local","password":"sv123456"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl localhost:5000/api/v1/schedule?kind=room\&id=1 -H "Authorization: Bearer $TOKEN"
```
### Postman
Tạo request `POST /auth/login` → copy `token` → tab **Authorization** chọn *Bearer Token* và dán vào.

## Bảo mật
| Mối đe dọa | Biện pháp trong `api.py` |
|---|---|
| Lộ CSDL làm lộ token | Token ngẫu nhiên 256 bit, chỉ lưu băm SHA-256 |
| Token bị đánh cắp | Hết hạn sau 12 giờ hoặc 2 giờ không dùng; tối đa 5 token mỗi tài khoản; `logout-all` |
| Đổi mật khẩu mà token cũ vẫn dùng được | Mỗi token gắn dấu vân tay mật khẩu lúc cấp, đổi mật khẩu hoặc khóa tài khoản thì token vô hiệu ngay |
| Dò mật khẩu | Khóa tạm sau 5 lần sai/email/15 phút và 30 lần sai/IP; trả 429 kèm `Retry-After` |
| Dò xem email nào tồn tại | Cùng thông báo, cùng thời gian xử lý dù email có tồn tại hay không |
| Lạm dụng, quá tải | 120 lời gọi/phút/token; JSON tối đa 64 KB; bắt buộc `application/json`; giới hạn độ dài và số lượng mọi trường |
| Xem dữ liệu người khác | Phân quyền theo vai trò và theo chủ sở hữu (yêu cầu của người khác trả 404) |
| Lộ thông tin qua lỗi | Lỗi nội bộ chỉ ghi log máy chủ, client chỉ nhận 500 chung |
| Tấn công trình duyệt | `nosniff`, `no-store`, CSP chặt, `X-Frame-Options`, HSTS khi `COOKIE_SECURE=1` |
| Không biết ai đã làm gì | Nhật ký `api_audit`: đăng nhập thành công/sai/bị khóa, truy cập trái quyền, duyệt yêu cầu (không ghi mật khẩu hay token) |

**Giới hạn cần biết**
- Token đi trong header nên **phải chạy sau HTTPS khi triển khai thật** (Nginx, Caddy, Cloudflare…), rồi đặt `COOKIE_SECURE=1`. Qua HTTP thường token có thể bị nghe lén.
- Bộ đếm giới hạn tốc độ nằm trong bộ nhớ của một tiến trình (cấu hình Docker hiện dùng 1 worker). Muốn chạy nhiều worker/máy cần dùng Redis hoặc tương tự.
- Phía sau proxy, mọi yêu cầu có thể cùng một IP nên bộ đếm theo IP sẽ gộp chung; khi đó cần bật `ProxyFix` của Werkzeug.
- API chưa bật CORS nên trình duyệt từ tên miền khác không gọi được. Muốn cho phép thì dùng `flask-cors` với danh sách tên miền cụ thể, không dùng `*`.
- Bản nâng cấp tạo lại bảng `api_tokens`, nên token cũ bị hủy và cần đăng nhập lại.

## Chạy kiểm thử
```bash
python tests/test_api.py      # 64 kiểm thử (gồm 23 kiểm thử bảo mật), dùng CSDL tạm
```

## Ghi chú thiết kế
- API nằm trong `api.py` (Blueprint), tự tạo bảng `api_tokens`, không sửa `db.py`; `app.py` chỉ nối vào ở cuối file.
- Đặt lịch dùng lại `create_booking` trong `app.py` nên quy tắc chống trùng lịch và ưu tiên giảng viên giống hệt giao diện web (trigger ở CSDL vẫn là lớp chặn cuối).
- `app.py` có vài chỗ nhỏ dành cho API: bỏ kiểm CSRF với đường dẫn `/api/` (API dùng Bearer token) và trả lỗi dạng JSON cho `/api/`.

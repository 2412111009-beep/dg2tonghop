# LabBook – Đặt phòng lab & mượn thiết bị (Flask + SQLite)

## Chạy
    pip install -r requirements.txt
    python app.py          # mở http://127.0.0.1:5000

Lần chạy đầu tự tạo `labbook.db` kèm dữ liệu mẫu.

| Vai trò   | Email          | Mật khẩu |
|-----------|----------------|----------|
| Quản trị  | admin@lab.local | admin123 |
| Giảng viên| gv@lab.local    | gv123456 |
| Sinh viên | sv@lab.local    | sv123456 |

Đổi mật khẩu các tài khoản mẫu trước khi dùng thật.

## Quên mật khẩu
Chưa cấu hình SMTP: liên kết đặt lại hiện ngay trên trang và in ra console (chế độ phát triển).
Muốn gửi email thật, đặt biến môi trường: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM.

## Cấu trúc
- `db.py`  schema 8 bảng + trigger chống trùng lịch (ROOM_CONFLICT, EQUIP_CONFLICT)
- `app.py` route, phân quyền, đặt lịch/ưu tiên giảng viên, mượn–trả, báo hỏng, thống kê
- `api.py` REST API JSON (Bearer token), tài liệu tại `/api/docs`, xem `docs/API.md`; kiểm thử: `python tests/test_api.py` (64 mục, có bảo mật)
- `templates/` giao diện (mỗi vai trò có dashboard và menu riêng), `static/style.css`

## Docker
    docker compose up -d --build     # mở http://localhost:5000
    docker compose logs -f           # xem log (liên kết quên mật khẩu in ở đây nếu chưa có SMTP)
    docker compose down              # dừng, DỮ LIỆU VẪN GIỮ trong volume labbook_data
    docker compose down -v           # dừng và XÓA dữ liệu

CSDL, ảnh báo hỏng và khóa bí mật nằm trong volume `labbook_data` (thư mục /data).
Sao lưu: `docker run --rm -v labbook_data:/data -v $PWD:/b alpine tar czf /b/labbook-backup.tgz -C /data .`
Đặt `SECRET_KEY` và `COOKIE_SECURE=1` trong file `.env` khi triển khai sau HTTPS.

## API
Tài liệu: http://localhost:5000/api/docs · chi tiết và ví dụ trong `docs/API.md`.
Địa chỉ gốc `/api/v1`. Có giới hạn tốc độ, khóa tạm khi dò mật khẩu, token hết hạn và nhật ký an ninh (xem mục Bảo mật trong `docs/API.md`). Đăng nhập `POST /api/v1/auth/login` lấy token, các yêu cầu sau gửi `Authorization: Bearer <token>`.
"# b-i-g2--t-ng-h-p-" 

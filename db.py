"""Lớp CSDL (SQLite) - toàn bộ schema + ràng buộc chống trùng lịch nằm ở mức CSDL."""
import sqlite3, os
from werkzeug.security import generate_password_hash

DATA_DIR = os.environ.get("LABBOOK_DATA", os.path.dirname(os.path.abspath(__file__)))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "labbook.db")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  phone TEXT,
  role TEXT NOT NULL CHECK (role IN ('admin','lecturer','student')),
  group_name TEXT,                       -- nhóm đồ án (sinh viên)
  is_active INTEGER NOT NULL DEFAULT 1,  -- giảng viên mới đăng ký cần admin kích hoạt
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  location TEXT,
  capacity INTEGER,
  description TEXT,
  is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS equipment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  category TEXT,
  quantity INTEGER NOT NULL DEFAULT 1 CHECK (quantity >= 0),
  broken_qty INTEGER NOT NULL DEFAULT 0 CHECK (broken_qty >= 0),
  description TEXT,
  is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  room_id INTEGER REFERENCES rooms(id),
  start_time TEXT NOT NULL,              -- 'YYYY-MM-DD HH:MM'
  end_time TEXT NOT NULL,
  purpose TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected','cancelled','bumped','done')),
  admin_note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  CHECK (start_time < end_time)
);
CREATE INDEX IF NOT EXISTS idx_bookings_room_time ON bookings(room_id, start_time, end_time);

CREATE TABLE IF NOT EXISTS booking_equipment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
  equipment_id INTEGER NOT NULL REFERENCES equipment(id),
  quantity INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0),
  UNIQUE (booking_id, equipment_id)
);

CREATE TABLE IF NOT EXISTS loans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  booking_id INTEGER NOT NULL REFERENCES bookings(id),
  equipment_id INTEGER NOT NULL REFERENCES equipment(id),
  quantity INTEGER NOT NULL,
  borrowed_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  returned_at TEXT,
  return_condition TEXT CHECK (return_condition IN ('good','damaged','lost')),
  return_note TEXT,
  handled_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS damage_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL REFERENCES users(id),
  equipment_id INTEGER REFERENCES equipment(id),
  room_id INTEGER REFERENCES rooms(id),
  loan_id INTEGER REFERENCES loans(id),
  description TEXT NOT NULL,
  photo TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- ===== RÀNG BUỘC CHỐNG TRÙNG LỊCH Ở MỨC CSDL =====
-- 1) Một phòng không được có 2 yêu cầu (pending/approved) chồng khung giờ.
DROP TRIGGER IF EXISTS trg_room_no_overlap_ins;
CREATE TRIGGER trg_room_no_overlap_ins BEFORE INSERT ON bookings
WHEN NEW.room_id IS NOT NULL AND NEW.status IN ('pending','approved')
BEGIN
  SELECT RAISE(ABORT, 'ROOM_CONFLICT') WHERE EXISTS (
    SELECT 1 FROM bookings b
    WHERE b.room_id = NEW.room_id AND b.status IN ('pending','approved')
      AND b.start_time < NEW.end_time AND b.end_time > NEW.start_time);
END;

DROP TRIGGER IF EXISTS trg_room_no_overlap_upd;
CREATE TRIGGER trg_room_no_overlap_upd BEFORE UPDATE OF room_id, start_time, end_time, status ON bookings
WHEN NEW.room_id IS NOT NULL AND NEW.status IN ('pending','approved')
BEGIN
  SELECT RAISE(ABORT, 'ROOM_CONFLICT') WHERE EXISTS (
    SELECT 1 FROM bookings b
    WHERE b.id != NEW.id AND b.room_id = NEW.room_id AND b.status IN ('pending','approved')
      AND b.start_time < NEW.end_time AND b.end_time > NEW.start_time);
END;

-- 2) Thiết bị: tổng số lượng được đặt trong cùng khung giờ không vượt số lượng còn dùng được.
DROP TRIGGER IF EXISTS trg_equip_capacity_ins;
CREATE TRIGGER trg_equip_capacity_ins BEFORE INSERT ON booking_equipment
BEGIN
  SELECT RAISE(ABORT, 'EQUIP_CONFLICT') WHERE
    (SELECT COALESCE(SUM(be.quantity),0)
       FROM booking_equipment be JOIN bookings b ON b.id = be.booking_id
      WHERE be.equipment_id = NEW.equipment_id
        AND b.id != NEW.booking_id AND b.status IN ('pending','approved')
        AND b.start_time < (SELECT end_time FROM bookings WHERE id = NEW.booking_id)
        AND b.end_time   > (SELECT start_time FROM bookings WHERE id = NEW.booking_id))
    + NEW.quantity
    > (SELECT quantity - broken_qty FROM equipment WHERE id = NEW.equipment_id);
END;
"""


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        seed(conn)
    conn.commit()
    conn.close()


def seed(conn):
    users = [
        ("admin@lab.local", "admin123", "Cán bộ phòng lab", "admin", None),
        ("gv@lab.local", "gv123456", "Đỗ Văn Tuyên", "lecturer", None),
        ("sv@lab.local", "sv123456", "Trần Thị Bình", "student", "Nhóm IoT-03"),
    ]
    for email, pw, name, role, grp in users:
        conn.execute(
            "INSERT INTO users(email,password_hash,full_name,role,group_name) VALUES (?,?,?,?,?)",
            (email, generate_password_hash(pw), name, role, grp))
    for n, loc, cap in [("Lab IoT 301", "Nhà A3, tầng 3", 30),
                        ("Lab Mạng 205", "Nhà A3, tầng 2", 40),
                        ("Phòng đồ án 102", "Nhà A1, tầng 1", 12)]:
        conn.execute("INSERT INTO rooms(name,location,capacity) VALUES (?,?,?)", (n, loc, cap))
    for n, cat, q in [("Máy chiếu Epson", "Trình chiếu", 3),
                      ("Bộ kit ESP32", "IoT", 10),
                      ("Bộ kit Raspberry Pi 4", "IoT", 6),
                      ("Oscilloscope", "Đo lường", 2)]:
        conn.execute("INSERT INTO equipment(name,category,quantity) VALUES (?,?,?)", (n, cat, q))

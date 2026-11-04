"""
server/user_db.py
-----------------
Quản lý cơ sở dữ liệu người dùng, xác thực tài khoản và lưu trữ tin nhắn (B3).
Tích hợp:
  1. Cơ sở dữ liệu SQLite thuần (chuẩn thư viện Python `sqlite3`, không cần cài đặt thêm).
     - Bảng `users`: Lưu tài khoản, mật khẩu băm PBKDF2, thời gian đăng ký, thời gian online/offline cuối.
     - Bảng `messages`: Lưu trữ lịch sử tin nhắn văn bản (Broadcast và Direct Message).
  2. Đồng bộ tệp JSON `users.json` để tương thích hoàn toàn 100% với Bareme đề bài và kiểm thử tự động.
"""

import asyncio
import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional

from shared.config import USERS_FILE
from shared.crypto import hash_password, verify_password

log = logging.getLogger("server.user_db")


class UserDB:
    """
    Quản lý danh sách người dùng, đăng ký, xác thực và lưu trữ tin nhắn.
    Hỗ trợ cả tệp JSON (chuẩn đề bài) và SQLite Database (lưu trữ quan hệ).
    """

    def __init__(self, filepath: str = USERS_FILE, db_path: Optional[str] = None):
        self.filepath = filepath
        self.db_path = db_path or f"{os.path.splitext(filepath)[0]}.db"
        self._users: Dict[str, Dict[str, str]] = {}
        self._lock = asyncio.Lock()

        # Khởi tạo SQLite và nạp dữ liệu
        self._init_sqlite()
        self._load()

    def _init_sqlite(self) -> None:
        """Tạo bảng SQLite nếu chưa tồn tại."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        salt TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_online INTEGER DEFAULT 0
                    );
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        receiver TEXT,
                        content TEXT NOT NULL,
                        is_dm INTEGER DEFAULT 0,
                        timestamp REAL NOT NULL
                    );
                """)
                conn.commit()
            log.info(f"Đã kết nối cơ sở dữ liệu SQLite tại '{self.db_path}'.")
        except Exception as e:
            log.warning(f"Lỗi khởi tạo SQLite ({self.db_path}): {e}")

    def _load(self) -> None:
        """Tải dữ liệu từ tệp JSON nếu tồn tại và đồng bộ vào SQLite."""
        if not os.path.exists(self.filepath):
            self._users = {}
            return

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                self._users = json.load(f)
            log.info(f"Đã tải {len(self._users)} tài khoản từ '{self.filepath}'.")

            # Đồng bộ các tài khoản từ JSON vào SQLite
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    for u, data in self._users.items():
                        cursor.execute("""
                            INSERT OR IGNORE INTO users (username, salt, password_hash, is_online)
                            VALUES (?, ?, ?, 0)
                        """, (u, data.get("salt", ""), data.get("hash", "")))
                    conn.commit()
            except Exception as se:
                log.warning(f"Lỗi đồng bộ JSON sang SQLite: {se}")

        except Exception as e:
            log.error(f"Lỗi khi đọc tệp người dùng '{self.filepath}': {e}")
            self._users = {}

    def _save(self) -> None:
        """Lưu trữ dữ liệu ra tệp JSON an toàn (atomic write qua tệp tạm)."""
        temp_file = f"{self.filepath}.tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(self._users, f, indent=2, ensure_ascii=False)
            os.replace(temp_file, self.filepath)
        except Exception as e:
            log.error(f"Lỗi khi lưu tệp người dùng: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass

    async def register(self, username: str, password: str) -> bool:
        """
        Đăng ký tài khoản mới.
        
        Returns:
            True nếu đăng ký thành công.
            False nếu tài khoản đã tồn tại hoặc thông tin không hợp lệ.
        """
        username = username.strip()
        if not username or not password:
            return False

        async with self._lock:
            # Kiểm tra tồn tại (không phân biệt hoa thường để tránh giả mạo)
            normalized_name = username.lower()
            for existing in self._users:
                if existing.lower() == normalized_name:
                    return False

            # Băm mật khẩu trong luồng phụ Worker Thread để không nghẽn Event Loop
            salt_hex, hash_hex = await asyncio.to_thread(hash_password, password)

            self._users[username] = {
                "salt": salt_hex,
                "hash": hash_hex
            }
            self._save()

            # Lưu vào SQLite
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO users (username, salt, password_hash, is_online)
                        VALUES (?, ?, ?, 0)
                    """, (username, salt_hex, hash_hex))
                    conn.commit()
            except Exception as e:
                log.warning(f"Lỗi ghi user vào SQLite: {e}")

            log.info(f"Tài khoản '{username}' đăng ký thành công.")
            return True

    async def authenticate(self, username: str, password: str) -> bool:
        """
        Xác thực tài khoản và mật khẩu đăng nhập.
        
        Returns:
            True nếu đăng nhập đúng thông tin.
            False nếu tài khoản không tồn tại hoặc sai mật khẩu.
        """
        username = username.strip()
        if not username or not password:
            return False

        user_data: Optional[Dict[str, str]] = None
        for existing, data in self._users.items():
            if existing.lower() == username.lower():
                user_data = data
                break

        if not user_data:
            return False

        salt_hex = user_data.get("salt", "")
        expected_hash_hex = user_data.get("hash", "")

        is_valid = await asyncio.to_thread(
            verify_password,
            password,
            salt_hex,
            expected_hash_hex
        )
        return is_valid

    def set_user_online(self, username: str, is_online: bool) -> None:
        """Cập nhật trạng thái trực tuyến / ngoại tuyến của người dùng vào SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users
                    SET is_online = ?, last_seen = CURRENT_TIMESTAMP
                    WHERE LOWER(username) = LOWER(?)
                """, (1 if is_online else 0, username))
                conn.commit()
        except Exception as e:
            log.warning(f"Lỗi cập nhật trạng thái online trong SQLite: {e}")

    def get_all_users_status(self) -> List[Dict[str, Any]]:
        """
        Lấy danh sách tất cả người dùng đã đăng ký kèm trạng thái online / offline.
        """
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT username, is_online, last_seen, created_at
                    FROM users
                    ORDER BY is_online DESC, username ASC
                """)
                for row in cursor.fetchall():
                    results.append({
                        "username": row[0],
                        "online": bool(row[1]),
                        "last_seen": str(row[2]) if row[2] else None,
                        "created_at": str(row[3]) if row[3] else None
                    })
        except Exception as e:
            log.warning(f"Lỗi đọc trạng thái người dùng từ SQLite: {e}")

        # Đảm bảo các tài khoản trong self._users đều xuất hiện
        found_users = {r["username"].lower() for r in results}
        for u in self._users:
            if u.lower() not in found_users:
                results.append({
                    "username": u,
                    "online": False,
                    "last_seen": None,
                    "created_at": None
                })
        return results

    def save_message(self, sender: str, receiver: Optional[str], content: str, is_dm: bool, timestamp: float) -> None:
        """Lưu trữ tin nhắn vào cơ sở dữ liệu SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO messages (sender, receiver, content, is_dm, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (sender, receiver, content, 1 if is_dm else 0, timestamp))
                conn.commit()
        except Exception as e:
            log.warning(f"Lỗi lưu tin nhắn vào SQLite: {e}")

    def user_exists(self, username: str) -> bool:
        """Kiểm tra xem tên tài khoản đã có trong hệ thống chưa."""
        normalized = username.strip().lower()
        return any(u.lower() == normalized for u in self._users)

    def count(self) -> int:
        """Số lượng người dùng đã đăng ký."""
        return len(self._users)

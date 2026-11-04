"""B3 - Lưu và kiểm tra mật khẩu bằng PBKDF2-HMAC-SHA256.

- Băm chạy trong executor (PBKDF2 tốn ~50-100ms CPU; chạy thẳng sẽ treo mọi client khác).
- users.json chỉ chứa salt + hash, ghi nguyên tử (file tạm + os.replace) để không bao giờ hỏng nửa chừng.
- Đăng ký đồng thời cùng tên: chỉ một bên thắng (kiểm tra lại trong lock sau khi băm).
- Tên không tồn tại vẫn băm giả để thời gian trả lời không lộ tên nào có thật.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import tempfile

from shared import config, messages

log = logging.getLogger("server.auth")


class UserStore:
    def __init__(self, path: str = config.USERS_FILE, iterations: int = config.PBKDF2_ITERATIONS):
        self.path = path
        self.iterations = iterations
        self._lock = asyncio.Lock()
        self._users: dict[str, dict] = self._load()
        self._dummy_salt = os.urandom(config.SALT_BYTES)

    # ---------------------------------------------------------------- lưu trữ
    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return dict(data.get("users", {}))
        except (OSError, json.JSONDecodeError) as e:
            # Không tự ghi đè file hỏng: dừng hẳn để người vận hành xử lý, tránh mất tài khoản.
            raise RuntimeError(f"không đọc được {self.path}: {e}") from e

    def _save_sync(self, snapshot: dict) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".users.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "users": snapshot}, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    async def _hash(self, password: str, salt: bytes, iterations: int) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, hashlib.pbkdf2_hmac, "sha256", password.encode("utf-8"), salt, iterations)

    # ---------------------------------------------------------------- API
    def exists(self, username: str) -> bool:
        return username in self._users

    async def register(self, username: str, password: str) -> tuple[bool, str]:
        """Trả (True, "") hoặc (False, mã lỗi)."""
        if not messages.valid_username(username):
            return False, messages.E_INVALID_INPUT
        pw_len = len(password.encode("utf-8"))
        if not config.PASSWORD_MIN_BYTES <= pw_len <= config.PASSWORD_MAX_BYTES:
            return False, messages.E_INVALID_INPUT
        if username in self._users:                      # kiểm nhanh, chưa tốn công băm
            return False, messages.E_USER_EXISTS
        salt = os.urandom(config.SALT_BYTES)
        digest = await self._hash(password, salt, self.iterations)
        async with self._lock:
            if username in self._users:                  # kiểm lại: có thể ai đó vừa đăng ký trong lúc băm
                return False, messages.E_USER_EXISTS
            self._users[username] = {"salt": salt.hex(), "hash": digest.hex(),
                                     "iterations": self.iterations, "algo": "pbkdf2_sha256"}
            snapshot = dict(self._users)
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, self._save_sync, snapshot)
            except OSError:
                del self._users[username]
                log.exception("ghi %s thất bại", self.path)
                return False, messages.E_SERVER
        log.info("đăng ký mới: %s", username)
        return True, ""

    async def verify(self, username: str, password: str) -> bool:
        rec = self._users.get(username)
        if rec is None:
            await self._hash(password, self._dummy_salt, self.iterations)   # cân bằng thời gian
            return False
        digest = await self._hash(password, bytes.fromhex(rec["salt"]), int(rec["iterations"]))
        return hmac.compare_digest(digest, bytes.fromhex(rec["hash"]))

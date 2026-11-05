"""
client/agent.py
---------------
Lớp điều phối phía client (ClientAgent): nối giao diện (Web UI / CLI) với mạng.
Đăng nhập TCP theo protocol_messages.md §3 (client/tcp_login.py), rồi phiên UDP §4-§7 (client/udp_client.py).
"""

import asyncio
import inspect
import logging
import os
from typing import Callable, Dict, List, Optional

from client.tcp_login import AuthError, tcp_login
from client.udp_client import UDPClient
from shared import config

log = logging.getLogger("client.agent")

# AUTH_FAIL.code (protocol_messages.md §3.7) -> câu cho người dùng
AUTH_MESSAGES: Dict[str, str] = {
    "BAD_CREDENTIALS": "Sai tên đăng nhập hoặc mật khẩu.",
    "USER_EXISTS": "Tên đăng nhập đã có người dùng.",
    "INVALID_INPUT": "Tên 3–20 ký tự (chữ không dấu, số, dấu _), mật khẩu 6–128 byte.",
    "TOO_MANY_ATTEMPTS": "Sai quá nhiều lần, server đã đóng kết nối. Thử lại sau.",
    "BAD_SIGNATURE": "Chữ ký khóa server không khớp khóa đã ghim: có thể đang kết nối nhầm server hoặc bị giả mạo.",
    "SERVER_ERROR": "Server gặp lỗi khi xử lý tài khoản.",
}


class ClientAgent:
    def __init__(
        self,
        server_host: str = config.SERVER_HOST,
        tcp_port: int = config.TCP_PORT,
        udp_port: int = config.UDP_PORT,
        downloads_dir: str = "downloads",
        loss_pct: float = 0.0,
        server_key_hex: Optional[str] = None,
    ):
        self.server_host = server_host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.downloads_dir = downloads_dir
        self.loss_pct = loss_pct
        self.pinned_identity = bytes.fromhex(server_key_hex) if server_key_hex else None

        self.username: Optional[str] = None
        self.conn_id: Optional[int] = None
        self.udp_client: Optional[UDPClient] = None

        self._event_callbacks: List[Callable[[dict], None]] = []
        self._pump_task: Optional[asyncio.Task] = None
        self._connected: bool = False

    @property
    def user_downloads_dir(self) -> str:
        d = os.path.join(self.downloads_dir, self.username) if self.username else self.downloads_dir
        os.makedirs(d, exist_ok=True)
        return d

    @property
    def is_authenticated(self) -> bool:
        return self._connected and self.conn_id is not None

    @property
    def online_users(self) -> List[str]:
        return self.udp_client.online_users if self.udp_client else []

    @property
    def all_users(self) -> List[dict]:
        return self.udp_client.all_users if self.udp_client else []

    async def register(self, username: str, password: str) -> None:
        """Đăng ký rồi đăng nhập luôn trên cùng kết nối TCP."""
        await self._login(username, password, register=True)

    async def login(self, username: str, password: str) -> None:
        await self._login(username, password, register=False)

    async def _login(self, username: str, password: str, register: bool) -> None:
        if self._connected:
            await self.disconnect()
        try:
            res = await tcp_login(self.server_host, self.tcp_port, username, password, register=register,
                                  pinned_identity=self.pinned_identity)
        except AuthError as e:
            raise RuntimeError(AUTH_MESSAGES.get(e.code, str(e))) from None
        except (ConnectionError, OSError, asyncio.TimeoutError) as e:
            raise RuntimeError(f"Không kết nối được server {self.server_host}:{self.tcp_port} ({e!r}).") from None
        self.username = res.username
        self.conn_id = res.conn_id
        log.info("đăng nhập '%s' thành công, ConnID=%#010x", username, res.conn_id)

        self.udp_client = UDPClient(res, self.server_host, self.user_downloads_dir, self.loss_pct)
        try:
            await self.udp_client.connect()
        except Exception:
            self.username = self.conn_id = self.udp_client = None
            raise
        self._connected = True
        self._pump_task = asyncio.create_task(self._event_pump())

    async def _event_pump(self) -> None:
        client = self.udp_client
        while client is self.udp_client and client is not None:
            try:
                msg = await client.inbox.get()
            except asyncio.CancelledError:
                break
            if msg.get("type") == "DISCONNECTED" or (msg.get("type") == "ERROR"
                                                     and msg.get("code") == "SESSION_REPLACED"):
                self._connected = False
            for cb in self._event_callbacks:
                try:
                    if inspect.iscoroutinefunction(cb):
                        asyncio.create_task(cb(msg))
                    else:
                        cb(msg)
                except Exception as e:
                    log.error("lỗi event callback: %s", e)

    def on_event(self, callback: Callable[[dict], None]) -> None:
        self._event_callbacks.append(callback)

    def _require(self) -> UDPClient:
        if not self.udp_client or not self._connected:
            raise ConnectionError("Chưa kết nối với server.")
        return self.udp_client

    async def send_chat(self, text: str) -> None:
        await self._require().send_broadcast(text)

    async def send_dm(self, to_user: str, text: str) -> None:
        await self._require().send_dm(to_user, text)

    async def send_file(self, to_user: str, file_bytes: bytes, filename: str) -> str:
        return await self._require().send_file(to_user, file_bytes, filename)

    async def disconnect(self) -> None:
        self._connected = False
        if self._pump_task:
            self._pump_task.cancel()
            self._pump_task = None
        if self.udp_client:
            await self.udp_client.disconnect()
        self.udp_client = None
        self.conn_id = None
        self.username = None
        log.info("ClientAgent đã ngắt kết nối.")

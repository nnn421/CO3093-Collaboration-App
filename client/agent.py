"""
client/agent.py
---------------
Lớp điều phối trung tâm phía máy khách (ClientAgent) (C2).
Đóng vai trò cầu nối thống nhất giữa:
  - Tầng mạng lõi: Bắt tay TCP (X25519 + PBKDF2) & Phiên làm việc UDP tin cậy (Stop-and-Wait).
  - Tầng giao diện người dùng: Web UI (HTTP Server) hoặc CLI console.
"""

import asyncio
import inspect
import logging
from typing import Callable, Dict, List, Optional

from client.tcp_client import AuthenticationError, perform_tcp_handshake
from client.udp_client import UDPClient
from shared.config import (
    DEFAULT_SERVER_HOST,
    TCP_PORT,
    UDP_TRANSPORT_PORT,
)

log = logging.getLogger("client.agent")


class ClientAgent:
    """
    Quản lý vòng đời kết nối của 1 Client:
    Đăng ký -> Đăng nhập TCP -> Chuyển giao UDP -> Chat/File -> Đăng xuất.
    """

    def __init__(
        self,
        server_host: str = DEFAULT_SERVER_HOST,
        tcp_port: int = TCP_PORT,
        udp_port: int = UDP_TRANSPORT_PORT,
        downloads_dir: str = "downloads",
        loss_pct: float = 0.0
    ):
        self.server_host = server_host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.downloads_dir = downloads_dir
        self.loss_pct = loss_pct

        self.username: Optional[str] = None
        self.conn_id: Optional[int] = None
        self.session_keys: Optional[Dict[str, bytes]] = None
        self.udp_client: Optional[UDPClient] = None

        self._event_callbacks: List[Callable[[dict], None]] = []
        self._pump_task: Optional[asyncio.Task] = None
        self._connected: bool = False

    @property
    def user_downloads_dir(self) -> str:
        """
        Thư mục lưu trữ riêng biệt của từng tài khoản người dùng (User Isolation).
        Đảm bảo khi chạy nhiều client trên cùng một máy (localhost), tệp tin nhận
        của ai sẽ chỉ lưu riêng cho người đó, không bị lẫn hay hiển thị cho người khác.
        """
        import os
        if self.username:
            d = os.path.join(self.downloads_dir, self.username)
        else:
            d = self.downloads_dir
        os.makedirs(d, exist_ok=True)
        return d

    @property
    def is_authenticated(self) -> bool:
        """Kiểm tra xem client đã đăng nhập thành công hay chưa."""
        return self._connected and (self.conn_id is not None)

    @property
    def online_users(self) -> List[str]:
        """Danh sách những người dùng khác đang trực tuyến."""
        if self.udp_client:
            return self.udp_client.online_users
        return []

    @property
    def all_users(self) -> List[dict]:
        """Danh sách toàn bộ người dùng và trạng thái trực tuyến / ngoại tuyến."""
        if self.udp_client:
            return getattr(self.udp_client, "all_users", [])
        return []

    async def register(self, username: str, password: str) -> None:
        """Đăng ký tài khoản mới qua kênh TCP 9000."""
        log.info(f"Đang đăng ký tài khoản '{username}' qua TCP {self.server_host}:{self.tcp_port}...")
        self.conn_id, self.session_keys = await perform_tcp_handshake(
            host=self.server_host,
            port=self.tcp_port,
            action="REGISTER",
            username=username,
            password=password
        )
        self.username = username
        log.info(f"Đăng ký thành công! Đã cấp ConnID={self.conn_id:#010x}.")

        # Khởi tạo và kết nối UDP session
        await self._init_udp_session()

    async def login(self, username: str, password: str) -> None:
        """Đăng nhập tài khoản qua kênh TCP 9000."""
        log.info(f"Đang đăng nhập tài khoản '{username}' qua TCP {self.server_host}:{self.tcp_port}...")
        self.conn_id, self.session_keys = await perform_tcp_handshake(
            host=self.server_host,
            port=self.tcp_port,
            action="LOGIN",
            username=username,
            password=password
        )
        self.username = username
        log.info(f"Đăng nhập thành công! Đã cấp ConnID={self.conn_id:#010x}.")

        # Khởi tạo và kết nối UDP session
        await self._init_udp_session()

    async def _init_udp_session(self) -> None:
        """Khởi chạy phiên làm việc UDP sau khi đã có ConnID và chìa khóa."""
        if not self.conn_id or not self.session_keys:
            raise RuntimeError("Chưa có ConnID hoặc chìa khóa phiên.")

        self.udp_client = UDPClient(
            conn_id=self.conn_id,
            session_keys=self.session_keys,
            server_host=self.server_host,
            server_port=self.udp_port,
            downloads_dir=self.user_downloads_dir,
            loss_pct=self.loss_pct
        )
        await self.udp_client.connect()
        self._connected = True

        # Bắt đầu bơm tin nhắn từ inbox của UDPClient tới các subscriber callback
        self._pump_task = asyncio.create_task(self._event_pump())
        log.info(f"ClientAgent đã kết nối hoàn chỉnh với phòng cộng tác dưới tên '{self.username}'.")

    async def _event_pump(self) -> None:
        """Đọc tin nhắn từ UDPClient.inbox và kích hoạt callback."""
        if not self.udp_client:
            return
        while self._connected:
            try:
                msg = await self.udp_client.inbox.get()
                for cb in self._event_callbacks:
                    try:
                        if inspect.iscoroutinefunction(cb):
                            asyncio.create_task(cb(msg))
                        else:
                            cb(msg)
                    except Exception as e:
                        log.error(f"Lỗi khi thực thi event callback: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Lỗi trong event pump: {e}")

    def on_event(self, callback: Callable[[dict], None]) -> None:
        """Đăng ký hàm lắng nghe sự kiện (tin nhắn chat, cập nhật online, file đến)."""
        self._event_callbacks.append(callback)

    async def send_chat(self, content: str) -> None:
        """Gửi tin nhắn phát thanh (Broadcast)."""
        if not self.udp_client or not self._connected:
            raise ConnectionError("Chưa kết nối UDP với máy chủ.")
        await self.udp_client.send_broadcast(content)

    async def send_dm(self, to_user: str, content: str) -> None:
        """Gửi tin nhắn riêng tới đích danh người dùng."""
        if not self.udp_client or not self._connected:
            raise ConnectionError("Chưa kết nối UDP với máy chủ.")
        await self.udp_client.send_dm(to_user, content)

    async def send_file(self, to_user: str, file_bytes: bytes, filename: str) -> str:
        """Gửi file nhị phân qua luồng Stream chuyên dụng."""
        if not self.udp_client or not self._connected:
            raise ConnectionError("Chưa kết nối UDP với máy chủ.")
        return await self.udp_client.send_file(to_user, file_bytes, filename)

    async def disconnect(self) -> None:
        """Ngắt kết nối an toàn với máy chủ."""
        self._connected = False
        if self._pump_task:
            self._pump_task.cancel()
        if self.udp_client:
            await self.udp_client.disconnect()
        self.conn_id = None
        self.username = None
        self.session_keys = None
        log.info("ClientAgent đã ngắt kết nối.")

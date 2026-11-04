"""
server/session_manager.py
-------------------------
Quản lý trạng thái phiên kết nối của các Client trên Server (B4).
Lưu trữ thông tin xác thực, khóa mã hóa UDP, địa chỉ mạng UDP socket,
và thời gian hoạt động cuối cùng (Last Seen) để phát hiện timeout.
"""

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from shared.config import HEARTBEAT_TIMEOUT

log = logging.getLogger("server.session_manager")


@dataclass
class ClientSession:
    """Đại diện cho 1 phiên làm việc của Client đã xác thực thành công."""
    conn_id: int                                # Mã định danh phiên 32-bit (duy nhất)
    username: str                               # Tên người dùng đã xác thực
    udp_c2s_key: bytes                          # Khóa AES-256 giải mã gói Client -> Server
    udp_s2c_key: bytes                          # Khóa AES-256 mã hóa gói Server -> Client
    tcp_c2s_key: bytes = b""                    # Khóa TCP Client -> Server
    tcp_s2c_key: bytes = b""                    # Khóa TCP Server -> Client
    udp_addr: Optional[Tuple[str, int]] = None  # (IP, Port) thực tế của Client trên UDP
    udp_connected: bool = False                 # Đã bắt tay UDP HELLO thành công hay chưa
    last_seen: float = field(default_factory=time.time) # Thời điểm nhận gói tin gần nhất
    send_pkt_num: int = 0                       # Bộ đếm PktNum của Server gửi tới Client này
    recv_pkt_num: int = 0                       # PktNum lớn nhất nhận được từ Client

    def update_activity(self) -> None:
        """Cập nhật timestamp hoạt động mới nhất."""
        self.last_seen = time.time()

    def is_expired(self, timeout: float = HEARTBEAT_TIMEOUT) -> bool:
        """Kiểm tra phiên đã quá hạn không nhận được heartbeat hay chưa."""
        return (time.time() - self.last_seen) > timeout

    def next_server_pkt_num(self) -> int:
        """Lấy số PktNum tiếp theo cho gói tin Server gửi đi."""
        curr = self.send_pkt_num
        self.send_pkt_num = (self.send_pkt_num + 1) & 0xFFFFFFFF
        return curr


class SessionManager:
    """Quản lý tập trung toàn bộ các phiên Client đang hoạt động trên hệ thống."""

    def __init__(self):
        self._by_conn_id: Dict[int, ClientSession] = {}
        self._by_username: Dict[str, ClientSession] = {}
        self._by_addr: Dict[Tuple[str, int], ClientSession] = {}

    def create_session(
        self,
        username: str,
        udp_c2s_key: bytes,
        udp_s2c_key: bytes,
        tcp_c2s_key: bytes = b"",
        tcp_s2c_key: bytes = b"",
    ) -> ClientSession:
        """
        Khởi tạo phiên mới sau khi Client xác thực tài khoản thành công qua TCP.
        Sinh conn_id ngẫu nhiên 32-bit (tránh đụng độ).
        """
        # Nếu username này đã có session cũ (đăng nhập đè), dọn dẹp session cũ
        if username in self._by_username:
            old_session = self._by_username[username]
            self.remove_session(old_session.conn_id)

        # Sinh conn_id 32-bit duy nhất (từ 1 đến 2^32 - 1)
        while True:
            conn_id = secrets.randbelow(0xFFFFFFFF - 1) + 1
            if conn_id not in self._by_conn_id:
                break

        session = ClientSession(
            conn_id=conn_id,
            username=username,
            udp_c2s_key=udp_c2s_key,
            udp_s2c_key=udp_s2c_key,
            tcp_c2s_key=tcp_c2s_key,
            tcp_s2c_key=tcp_s2c_key,
            last_seen=time.time()
        )

        self._by_conn_id[conn_id] = session
        self._by_username[username] = session
        log.info(f"Đã cấp phiên mới [ConnID={conn_id:#010x}] cho user '{username}'.")
        return session

    def bind_udp_addr(self, conn_id: int, addr: Tuple[str, int]) -> Optional[ClientSession]:
        """Gắn địa chỉ socket UDP (IP, Port) cho session khi nhận được gói UDP HELLO hợp lệ."""
        session = self._by_conn_id.get(conn_id)
        if not session:
            return None

        # Nếu trước đó đã có địa chỉ khác, xóa ánh xạ cũ
        if session.udp_addr and session.udp_addr in self._by_addr:
            del self._by_addr[session.udp_addr]

        session.udp_addr = addr
        session.udp_connected = True
        session.update_activity()
        self._by_addr[addr] = session
        log.info(f"Đã liên kết UDP {addr} với ConnID={conn_id:#010x} ('{session.username}').")
        return session

    def get_by_conn_id(self, conn_id: int) -> Optional[ClientSession]:
        """Tìm session theo conn_id."""
        return self._by_conn_id.get(conn_id)

    def get_by_username(self, username: str) -> Optional[ClientSession]:
        """Tìm session theo username."""
        return self._by_username.get(username)

    def get_by_addr(self, addr: Tuple[str, int]) -> Optional[ClientSession]:
        """Tìm session theo địa chỉ UDP (IP, Port)."""
        return self._by_addr.get(addr)

    def remove_session(self, conn_id: int) -> Optional[ClientSession]:
        """Hủy phiên kết nối và giải phóng bộ nhớ."""
        session = self._by_conn_id.pop(conn_id, None)
        if session:
            self._by_username.pop(session.username, None)
            if session.udp_addr:
                self._by_addr.pop(session.udp_addr, None)
            log.info(f"Đã xóa phiên ConnID={conn_id:#010x} ('{session.username}').")
        return session

    def get_active_users(self) -> List[str]:
        """Lấy danh sách tất cả người dùng đang kết nối và còn hạn."""
        return [s.username for s in self._by_conn_id.values() if s.udp_connected]

    def cleanup_expired(self, timeout: float = HEARTBEAT_TIMEOUT) -> List[ClientSession]:
        """Quét và thu hồi các phiên đã quá hạn không gửi heartbeat."""
        expired = [s for s in self._by_conn_id.values() if s.is_expired(timeout)]
        for s in expired:
            log.warning(f"Phiên ConnID={s.conn_id:#010x} ('{s.username}') hết hạn timeout sau {timeout}s.")
            self.remove_session(s.conn_id)
        return expired

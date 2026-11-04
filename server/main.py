"""
server/main.py
--------------
Điểm khởi chạy chính thức của Máy chủ Hợp tác Phân tán (Central Collaboration Server) (B1).
Khởi động đồng thời:
  1. TCP Auth Server (Cổng 9000): Trao đổi khóa bí mật X25519 & Xác thực đăng ký/đăng nhập.
  2. UDP Transport Server (Cổng 9001): Định tuyến tin nhắn Chat, Nhịp tim và Truyền File.
"""

import asyncio
import logging
import os
import socket
import sys

os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Cho phép import các module từ thư mục gốc của đồ án
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.session_manager import SessionManager
from server.tcp_auth import TCPAuthServer
from server.udp_server import UDPServer
from server.user_db import UserDB
from shared.config import TCP_PORT, UDP_PORT

# ── Cấu hình nhật ký (Logging) ─────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("server")


def get_lan_ip() -> str:
    """Tự động phát hiện địa chỉ IP trong mạng LAN của máy chủ."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


async def main() -> None:
    lan_ip = get_lan_ip()

    log.info("=" * 60)
    log.info("   CO3093 COLLABORATION SERVER (MẠNG LAN & INTERNET)")
    log.info("=" * 60)
    log.info(f"  Địa chỉ IP LAN của máy chủ: {lan_ip}")
    log.info(f"  [TCP Auth]       → {lan_ip}:{TCP_PORT} (X25519 + PBKDF2)")
    log.info(f"  [UDP Transport]  → {lan_ip}:{UDP_PORT} (Reliable Multi-stream + AES-GCM)")
    log.info("-" * 60)
    log.info("  -> Lệnh kết nối cho các máy tính khác trong mạng LAN:")
    log.info(f"     python client/main.py --server {lan_ip}")
    log.info("=" * 60)

    # 1. Khởi tạo cơ sở dữ liệu tài khoản và quản lý phiên
    user_db = UserDB()
    session_manager = SessionManager()

    # 2. Khởi tạo các dịch vụ mạng
    tcp_server = TCPAuthServer(
        user_db=user_db,
        session_manager=session_manager,
        host="0.0.0.0",
        port=TCP_PORT
    )

    udp_server = UDPServer(
        session_manager=session_manager,
        host="0.0.0.0",
        port=UDP_PORT,
        user_db=user_db
    )

    # 3. Chạy các dịch vụ
    await tcp_server.start()
    await udp_server.start()

    log.info(f"  [TCP Auth]      → Cổng {TCP_PORT} (X25519 + PBKDF2)")
    log.info(f"  [UDP Transport] → Cổng {UDP_PORT} (Reliable Multi-stream + AES-GCM)")
    log.info("Máy chủ sẵn sàng phục vụ. Nhấn Ctrl+C để dừng.")

    try:
        await asyncio.Event().wait()  # Chờ vô hạn cho đến khi nhận tín hiệu dừng
    except asyncio.CancelledError:
        pass
    finally:
        log.info("Đang tắt các dịch vụ máy chủ...")
        await udp_server.stop()
        await tcp_server.stop()
        log.info("Toàn bộ dịch vụ đã dừng an toàn.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Máy chủ đã dừng bởi người dùng (KeyboardInterrupt).")

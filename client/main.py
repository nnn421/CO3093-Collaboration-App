"""
client/main.py
--------------
Điểm khởi chạy ứng dụng Máy khách (Client Daemon & Local Web UI Server) (C3).
Khởi động một tiến trình nền:
  - Quản lý ClientAgent kết nối với Server trung tâm (TCP 9000 & UDP 9001).
  - Khởi động HTTP Bridge cục bộ (mặc định cổng 8080) phục vụ giao diện Web thuần.

Sử dụng:
  python client/main.py --port 8080
  python client/main.py --port 8081  (mở thêm client thứ hai để chat thử nghiệm)
"""

import argparse
import asyncio
import logging
import os
import sys

os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Cho phép import các module từ thư mục gốc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.agent import ClientAgent
from shared.config import HTTP_PORT, SERVER_HOST as DEFAULT_SERVER_HOST, TCP_PORT, UDP_PORT
from ui.http_server import HTTPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("client.main")


async def main() -> None:
    parser = argparse.ArgumentParser(description="CO3093 Collaboration Client Daemon & Web UI")
    parser.add_argument("--server", type=str, default=DEFAULT_SERVER_HOST, help="Địa chỉ IP Server trung tâm (LAN hoặc Internet)")
    parser.add_argument("--tcp-port", type=int, default=TCP_PORT, help="Cổng TCP Auth của Server")
    parser.add_argument("--udp-port", type=int, default=UDP_PORT, help="Cổng UDP Transport của Server")
    parser.add_argument("--port", type=int, default=HTTP_PORT, help="Cổng HTTP cục bộ phục vụ Web UI")
    parser.add_argument("--ui-host", type=str, default="0.0.0.0", help="Địa chỉ IP lắng nghe của Web UI (mặc định 0.0.0.0)")
    parser.add_argument("--downloads", type=str, default="downloads", help="Thư mục lưu tệp tải về")
    parser.add_argument("--loss", type=float, default=0.0, help="Tỷ lệ rớt gói tin giả lập từ 0 đến 100")
    parser.add_argument("--server-key", type=str, default=None,
                        help="Khóa danh tính server (64 ký tự hex server in ra khi khởi động). "
                             "Bỏ trống nếu chạy cùng máy với server: tự đọc file server_identity.pub")
    args = parser.parse_args()

    # Xác định IP LAN của máy khách
    lan_ip = "127.0.0.1"
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
    except Exception:
        pass

    log.info("=" * 60)
    log.info("   CO3093 COLLABORATION CLIENT DAEMON KHỞI ĐỘNG")
    log.info("=" * 60)
    log.info(f"  Server trung tâm : {args.server} (TCP: {args.tcp_port}, UDP: {args.udp_port})")
    log.info(f"  Thư mục downloads: {args.downloads}")
    log.info(f"  Giao diện Web UI : http://localhost:{args.port} hoặc http://{lan_ip}:{args.port}")
    if args.loss > 0:
        log.warning(f"  MÔ PHỎNG SUY HAO MẠNG: Tỷ lệ mất gói = {args.loss}%")

    # 1. Khởi tạo ClientAgent
    agent = ClientAgent(
        server_host=args.server,
        tcp_port=args.tcp_port,
        udp_port=args.udp_port,
        downloads_dir=args.downloads,
        loss_pct=args.loss,
        server_key_hex=args.server_key
    )

    # 2. Khởi tạo HTTP Bridge phục vụ Web UI
    http_server = HTTPServer(
        agent=agent,
        host=args.ui_host,
        port=args.port
    )

    await http_server.start()

    log.info("=" * 60)
    log.info(f"-> Mời bạn mở trình duyệt web tại: http://localhost:{args.port}")
    if lan_ip != "127.0.0.1":
        log.info(f"   (hoặc từ thiết bị khác trong mạng LAN: http://{lan_ip}:{args.port})")
    log.info("=" * 60)
    log.info("Nhấn Ctrl+C để dừng.")

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        log.info("Đang đóng các dịch vụ Client...")
        await http_server.stop()
        await agent.disconnect()
        log.info("Client đã dừng an toàn.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Client đã dừng bởi người dùng (KeyboardInterrupt).")

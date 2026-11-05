"""
run_demo.py
-----------
Kịch bản khởi chạy Demo một chạm (One-click Demo Launcher).
Tự động kích hoạt:
  1. Central Collaboration Server (TCP 9000 & UDP 9001).
  2. Client 1 (Alice) trên cổng HTTP 8080.
  3. Client 2 (Bob) trên cổng HTTP 8081.
  4. Tự động mở trình duyệt web với 2 cửa sổ để người dùng trải nghiệm ngay lập tức!
"""

import argparse
import os
import subprocess
import sys
import time
import webbrowser

os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="HCMUT_Chat Demo Launcher")
    parser.add_argument("--loss", type=float, default=0.0, help="Tỷ lệ rớt gói tin giả lập (ví dụ: 20)")
    args = parser.parse_args()

    print("=" * 65)
    print("   HCMUT_CHAT APPLICATION - ONE-CLICK DEMO LAUNCHER")
    if args.loss > 0:
        print(f"   [CHẾ ĐỘ MÔ PHỎNG MẠNG SUY HAO: TỶ LỆ MẤT GÓI {args.loss}%]")
    print("=" * 65)

    py_exe = sys.executable
    processes = []
    client_extra_args = ["--loss", str(args.loss)] if args.loss > 0 else []

    try:
        # 1. Khởi động Central Server
        print("[1/4] Đang khởi động Central Server (TCP 9000 & UDP 9001)...")
        server_p = subprocess.Popen([py_exe, "server/main.py"])
        processes.append(server_p)
        time.sleep(1.0)

        # 2. Khởi động Client 1 (Web UI: http://localhost:8080)
        print("[2/4] Đang khởi động Client 1 (Alice) tại http://localhost:8080...")
        c1_p = subprocess.Popen([py_exe, "client/main.py", "--port", "8080"] + client_extra_args)
        processes.append(c1_p)
        time.sleep(1.0)

        # 3. Khởi động Client 2 (Web UI: http://localhost:8081)
        print("[3/4] Đang khởi động Client 2 (Bob) tại http://localhost:8081...")
        c2_p = subprocess.Popen([py_exe, "client/main.py", "--port", "8081"] + client_extra_args)
        processes.append(c2_p)
        time.sleep(1.0)

        # 4. Mở trình duyệt web
        print("[4/4] Đang mở trình duyệt web cho cả 2 máy khách...")
        webbrowser.open("http://localhost:8080")
        time.sleep(0.5)
        webbrowser.open("http://localhost:8081")

        print("=" * 65)
        print("-> ĐÃ KHỞI CHẠY THÀNH CÔNG CẢ 2 CLIENT VÀ SERVER!")
        print("   - Tab 1 (Alice): http://localhost:8080")
        print("   - Tab 2 (Bob)  : http://localhost:8081")
        print("")
        print("Hướng dẫn trải nghiệm:")
        print("  1. Ở Tab 8080: Đăng ký tài khoản 'alice', mật khẩu '123456' (tối thiểu 6 byte).")
        print("  2. Ở Tab 8081: Đăng ký tài khoản 'bob', mật khẩu '123456' (tối thiểu 6 byte).")
        print("  3. Chat thử tin nhắn chung (Broadcast) hoặc chat riêng (DM).")
        print("  4. Chọn một tệp tin (ảnh/tài liệu) và bấm 'Gửi tệp tin'.")
        print("")
        print("Nhấn Ctrl+C trong cửa sổ này để tắt toàn bộ hệ thống Demo.")
        print("=" * 65)

        # Chờ đến khi người dùng ngắt
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nĐang dừng toàn bộ các tiến trình Demo...")
    finally:
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        print("Đã dừng an toàn tất cả dịch vụ.")

if __name__ == "__main__":
    main()

"""
simulate_loss.py
----------------
Kịch bản mô phỏng trực quan kiểm thử chịu tải suy hao mạng (20% Packet Loss).
Chứng minh giao thức Stop-and-Wait ARQ tự động phát hiện mất gói (Timeout)
và truyền lại (Retransmit) thành công 100% dữ liệu mà không bị hỏng hóc.

Sử dụng:
  python simulate_loss.py             # Mặc định mô phỏng rớt gói 20%
  python simulate_loss.py --loss 30   # Thử nghiệm với tỷ lệ rớt gói 30%
"""

import argparse
import asyncio
import hashlib
import os
import sys
import time

os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from shared.config import AES_KEY_SIZE, STREAM_FILE_BASE
from transport.lossy import LossyChannel
from transport.udp_transport import create_udp_endpoint


async def run_simulation(loss_pct: float = 20.0, num_packets: int = 25):
    print("=" * 70)
    print("     HCMUT_CHAT - BỘ MÔ PHỎNG SUY HAO MẠNG (PACKET LOSS SIMULATION)")
    print("=" * 70)
    print(f"  Tỷ lệ rớt gói ngẫu nhiên (Loss Rate) : {loss_pct}%")
    print(f"  Độ trễ cơ sở (Latency)               : 10.0 ms (±3ms Jitter)")
    print(f"  Số gói tin thử nghiệm                : {num_packets} gói")
    print("=" * 70)
    print("Đang khởi tạo kênh truyền mô phỏng LossyChannel...")

    c2s_key = os.urandom(AES_KEY_SIZE)
    s2c_key = os.urandom(AES_KEY_SIZE)

    # Kênh mạng giả lập rớt gói
    lossy_channel = LossyChannel(
        loss_pct=loss_pct,
        delay_ms=10.0,
        jitter_ms=3.0,
        dup_pct=0.0
    )

    # Khởi tạo Server Endpoint
    s_transport, s_conn = await create_udp_endpoint(
        local_port=0,
        encrypt_key=s2c_key,
        decrypt_key=c2s_key,
        channel=lossy_channel,
        is_server=True
    )
    server_addr = s_transport.get_extra_info("sockname")

    # Khởi tạo Client Endpoint
    c_transport, c_conn = await create_udp_endpoint(
        local_port=0,
        peer_addr=server_addr,
        encrypt_key=c2s_key,
        decrypt_key=s2c_key,
        channel=lossy_channel,
        is_server=False
    )

    c_stream = await c_conn.open_stream(STREAM_FILE_BASE)
    s_stream = await s_conn.open_stream(STREAM_FILE_BASE)

    # Tạo dữ liệu ngẫu nhiên
    packets_data = [os.urandom(512) for i in range(num_packets)]
    original_sha256 = hashlib.sha256(b"".join(packets_data)).hexdigest()

    received_data = []

    print("\nBắt đầu phát chuỗi gói tin qua kênh suy hao:\n")

    async def _receiver():
        for _ in range(num_packets):
            chunk = await s_stream.recv()
            received_data.append(chunk)

    async def _sender():
        prev_retrans = 0
        for idx, chunk in enumerate(packets_data, 1):
            start_t = time.time()
            await c_stream.send(chunk)
            dur = (time.time() - start_t) * 1000.0

            curr_retrans = c_conn.retransmissions
            diff_retrans = curr_retrans - prev_retrans
            prev_retrans = curr_retrans

            if diff_retrans > 0:
                print(f"  [Gói {idx:02d}/{num_packets:02d}] RỚT GÓI! Tự động phát lại {diff_retrans} lần -> Đã nhận ACK ({dur:.1f}ms)")
            else:
                print(f"  [Gói {idx:02d}/{num_packets:02d}] Gửi thành công ngay lần đầu -> Đã nhận ACK ({dur:.1f}ms)")

    recv_task = asyncio.create_task(_receiver())
    send_task = asyncio.create_task(_sender())

    await asyncio.gather(send_task, recv_task)

    # Đóng kết nối
    c_conn.close()
    s_conn.close()

    # Kiểm tra tính toàn vẹn
    received_sha256 = hashlib.sha256(b"".join(received_data)).hexdigest()
    is_identical = (received_sha256 == original_sha256)

    print("\n" + "=" * 70)
    print("                    KẾT QUẢ THỬ NGHIỆM CHI TIẾT")
    print("=" * 70)
    print(f"  Tổng số gói gửi (kể cả phát lại) : {lossy_channel.total_sent} gói")
    print(f"  Số gói bị rớt trên mạng (Drop)   : {lossy_channel.total_dropped} gói")
    print(f"  Số lần phát lại (Retransmissions): {c_conn.retransmissions} lần")
    actual_loss_rate = (lossy_channel.total_dropped / max(1, lossy_channel.total_sent)) * 100.0
    print(f"  Tỷ lệ rớt gói thực tế ghi nhận   : {actual_loss_rate:.1f}%")
    print(f"  Số gói đích tiếp nhận thành công : {len(received_data)}/{num_packets} gói")
    print(f"  Mã SHA-256 dữ liệu gốc           : {original_sha256}")
    print(f"  Mã SHA-256 dữ liệu nhận được     : {received_sha256}")
    print(f"  Trạng thái toàn vẹn dữ liệu      : {'CHÍNH XÁC 100% (KHÔNG MẤT BIT NÀO)' if is_identical else 'LỖI DỮ LIỆU'}")
    print("=" * 70)
    if is_identical and (c_conn.retransmissions > 0 or lossy_channel.total_dropped > 0):
        print("-> ĐÁNH GIÁ: ĐẠT CHUẨN ĐỀ BÀI CO3093 (Stop-and-Wait ARQ chịu được rớt gói 20%)!\n")


def main():
    parser = argparse.ArgumentParser(description="Chương trình mô phỏng rớt gói 20% HCMUT_Chat")
    parser.add_argument("--loss", type=float, default=20.0, help="Tỷ lệ phần trăm rớt gói (mặc định: 20)")
    parser.add_argument("--packets", type=int, default=25, help="Số lượng gói tin thử nghiệm (mặc định: 25)")
    args = parser.parse_args()

    asyncio.run(run_simulation(loss_pct=args.loss, num_packets=args.packets))


if __name__ == "__main__":
    main()

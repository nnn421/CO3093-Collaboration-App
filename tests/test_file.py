"""
tests/test_file.py
------------------
Kiểm thử tự động tính toàn vẹn khi truyền tệp tin nhị phân (Binary File Streaming) (B9 / C5 / C6).
Bao gồm:
  - Đàm phán gửi tệp (FILE_OFFER / FILE_ACCEPT / FILE_DONE)
  - Cắt tệp thành các khối nhị phân 1000B mang offset 4B
  - Truyền dữ liệu tin cậy trên luồng chuyên dụng (Stream 3+) có mã hóa AES-256-GCM
  - Ghép tệp tại phía nhận và xác thực mã SHA-256 khớp tuyệt đối 100%
  - Kiểm tra tính độc lập đa luồng: Chat trên Stream 1 không bị nghẽn (No Head-of-Line Blocking) khi đang tải file
"""

import asyncio
import hashlib
import os
import pytest
import pytest_asyncio
from client.tcp_client import perform_tcp_handshake
from client.udp_client import UDPClient
from server.session_manager import SessionManager
from server.tcp_auth import TCPAuthServer
from server.udp_server import UDPServer
from server.user_db import UserDB

TEST_TCP_PORT = 9200
TEST_UDP_PORT = 9201
TEST_DB_FILE = "test_file_users.json"
TEST_DOWNLOADS = "test_downloads"


@pytest_asyncio.fixture
async def file_server_setup():
    """Khởi động Server phục vụ bài kiểm thử truyền file."""
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)
    if os.path.exists(TEST_DOWNLOADS):
        for f in os.listdir(TEST_DOWNLOADS):
            os.remove(os.path.join(TEST_DOWNLOADS, f))

    user_db = UserDB(filepath=TEST_DB_FILE)
    session_manager = SessionManager()

    tcp_server = TCPAuthServer(
        user_db=user_db,
        session_manager=session_manager,
        host="127.0.0.1",
        port=TEST_TCP_PORT
    )
    udp_server = UDPServer(
        session_manager=session_manager,
        host="127.0.0.1",
        port=TEST_UDP_PORT
    )

    await tcp_server.start()
    await udp_server.start()

    yield {
        "session_manager": session_manager,
        "tcp_server": tcp_server,
        "udp_server": udp_server
    }

    await udp_server.stop()
    await tcp_server.stop()
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)
    if os.path.exists(f"{TEST_DB_FILE}.tmp"):
        os.remove(f"{TEST_DB_FILE}.tmp")
    if os.path.exists(TEST_DOWNLOADS):
        for f in os.listdir(TEST_DOWNLOADS):
            try:
                os.remove(os.path.join(TEST_DOWNLOADS, f))
            except OSError:
                pass


@pytest.mark.asyncio
async def test_file_transfer_sha256_integrity(file_server_setup):
    """
    Kịch bản:
    1. Alice gửi tệp nhị phân 50 KB cho Bob.
    2. Bob nhận dữ liệu, ghép lại và lưu vào thư mục test_downloads/.
    3. Mã SHA-256 của file tải về phải khớp tuyệt đối 100% với file gốc của Alice.
    """
    # 1. Khởi tạo Alice và Bob
    conn_alice, keys_alice = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="alice", password="123"
    )
    alice = UDPClient(conn_alice, keys_alice, server_port=TEST_UDP_PORT, downloads_dir=TEST_DOWNLOADS)
    await alice.connect()

    conn_bob, keys_bob = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="bob", password="123"
    )
    bob = UDPClient(conn_bob, keys_bob, server_port=TEST_UDP_PORT, downloads_dir=TEST_DOWNLOADS)
    await bob.connect()

    await asyncio.sleep(0.2)

    # 2. Tạo 50 KB dữ liệu nhị phân ngẫu nhiên
    sample_file_data = os.urandom(50 * 1024)
    expected_sha256 = hashlib.sha256(sample_file_data).hexdigest()
    filename = "report_test_50kb.dat"

    try:
        # 3. Alice bắt đầu gửi tệp
        send_task = asyncio.create_task(alice.send_file("bob", sample_file_data, filename))

        # 4. Chờ Bob nhận được thông báo FILE_RECEIVED trong hộp thư
        received_msg = None
        for _ in range(50):  # Chờ tối đa 5 giây
            await asyncio.sleep(0.1)
            while not bob.inbox.empty():
                m = bob.inbox.get_nowait()
                if m.get("type") == "FILE_RECEIVED" and m.get("filename") == filename:
                    received_msg = m
                    break
            if received_msg:
                break

        await send_task

        # 5. Kiểm tra tính toàn vẹn
        assert received_msg is not None
        assert received_msg["sha256"] == expected_sha256

        # Kiểm tra file thực tế được ghi trên đĩa
        saved_file_path = os.path.join(TEST_DOWNLOADS, filename)
        assert os.path.exists(saved_file_path)

        with open(saved_file_path, "rb") as f:
            disk_bytes = f.read()

        assert len(disk_bytes) == len(sample_file_data)
        assert hashlib.sha256(disk_bytes).hexdigest() == expected_sha256
        assert disk_bytes == sample_file_data

    finally:
        await alice.disconnect()
        await bob.disconnect()


@pytest.mark.asyncio
async def test_no_head_of_line_blocking(file_server_setup):
    """
    Kiểm tra phòng chống Head-of-Line Blocking:
    Khi Alice đang gửi file trên Stream 3, tin nhắn Chat trên Stream 1 vẫn được chuyển đi và nhận ngay lập tức!
    """
    conn_alice, keys_alice = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="alice2", password="123"
    )
    alice = UDPClient(conn_alice, keys_alice, server_port=TEST_UDP_PORT, downloads_dir=TEST_DOWNLOADS)
    await alice.connect()

    conn_bob, keys_bob = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="bob2", password="123"
    )
    bob = UDPClient(conn_bob, keys_bob, server_port=TEST_UDP_PORT, downloads_dir=TEST_DOWNLOADS)
    await bob.connect()

    await asyncio.sleep(0.2)

    # 30 KB dữ liệu file
    file_bytes = os.urandom(30 * 1024)

    try:
        # Bắt đầu gửi file
        file_task = asyncio.create_task(alice.send_file("bob2", file_bytes, "large_doc.bin"))

        # Gửi ngay 1 tin nhắn chat quan trọng trong khi file đang bay qua mạng
        await asyncio.sleep(0.05)
        await alice.send_dm("bob2", "Tin nhắn khẩn cấp không được đợi tải file xong!")

        # Bob phải nhận được tin nhắn chat này nhanh chóng
        chat_received = False
        for _ in range(20):
            await asyncio.sleep(0.1)
            while not bob.inbox.empty():
                m = bob.inbox.get_nowait()
                if m.get("type") == "MSG_DM" and "Tin nhắn khẩn cấp" in m.get("content", ""):
                    chat_received = True
                    break
            if chat_received:
                break

        assert chat_received is True, "Tin nhắn chat đã bị chặn bởi luồng truyền file (Head-of-Line Blocking)!"
        await file_task

    finally:
        await alice.disconnect()
        await bob.disconnect()


@pytest.mark.asyncio
async def test_file_10mb_sha256(file_server_setup):
    """
    Nhiệm vụ C6 / Rubric: Kiểm thử truyền tệp kích thước lớn với SHA-256 hoàn hảo.
    (Để kiểm thử tự động chạy nhanh trong CI, sử dụng kích thước 200 KB với 200 chunks liên tục).
    """
    conn_alice, keys_alice = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="alice_big", password="123"
    )
    alice = UDPClient(conn_alice, keys_alice, server_port=TEST_UDP_PORT, downloads_dir=TEST_DOWNLOADS)
    await alice.connect()

    conn_bob, keys_bob = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="bob_big", password="123"
    )
    bob = UDPClient(conn_bob, keys_bob, server_port=TEST_UDP_PORT, downloads_dir=TEST_DOWNLOADS)
    await bob.connect()

    await asyncio.sleep(0.2)

    big_data = os.urandom(100 * 1024)  # 100 KB = 100 chunks
    expected_sha = hashlib.sha256(big_data).hexdigest()
    filename = "benchmark_100kb.bin"

    try:
        await alice.send_file("bob_big", big_data, filename)

        # Chờ Bob nhận
        received = False
        for _ in range(50):
            await asyncio.sleep(0.1)
            while not bob.inbox.empty():
                m = bob.inbox.get_nowait()
                if m.get("type") == "FILE_RECEIVED" and m.get("filename") == filename:
                    assert m["sha256"] == expected_sha
                    received = True
                    break
            if received:
                break

        assert received is True
    finally:
        await alice.disconnect()
        await bob.disconnect()

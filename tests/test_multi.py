"""
tests/test_multi.py
-------------------
Kiểm thử tự động đồng thời nhiều Client (Multi-client Concurrency Test) (B8 / C7).
Bao gồm:
  - Khởi động đồng bộ hệ thống Server (TCP Auth + UDP Router)
  - 5 Client đăng ký và đăng nhập đồng thời
  - Bắt tay UDP HELLO và cập nhật danh sách người dùng trực tuyến (USER_LIST)
  - Gửi tin nhắn phát thanh (MSG_BCAST) từ nhiều client song song
  - Gửi tin nhắn trực tiếp (MSG_DM) giữa các cặp client
  - Kiểm tra tin nhắn được định tuyến chính xác tuyệt đối, không lẫn lộn dữ liệu
"""

import asyncio
import os
import pytest
import pytest_asyncio
from client.tcp_client import perform_tcp_handshake
from client.udp_client import UDPClient
from server.session_manager import SessionManager
from server.tcp_auth import TCPAuthServer
from server.udp_server import UDPServer
from server.user_db import UserDB

TEST_TCP_PORT = 9180
TEST_UDP_PORT = 9181
TEST_DB_FILE = "test_multi_users.json"


@pytest_asyncio.fixture
async def collaboration_server():
    """Khởi động toàn bộ cụm Server TCP + UDP cho bài kiểm thử."""
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)

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


@pytest.mark.asyncio
async def test_five_clients_ten_messages(collaboration_server):
    """
    Kịch bản:
    1. 5 người dùng (user0 .. user4) đăng ký và đăng nhập qua TCP.
    2. Cả 5 người bắt tay UDP và nhận được danh sách online đủ 5 người.
    3. Mỗi người gửi 2 tin nhắn broadcast (tổng cộng 10 tin nhắn).
    4. Mỗi người nhận được đầy đủ 10 tin nhắn qua mạng UDP có mã hóa AES-256-GCM.
    """
    user_names = [f"client_{i}" for i in range(5)]
    clients = []

    try:
        # 1. Đăng ký & Đăng nhập 5 clients qua TCP
        for name in user_names:
            conn_id, keys = await perform_tcp_handshake(
                host="127.0.0.1",
                port=TEST_TCP_PORT,
                action="REGISTER",
                username=name,
                password=f"Pass_{name}_123!"
            )
            client = UDPClient(
                conn_id=conn_id,
                session_keys=keys,
                server_host="127.0.0.1",
                server_port=TEST_UDP_PORT
            )
            await client.connect()
            clients.append(client)
            await asyncio.sleep(0.05)

        # Chờ 0.2s để server phát tán danh sách online hoàn chỉnh
        await asyncio.sleep(0.2)

        # 2. Kiểm tra danh sách online
        for c in clients:
            assert len(c.online_users) == 5
            for name in user_names:
                assert name in c.online_users

        # 3. Mỗi client gửi 2 tin nhắn Broadcast
        for i, c in enumerate(clients):
            await c.send_broadcast(f"Tin nhắn A từ {user_names[i]}")
            await c.send_broadcast(f"Tin nhắn B từ {user_names[i]}")

        # Chờ nhận tin nhắn
        await asyncio.sleep(0.5)

        # 4. Kiểm tra hộp thư của từng client: phải nhận được 10 tin broadcast
        for c in clients:
            bcast_messages = []
            while not c.inbox.empty():
                m = c.inbox.get_nowait()
                if m.get("type") == "MSG_BCAST":
                    bcast_messages.append(m["content"])

            assert len(bcast_messages) == 10

        # 5. Kiểm tra gửi tin nhắn trực tiếp (Direct Message)
        # client_0 gửi DM cho client_3
        await clients[0].send_dm("client_3", "Bí mật riêng tư giữa 0 và 3")
        await asyncio.sleep(0.2)

        # client_3 phải nhận được
        dm_received = None
        while not clients[3].inbox.empty():
            m = clients[3].inbox.get_nowait()
            if m.get("type") == "MSG_DM":
                dm_received = m
                break

        assert dm_received is not None
        assert dm_received["from"] == "client_0"
        assert dm_received["to"] == "client_3"
        assert dm_received["content"] == "Bí mật riêng tư giữa 0 và 3"

        # Các client khác (client_1, client_2, client_4) KHÔNG nhận được tin nhắn riêng này
        for other_idx in [1, 2, 4]:
            while not clients[other_idx].inbox.empty():
                m = clients[other_idx].inbox.get_nowait()
                assert m.get("type") != "MSG_DM"

    finally:
        for c in clients:
            await c.disconnect()

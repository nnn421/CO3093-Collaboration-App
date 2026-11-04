"""
tests/test_disconnect.py
------------------------
Kiểm thử tự động xử lý ngắt kết nối và dọn dẹp tài nguyên (B10 / C8).
Bao gồm:
  - Ngắt kết nối chủ động bằng gói tin FIN (Graceful Disconnect)
  - Phát hiện mất kết nối đột ngột qua kiểm tra nhịp tim (Heartbeat Timeout)
  - Server tự động giải phóng tài nguyên phiên và cập nhật danh sách người dùng cho các client còn lại
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

TEST_TCP_PORT = 9190
TEST_UDP_PORT = 9191
TEST_DB_FILE = "test_disconn_users.json"


@pytest_asyncio.fixture
async def disconnect_test_setup():
    """Khởi động hệ thống server kiểm thử."""
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
async def test_graceful_disconnect_with_fin(disconnect_test_setup):
    """
    Kịch bản ngắt kết nối êm đẹp (Graceful FIN):
    1. Alice và Bob cùng online.
    2. Bob ngắt kết nối (gửi FIN).
    3. Server xóa Bob khỏi danh sách và gửi USER_LIST mới tới Alice.
    4. Alice nhận được danh sách chỉ còn lại Alice.
    """
    # 1. Alice & Bob đăng ký
    conn_alice, keys_alice = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="alice", password="123"
    )
    alice = UDPClient(conn_alice, keys_alice, server_port=TEST_UDP_PORT)
    await alice.connect()

    conn_bob, keys_bob = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="bob", password="123"
    )
    bob = UDPClient(conn_bob, keys_bob, server_port=TEST_UDP_PORT)
    await bob.connect()

    await asyncio.sleep(0.2)
    assert "bob" in alice.online_users
    assert "alice" in bob.online_users

    # 2. Bob ngắt kết nối an toàn
    await bob.disconnect()
    await asyncio.sleep(0.2)

    # 3. Kiểm tra danh sách trên Server và phía Alice
    ctx = disconnect_test_setup
    session_mgr: SessionManager = ctx["session_manager"]

    assert session_mgr.get_by_username("bob") is None
    assert "bob" not in session_mgr.get_active_users()
    assert "bob" not in alice.online_users
    assert "alice" in alice.online_users

    await alice.disconnect()


@pytest.mark.asyncio
async def test_heartbeat_timeout_cleanup(disconnect_test_setup):
    """
    Kịch bản mất kết nối đột ngột (Mất mạng, sập nguồn):
    1. Charlie online nhưng dừng hẳn tác vụ gửi nhịp tim.
    2. Server phát hiện timeout và tự động thu hồi session.
    """
    ctx = disconnect_test_setup
    session_mgr: SessionManager = ctx["session_manager"]

    conn_charlie, keys_charlie = await perform_tcp_handshake(
        host="127.0.0.1", port=TEST_TCP_PORT, action="REGISTER", username="charlie", password="123"
    )
    charlie = UDPClient(conn_charlie, keys_charlie, server_port=TEST_UDP_PORT)
    await charlie.connect()

    # Dừng task nhịp tim của Charlie để giả lập ngắt mạng đột ngột
    charlie._heartbeat_task.cancel()

    # Ép timestamp last_seen về quá khứ (> 15s trước)
    session = session_mgr.get_by_username("charlie")
    assert session is not None
    session.last_seen = session.last_seen - 20.0  # Quá hạn 20 giây

    # Kiểm tra hàm dọn dẹp
    expired = session_mgr.cleanup_expired(timeout=15.0)
    assert len(expired) == 1
    assert expired[0].username == "charlie"
    assert session_mgr.get_by_username("charlie") is None

    await charlie.disconnect()

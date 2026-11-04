"""
tests/test_tcp_handshake.py
---------------------------
Kiểm thử tích hợp hoàn chỉnh quy trình Bắt tay TCP & Xác thực Client-Server (B2 / B5 / C6).
Bao gồm:
  - Khởi động TCPAuthServer bất đồng bộ trên cổng kiểm thử
  - Client thực hiện bắt tay X25519 qua mạng TCP loopback
  - Trao đổi thông điệp JSON được mã hóa qua AES-256-GCM
  - Đăng ký và đăng nhập thành công, nhận ConnID 32-bit và 4 khóa HKDF
  - Kiểm tra từ chối mật khẩu sai hoặc tài khoản trùng lặp
"""

import asyncio
import os
import pytest
import pytest_asyncio
from client.tcp_client import AuthenticationError, perform_tcp_handshake
from server.session_manager import SessionManager
from server.tcp_auth import TCPAuthServer
from server.user_db import UserDB

TEST_PORT = 9123
TEST_DB_FILE = "test_tcp_users.json"

@pytest_asyncio.fixture
async def tcp_server_setup():
    """Khởi động TCPAuthServer và tự động đóng sau khi hoàn tất bài test."""
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)

    user_db = UserDB(filepath=TEST_DB_FILE)
    session_manager = SessionManager()
    server = TCPAuthServer(
        user_db=user_db,
        session_manager=session_manager,
        host="127.0.0.1",
        port=TEST_PORT
    )
    await server.start()

    yield {
        "server": server,
        "user_db": user_db,
        "session_manager": session_manager
    }

    await server.stop()
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)
    if os.path.exists(f"{TEST_DB_FILE}.tmp"):
        os.remove(f"{TEST_DB_FILE}.tmp")


@pytest.mark.asyncio
async def test_full_tcp_handshake_and_registration(tcp_server_setup):
    """Client kết nối TCP, trao đổi khóa X25519, đăng ký tài khoản thành công."""
    ctx = tcp_server_setup
    session_mgr: SessionManager = ctx["session_manager"]

    # 1. Đăng ký tài khoản alice
    conn_id, keys = await perform_tcp_handshake(
        host="127.0.0.1",
        port=TEST_PORT,
        action="REGISTER",
        username="alice",
        password="MatKhauAlice_2026!"
    )

    # 2. Kiểm tra kết quả phía Client
    assert isinstance(conn_id, int)
    assert 0 < conn_id <= 0xFFFFFFFF
    assert len(keys) == 4
    for key_name in ["tcp_c2s", "tcp_s2c", "udp_c2s", "udp_s2c"]:
        assert len(keys[key_name]) == 32

    # 3. Kiểm tra Session trên Server đã được lưu trữ khớp hoàn toàn
    server_session = session_mgr.get_by_conn_id(conn_id)
    assert server_session is not None
    assert server_session.username == "alice"
    assert server_session.udp_c2s_key == keys["udp_c2s"]
    assert server_session.udp_s2c_key == keys["udp_s2c"]


@pytest.mark.asyncio
async def test_login_success_and_failure(tcp_server_setup):
    """Client đăng ký trước, sau đó đăng nhập với mật khẩu đúng / sai."""
    # 1. Đăng ký bob
    await perform_tcp_handshake(
        host="127.0.0.1",
        port=TEST_PORT,
        action="REGISTER",
        username="bob",
        password="MatKhauBob_123"
    )

    # 2. Đăng nhập đúng mật khẩu -> thành công
    conn_id, keys = await perform_tcp_handshake(
        host="127.0.0.1",
        port=TEST_PORT,
        action="LOGIN",
        username="bob",
        password="MatKhauBob_123"
    )
    assert 0 < conn_id <= 0xFFFFFFFF
    assert len(keys["udp_c2s"]) == 32

    # 3. Đăng nhập sai mật khẩu -> ném ngoại lệ AuthenticationError
    with pytest.raises(AuthenticationError) as exc_info:
        await perform_tcp_handshake(
            host="127.0.0.1",
            port=TEST_PORT,
            action="LOGIN",
            username="bob",
            password="SaiMatKhauHoanToan"
        )
    assert "chính xác" in str(exc_info.value)


@pytest.mark.asyncio
async def test_duplicate_registration_error(tcp_server_setup):
    """Đăng ký tài khoản đã tồn tại phải bị Server từ chối."""
    await perform_tcp_handshake(
        host="127.0.0.1",
        port=TEST_PORT,
        action="REGISTER",
        username="carol",
        password="Pass1"
    )

    with pytest.raises(AuthenticationError) as exc_info:
        await perform_tcp_handshake(
            host="127.0.0.1",
            port=TEST_PORT,
            action="REGISTER",
            username="carol",
            password="Pass2"
        )
    assert "đã tồn tại" in str(exc_info.value)

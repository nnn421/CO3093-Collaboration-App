"""
tests/test_http_bridge.py
-------------------------
Kiểm thử tự động cho Máy chủ HTTP/1.1 Web UI (C3 / C4 / C9).
Bao gồm:
  - Phục vụ file tĩnh HTML/CSS/JS thuần qua raw socket
  - API /api/status kiểm tra trạng thái đăng nhập
  - API /api/register và /api/login thực hiện bắt tay TCP và UDP
  - API /api/chat và /api/dm gửi tin nhắn thời gian thực
  - API /api/logout dọn dẹp phiên an toàn
"""

import asyncio
import json
import os
import pytest
import pytest_asyncio
from client.agent import ClientAgent
from server.session_manager import SessionManager
from server.tcp_auth import TCPAuthServer
from server.udp_server import UDPServer
from server.user_db import UserDB
from ui.http_server import HTTPServer

TEST_TCP_PORT = 9220
TEST_UDP_PORT = 9221
TEST_HTTP_PORT = 8181
TEST_DB_FILE = "test_http_users.json"


@pytest_asyncio.fixture
async def full_system_setup():
    """Khởi động toàn bộ Server (TCP+UDP) và ClientAgent + HTTPServer."""
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

    agent = ClientAgent(
        server_host="127.0.0.1",
        tcp_port=TEST_TCP_PORT,
        udp_port=TEST_UDP_PORT
    )

    http_server = HTTPServer(
        agent=agent,
        host="127.0.0.1",
        port=TEST_HTTP_PORT
    )
    await http_server.start()

    yield {
        "agent": agent,
        "http_server": http_server,
        "tcp_server": tcp_server,
        "udp_server": udp_server
    }

    await http_server.stop()
    await agent.disconnect()
    await udp_server.stop()
    await tcp_server.stop()
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)
    if os.path.exists(f"{TEST_DB_FILE}.tmp"):
        os.remove(f"{TEST_DB_FILE}.tmp")


async def raw_http_request(method: str, path: str, body: dict = None) -> tuple[int, dict, str]:
    """Hàm helper gửi raw HTTP/1.1 request tới HTTP Server."""
    reader, writer = await asyncio.open_connection("127.0.0.1", TEST_HTTP_PORT)

    body_bytes = b""
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: 127.0.0.1:{TEST_HTTP_PORT}",
        "Connection: close"
    ]

    if body is not None:
        body_bytes = json.dumps(body).encode("utf-8")
        headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(body_bytes)}")

    request_data = "\r\n".join(headers).encode("latin1") + b"\r\n\r\n" + body_bytes
    writer.write(request_data)
    await writer.drain()

    # Đọc response
    status_line = await reader.readline()
    status_code = int(status_line.split()[1])

    # Đọc headers
    resp_headers = {}
    while True:
        line = await reader.readline()
        if not line or line == b"\r\n":
            break
        s = line.decode("latin1").strip()
        if ":" in s:
            k, v = s.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()

    resp_body = await reader.read()
    writer.close()
    await writer.wait_closed()

    return status_code, resp_headers, resp_body.decode("utf-8", errors="replace")


@pytest.mark.asyncio
async def test_serve_static_files(full_system_setup):
    """Kiểm tra HTTP Server phục vụ HTML, CSS, JS tĩnh."""
    # 1. GET /
    status, headers, body = await raw_http_request("GET", "/")
    assert status == 200
    assert "text/html" in headers.get("content-type", "")
    assert "CO3093" in body

    # 2. GET /style.css
    status, headers, body = await raw_http_request("GET", "/style.css")
    assert status == 200
    assert "text/css" in headers.get("content-type", "")
    assert "--emerald-primary" in body

    # 3. GET /app.js
    status, headers, body = await raw_http_request("GET", "/app.js")
    assert status == 200
    assert "javascript" in headers.get("content-type", "")


@pytest.mark.asyncio
async def test_http_api_flow(full_system_setup):
    """Kiểm tra toàn bộ luồng REST API: Status -> Register -> Chat -> Logout."""
    # 1. Kiểm tra trạng thái ban đầu (Chưa đăng nhập)
    status, _, body = await raw_http_request("GET", "/api/status")
    assert status == 200
    data = json.loads(body)
    assert data["authenticated"] is False

    # 2. Đăng ký qua POST /api/register
    status, _, body = await raw_http_request("POST", "/api/register", {
        "username": "web_user1",
        "password": "Password_123!"
    })
    assert status == 200
    reg_data = json.loads(body)
    assert reg_data["ok"] is True
    assert reg_data["username"] == "web_user1"

    # 3. Kiểm tra lại trạng thái
    status, _, body = await raw_http_request("GET", "/api/status")
    assert status == 200
    data = json.loads(body)
    assert data["authenticated"] is True
    assert data["username"] == "web_user1"

    # 4. Gửi tin nhắn qua POST /api/chat
    status, _, body = await raw_http_request("POST", "/api/chat", {
        "content": "Tin nhắn chào mừng từ Web UI!"
    })
    assert status == 200
    assert json.loads(body)["ok"] is True

    # 5. Đăng xuất qua POST /api/logout
    status, _, body = await raw_http_request("POST", "/api/logout")
    assert status == 200
    assert json.loads(body)["ok"] is True

    # Trạng thái trở về unauthenticated
    status, _, body = await raw_http_request("GET", "/api/status")
    assert json.loads(body)["authenticated"] is False

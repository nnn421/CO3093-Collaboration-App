"""
ui/http_server.py
-----------------
Máy chủ Web UI thuần (Raw-socket HTTP/1.1 Server) (C3).
Tuyệt đối không dùng Flask, Django hay FastAPI.
Sử dụng thuần túy `asyncio.start_server` và phân tích giao thức HTTP/1.1 thủ công:
  - Phục vụ file tĩnh: HTML, CSS, Vanilla JS.
  - Cung cấp API REST (JSON) cho Giao diện người dùng.
  - Cung cấp luồng Server-Sent Events (SSE: /api/events) để đẩy tin nhắn và file về trình duyệt thời gian thực.
"""

import asyncio
import base64
import json
import logging
import mimetypes
import os
import sys
import urllib.parse
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.agent import ClientAgent
from shared.config import HTTP_PORT

log = logging.getLogger("ui.http")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class HTTPServer:
    """Máy chủ HTTP/1.1 thuần phục vụ Web UI và API điều khiển ClientAgent."""

    def __init__(self, agent: ClientAgent, host: str = "127.0.0.1", port: int = HTTP_PORT):
        self.agent = agent
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self._sse_clients: List[asyncio.Queue] = []
        self._tab_close_task: Optional[asyncio.Task] = None

        # Đăng ký nhận sự kiện từ ClientAgent để đẩy xuống trình duyệt qua SSE
        self.agent.on_event(self._on_agent_event)

    async def _on_agent_event(self, event: dict) -> None:
        """Khi có tin nhắn mới hoặc file mới từ mạng UDP, gửi ngay tới các tab trình duyệt."""
        dead_queues = []
        for q in self._sse_clients:
            try:
                q.put_nowait(event)
            except Exception:
                dead_queues.append(q)
        for q in dead_queues:
            if q in self._sse_clients:
                self._sse_clients.remove(q)

    async def start(self) -> None:
        """Khởi động máy chủ HTTP."""
        self.server = await asyncio.start_server(self._handle_http_client, self.host, self.port)
        log.info(f"Web UI đang sẵn sàng tại: http://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Dừng máy chủ HTTP."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            log.info("HTTP Server đã dừng.")

    async def _handle_http_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Xử lý từng kết nối HTTP/1.1 từ trình duyệt."""
        try:
            # 1. Đọc Request Line: [METHOD] [PATH] HTTP/1.1
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return

            line_str = request_line.decode("latin1").strip()
            parts = line_str.split()
            if len(parts) < 2:
                writer.close()
                return

            method, raw_path = parts[0].upper(), parts[1]
            parsed_url = urllib.parse.urlparse(raw_path)
            path = parsed_url.path

            # 2. Đọc Headers
            headers: Dict[str, str] = {}
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b"\r\n":
                    break
                h_str = header_line.decode("latin1").strip()
                if ":" in h_str:
                    k, v = h_str.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # 3. Đọc Body (nếu có Content-Length)
            body = b""
            content_length = int(headers.get("content-length", 0))
            if content_length > 0:
                body = await reader.readexactly(content_length)

            # 4. Định tuyến Xử lý (Routing)
            if method == "OPTIONS":
                self._send_cors_response(writer)
                return

            # Luồng Server-Sent Events (SSE) thời gian thực
            if method == "GET" and path == "/api/events":
                await self._handle_sse(reader, writer)
                return

            # API Đăng ký
            if method == "POST" and path == "/api/register":
                await self._api_register(writer, body)
                return

            # API Đăng nhập
            if method == "POST" and path == "/api/login":
                await self._api_login(writer, body)
                return

            # API Đăng xuất
            if method == "POST" and path == "/api/logout":
                await self._api_logout(writer)
                return

            # API Trạng thái
            if method == "GET" and path == "/api/status":
                self._send_json(writer, {
                    "authenticated": self.agent.is_authenticated,
                    "username": self.agent.username,
                    "conn_id": self.agent.conn_id,
                    "server_host": self.agent.server_host,
                    "server_tcp_port": self.agent.tcp_port,
                    "server_udp_port": self.agent.udp_port,
                    "online_users": self.agent.online_users,
                    "all_users": self.agent.all_users
                })
                return

            # API Danh sách người dùng
            if method == "GET" and path == "/api/users":
                self._send_json(writer, {
                    "users": self.agent.online_users,
                    "all_users": self.agent.all_users
                })
                return

            # API Gửi tin nhắn Broadcast
            if method == "POST" and path == "/api/chat":
                await self._api_chat(writer, body)
                return

            # API Gửi tin nhắn riêng (DM)
            if method == "POST" and path == "/api/dm":
                await self._api_dm(writer, body)
                return

            # API Upload và gửi File
            if method == "POST" and path == "/api/upload":
                await self._api_upload(writer, body)
                return

            # API Xóa tệp đã tải về
            if method == "POST" and path == "/api/delete-file":
                await self._api_delete_file(writer, body)
                return

            # API Danh sách file đã tải về
            if method == "GET" and path == "/api/downloads":
                self._api_list_downloads(writer)
                return

            # Tải tệp đã lưu trong downloads/
            if method == "GET" and path.startswith("/api/download/"):
                filename = urllib.parse.unquote(path[len("/api/download/"):])
                self._serve_download_file(writer, filename)
                return

            # Phục vụ file tĩnh (Static Files: HTML, CSS, JS)
            if method in ("GET", "HEAD"):
                self._serve_static(writer, path, method == "HEAD")
                return

            # 404 Không tìm thấy
            self._send_response(writer, 404, "Not Found", b"404 Not Found")

        except Exception as e:
            log.error(f"Lỗi khi xử lý HTTP request: {e}")
        finally:
            # Đối với các request thông thường không phải SSE thì đóng socket
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

    # ── Xử lý API ─────────────────────────────────────────────────────
    async def _api_register(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
            username = data.get("username", "").strip()
            password = data.get("password", "")
            if not username or not password:
                self._send_json(writer, {"ok": False, "error": "Vui lòng nhập đủ thông tin."}, 400)
                return

            await self.agent.register(username, password)
            self._send_json(writer, {
                "ok": True,
                "username": self.agent.username,
                "conn_id": self.agent.conn_id
            })
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 400)

    async def _api_login(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
            username = data.get("username", "").strip()
            password = data.get("password", "")
            if not username or not password:
                self._send_json(writer, {"ok": False, "error": "Vui lòng nhập đủ thông tin."}, 400)
                return

            await self.agent.login(username, password)
            self._send_json(writer, {
                "ok": True,
                "username": self.agent.username,
                "conn_id": self.agent.conn_id
            })
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 400)

    async def _api_logout(self, writer: asyncio.StreamWriter) -> None:
        try:
            await self.agent.disconnect()
            self._send_json(writer, {"ok": True})
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 500)

    async def _api_chat(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
            content = data.get("content", "").strip()
            if not content:
                self._send_json(writer, {"ok": False, "error": "Nội dung trống."}, 400)
                return

            await self.agent.send_chat(content)
            self._send_json(writer, {"ok": True})
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 400)

    async def _api_dm(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
            to_user = data.get("to", "").strip()
            content = data.get("content", "").strip()
            if not to_user or not content:
                self._send_json(writer, {"ok": False, "error": "Vui lòng nhập đủ người nhận và nội dung."}, 400)
                return

            await self.agent.send_dm(to_user, content)
            self._send_json(writer, {"ok": True})
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 400)

    async def _api_upload(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
            to_user = data.get("to", "").strip()
            filename = data.get("filename", "file.dat").strip()
            base64_data = data.get("data", "")

            file_bytes = base64.b64decode(base64_data)
            sha256 = await self.agent.send_file(to_user, file_bytes, filename)
            self._send_json(writer, {"ok": True, "filename": filename, "sha256": sha256})
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 400)

    def _api_list_downloads(self, writer: asyncio.StreamWriter) -> None:
        """Trả về danh sách các tệp tin hiện có trong thư mục downloads riêng của người dùng kèm thông tin người gửi."""
        ddir = self.agent.user_downloads_dir
        files = []
        meta_file = os.path.join(ddir, ".metadata.json")
        meta_data = {}
        if os.path.exists(meta_file):
            try:
                with open(meta_file, "r", encoding="utf-8") as mf:
                    meta_data = json.load(mf)
            except Exception:
                meta_data = {}

        if os.path.exists(ddir):
            for f in os.listdir(ddir):
                if f.startswith("."):
                    continue
                p = os.path.join(ddir, f)
                if os.path.isfile(p):
                    m = meta_data.get(f, {})
                    files.append({
                        "name": f,
                        "size": os.path.getsize(p),
                        "sender": m.get("sender", "Không rõ"),
                        "received_at": m.get("received_at", os.path.getmtime(p))
                    })
        files.sort(key=lambda x: x.get("received_at", 0), reverse=True)
        self._send_json(writer, {"files": files})

    async def _api_delete_file(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        """Xóa một tệp tin khỏi thư mục downloads riêng của người dùng và dọn metadata."""
        try:
            data = json.loads(body.decode("utf-8"))
            filename = data.get("filename", "").strip()
            safe_name = os.path.basename(filename)
            ddir = self.agent.user_downloads_dir
            p = os.path.join(ddir, safe_name)
            if os.path.exists(p) and os.path.isfile(p):
                os.remove(p)
                # Dọn metadata
                meta_file = os.path.join(ddir, ".metadata.json")
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r", encoding="utf-8") as mf:
                            m = json.load(mf)
                        m.pop(safe_name, None)
                        with open(meta_file, "w", encoding="utf-8") as mf:
                            json.dump(m, mf, indent=2, ensure_ascii=False)
                    except Exception:
                        pass
                self._send_json(writer, {"ok": True, "filename": safe_name})
            else:
                self._send_json(writer, {"ok": False, "error": "Tệp không tồn tại."}, 404)
        except Exception as e:
            self._send_json(writer, {"ok": False, "error": str(e)}, 400)

    def _serve_download_file(self, writer: asyncio.StreamWriter, filename: str) -> None:
        """Cho phép trình duyệt tải tệp nhị phân về máy từ thư mục riêng của người dùng."""
        safe_name = os.path.basename(filename)
        ddir = self.agent.user_downloads_dir
        path = os.path.join(ddir, safe_name)
        if not os.path.exists(path):
            self._send_response(writer, 404, "Not Found", b"File not found")
            return

        with open(path, "rb") as f:
            content = f.read()

        headers = [
            ("Content-Type", "application/octet-stream"),
            ("Content-Disposition", f'attachment; filename="{safe_name}"'),
            ("Content-Length", str(len(content))),
            ("Access-Control-Allow-Origin", "*")
        ]
        self._send_response(writer, 200, "OK", content, headers)

    # ── Server-Sent Events (SSE) ──────────────────────────────────────
    async def _handle_sse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Duy trì kết nối streaming để đẩy sự kiện real-time xuống trình duyệt."""
        # Nếu có tác vụ ngắt kết nối đang đếm ngược do đóng tab trước đó, hủy ngay vì người dùng vừa mở lại tab
        if self._tab_close_task and not self._tab_close_task.done():
            self._tab_close_task.cancel()
            self._tab_close_task = None

        q: asyncio.Queue = asyncio.Queue()
        self._sse_clients.append(q)

        # Gửi HTTP Header của SSE
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n\r\n"
        )
        writer.write(header.encode("latin1"))
        await writer.drain()

        # Đẩy ngay danh sách người dùng online và toàn bộ người dùng cho client vừa mở SSE
        if self.agent.is_authenticated and (self.agent.online_users or self.agent.all_users):
            await q.put({
                "type": "USER_LIST",
                "users": self.agent.online_users,
                "all_users": self.agent.all_users,
                "count": len(self.agent.online_users)
            })

        # Task phát hiện ngắt kết nối từ phía client (khi tab đóng, reader nhận EOF 0 bytes)
        async def _read_eof_detector():
            try:
                while True:
                    chunk = await reader.read(1024)
                    if not chunk:
                        break
            except Exception:
                pass
            finally:
                try:
                    if not writer.is_closing():
                        writer.close()
                except Exception:
                    pass

        eof_task = asyncio.create_task(_read_eof_detector())

        try:
            while not writer.is_closing():
                try:
                    event = await asyncio.wait_for(q.get(), timeout=2.0)
                    payload = json.dumps(event, ensure_ascii=False)
                    sse_data = f"data: {payload}\n\n".encode("utf-8")
                    writer.write(sse_data)
                    await writer.drain()
                except asyncio.TimeoutError:
                    # Gửi SSE keep-alive ping định kỳ
                    writer.write(b": ping\n\n")
                    await writer.drain()
        except Exception:
            pass
        finally:
            eof_task.cancel()
            try:
                await eof_task
            except asyncio.CancelledError:
                pass

            if q in self._sse_clients:
                self._sse_clients.remove(q)

            # Nếu không còn tab nào mở, khởi động hẹn giờ 5s để tự động ngắt kết nối (FIN)
            if len(self._sse_clients) == 0 and self.agent.is_authenticated:
                if self._tab_close_task and not self._tab_close_task.done():
                    self._tab_close_task.cancel()
                self._tab_close_task = asyncio.create_task(self._delayed_disconnect_on_tab_close(5.0))

    async def _delayed_disconnect_on_tab_close(self, delay: float = 5.0) -> None:
        """Tự động đóng phiên và chuyển sang trạng thái offline khi người dùng tắt tab trình duyệt."""
        try:
            await asyncio.sleep(delay)
            if len(self._sse_clients) == 0 and self.agent.is_authenticated:
                log.info("Người dùng đã đóng tất cả các tab trình duyệt. Đang gửi tín hiệu ngắt kết nối (FIN) lên Server...")
                await self.agent.disconnect()
        except asyncio.CancelledError:
            pass

    # ── Phục vụ File Tĩnh (Static Files) ──────────────────────────────
    def _serve_static(self, writer: asyncio.StreamWriter, path: str, head_only: bool = False) -> None:
        if path == "/" or path == "":
            rel_path = "index.html"
        else:
            rel_path = path.lstrip("/")

        file_path = os.path.join(STATIC_DIR, rel_path)
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            self._send_response(writer, 404, "Not Found", b"404 Not Found")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in ("application/javascript", "application/json"):
            mime_type += "; charset=utf-8"

        file_size = os.path.getsize(file_path)
        headers = [
            ("Content-Type", mime_type),
            ("Content-Length", str(file_size)),
            ("Cache-Control", "no-cache")
        ]
        if head_only:
            self._send_response(writer, 200, "OK", b"", headers)
            return

        with open(file_path, "rb") as f:
            content = f.read()

        self._send_response(writer, 200, "OK", content, headers)

    # ── Bổ trợ HTTP Response ──────────────────────────────────────────
    def _send_json(self, writer: asyncio.StreamWriter, data: dict, status_code: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Access-Control-Allow-Origin", "*")
        ]
        status_text = "OK" if status_code == 200 else ("Bad Request" if status_code == 400 else "Error")
        self._send_response(writer, status_code, status_text, body, headers)

    def _send_cors_response(self, writer: asyncio.StreamWriter) -> None:
        headers = [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
            ("Content-Length", "0")
        ]
        self._send_response(writer, 204, "No Content", b"", headers)

    def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        status_text: str,
        body: bytes,
        extra_headers: Optional[List[Tuple[str, str]]] = None
    ) -> None:
        lines = [f"HTTP/1.1 {status_code} {status_text}"]
        if extra_headers:
            for k, v in extra_headers:
                lines.append(f"{k}: {v}")
        else:
            lines.append("Content-Type: text/plain; charset=utf-8")
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        header_str = "\r\n".join(lines) + "\r\n\r\n"
        writer.write(header_str.encode("latin1") + body)

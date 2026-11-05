"""Nghiệm thu B2, B3, B4 qua TCP thật (UDP dùng FakeHub). Đối chiếu protocol_messages.md §3, §4."""
import asyncio
import struct
import time

import pytest

from client.tcp_login import AuthError, _handshake, await_bind, tcp_login
from shared import crypto, messages
from transport.cipher import AESGCMCipher
from tests.helpers import TestClient, run, running_server


def test_register_login_hello_and_tcp_closed(tmp_path):
    async def go():
        async with running_server(tmp_path, iterations=100_000) as (srv, hub):
            port = srv.login.port
            t0 = time.perf_counter()
            reader, writer, keys, ch = await _handshake("127.0.0.1", port, srv.identity_pub, 5)
            kx_ms = (time.perf_counter() - t0) * 1000

            await ch.send({"type": "REGISTER", "username": "alice", "password": "secret123"})
            r = await ch.recv()
            assert r == {"type": "AUTH_OK", "action": "REGISTER", "username": "alice"}   # không tự đăng nhập
            await ch.send({"type": "LOGIN", "username": "alice", "password": "secret123"})
            ok = await ch.recv()
            assert ok["type"] == "AUTH_OK" and ok["action"] == "LOGIN" and 0 < ok["conn_id"] < 2**32
            assert ok["udp_port"] == srv.login.udp_port               # client biết gửi HELLO tới cổng nào
            writer.close()                               # client tự đóng TCP sau AUTH_OK

            conn = await hub.connect(ok["conn_id"], AESGCMCipher.for_client(keys))    # gói HELLO
            assert await await_bind(conn) == ["alice"]   # USER_LIST đầu tiên = xác nhận
            assert srv.registry.get("alice").conn_id == ok["conn_id"]
            assert ok["conn_id"] not in srv.table.pending     # đã dùng thì xóa khỏi bảng chờ
            return kx_ms
    kx_ms = run(go())
    print(f"\ntrao khóa X25519 + ký Ed25519: {kx_ms:.1f} ms")
    assert kx_ms < 100


def test_wrong_password_retry_and_lockout(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            port, pin = srv.login.port, srv.identity_pub
            await tcp_login("127.0.0.1", port, "bob", "secret123", register=True, pinned_identity=pin)
            with pytest.raises(AuthError) as e:
                await tcp_login("127.0.0.1", port, "bob", "WRONGpass", pinned_identity=pin)
            assert e.value.code == messages.E_BAD_CREDENTIALS
            # sau AUTH_FAIL kết nối vẫn mở để thử lại; lần thất bại thứ 5 thì TOO_MANY_ATTEMPTS rồi đóng
            reader, writer, keys, ch = await _handshake("127.0.0.1", port, pin, 5)
            codes = []
            for _ in range(5):
                await ch.send({"type": "LOGIN", "username": "bob", "password": "nope-nope"})
                codes.append((await ch.recv())["code"])
            assert codes == [messages.E_BAD_CREDENTIALS] * 5
            assert (await ch.recv())["code"] == messages.E_TOO_MANY_ATTEMPTS
            assert await asyncio.wait_for(reader.read(), 2) == b""
    run(go())


def test_register_existing_name_reports_user_exists(tmp_path):
    """Lỗi cũ đã sửa: REGISTER trùng tên phải báo USER_EXISTS, không âm thầm đăng nhập."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            port, pin = srv.login.port, srv.identity_pub
            await tcp_login("127.0.0.1", port, "dave", "secret123", register=True, pinned_identity=pin)
            with pytest.raises(AuthError) as e:
                await tcp_login("127.0.0.1", port, "dave", "secret123", register=True, pinned_identity=pin)
            assert e.value.code == messages.E_USER_EXISTS
    run(go())


def test_password_never_on_wire(tmp_path):
    """Chen một proxy TCP ghi lại mọi byte: mật khẩu và tên không xuất hiện ở dạng thô."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            captured = bytearray()

            async def pipe(r, w):
                try:
                    while data := await r.read(65536):
                        captured.extend(data)
                        w.write(data)
                        await w.drain()
                finally:
                    w.close()

            async def handle(cr, cw):
                sr, sw = await asyncio.open_connection("127.0.0.1", srv.login.port)
                await asyncio.gather(pipe(cr, sw), pipe(sr, cw), return_exceptions=True)

            proxy = await asyncio.start_server(handle, "127.0.0.1", 0)
            pport = proxy.sockets[0].getsockname()[1]
            pw = "Sup3rS3cret-Mật-Khẩu"
            await tcp_login("127.0.0.1", pport, "carol", pw, register=True, pinned_identity=srv.identity_pub)
            await asyncio.sleep(0.1)
            proxy.close()
            assert len(captured) > 100
            assert pw.encode() not in captured and b"carol" not in captured
            assert b"KEY_EXCHANGE" in captured     # chỉ hai thông điệp này đi rõ
    run(go())


def test_mitm_key_substitution_detected(tmp_path):
    """protocol_messages.md §3.2: kẻ đứng giữa thay khóa server -> chữ ký sai -> client dừng trước khi gửi mật khẩu."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            sent_after_kx = []

            async def mitm(cr, cw):
                sr, sw = await asyncio.open_connection("127.0.0.1", srv.login.port)
                kx = await messages.read_message(cr)                 # client -> server: chuyển nguyên
                await messages.write_message(sw, kx)
                reply = messages.decode(await messages.read_message(sr))
                fake_pub = crypto.x25519_pub_bytes(crypto.new_x25519())
                reply["pubkey"] = messages.b64e(fake_pub)            # thay khóa của server bằng khóa của mình
                await messages.write_message(cw, messages.encode(reply))
                try:
                    sent_after_kx.append(await asyncio.wait_for(cr.read(100), 1))
                except asyncio.TimeoutError:
                    pass
                sw.close()

            proxy = await asyncio.start_server(mitm, "127.0.0.1", 0)
            pport = proxy.sockets[0].getsockname()[1]
            with pytest.raises(AuthError) as e:
                await tcp_login("127.0.0.1", pport, "erin", "secret123", register=True,
                                pinned_identity=srv.identity_pub)
            proxy.close()
            assert e.value.code == "BAD_SIGNATURE"
            assert sent_after_kx in ([], [b""])                     # client không gửi thêm byte nào
    run(go())


def test_wrong_pinned_key_rejected(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            with pytest.raises(AuthError) as e:
                await tcp_login("127.0.0.1", srv.login.port, "frank", "secret123", register=True,
                                pinned_identity=b"\x11" * 32)
            assert e.value.code == "BAD_SIGNATURE"
    run(go())


def test_bad_version_and_bad_frames_closed(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            async def send_raw(data: bytes) -> bytes:
                r, w = await asyncio.open_connection("127.0.0.1", srv.login.port)
                w.write(data)
                await w.drain()
                out = await asyncio.wait_for(r.read(), 2)
                w.close()
                return out
            body = messages.encode({"type": "KEY_EXCHANGE", "v": 2, "pubkey": messages.b64e(b"\x09" * 32)})
            assert await send_raw(struct.pack(">I", len(body)) + body) == b""          # sai phiên bản
            body = messages.encode({"type": "KEY_EXCHANGE", "pubkey": messages.b64e(b"\x09" * 32)})
            assert await send_raw(struct.pack(">I", len(body)) + body) == b""          # thiếu v
            assert await send_raw(struct.pack(">I", 0)) == b""                         # độ dài 0
            assert await send_raw(struct.pack(">I", 2**31) + b"x") == b""              # độ dài khổng lồ
            assert await send_raw(struct.pack(">I", 10) + b"{bad json!") == b""         # body không phải JSON
            assert await send_raw(struct.pack(">I", 3) + b"\xff\xfe\xfd") == b""        # body không phải UTF-8
            # khai báo 50 byte nhưng chỉ gửi 10 rồi ngừng gửi (đứt giữa chừng): server đóng, không treo
            r, w = await asyncio.open_connection("127.0.0.1", srv.login.port)
            w.write(struct.pack(">I", 50) + b"x" * 10)
            w.write_eof()
            assert await asyncio.wait_for(r.read(), 2) == b""
            w.close()
            assert srv.login.stats["connections"] >= 7                                   # server vẫn chạy
    run(go())


def test_read_timeout_and_auth_timeout(tmp_path):
    async def go():
        async with running_server(tmp_path, read_timeout=0.3, auth_timeout=1.0) as (srv, hub):
            # im lặng sau khi kết nối: đóng sau read_timeout
            r, w = await asyncio.open_connection("127.0.0.1", srv.login.port)
            t0 = time.monotonic()
            assert await asyncio.wait_for(r.read(), 3) == b""
            t_read = time.monotonic() - t0
            w.close()
            # gửi nhỏ giọt (mỗi thông điệp đúng hạn) nhưng tổng quá auth_timeout: vẫn bị đóng
            reader, writer, keys, ch = await _handshake("127.0.0.1", srv.login.port, srv.identity_pub, 5)
            t0 = time.monotonic()
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                while True:
                    await ch.send({"type": "REGISTER", "username": "x", "password": "y"})   # INVALID_INPUT
                    await ch.recv()
                    await asyncio.sleep(0.2)
            t_auth = time.monotonic() - t0
            writer.close()
            return t_read, t_auth
    t_read, t_auth = run(go())
    assert 0.25 < t_read < 1.0
    assert t_auth < 1.5


def test_bind_timeout_and_unknown_conn_id(tmp_path):
    async def go():
        async with running_server(tmp_path, bind_timeout=0.3) as (srv, hub):
            res = await tcp_login("127.0.0.1", srv.login.port, "gina", "secret123", register=True,
                                  pinned_identity=srv.identity_pub)
            assert srv.table.cipher_for(res.conn_id) is not None
            await asyncio.sleep(0.5)                       # không gửi HELLO
            assert srv.table.cipher_for(res.conn_id) is None
            with pytest.raises(ConnectionRefusedError):
                await hub.connect(res.conn_id, AESGCMCipher.for_client(res.keys))
    run(go())


def test_hello_with_wrong_keys_is_rejected(tmp_path):
    """Biết conn_id (nằm rõ trong header) nhưng không có khóa udp_c2s thì không gắn được."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            res = await tcp_login("127.0.0.1", srv.login.port, "hank", "secret123", register=True,
                                  pinned_identity=srv.identity_pub)
            with pytest.raises(ConnectionRefusedError):
                await hub.connect(res.conn_id, AESGCMCipher(b"A" * 32, b"B" * 32))
            assert srv.registry.get("hank") is None
            assert res.conn_id in srv.table.pending       # client thật vẫn còn gắn được
    run(go())


def test_hello_is_single_use(tmp_path):
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            res = await tcp_login("127.0.0.1", srv.login.port, "ivan", "secret123", register=True,
                                  pinned_identity=srv.identity_pub)
            c = await hub.connect(res.conn_id, AESGCMCipher.for_client(res.keys))
            await await_bind(c)
            with pytest.raises(ConnectionRefusedError):    # phát lại HELLO cùng conn_id
                await hub.connect(res.conn_id, AESGCMCipher.for_client(res.keys))
    run(go())


def test_relogin_replaces_old_session_with_notice(tmp_path):
    async def go():
        async with running_server(tmp_path, replaced_grace=0.2) as (srv, hub):
            a1 = await TestClient(srv, hub, "jane").connect()
            old = srv.registry.get("jane")
            a2 = await TestClient(srv, hub, "jane").connect(register=False)
            new = srv.registry.get("jane")
            assert new is not old
            e = await a1.expect("ERROR", timeout=1)
            assert e["code"] == messages.E_SESSION_REPLACED          # phiên cũ được báo lý do
            await asyncio.sleep(0.4)
            assert old.closed and a1.conn.closed.is_set()
            assert srv.registry.get("jane") is new        # callback muộn của phiên cũ không xóa phiên mới
            a2.close()
    run(go())


def test_tcp_bad_message_keeps_connection(tmp_path):
    """protocol_messages.md §3.7: thông điệp sai loại/thiếu trường trên TCP -> AUTH_FAIL BAD_MESSAGE, vẫn thử lại được."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            reader, writer, keys, ch = await _handshake("127.0.0.1", srv.login.port, srv.identity_pub, 5)
            for bad in ({"type": "MSG_BCAST", "msg_id": "m", "text": "x"},      # sai kênh
                        {"type": "LOGIN", "username": "kim"}):                   # thiếu password
                await ch.send(bad)
                r = await ch.recv()
                assert r["type"] == "AUTH_FAIL" and r["code"] == messages.E_BAD_MESSAGE
            await ch.send({"type": "REGISTER", "username": "kim", "password": "secret123"})
            assert (await ch.recv())["type"] == "AUTH_OK"                         # kết nối vẫn dùng được
            writer.close()
    run(go())


def test_each_login_gets_fresh_keys_and_conn_id(tmp_path):
    """protocol_messages.md §3.2, §8: mỗi lần đăng nhập là khóa tạm thời mới -> 4 khóa mới, conn_id mới."""
    async def go():
        async with running_server(tmp_path) as (srv, hub):
            pin = srv.identity_pub
            r1 = await tcp_login("127.0.0.1", srv.login.port, "lan", "secret123", register=True, pinned_identity=pin)
            r2 = await tcp_login("127.0.0.1", srv.login.port, "lan", "secret123", pinned_identity=pin)
            assert r1.keys != r2.keys and r1.keys.udp_c2s != r2.keys.udp_c2s
            assert r1.conn_id != r2.conn_id
    run(go())

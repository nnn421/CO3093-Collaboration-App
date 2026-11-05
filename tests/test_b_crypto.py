"""Nghiệm thu B2 + B6 ở mức đơn vị."""
import asyncio

import pytest
from cryptography.exceptions import InvalidTag

from shared import crypto, messages
from transport.cipher import AESGCMCipher


def _pair():
    c, s = crypto.new_x25519(), crypto.new_x25519()
    cp, sp = crypto.x25519_pub_bytes(c), crypto.x25519_pub_bytes(s)
    return crypto.derive_session_keys(c, sp, cp, sp), crypto.derive_session_keys(s, cp, cp, sp)


def test_both_sides_derive_same_four_distinct_keys():
    kc, ks = _pair()
    assert kc == ks
    vals = [kc.tcp_c2s, kc.tcp_s2c, kc.udp_c2s, kc.udp_s2c]
    assert len(set(vals)) == 4 and all(len(v) == 32 for v in vals)


def test_low_order_public_key_rejected():
    with pytest.raises(ValueError):
        crypto.derive_session_keys(crypto.new_x25519(), b"\x00" * 32, b"\x00" * 32, b"\x01" * 32)


def test_nonce_format_and_overflow():
    assert crypto.nonce_from_counter(1) == b"\x00\x00\x00\x01" + b"\x00" * 8
    assert len(crypto.nonce_from_counter(2**32 - 1)) == 12
    with pytest.raises(OverflowError):
        crypto.nonce_from_counter(2**32)


def test_udp_cipher_directions_and_tamper():
    kc, ks = _pair()
    cli, srv = AESGCMCipher.for_client(kc), AESGCMCipher.for_server(ks)
    hdr = bytes(range(31))
    n = AESGCMCipher.nonce(7)
    ct = cli.encrypt(n, b"hello", hdr)
    assert len(ct) == 5 + AESGCMCipher.overhead
    assert srv.decrypt(n, ct, hdr) == b"hello"
    # chiều ngược lại dùng khóa khác: gói c2s không thể giải bằng khóa của chính client
    with pytest.raises(InvalidTag):
        cli.decrypt(n, ct, hdr)
    # sửa 1 bit header (AAD) -> bị từ chối
    bad = bytearray(hdr)
    bad[5] ^= 1
    with pytest.raises(InvalidTag):
        srv.decrypt(n, ct, bytes(bad))
    # sửa 1 bit ciphertext -> bị từ chối
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 1
    with pytest.raises(InvalidTag):
        srv.decrypt(n, bytes(bad_ct), hdr)
    # sai nonce (PktNum) -> bị từ chối
    with pytest.raises(InvalidTag):
        srv.decrypt(AESGCMCipher.nonce(8), ct, hdr)


def test_same_key_both_directions_rejected():
    with pytest.raises(ValueError):
        AESGCMCipher(b"k" * 32, b"k" * 32)


class _Sink:
    def __init__(self):
        self.buf = bytearray()

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass


def test_tcp_channel_roundtrip_counter_and_replay():
    async def go():
        kc, ks = _pair()
        sink = _Sink()
        client = crypto.TcpSecureChannel(None, sink, kc.tcp_c2s, kc.tcp_s2c)
        await client.send({"type": "LOGIN", "username": "an", "password": "mật khẩu"})
        await client.send({"type": "LOGIN", "username": "an", "password": "x"})
        wire = bytes(sink.buf)
        assert b"\xe1\xba\xad" not in wire and b"username" not in wire   # không lộ nội dung

        r = asyncio.StreamReader()
        r.feed_data(wire)
        server = crypto.TcpSecureChannel(r, _Sink(), ks.tcp_s2c, ks.tcp_c2s)
        assert (await server.recv())["password"] == "mật khẩu"
        assert (await server.recv())["password"] == "x"

        # phát lại thông điệp đầu: bộ đếm đã lên 2 nên giải mã thất bại
        first_len = int.from_bytes(wire[:4], "big")
        r.feed_data(wire[:4 + first_len])
        with pytest.raises(InvalidTag):
            await server.recv()
    asyncio.run(go())


def test_kx_signature_bound_to_transcript(tmp_path):
    """protocol_messages.md §3.2: chữ ký phủ nhãn + khóa client + khóa server + khóa danh tính."""
    ident = crypto.load_or_create_identity(str(tmp_path / "id.key"), str(tmp_path / "id.pub"))
    pub = crypto.identity_pub_bytes(ident)
    # đọc lại file cho ra cùng khóa; file .pub chứa đúng bản hex
    assert crypto.identity_pub_bytes(crypto.load_or_create_identity(str(tmp_path / "id.key"), None)) == pub
    assert (tmp_path / "id.pub").read_text().strip() == pub.hex()
    c, s_, other_c, other_s = b"C" * 32, b"S" * 32, b"X" * 32, b"Y" * 32
    sig = crypto.sign_kx(ident, c, s_)
    assert crypto.verify_kx(pub, sig, c, s_)
    assert not crypto.verify_kx(pub, sig, other_c, s_)      # phát lại với khóa client mới -> sai
    assert not crypto.verify_kx(pub, sig, c, other_s)       # thay khóa server -> sai
    other = crypto.identity_pub_bytes(crypto.load_or_create_identity(str(tmp_path / "id2.key"), None))
    assert not crypto.verify_kx(other, sig, c, s_)          # server khác -> sai
    assert crypto.kx_transcript(c, s_, pub).startswith(b"MMT-KX-v1")


def test_json_compact_utf8():
    """protocol_messages.md §1: không dấu cách, chữ tiếng Việt giữ nguyên dạng UTF-8 (không thành \\u00e0)."""
    b = messages.encode({"type": "MSG_BCAST", "msg_id": "m", "text": "chào"})
    assert b == '{"type":"MSG_BCAST","msg_id":"m","text":"chào"}'.encode("utf-8")
    assert b"\\u" not in b and b" " not in b
    assert messages.decode(b) == {"type": "MSG_BCAST", "msg_id": "m", "text": "chào"}


def _b64(n):
    return messages.b64e(b"\x01" * n)


def test_message_validation():
    ok = {"type": "MSG_DM", "msg_id": "m-1", "to": "bob", "text": "hi", "extra": "bị bỏ qua"}
    assert messages.validate_c2s(ok, {"MSG_DM"}) is ok          # trường lạ: bỏ qua, không lỗi
    bad_cases = [
        {"type": "MSG_DM", "msg_id": "m-1", "to": "bob"},                         # thiếu text
        {"type": "MSG_DM", "to": "bob", "text": "x"},                              # thiếu msg_id
        {"type": "MSG_DM", "msg_id": "", "to": "bob", "text": "x"},                # msg_id rỗng
        {"type": "MSG_BCAST", "msg_id": "x" * 65, "text": "x"},                   # msg_id > 64 byte
        {"type": "MSG_DM", "msg_id": "m", "to": 1, "text": "x"},                   # sai kiểu
        {"type": "MSG_BCAST", "msg_id": "m", "text": "x" * 5000},                  # quá dài
        {"type": "FILE_OFFER", "transfer_id": "zz", "to": "b", "name": "a", "size": 1},          # không phải base64
        {"type": "FILE_OFFER", "transfer_id": _b64(15), "to": "b", "name": "a", "size": 1},      # 15 byte
        {"type": "FILE_OFFER", "transfer_id": _b64(16), "to": "b", "name": "../x", "size": 1},   # đường dẫn
        {"type": "FILE_OFFER", "transfer_id": _b64(16), "to": "b", "name": "..", "size": 1},
        {"type": "FILE_OFFER", "transfer_id": _b64(16), "to": "b", "name": "a\\b", "size": 1},
        {"type": "FILE_OFFER", "transfer_id": _b64(16), "to": "b", "name": "a\nb", "size": 1},
        {"type": "FILE_OFFER", "transfer_id": _b64(16), "to": "b", "name": "a", "size": -1},
        {"type": "FILE_OFFER", "transfer_id": _b64(16), "to": "b", "name": "a", "size": 2**32},  # > MAX_FILE_SIZE
        {"type": "FILE_DONE", "transfer_id": _b64(16), "sha256": _b64(31)},                     # sha 31 byte
        {"type": "KEY_EXCHANGE", "v": True, "pubkey": _b64(32)},                                 # bool không phải int
        {"type": "AUTH_OK"},                                                                     # client không được gửi
    ]
    for bad in bad_cases:
        with pytest.raises(messages.ProtocolError) as e:
            messages.validate_c2s(bad, messages.CHAT_C2S | {"KEY_EXCHANGE"})
        assert e.value.code == messages.E_BAD_MESSAGE, bad
    # độ dài tính theo byte, không theo ký tự
    assert len("ệ".encode()) == 3
    with pytest.raises(messages.ProtocolError):
        messages.validate_c2s({"type": "MSG_BCAST", "msg_id": "m", "text": "ệ" * 1400}, {"MSG_BCAST"})
    # ref của lỗi = msg_id, để client ghép được
    with pytest.raises(messages.ProtocolError) as e:
        messages.validate_c2s({"type": "MSG_DM", "msg_id": "m-9", "to": "b"}, {"MSG_DM"})
    assert e.value.ref == "m-9"


def test_tcp_frame_length_checked_before_body():
    async def go():
        for n in (0, 10**9):
            r = asyncio.StreamReader()
            r.feed_data(n.to_bytes(4, "big"))       # không có body nào phía sau
            with pytest.raises(messages.ProtocolError):
                await messages.read_message(r)
    asyncio.run(go())


def test_frame_reader_handles_fragments():
    class Pieces:
        def __init__(self, data, step):
            self.parts = [data[i:i + step] for i in range(0, len(data), step)] + [b""]

        async def recv(self):
            return self.parts.pop(0)

    async def go():
        data = messages.frame(b"abc") + messages.frame(b"") + messages.frame(b"x" * 300)
        r = messages.FrameReader(Pieces(data, 7))
        assert await r.read() == b"abc"
        assert await r.read() == b""
        assert await r.read() == b"x" * 300
        with pytest.raises(ConnectionError):
            await r.read()
    asyncio.run(go())

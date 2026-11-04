"""
tests/test_packet.py
--------------------
Bộ kiểm thử tự động toàn diện cho tầng đóng gói gói tin nhị phân (Binary Packet).
Bao gồm:
  - Kiểm tra kích thước Header cố định (31 bytes)
  - Kiểm tra đóng gói & giải gói đối xứng (Roundtrip Serialization)
  - Kiểm tra tính toán và xác thực mã CRC32 (Toàn vẹn dữ liệu)
  - Kiểm tra phát hiện lỗi đảo bit (Bit-flip corruption)
  - Kiểm tra các giá trị biên lớn nhất (Boundary 2^32 - 1)
  - Kiểm tra cơ chế chống Replay qua Nonce (12 bytes AES-GCM)
  - Kiểm tra các trường hợp bất thường và ngoại lệ
"""

import struct
import pytest
from shared.config import (
    HEADER_FORMAT,
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    PROTOCOL_VERSION,
    PacketFlag,
    PacketType,
)
from shared.packet import (
    Packet,
    PacketChecksumError,
    PacketLengthMismatchError,
    PacketPayloadOverflowError,
    PacketTooShortError,
)

class TestPacketHeaderFormat:
    """Kiểm tra đặc tả định dạng Header 31 bytes."""

    def test_header_size_exact_31_bytes(self):
        """Header bắt buộc phải có kích thước đúng 31 bytes không xê dịch."""
        calculated_size = struct.calcsize(HEADER_FORMAT)
        assert calculated_size == 31
        assert HEADER_SIZE == 31

    def test_default_packet_creation(self):
        """Khởi tạo gói tin với các giá trị mặc định chuẩn."""
        pkt = Packet(pkt_type=PacketType.DATA)
        assert pkt.version == PROTOCOL_VERSION
        assert pkt.flags == PacketFlag.NONE
        assert pkt.conn_id == 0
        assert pkt.stream_id == 0
        assert pkt.pkt_num == 0
        assert pkt.seq == 0
        assert pkt.ack == 0
        assert pkt.window == 65535
        assert pkt.payload == b""
        assert pkt.length == 0


class TestPacketRoundtrip:
    """Kiểm tra chu trình Đóng gói (pack) -> Giải gói (unpack)."""

    def test_empty_payload_packet(self):
        """Gói tin không có payload (như ACK thuần hoặc Heartbeat)."""
        original = Packet(
            pkt_type=PacketType.ACK,
            flags=PacketFlag.ACK,
            conn_id=12345,
            stream_id=1,
            pkt_num=42,
            seq=0,
            ack=100,
            window=32768,
            payload=b""
        )
        raw = original.pack()
        assert len(raw) == HEADER_SIZE  # Đúng 31 bytes

        restored = Packet.unpack(raw)
        assert restored.pkt_type == PacketType.ACK
        assert restored.flags == PacketFlag.ACK
        assert restored.conn_id == 12345
        assert restored.stream_id == 1
        assert restored.pkt_num == 42
        assert restored.seq == 0
        assert restored.ack == 100
        assert restored.window == 32768
        assert restored.payload == b""
        assert restored.is_ack() is True

    def test_data_payload_packet(self):
        """Gói tin mang payload dữ liệu UTF-8 và nhị phân."""
        sample_text = "Xin chào CO3093! Ứng dụng cộng tác thời gian thực.".encode("utf-8")
        original = Packet(
            pkt_type=PacketType.DATA,
            flags=PacketFlag.ENCRYPTED,
            conn_id=999999,
            stream_id=1,
            pkt_num=101,
            seq=1024,
            ack=512,
            window=65535,
            payload=sample_text
        )
        raw = original.pack()
        assert len(raw) == HEADER_SIZE + len(sample_text)

        restored = Packet.unpack(raw)
        assert restored.pkt_type == PacketType.DATA
        assert restored.flags == PacketFlag.ENCRYPTED
        assert restored.conn_id == 999999
        assert restored.payload == sample_text
        assert restored.is_encrypted() is True


class TestIntegrityAndChecksum:
    """Kiểm tra cơ chế phát hiện lỗi toàn vẹn với CRC32."""

    def test_corrupted_payload_detected(self):
        """Sửa đổi 1 byte trong payload phải gây lỗi Checksum."""
        original = Packet(
            pkt_type=PacketType.DATA,
            conn_id=1,
            payload=b"Chinh xac tuyet doi"
        )
        raw = bytearray(original.pack())

        # Làm biến đổi byte cuối cùng của payload
        raw[-1] ^= 0x01

        with pytest.raises(PacketChecksumError):
            Packet.unpack(bytes(raw))

    def test_corrupted_header_detected(self):
        """Sửa đổi 1 bit trong header (ví dụ conn_id) phải gây lỗi Checksum."""
        original = Packet(
            pkt_type=PacketType.DATA,
            conn_id=1000,
            payload=b"Du lieu quan trong"
        )
        raw = bytearray(original.pack())

        # Đảo 1 bit trong phần conn_id (vị trí byte thứ 4)
        raw[4] ^= 0xFF

        with pytest.raises(PacketChecksumError):
            Packet.unpack(bytes(raw))


class TestBoundaryValues:
    """Kiểm tra các giá trị biên tối đa của kiểu dữ liệu (Unsigned Int, Unsigned Short)."""

    def test_maximum_unsigned_integers(self):
        """Kiểm tra các trường 32-bit (2^32 - 1 = 4294967295) và 16-bit (2^16 - 1 = 65535)."""
        max_u32 = 0xFFFFFFFF
        max_u16 = 0xFFFF

        original = Packet(
            version=PROTOCOL_VERSION,
            pkt_type=0xFF,
            flags=0xFF,
            conn_id=max_u32,
            stream_id=max_u16,
            pkt_num=max_u32,
            seq=max_u32,
            ack=max_u32,
            window=max_u32,
            payload=b"X" * MAX_PAYLOAD_SIZE
        )
        raw = original.pack()
        restored = Packet.unpack(raw)

        assert restored.conn_id == max_u32
        assert restored.stream_id == max_u16
        assert restored.pkt_num == max_u32
        assert restored.seq == max_u32
        assert restored.ack == max_u32
        assert restored.window == max_u32
        assert len(restored.payload) == MAX_PAYLOAD_SIZE


class TestSecurityHelpers:
    """Kiểm tra các hàm bổ trợ bảo mật (Nonce & AAD cho AES-256-GCM)."""

    def test_nonce_format_and_length(self):
        """Nonce phải có độ dài đúng 12 bytes chuẩn AES-GCM và mã hóa pkt_num."""
        pkt = Packet(pkt_type=PacketType.DATA, pkt_num=0x01020304)
        nonce = pkt.get_nonce()

        assert len(nonce) == 12
        # 4 bytes đầu là pkt_num Big-Endian
        assert nonce[:4] == b"\x01\x02\x03\x04"
        # 8 bytes sau là padding 0
        assert nonce[4:] == b"\x00" * 8

    def test_aad_has_checksum_zero(self):
        """AAD cho AES-GCM phải luôn có độ dài 31 bytes với trường checksum = 0."""
        pkt = Packet(
            pkt_type=PacketType.DATA,
            conn_id=777,
            pkt_num=10,
            payload=b"test data"
        )
        aad = pkt.get_aad()
        assert len(aad) == HEADER_SIZE

        # Unpack trường checksum từ AAD và xác nhận nó bằng 0
        fields = struct.unpack(HEADER_FORMAT, aad)
        assert fields[-1] == 0  # Checksum field trong AAD phải bằng 0


class TestErrorConditions:
    """Kiểm tra xử lý các tình huống lỗi và gói tin không hợp lệ."""

    def test_packet_too_short(self):
        """Chuỗi nhị phân ngắn hơn 31 bytes phải ném ngoại lệ PacketTooShortError."""
        with pytest.raises(PacketTooShortError):
            Packet.unpack(b"Ngan qua khong du 31 bytes")

    def test_payload_length_mismatch(self):
        """Khai báo length không khớp với độ dài thực tế của payload."""
        # Tạo gói tin hợp lệ
        valid_raw = Packet(pkt_type=PacketType.DATA, payload=b"ABCDE").pack()

        # Cắt bớt 2 bytes ở đuôi
        truncated = valid_raw[:-2]
        with pytest.raises(PacketLengthMismatchError):
            Packet.unpack(truncated)

    def test_payload_overflow_rejected(self):
        """Payload vượt quá 1400 bytes phải bị từ chối ngay khi tạo đối tượng."""
        oversized = b"A" * (MAX_PAYLOAD_SIZE + 1)
        with pytest.raises(PacketPayloadOverflowError):
            Packet(pkt_type=PacketType.DATA, payload=oversized)

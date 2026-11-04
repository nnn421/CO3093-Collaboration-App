"""
shared/packet.py
----------------
Định nghĩa cấu trúc đóng gói gói tin nhị phân (Binary Packet Serialization)
cho toàn bộ ứng dụng cộng tác phân tán CO3093.

Mỗi gói tin UDP gồm:
  - Header cố định: 31 bytes (Big-Endian)
  - Payload: 0 đến 1400 bytes (Plaintext hoặc Ciphertext AES-256-GCM)

Header Layout (31 bytes):
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Version (1B) |   Type (1B)   |   Flags (1B)  |               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
 |                       Connection ID (4B)                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |        Stream ID (2B)         |         Packet Number (4B)    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |        (PktNum cont.)         |        Sequence Number (4B)   |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         (Seq cont.)           |        Acknowledgment (4B)    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         (Ack cont.)           |        Window Size (4B)       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         (Window cont.)        |          Length (2B)          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Checksum CRC32 (4B)                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Payload (0 - 1400B)                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import binascii
import struct
from dataclasses import dataclass, field
from typing import Optional

from shared.config import (
    HEADER_FORMAT,
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    MAX_PACKET_SIZE,
    PROTOCOL_VERSION,
    PacketFlag,
    PacketType,
    AES_GCM_NONCE_SIZE,
)

# ============================================================================
# CÁC NGOẠI LỆ ĐẶC THÙ CHO TẦNG ĐÓNG GÓI
# ============================================================================
class PacketError(Exception):
    """Ngoại lệ cơ sở cho mọi lỗi liên quan đến gói tin."""
    pass

class PacketTooShortError(PacketError):
    """Gói tin nhận được có kích thước nhỏ hơn Header tối thiểu (31 bytes)."""
    pass

class PacketChecksumError(PacketError):
    """Mã kiểm tra toàn vẹn CRC32 không khớp (bị lỗi bit hoặc sửa đổi)."""
    pass

class PacketLengthMismatchError(PacketError):
    """Độ dài payload thực tế không khớp với trường Length khai báo trong Header."""
    pass

class PacketPayloadOverflowError(PacketError):
    """Payload vượt quá kích thước cho phép MAX_PAYLOAD_SIZE (1400 bytes)."""
    pass


# ============================================================================
# LỚP DỮ LIỆU ĐẠI DIỆN CHO GÓI TIN (PACKET)
# ============================================================================
@dataclass
class Packet:
    """
    Đại diện cho 1 gói tin hoàn chỉnh của giao thức vận tải CO3093.
    """
    pkt_type: int                      # Loại gói tin (PacketType)
    flags: int = PacketFlag.NONE        # Cờ điều khiển bitfield
    conn_id: int = 0                    # ID phiên kết nối (Server cấp phát)
    stream_id: int = 0                  # ID luồng logic (0=Ctrl, 1=Chat, 2=Heartbeat, 3+=File)
    pkt_num: int = 0                    # Số thứ tự gói truyền tải (Nonce tăng đơn điệu)
    seq: int = 0                        # Số thứ tự byte dữ liệu trên luồng
    ack: int = 0                        # Số thứ tự byte kỳ vọng nhận tiếp theo
    window: int = 65535                 # Cửa sổ nhận quảng bá (Receive Window Size)
    payload: bytes = field(default_factory=bytes) # Dữ liệu ứng dụng hoặc mã hóa
    version: int = PROTOCOL_VERSION     # Phiên bản giao thức (mặc định 1)
    checksum: int = 0                   # Mã kiểm tra toàn vẹn CRC32 (tự động tính khi pack)

    def __post_init__(self):
        """Kiểm tra ràng buộc kích thước khi khởi tạo."""
        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise PacketPayloadOverflowError(
                f"Kích thước payload {len(self.payload)}B vượt quá giới hạn tối đa {MAX_PAYLOAD_SIZE}B."
            )

    @property
    def length(self) -> int:
        """Độ dài thực tế của payload (2 bytes, 0..65535)."""
        return len(self.payload)

    def is_ack(self) -> bool:
        """Kiểm tra gói tin có chứa thông tin ACK hay không."""
        return bool(self.flags & PacketFlag.ACK) or (
            self.pkt_type in (PacketType.ACK, PacketType.HELLO_ACK, PacketType.FIN_ACK)
        )

    def is_heartbeat(self) -> bool:
        """Kiểm tra gói tin nhịp tim."""
        return self.pkt_type in (PacketType.HEARTBEAT, PacketType.HEARTBEAT_ACK)

    def is_encrypted(self) -> bool:
        """Kiểm tra cờ dữ liệu đã mã hóa."""
        return bool(self.flags & PacketFlag.ENCRYPTED)

    def get_nonce(self) -> bytes:
        """
        Tạo Nonce 12 bytes (96 bits) chuẩn cho AES-256-GCM:
        - 4 bytes đầu: pkt_num (Big-Endian unsigned int)
        - 8 bytes sau: 0x00 (Zero padding)
        Đảm bảo không bao giờ tái sử dụng nonce với cùng một khóa bí mật,
        ngay cả khi gói tin được truyền lại (vì mỗi lần gửi đều tăng pkt_num).
        """
        return struct.pack(">I", self.pkt_num & 0xFFFFFFFF) + b"\x00" * 8

    def get_aad(self) -> bytes:
        """
        Tạo dữ liệu xác thực bổ sung (Additional Authenticated Data - AAD) cho AES-GCM.
        AAD chính là Header 31 bytes với trường Checksum = 0.
        Giúp AES-GCM bảo vệ toàn bộ Header không bị bên thứ ba sửa đổi lén lút.
        """
        return struct.pack(
            HEADER_FORMAT,
            self.version,
            int(self.pkt_type),
            int(self.flags),
            self.conn_id & 0xFFFFFFFF,
            self.stream_id & 0xFFFF,
            self.pkt_num & 0xFFFFFFFF,
            self.seq & 0xFFFFFFFF,
            self.ack & 0xFFFFFFFF,
            self.window & 0xFFFFFFFF,
            len(self.payload) & 0xFFFF,
            0  # Checksum luôn là 0 trong AAD
        )

    def encrypt_payload(self, key: bytes) -> None:
        """
        Mã hóa self.payload bằng AES-256-GCM in-place:
        1. Tính toán trước độ dài ciphertext (len(plaintext) + 16B Tag).
        2. Bật cờ PacketFlag.ENCRYPTED.
        3. Tạo AAD chuẩn với trường Length = độ dài ciphertext.
        4. Mã hóa bằng AES-256-GCM và gán lại self.payload = ciphertext.
        """
        from shared.crypto import aes_gcm_encrypt
        plaintext = self.payload
        expected_len = len(plaintext) + 16
        if expected_len > MAX_PAYLOAD_SIZE:
            raise PacketPayloadOverflowError(
                f"Kích thước sau mã hóa {expected_len}B vượt quá giới hạn {MAX_PAYLOAD_SIZE}B."
            )
        self.flags |= PacketFlag.ENCRYPTED
        aad = struct.pack(
            HEADER_FORMAT,
            self.version,
            int(self.pkt_type),
            int(self.flags),
            self.conn_id & 0xFFFFFFFF,
            self.stream_id & 0xFFFF,
            self.pkt_num & 0xFFFFFFFF,
            self.seq & 0xFFFFFFFF,
            self.ack & 0xFFFFFFFF,
            self.window & 0xFFFFFFFF,
            expected_len & 0xFFFF,
            0
        )
        self.payload = aes_gcm_encrypt(key, self.get_nonce(), plaintext, aad=aad)

    def decrypt_payload(self, key: bytes) -> bytes:
        """
        Giải mã self.payload bằng AES-256-GCM và trả về dữ liệu gốc (plaintext).
        Tự động xác thực AAD từ Header 31 bytes hiện tại.
        """
        if not self.is_encrypted():
            return self.payload
        from shared.crypto import aes_gcm_decrypt
        return aes_gcm_decrypt(key, self.get_nonce(), self.payload, aad=self.get_aad())

    def compute_checksum(self) -> int:
        """
        Tính toán mã kiểm tra CRC32 (32-bit unsigned int) trên:
        AAD (Header với Checksum=0) + Payload.
        """
        aad = self.get_aad()
        return binascii.crc32(aad + self.payload) & 0xFFFFFFFF

    def pack(self) -> bytes:
        """
        Đóng gói toàn bộ Packet thành chuỗi nhị phân (bytes) để gửi qua UDP socket.
        Tự động tính độ dài payload và mã kiểm tra toàn vẹn CRC32.
        """
        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise PacketPayloadOverflowError(
                f"Kích thước payload {len(self.payload)}B vượt quá {MAX_PAYLOAD_SIZE}B."
            )

        payload_len = len(self.payload)
        calculated_crc = self.compute_checksum()
        self.checksum = calculated_crc

        header_bytes = struct.pack(
            HEADER_FORMAT,
            self.version,
            int(self.pkt_type),
            int(self.flags),
            self.conn_id & 0xFFFFFFFF,
            self.stream_id & 0xFFFF,
            self.pkt_num & 0xFFFFFFFF,
            self.seq & 0xFFFFFFFF,
            self.ack & 0xFFFFFFFF,
            self.window & 0xFFFFFFFF,
            payload_len & 0xFFFF,
            calculated_crc & 0xFFFFFFFF
        )

        return header_bytes + self.payload

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> "Packet":
        """
        Giải mã chuỗi nhị phân nhận được từ UDP socket thành đối tượng Packet.
        Bao gồm quy trình xác thực toàn vẹn 3 bước:
          1. Kiểm tra kích thước tối thiểu (>= 31 bytes Header).
          2. Kiểm tra độ dài Payload khớp với trường Length.
          3. Kiểm tra mã CRC32 để phát hiện lỗi đường truyền.
        """
        if len(raw_bytes) < HEADER_SIZE:
            raise PacketTooShortError(
                f"Kích thước gói {len(raw_bytes)}B nhỏ hơn Header tối thiểu {HEADER_SIZE}B."
            )

        # 1. Trích xuất các trường từ 31 bytes Header
        (
            version,
            pkt_type,
            flags,
            conn_id,
            stream_id,
            pkt_num,
            seq,
            ack,
            window,
            length,
            checksum
        ) = struct.unpack(HEADER_FORMAT, raw_bytes[:HEADER_SIZE])

        # 2. Tách payload và xác thực kích thước
        payload = raw_bytes[HEADER_SIZE:]
        if len(payload) != length:
            raise PacketLengthMismatchError(
                f"Payload thực tế ({len(payload)}B) không khớp với trường Length ({length}B)."
            )

        # 3. Xác thực mã toàn vẹn CRC32
        # Tái tạo header với checksum = 0 để tính toán
        header_zero = struct.pack(
            HEADER_FORMAT,
            version,
            pkt_type,
            flags,
            conn_id,
            stream_id,
            pkt_num,
            seq,
            ack,
            window,
            length,
            0
        )
        expected_crc = binascii.crc32(header_zero + payload) & 0xFFFFFFFF

        if checksum != expected_crc:
            raise PacketChecksumError(
                f"Lỗi toàn vẹn dữ liệu: Checksum nhận được {checksum:#010x} "
                f"không khớp với tính toán {expected_crc:#010x}."
            )

        # Trả về đối tượng Packet hoàn chỉnh
        return cls(
            version=version,
            pkt_type=pkt_type,
            flags=flags,
            conn_id=conn_id,
            stream_id=stream_id,
            pkt_num=pkt_num,
            seq=seq,
            ack=ack,
            window=window,
            payload=payload,
            checksum=checksum
        )

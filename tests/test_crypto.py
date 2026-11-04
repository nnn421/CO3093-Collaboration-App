"""
tests/test_crypto.py
--------------------
Bộ kiểm thử tự động toàn diện cho tầng bảo mật & mật mã học (Security & Crypto).
Bao gồm:
  - Kiểm tra băm và xác thực mật khẩu PBKDF2-HMAC-SHA256 (chống timing attack)
  - Kiểm tra trao đổi khóa bất đối xứng X25519 (ECDH)
  - Kiểm tra dẫn xuất 4 khóa phiên HKDF-SHA256 (tính độc lập của các chiều)
  - Kiểm tra mã hóa và giải mã xác thực AES-256-GCM (với Nonce 12B và AAD)
  - Kiểm tra phát hiện can thiệp dữ liệu (InvalidTag tampering detection)
  - Kiểm tra tích hợp end-to-end giữa Packet Header nhị phân và Lớp mã hóa
"""

import os
import pytest
from shared.config import (
    AES_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    PacketFlag,
    PacketType,
)
from shared.crypto import (
    CryptoDecryptionError,
    CryptoKeyExchangeError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_session_keys,
    derive_shared_secret,
    generate_x25519_keypair,
    hash_password,
    verify_password,
)
from shared.packet import Packet


class TestPasswordHashing:
    """Kiểm tra chức năng xác thực và lưu trữ mật khẩu an toàn."""

    def test_hash_and_verify_success(self):
        """Mật khẩu đúng phải xác thực thành công."""
        password = "MatKhauSieuBaoMat_2026!#"
        salt_hex, hash_hex = hash_password(password)

        assert len(salt_hex) == 32  # 16 bytes = 32 hex chars
        assert len(hash_hex) == 64  # 32 bytes (256-bit) = 64 hex chars
        assert verify_password(password, salt_hex, hash_hex) is True

    def test_wrong_password_fails(self):
        """Mật khẩu sai phải bị từ chối ngay lập tức."""
        password = "MatKhauChuan"
        salt_hex, hash_hex = hash_password(password)

        assert verify_password("MatKhauSai", salt_hex, hash_hex) is False
        assert verify_password("", salt_hex, hash_hex) is False

    def test_salt_uniqueness(self):
        """Cùng một mật khẩu nhưng 2 lần băm khác nhau phải sinh ra 2 mã băm khác nhau (nhờ Salt)."""
        password = "GiongNhauNhungKhacSalt"
        salt1, hash1 = hash_password(password)
        salt2, hash2 = hash_password(password)

        assert salt1 != salt2
        assert hash1 != hash2

    def test_corrupt_salt_or_hash_handled_gracefully(self):
        """Chuỗi salt hoặc hash bị lỗi định dạng không được làm sập chương trình."""
        assert verify_password("test", "invalid_hex", "123456") is False


class TestKeyExchangeX25519:
    """Kiểm tra bắt tay thỏa thuận khóa bất đối xứng qua X25519."""

    def test_x25519_handshake_agreement(self):
        """Client và Server độc lập tính toán phải cho ra cùng một bí mật chung (shared_secret)."""
        client_priv, client_pub = generate_x25519_keypair()
        server_priv, server_pub = generate_x25519_keypair()

        assert len(client_pub) == 32
        assert len(server_pub) == 32

        # Client tính bí mật chung từ khóa riêng của mình + khóa công khai của Server
        client_shared = derive_shared_secret(client_priv, server_pub)

        # Server tính bí mật chung từ khóa riêng của mình + khóa công khai của Client
        server_shared = derive_shared_secret(server_priv, client_pub)

        assert len(client_shared) == 32
        assert client_shared == server_shared

    def test_invalid_peer_public_key_rejected(self):
        """Khóa công khai có kích thước sai lệch phải bị từ chối."""
        client_priv, _ = generate_x25519_keypair()
        with pytest.raises(CryptoKeyExchangeError):
            derive_shared_secret(client_priv, b"short_key_16b___")


class TestKeyDerivationHKDF:
    """Kiểm tra phái sinh 4 chìa khóa phiên độc lập qua HKDF."""

    def test_derive_4_distinct_session_keys(self):
        """Phải sinh ra 4 chìa khóa AES-256 (32B) hoàn toàn khác biệt nhau."""
        dummy_secret = os.urandom(32)
        keys = derive_session_keys(dummy_secret)

        assert len(keys) == 4
        expected_keys = {"tcp_c2s", "tcp_s2c", "udp_c2s", "udp_s2c"}
        assert set(keys.keys()) == expected_keys

        # Kiểm tra kích thước từng khóa
        for name, key in keys.items():
            assert len(key) == AES_KEY_SIZE, f"Khóa {name} có kích thước sai"

        # Đảm bảo cả 4 khóa là độc lập (không trùng nhau)
        unique_keys = set(keys.values())
        assert len(unique_keys) == 4

    def test_deterministic_derivation(self):
        """Cùng một secret và salt phải cho ra cùng một bộ 4 khóa."""
        secret = b"K" * 32
        salt = b"S" * 16
        keys1 = derive_session_keys(secret, salt=salt)
        keys2 = derive_session_keys(secret, salt=salt)
        assert keys1 == keys2


class TestAuthenticatedEncryptionAESGCM:
    """Kiểm tra mã hóa & giải mã dữ liệu có xác thực bằng AES-256-GCM."""

    def test_encrypt_decrypt_roundtrip(self):
        """Mã hóa bản rõ và giải mã thành công về dữ liệu gốc."""
        key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        plaintext = "Dữ liệu cực kỳ quan trọng cần bảo mật trên UDP!".encode("utf-8")
        aad = b"Header 31 bytes AAD"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_tampered_ciphertext_fails(self):
        """Sửa đổi bất kỳ byte nào trong ciphertext phải làm giải mã thất bại."""
        key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        plaintext = b"Thong diep bi mat"
        ciphertext = bytearray(aes_gcm_encrypt(key, nonce, plaintext))

        # Đảo 1 byte trong ciphertext
        ciphertext[0] ^= 0x01

        with pytest.raises(CryptoDecryptionError):
            aes_gcm_decrypt(key, nonce, bytes(ciphertext))

    def test_tampered_aad_fails(self):
        """Nếu kẻ gian sửa đổi Header AAD, giải mã phải báo lỗi xác thực InvalidTag."""
        key = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        plaintext = b"Tin nhan chat"
        aad = b"Header hop le"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad=aad)

        # Cố giải mã với AAD đã bị sửa đổi
        tampered_aad = b"Header bi sua"
        with pytest.raises(CryptoDecryptionError):
            aes_gcm_decrypt(key, nonce, ciphertext, aad=tampered_aad)

    def test_wrong_key_fails(self):
        """Giải mã bằng chìa khóa khác phải thất bại."""
        key1 = os.urandom(AES_KEY_SIZE)
        key2 = os.urandom(AES_KEY_SIZE)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)

        ciphertext = aes_gcm_encrypt(key1, nonce, b"Hello")
        with pytest.raises(CryptoDecryptionError):
            aes_gcm_decrypt(key2, nonce, ciphertext)

    def test_wrong_nonce_fails(self):
        """Giải mã bằng Nonce sai lệch phải thất bại."""
        key = os.urandom(AES_KEY_SIZE)
        nonce1 = os.urandom(AES_GCM_NONCE_SIZE)
        nonce2 = os.urandom(AES_GCM_NONCE_SIZE)

        ciphertext = aes_gcm_encrypt(key, nonce1, b"Hello")
        with pytest.raises(CryptoDecryptionError):
            aes_gcm_decrypt(key, nonce2, ciphertext)


class TestPacketCryptoIntegration:
    """Kiểm tra tích hợp hoàn hảo giữa Packet Header nhị phân và Tầng mã hóa."""

    def test_packet_encryption_and_decryption_flow(self):
        """
        Quy trình chuẩn:
        1. Người gửi tạo Packet với Plaintext.
        2. Dùng pkt.get_nonce() và pkt.get_aad() để mã hóa AES-GCM.
        3. Đặt ciphertext vào pkt.payload, bật cờ ENCRYPTED, đóng gói pack() (kèm CRC32).
        4. Gửi qua mạng (chuỗi bytes).
        5. Người nhận unpack() thành công (CRC32 kiểm tra toàn vẹn đường truyền).
        6. Người nhận giải mã payload bằng restored_pkt.get_nonce() và restored_pkt.get_aad().
        7. Nhận lại chính xác Plaintext ban đầu!
        """
        udp_key = os.urandom(AES_KEY_SIZE)
        original_plaintext = "Tin nhắn chat bí mật: Điểm thi 10 tuyệt đối!".encode("utf-8")

        # 1. Tạo gói tin chứa dữ liệu gốc
        sender_pkt = Packet(
            pkt_type=PacketType.DATA,
            conn_id=88888,
            stream_id=1,
            pkt_num=42,  # PktNum này quyết định Nonce
            seq=100,
            ack=0,
            payload=original_plaintext
        )

        # 2. Mã hóa dữ liệu bằng hàm tiện ích tự động khớp AAD
        sender_pkt.encrypt_payload(udp_key)
        assert sender_pkt.is_encrypted() is True
        assert len(sender_pkt.payload) == len(original_plaintext) + 16  # 16 bytes GCM tag

        # 3. Đóng gói nhị phân (31B Header + Ciphertext + CRC32)
        wire_bytes = sender_pkt.pack()

        # 4. Bên nhận giải gói từ socket
        receiver_pkt = Packet.unpack(wire_bytes)
        assert receiver_pkt.is_encrypted() is True
        assert receiver_pkt.conn_id == 88888
        assert receiver_pkt.pkt_num == 42

        # 5. Bên nhận giải mã
        decrypted_text = receiver_pkt.decrypt_payload(udp_key)
        assert decrypted_text == original_plaintext

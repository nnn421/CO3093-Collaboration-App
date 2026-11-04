"""
shared/config.py
----------------
Cấu hình tập trung và định nghĩa hằng số cho toàn bộ hệ thống CO3093.
Tất cả các module (Client, Server, Transport, Crypto, UI Bridge) đều
sử dụng các hằng số này để đảm bảo tính đồng bộ 100%.

Architecture summary:
  TCP (port 9000) is used ONLY for:
    1. X25519 key exchange
    2. REGISTER / LOGIN (PBKDF2-HMAC-SHA256)
    3. Server issues conn_id -> client sends UDP HELLO
  After login, TCP is closed immediately. Everything else runs over UDP transport (port 9001).
"""

from enum import IntEnum

# ============================================================================
# 1. THÔNG SỐ MẠNG (NETWORKING CONFIGURATION)
# ============================================================================
DEFAULT_SERVER_HOST: str = "127.0.0.1"
SERVER_HOST: str = DEFAULT_SERVER_HOST

TCP_PORT: int = 9000             # Cổng TCP dùng riêng cho bắt tay X25519 & xác thực
TCP_AUTH_PORT: int = TCP_PORT
UDP_PORT: int = 9001             # Cổng UDP chính phục vụ truyền dữ liệu đáng tin cậy
UDP_TRANSPORT_PORT: int = UDP_PORT
HTTP_PORT: int = 8080            # Cổng HTTP cục bộ phục vụ Web UI thuần
CLIENT_HTTP_PORT: int = HTTP_PORT

# ============================================================================
# 2. ĐỊNH DẠNG GÓI TIN NHỊ PHÂN (BINARY PACKET SPECIFICATION)
# ============================================================================
# Header chuẩn: 31 bytes cố định, thứ tự byte Big-Endian (Network Byte Order)
# >: Big-Endian
# B: Version (1B)
# B: Type (1B)
# B: Flags (1B)
# I: ConnID (4B)
# H: StreamID (2B)
# I: PktNum (4B)
# I: Seq (4B)
# I: Ack (4B)
# I: Window (4B)
# H: Length (2B)
# I: Checksum (4B - CRC32)
HEADER_FORMAT: str = ">BBBIHIIIIHI"
HEADER_SIZE: int = 31            # struct.calcsize('>BBBIHIIIIHI') == 31
PROTOCOL_VERSION: int = 1        # Phiên bản giao thức hiện tại

# Kích thước payload tối đa để tổng gói tin (31B Header + 1400B Data = 1431B)
# nằm trọn trong MTU tiêu chuẩn của Ethernet (1500B), tuyệt đối tránh IP Fragmentation
MAX_PAYLOAD_SIZE: int = 1400
CHUNK_SIZE: int = 1000           # Kích thước chunk truyền file (nằm trong MAX_PAYLOAD_SIZE)
MAX_PACKET_SIZE: int = HEADER_SIZE + MAX_PAYLOAD_SIZE  # 1431 bytes

# ============================================================================
# 3. PHÂN LOẠI LOẠI GÓI TIN (PACKET TYPES - 1 BYTE)
# ============================================================================
class PacketType(IntEnum):
    HELLO = 0x01          # Bắt tay khởi tạo phiên trên UDP
    HELLO_ACK = 0x02      # Server xác nhận phiên UDP thành công
    DATA = 0x03           # Dữ liệu tin cậy (Chat, File, Control)
    ACK = 0x04            # Gói báo nhận độc lập (không kèm payload)
    HEARTBEAT = 0x05      # Gói nhịp tim duy trì kết nối (Best-effort)
    HEARTBEAT_ACK = 0x06  # Báo nhận nhịp tim
    FIN = 0x07            # Yêu cầu ngắt kết nối phiên làm việc
    FIN_ACK = 0x08        # Xác nhận đã ngắt kết nối thành công

# Tương thích với các định nghĩa cũ
PKT_HELLO = PacketType.HELLO
PKT_HELLO_ACK = PacketType.HELLO_ACK
PKT_DATA = PacketType.DATA
PKT_ACK = PacketType.ACK
PKT_HEARTBEAT = PacketType.HEARTBEAT
PKT_HEARTBEAT_ACK = PacketType.HEARTBEAT_ACK
PKT_FIN = PacketType.FIN
PKT_FIN_ACK = PacketType.FIN_ACK

# ============================================================================
# 4. CỜ ĐIỀU KHIỂN (FLAGS BITFIELD - 1 BYTE)
# ============================================================================
class PacketFlag(IntEnum):
    NONE = 0x00
    ACK = 0x01            # Trường Ack trong header hợp lệ
    SYN = 0x02            # Gói khởi tạo kết nối
    FIN = 0x04            # Gói kết thúc kết nối
    ENCRYPTED = 0x08      # Payload đã được mã hóa bằng AES-256-GCM
    RETRANSMIT = 0x10     # Đánh dấu gói tin gửi lại (Retransmission)

# ============================================================================
# 5. ĐỊNH DANH PHÂN LUỒNG (STREAM IDS - 2 BYTES)
# ============================================================================
# Stream Multiplexing giúp các luồng chạy độc lập, ngăn ngừa Head-of-Line Blocking
STREAM_CONTROL: int = 0          # Luồng điều khiển phiên (HELLO, FIN, Reset)
STREAM_CHAT: int = 1             # Luồng tin nhắn chat (Broadcast, Direct Message, Room)
STREAM_HEARTBEAT: int = 2        # Luồng nhịp tim (Best-effort, không ACK/Retransmit)
STREAM_FILE_BASE: int = 3        # Các luồng truyền file sẽ được cấp phát từ ID >= 3

# Tiền tố độ dài thông điệp ứng dụng (JSON framing)
MSG_LENGTH_PREFIX_SIZE: int = 2  # 2 bytes độ dài trước mỗi message JSON

# ============================================================================
# 6. THÔNG SỐ ĐỘ TIN CẬY & THỜI GIAN CHỜ (RELIABILITY & TIMING)
# ============================================================================
INITIAL_RTO: float = 1.0         # Retransmission Timeout ban đầu (1.0 giây)
DEFAULT_RTO: float = INITIAL_RTO
MIN_RTO: float = 0.2             # Ngưỡng RTO tối thiểu (200ms)
MAX_RTO: float = 5.0             # Ngưỡng RTO tối đa (5.0s)
MAX_RETRIES: int = 15            # Số lần thử lại tối đa (chuẩn đề bài chịu loss 20%)

HEARTBEAT_INTERVAL: float = 5.0  # Định kỳ gửi gói nhịp tim mỗi 5.0 giây
HEARTBEAT_TIMEOUT: float = 15.0  # Hết 15 giây không nhận được gói nào coi như mất kết nối
IDLE_TIMEOUT: float = 15.0       # Thời gian giải phóng session nếu không có hoạt động
                                 # Bắt buộc bằng HEARTBEAT_TIMEOUT để đồng bộ phát hiện offline

# Cửa sổ trượt & Điều khiển tắc nghẽn (Sliding Window & Congestion Control)
WINDOW_SIZE: int = 16            # Số gói tối đa unACKed trong Stop-and-Wait/Sliding Window mở rộng
DEFAULT_WINDOW_SIZE: int = 64 * 1024  # 64 KB bộ đệm nhận mặc định
INITIAL_CWND: int = 1            # Khởi đầu Slow Start
INITIAL_SSTHRESH: int = 64       # Ngưỡng chuyển sang Congestion Avoidance

# ============================================================================
# 7. THÔNG SỐ BẢO MẬT & MÃ HÓA (CRYPTOGRAPHIC PARAMETERS)
# ============================================================================
AES_KEY_SIZE: int = 32           # 256 bits = 32 bytes (AES-256)
AES_GCM_NONCE_SIZE: int = 12     # 96 bits = 12 bytes chuẩn NIST SP 800-38D
NONCE_SIZE: int = AES_GCM_NONCE_SIZE
AES_GCM_TAG_SIZE: int = 16       # 128 bits = 16 bytes Authentication Tag
PBKDF2_ITERATIONS: int = 100_000 # Số vòng lặp băm mật khẩu (chống Brute-force)
SALT_LENGTH: int = 16            # Độ dài muối ngẫu nhiên (16 bytes)
PBKDF2_SALT_SIZE: int = SALT_LENGTH
USERS_FILE: str = "users.json"   # File lưu trữ tài khoản (hashed)

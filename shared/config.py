"""G4 - Cấu hình tập trung. Mọi hằng số của hệ thống nằm ở đây, không hardcode nơi khác.

Người phụ trách: B. Ai cần thêm hằng số thì thêm vào file này (kèm chú thích đơn vị).
Các tên dưới đây được docs/protocol_messages.md tham chiếu trực tiếp; đổi tên phải sửa cả tài liệu.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent   # thư mục gốc dự án, để đường dẫn không phụ thuộc chỗ đứng khi chạy

# ---------------------------------------------------------------- Mạng
BIND_HOST = "0.0.0.0"      # server nghe trên mọi card mạng (dùng cho cả TCP và UDP)
SERVER_HOST = "127.0.0.1"  # địa chỉ server mà client kết nối tới (đổi thành IP máy server khi chạy qua LAN)
TCP_PORT = 9000            # kênh bắt tay + đăng nhập
UDP_PORT = 9001            # kênh streaming (tầng A)
HTTP_PORT = 8080           # HTTP server trong client agent (C4), ghi đè bằng --http-port

PROTOCOL_VERSION = 1

# ---------------------------------------------------------------- Stream ID (G3)
STREAM_CONTROL = 0         # dự phòng cho điều khiển; HELLO là loại gói transport, không đi stream này
STREAM_CHAT = 1            # tin nhắn + thỏa thuận tệp (JSON có framing 2B)
STREAM_HEARTBEAT = 2       # best-effort, không framing
STREAM_FILE_BASE = 3       # 3..65535: mỗi phiên truyền tệp một stream, đánh số riêng trên từng kết nối
STREAM_ID_MAX = 0xFFFF

# ---------------------------------------------------------------- JSON (G2)
JSON_DUMPS_KWARGS = {"ensure_ascii": False, "separators": (",", ":")}

# ---------------------------------------------------------------- Kích thước (đơn vị: byte)
CHUNK_SIZE = 1000                  # dữ liệu tệp trong một FILE_CHUNK
TRANSFER_ID_BYTES = 16
SHA256_BYTES = 32
FILE_CHUNK_HEADER = TRANSFER_ID_BYTES + 4      # [16B transfer_id][4B offset]
MAX_PACKET_PAYLOAD = 1200          # payload tối đa 1 gói UDP (trước mã hóa); 31 + 1200 + 16 < 1472,
                                   # chọn 1200 như QUIC để an toàn cả khi đi qua VPN/đường hầm có MTU nhỏ
FRAME_LEN_BYTES = 2                # tiền tố framing trên stream 1 và 3+
MAX_FRAME = 0xFFFF                 # do tiền tố 2 byte
TCP_LEN_BYTES = 4                  # tiền tố framing trên kênh TCP đăng nhập
TCP_FRAME_MAX = 16 * 1024          # thông điệp đăng nhập không cần lớn hơn
MAX_TEXT_BYTES = 4000              # độ dài text tối đa của một tin chat (byte UTF-8)
MAX_MSG_ID_BYTES = 64
MAX_FILENAME_BYTES = 255
MAX_FILE_SIZE = 2**32 - 1          # offset 4B => tối đa 4 GiB - 1

# ---------------------------------------------------------------- Thời gian (đơn vị: giây)
IDLE_TIMEOUT = 15                  # = 3 x HEARTBEAT_INTERVAL: mất liên tiếp 2 heartbeat vẫn chưa ngắt
HEARTBEAT_TIMEOUT = IDLE_TIMEOUT   # cố ý trùng: một con số duy nhất cho "mất liên lạc"
HEARTBEAT_INTERVAL = 5
REGISTRY_SWEEP_INTERVAL = 5
TCP_READ_TIMEOUT = 10              # chờ đọc đủ MỘT thông điệp trên kênh TCP
AUTH_TIMEOUT = 60                  # tổng thời gian tối đa của cả giai đoạn TCP
UDP_BIND_TIMEOUT = 10              # từ AUTH_OK đến khi nhận gói HELLO; quá hạn thì hủy conn_id
UDP_HELLO_RETRY_INTERVAL = 1       # client gửi lại HELLO sau mỗi khoảng này
UDP_HELLO_MAX_TRIES = 5
FILE_OFFER_TIMEOUT = 120           # offer không ai trả lời thì hủy
SESSION_REPLACED_GRACE = 0.5       # thời gian cho phiên cũ nhận ERROR SESSION_REPLACED trước khi bị đóng
INITIAL_RTO = 2
MAX_RTO = 60

# ---------------------------------------------------------------- Transport (tầng A)
WINDOW_SIZE = 16                   # đơn vị: số gói
MAX_RETRIES = 15
PKTNUM_LIMIT = 2**32 - 1024        # gần tràn PktNum (nonce) thì đóng kết nối

# ---------------------------------------------------------------- Bảo mật
PBKDF2_ITERATIONS = 100_000        # OWASP khuyến nghị 600 000; chọn 100 000 để đăng nhập nhanh (ghi vào báo cáo)
SALT_BYTES = 16
AES_KEY_BYTES = 32                 # AES-256
GCM_TAG_BYTES = 16
X25519_PUB_BYTES = 32
ED25519_SIG_BYTES = 64
KX_LABEL = b"MMT-KX-v1"            # nhãn đầu transcript được ký khi trao khóa
MAX_LOGIN_ATTEMPTS = 5             # thất bại đến số này trên một kết nối TCP thì đóng
USERS_FILE = str(ROOT / "users.json")
SERVER_IDENTITY_FILE = str(ROOT / "server_identity.key")   # khóa Ed25519 dài hạn của server, tạo lần đầu chạy
SERVER_IDENTITY_PUB_FILE = str(ROOT / "server_identity.pub")  # bản công khai (hex) server ghi ra khi khởi động
SERVER_IDENTITY_PUB = ""           # client ghim: dán chuỗi hex server in ra khi khởi động.
                                   # Để trống thì client đọc SERVER_IDENTITY_PUB_FILE (chỉ hợp lệ khi chạy cùng máy server)
USERNAME_PATTERN = r"^[A-Za-z0-9_]{3,20}$"
PASSWORD_MIN_BYTES = 6
PASSWORD_MAX_BYTES = 128

# ---------------------------------------------------------------- Server
OUTBOX_MAX = 1000                  # số thông điệp chờ gửi tối đa cho 1 client; tràn => client quá chậm, ngắt
MAX_BAD_MESSAGES = 50              # quá số thông điệp sai này trên một phiên thì đóng phiên
LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# ---------------------------------------------------------------- Client
CLIENT_TCP_TIMEOUT = 10            # client chờ mỗi phản hồi trên kênh TCP
CLIENT_BIND_TIMEOUT = UDP_HELLO_RETRY_INTERVAL * UDP_HELLO_MAX_TRIES   # chờ USER_LIST đầu tiên sau HELLO

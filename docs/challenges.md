# Challenges & Solutions

> **CO3093 — Distributed and Streaming-based Client-Server Collaboration Application**  
> Tác giả: Người C (Client Daemon, Web UI & Testing)  
> Deadline: 08/11/2026

---

## 1. Tab-Close Detection trên Windows (Vấn đề nặng nhất)

**Thách thức:**  
Khi người dùng đóng tab trình duyệt, hệ thống mất đến 60+ giây mới phát hiện ra người dùng offline. Điều này khiến Server tiếp tục coi người dùng là Online và không gửi thông báo offline cho các Client khác.

**Nguyên nhân gốc rễ:**  
TCP có trạng thái **half-closed** trên Windows: Khi Chrome đóng tab, nó chỉ gửi một gói `FIN` ở chiều gửi, nhưng chiều nhận vẫn mở. Buffer gửi của Windows chấp nhận tất cả các lần ghi nhỏ (SSE ping `: ping\n\n` mỗi 2 giây) mà không báo lỗi. Tiến trình Python tưởng kết nối vẫn còn sống nên tiếp tục gửi Heartbeat UDP mỗi 5 giây lên Server.

**Giải pháp:**  
Thêm coroutine `_read_eof_detector()` chạy song song với vòng lặp SSE bên trong `ui/http_server.py`. Coroutine này gọi `await reader.read(1024)` liên tục — khi tab đóng, `reader` trả về ngay 0 bytes (EOF). Sau thời gian chờ **5 giây** (để phân biệt đóng tab với F5 refresh), hệ thống tự động gọi `agent.disconnect()` gửi gói `FIN` trên Stream 0 lên Server, Server nhận được và cập nhật trạng thái offline cho người dùng ngay lập tức.

---

## 2. Argparse Crash với Ký Tự Phần Trăm `%`

**Thách thức:**  
Chương trình crash với lỗi `TypeError: not enough arguments for format string` ngay khi khởi động do help string trong `argparse` chứa ký tự `%`.

**Nguyên nhân gốc rễ:**  
`argparse` xử lý nội dung help string qua hàm `%`-formatting của Python. Chuỗi `"từ 0 đến 100%"` khiến Python hiểu `%` là một format specifier và tìm kiếm tham số tương ứng nhưng không tìm thấy.

**Giải pháp:**  
Thay `%` trong help string bằng `%%` hoặc viết lại chuỗi tránh ký tự đặc biệt: `"từ 0 đến 100"`.

---

## 3. File Test Rác `test_*.db` Xuất Hiện Liên Tục Sau Mỗi Lần Chạy pytest

**Thách thức:**  
Sau mỗi lần chạy `pytest tests/`, thư mục gốc dự án xuất hiện 6 file SQLite rác: `test_disconn_users.db`, `test_file_users.db`, `test_http_users.db`, `test_multi_users.db`, `test_tcp_users.db`, `test_users_sandbox.db`. Điều này làm bẩn `git status` và gây nhầm lẫn.

**Nguyên nhân gốc rễ:**  
Trong `server/user_db.py`, class `UserDB` tự động tạo file `.db` (SQLite) cùng tên với file `.json` được truyền vào. Các test fixture truyền vào `filepath="test_disconn_users.json"`, `UserDB` tự sinh ra `test_disconn_users.db` kế bên. Fixture chỉ dọn `.json` sau test, bỏ sót `.db`.

**Giải pháp:**  
1. Thêm `*.db` và `test_*.db` vào `.gitignore` để Git không theo dõi chúng.  
2. Sau mỗi lần chạy `pytest`, chạy lệnh dọn thủ công: `Remove-Item test_*.db`.

---

## 4. Mô Phỏng Mất Gói Không Quyết Định (Non-Deterministic Loss Simulation)

**Thách thức:**  
Lớp `LossyChannel` ban đầu dùng `random.random() < loss_pct/100` để quyết định rớt gói. Kết quả mỗi lần test khác nhau hoàn toàn, không thể tái lập (reproduce) để kiểm chứng chính xác.

**Nguyên nhân gốc rễ:**  
Hàm `random()` không có hạt giống cố định (seed), mỗi lần chạy cho ra chuỗi số ngẫu nhiên hoàn toàn khác nhau.

**Giải pháp:**  
Thêm chế độ `deterministic=True` trong `transport/lossy.py`: Thay vì dùng `random`, dùng bộ đếm `_pkt_counter` chia lấy dư — cứ đúng **1 trong 5 gói** sẽ bị rớt (đảm bảo tỷ lệ 20% chính xác). Kết quả: Mỗi lần chạy `python simulate_loss.py` đều cho ra đúng 12/62 gói bị rớt, 12 lần truyền lại, 25/25 gói được giao, SHA-256 khớp 100%.

---

## 5. Ghép Nối Giữa Hai Tiến Trình Khác Nhau (Chrome vs Python)

**Thách thức:**  
Trình duyệt Chrome và tiến trình Python Client Daemon hoạt động trong 2 Process hoàn toàn tách biệt (Process Isolation). Không thể gọi hàm Python trực tiếp từ JavaScript.

**Nguyên nhân gốc rễ:**  
Hệ điều hành áp dụng cơ chế bảo vệ bộ nhớ (Memory Protection): Mỗi tiến trình chỉ có thể đọc/ghi trong vùng nhớ ảo (Virtual Address Space) của chính nó. Mọi truy cập vượt ranh giới đều bị CPU chặn ngay lập tức (`Access Violation` trên Windows).

**Giải pháp:**  
Triển khai **Raw HTTP/1.1 Server bằng socket thuần** (`asyncio.start_server` trên cổng 8080) đóng vai trò là "cầu nối giao thức" giữa 2 Process. Chrome giao tiếp qua HTTP REST API (`POST /api/chat`) và nhận dữ liệu thời gian thực qua cơ chế **Server-Sent Events (SSE)** trên kết nối `GET /api/events` được giữ mở liên tục. Toàn bộ implementation không dùng bất kỳ framework web nào (Flask/Django/FastAPI đều bị cấm theo đề bài).

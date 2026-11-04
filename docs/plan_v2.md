# KẾ HOẠCH TRIỂN KHAI DỰ ÁN (PROJECT PLAN)

Môn học: CO3093 - Phát triển Ứng dụng Mạng  
Dự án: Distributed and Streaming-based Client-Server Collaboration Application  
Hình thức: Nhóm 3 người (Cần xác nhận lại với giảng viên)  
Ngôn ngữ: Python 3.10+  
Ràng buộc: Raw socket / asyncio thuần, không dùng framework cấp cao  
Tiến độ: Phân định theo 4 giai đoạn kỹ thuật (chưa cố định ngày dương lịch cụ thể)  
Kênh truyền: TCP cho bắt tay + đăng nhập, UDP (tự làm tin cậy) cho tin nhắn và tệp. Cần xác nhận với giảng viên, vì đề tự mâu thuẫn (Mục 6 nói tệp/tin đi TCP; Mục 3 và Step 6 nói đi UDP). Nếu giảng viên yêu cầu tệp/tin đi TCP thì A2–A6 phải làm lại.  

> **Bản v2 (22/10/2026):** đã sửa header (thêm `PktNum`, 31 bytes), nonce AES-GCM, tách 4 khóa HKDF, thứ tự checksum/AAD, công thức congestion control, PBKDF2 chặn event loop, ưu tiên stream chat, vị trí HTTP server, các tiêu chí nghiệm thu và bổ sung định nghĩa còn thiếu. Chi tiết từng lỗi xem file `Bao_cao_loi_A1.xlsx`.

---

## 1. TỔNG QUAN VÀ PHÂN ĐỊNH TRÁCH NHIỆM

Hệ thống được thiết kế theo 3 tầng kỹ thuật độc lập tương ứng với 3 thành viên:

```
+-------------------------------------------------------------------------+
|                       NGƯỜI C: TẦNG CLIENT & UI                         |
|   ClientAgent - HTTP Server (Raw Socket) - Web UI (JS thuần)            |
|   Module packet.py - Bộ giả lập mạng LossyTransport                     |
|   Truyền file nhị phân SHA-256 - Kiểm thử tự động pytest - Tài liệu nộp |
+-------------------------------------------------------------------------+
                                    |
                                    v (HTTP API / EventStream nội bộ)
+-------------------------------------------------------------------------+
|                     NGƯỜI B: TẦNG SERVER & BẢO MẬT                      |
|   Máy chủ asyncio - Kênh đăng nhập TCP - Xác thực PBKDF2                |
|   User Registry - Định tuyến tin nhắn Broadcast/DM - Relay File         |
|   Trao đổi khóa X25519 - HKDF (2 khóa) - Cài đặt Cipher AES-256-GCM     |
+-------------------------------------------------------------------------+
                                    |
                                    v (Giao thức streaming qua UDP)
+-------------------------------------------------------------------------+
|                     NGƯỜI A: TẦNG GIAO THỨC TRUYỀN TẢI                  |
|   Fake Transport (RAM) - UDP Endpoint bất đồng bộ                       |
|   Stop-and-Wait - Cửa sổ trượt Sliding Window & Selective Repeat        |
|   SACK trong payload - Ước lượng RTO động - Đa luồng Multi-streaming    |
|   Flow Control (rwnd) - Congestion Control (Reno/CUBIC) - FIN/Timeout   |
+-------------------------------------------------------------------------+
```

---

## 2. LỘ TRÌNH VÀ CÁC MỐC TÍCH HỢP QUAN TRỌNG THEO GIAI ĐOẠN

| Giai đoạn | Tên giai đoạn | Trọng tâm công việc | Mốc bàn giao (Milestone) |
| :--- | :--- | :--- | :--- |
| **Giai đoạn 0** | **Hợp đồng chung nhóm** | Thống nhất đặc tả gói tin, 11 thông điệp ứng dụng, Stream ID, config chung | **Cuối Giai đoạn 0:** Bàn giao `transport/fake.py` (A) và `shared/config.py` (B) để bắt đầu code song song. |
| **Giai đoạn 1** | **Triển khai độc lập từng tầng** | A viết UDP Endpoint; B viết TCP login + auth; C viết `packet.py`, `lossy.py`, `agent.py` | **Đầu Giai đoạn 1:** C bàn giao `packet.py` và `lossy.py` cho A.<br>**Cuối Giai đoạn 1 (Mốc M1):** A hoàn thành Stop-and-Wait trên UDP thật. B & C chuyển từ Fake sang Real Transport. |
| **Giai đoạn 2** | **Tích hợp giao thức & Nâng cao** | A lên Sliding Window + Multi-stream; B làm Registry, Cipher AES-GCM, Router; C làm Web UI, File transfer | **Giữa Giai đoạn 2:** Xong HTTP server thô.<br>**Cuối Giai đoạn 2:** Chat realtime và gửi file qua Web UI ổn định. |
| **Giai đoạn 3** | **Chịu lỗi & Kiểm thử toàn diện** | A làm Congestion Control (Reno/CUBIC); B làm File Relay + Resilience; C viết test pytest cho mạng xấu | **Giữa Giai đoạn 3:** Hoàn thành toàn bộ tính năng kỹ thuật.<br>**Cuối Giai đoạn 3:** Hoàn thành bộ test tự động và Báo cáo kỹ thuật PDF. |
| **Giai đoạn 4** | **Đóng gói & Nghiệm thu** | Kiểm tra toàn diện trên máy tính sạch, rà soát mã nguồn và nộp bài | **Feature Freeze nội bộ:** Đóng băng toàn bộ mã nguồn, hoàn thiện hồ sơ bàn giao. |

---

## 3. NHIỆM VỤ CHI TIẾT GIAI ĐOẠN 0: HỢP ĐỒNG CHUNG NHÓM (G1 - G7)

### G1: Đặc tả Cấu trúc Gói tin (Packet Header)
- **Người thực hiện:** Người A
- **Thời hạn:** Giai đoạn 0
- **Làm gì:** Định nghĩa chi tiết 11 trường trong Header 31 bytes cố định, thứ tự Big-Endian: `Version (1B)`, `Type (1B)`, `Flags (1B)`, `ConnID (4B)`, `StreamID (2B)`, `PktNum (4B)`, `Seq (4B)`, `Ack (4B)`, `Window (4B)`, `Length (2B)`, `Checksum (4B)`. Struct format: `'>BBBIHIIIIHI'`. Định nghĩa cấu trúc SACK trong payload của gói ACK: `[1B số dải][N x 8B: start_seq (4B) + end_seq (4B)]`.
  - **Đơn vị:** `Seq`, `Ack` và SACK tính theo **số thứ tự gói** (không theo byte), riêng cho từng stream. `Window` (rwnd) tính theo **số gói**, cùng đơn vị với `cwnd`. `Length` là số byte payload của **gói này** (sau mã hóa, gồm cả thẻ GCM 16B).
  - **`PktNum`:** bộ đếm gói tăng đơn điệu theo từng chiều của kết nối, bắt đầu từ 0, áp dụng cho **mọi** gói (DATA, ACK, Heartbeat, FIN). Mỗi lần gửi, kể cả gửi lại, đều lấy `PktNum` mới; gói gửi lại giữ nguyên `Seq`. `PktNum` dùng làm nonce AES-GCM (xem B6). Khi `PktNum` sắp chạm 2^32 thì đóng kết nối để đăng nhập lại.
  - **Checksum (CRC32):** tính trên `header (với Checksum = 0) + payload đã mã hóa`, sau bước mã hóa. Bên nhận kiểm CRC trước rồi mới giải mã.
- **Tập tin tạo/sửa:** `docs/protocol.md`
- **Kết quả nghiệm thu:** Bảng đặc tả chính xác offset từng trường, đơn vị và định dạng SACK được toàn đội xác nhận.

### G2: Chuẩn hóa Danh mục Thông điệp Ứng dụng (11 loại)
- **Người thực hiện:** Người B
- **Thời hạn:** Giai đoạn 0
- **Làm gì:** Đặc tả cấu trúc JSON của 11 thông điệp:
  - TCP login: `KEY_EXCHANGE`, `REGISTER`, `LOGIN`, `AUTH_OK`, `AUTH_FAIL`.
  - UDP Stream 1: `MSG_BCAST`, `MSG_DM`, `USER_LIST`, `ERROR`, `FILE_OFFER`, `FILE_ACCEPT`, `FILE_DONE`.
  - UDP Stream 3+: `FILE_CHUNK` (dữ liệu nhị phân).
  - Trường nhị phân trong JSON (khóa công khai X25519 32B trong `KEY_EXCHANGE`, chữ ký nếu có) mã hóa **base64**. JSON gửi bằng `json.dumps(..., ensure_ascii=False, separators=(',', ':'))`, mã hóa UTF-8; mọi độ dài tính theo **byte** (`len(s.encode())`), không theo số ký tự.
- **Tập tin tạo/sửa:** `docs/protocol.md`
- **Kết quả nghiệm thu:** Danh mục 11 thông điệp có ví dụ JSON minh họa rõ ràng, ghi rõ kênh truyền tương ứng.

### G3: Quy ước Stream ID và Đóng khung Thông điệp (Framing)
- **Người thực hiện:** Người A
- **Thời hạn:** Giai đoạn 0
- **Làm gì:** Quy định Stream ID (0: Control, 1: Chat/Negotiation, 2: Heartbeat, 3+: File Chunks). Định nghĩa cơ chế đóng khung: 2 byte độ dài Big-Endian đi trước mỗi payload JSON trên Stream 1 và chunk nhị phân trên Stream 3+. Stream 2 không dùng framing.
  - **Chốt mô hình:** Stream 0, 1, 3+ là **dòng byte tin cậy, đúng thứ tự** (giống TCP). Vì vậy cần framing: một thông điệp có thể dài hơn một gói (ví dụ `USER_LIST` nhiều user) và bị cắt ra nhiều gói. Phân biệt rõ: `Length` trong header = độ dài payload của **một gói**; tiền tố 2B framing = độ dài của **một thông điệp** (có thể trải qua nhiều gói).
  - **Stream 2 (Heartbeat):** best-effort. Gói vẫn có `Seq` tăng dần nhưng **không gửi ACK, không gửi lại**; bên nhận chỉ cập nhật `last_seen`.
- **Tập tin tạo/sửa:** `docs/protocol.md`
- **Kết quả nghiệm thu:** Quy chuẩn framing thống nhất để bên nhận tách gói không bị dính thông điệp.

### G4: Cấu hình Tập trung Hệ thống (Central Config)
- **Người thực hiện:** Người B
- **Thời hạn:** Giai đoạn 0
- **Làm gì:** Định nghĩa toàn bộ hằng số trong `shared/config.py`: cổng (TCP 9000, UDP 9001, HTTP mặc định 8080 — ghi đè được bằng tham số dòng lệnh `--http-port`), kích thước chunk (1000B), timeout (`IDLE_TIMEOUT = HEARTBEAT_TIMEOUT = 15`), chu kỳ heartbeat (`HEARTBEAT_INTERVAL = 5`), kích thước cửa sổ (`WINDOW_SIZE = 16`), `INITIAL_RTO = 2`, `MAX_RTO = 60`, số lần gửi lại tối đa (`MAX_RETRIES = 15`).
- **Tập tin tạo/sửa:** `shared/config.py`
- **Kết quả nghiệm thu:** Không còn giá trị hardcode trong mã nguồn, biến timeout thống nhất tuyệt đối.

### G5: Bản Giả lập Giao thức Bộ nhớ (Fake Transport API)
- **Người thực hiện:** Người A (Nhiệm vụ then chốt)
- **Thời hạn:** Cuối Giai đoạn 0 (bàn giao trước khi bước vào Giai đoạn 1)
- **Làm gì:** Cài đặt `FakeConnection` và `FakeStream` sử dụng `asyncio.Queue` nội bộ. Cung cấp API: `open_stream(id)`, `await stream.send(data)`, `await stream.recv()`, `conn.on_disconnect(callback)`. Định nghĩa interface `Cipher` và lớp mặc định `NullCipher` để sẵn sàng gắn mã hóa sau này.
- **Tập tin tạo/sửa:** `transport/fake.py`
- **Kết quả nghiệm thu:** Người B và C import được ngay, gửi nhận thông điệp qua RAM thông suốt để bắt đầu code tầng trên.

### G6: Thiết kế Sơ đồ Trạng thái (State Diagrams)
- **Người thực hiện:** Người B (Đăng nhập) + Người C (Truyền file)
- **Thời hạn:** Giai đoạn 0
- **Làm gì:** 
  - B vẽ sơ đồ chu trình đăng nhập: DISCONNECTED -> KEY_EXCHANGE -> AUTH -> UDP_HELLO -> ONLINE.
  - C vẽ sơ đồ truyền tệp: IDLE -> OFFER -> ACCEPT -> CHUNKS -> DONE/ABORTED.
- **Tập tin tạo/sửa:** `docs/diagrams/login_state.png`, `docs/diagrams/file_transfer_state.png`
- **Kết quả nghiệm thu:** Hình vẽ trực quan chứa đầy đủ các nhánh lỗi và thời gian chờ (timeout).

### G7: Khởi tạo Repo Git và Danh mục Quản lý Công việc
- **Người thực hiện:** Người C
- **Thời hạn:** Giai đoạn 0
- **Làm gì:** Khởi tạo Git repository, file `.gitignore`, cấu trúc thư mục chuẩn (`shared/`, `transport/`, `server/`, `client/`, `ui/`, `tests/`, `docs/`), tạo GitHub Issues cho toàn bộ 35 task của dự án để theo dõi tiến độ chung.
- **Tập tin tạo/sửa:** Cấu trúc dự án, `.gitignore`, `README.md`
- **Kết quả nghiệm thu:** Máy chủ chạy được lệnh `python server/main.py` in log khởi động thành công.

---

## 4. CHI TIẾT NHIỆM VỤ NGƯỜI A: TẦNG TRUYỀN TẢI (TRANSPORT ENGINE)

### A1: Điểm cuối UDP Bất đồng bộ (UDP Endpoint)
- **Thời hạn:** Giai đoạn 1
- **Phụ thuộc:** Nhận `shared/packet.py` từ Người C ở đầu Giai đoạn 1.
- **Làm gì:** Dùng `asyncio.DatagramProtocol` xây dựng `UDPEndpoint`. Lắng nghe socket UDP, phân tích gói tin dựa trên `shared/packet.py`, định tuyến gói đến đối tượng `Connection` tương ứng theo `ConnID`. Tự động tạo kết nối mới khi nhận gói hợp lệ.
- **Tập tin tạo/sửa:** `transport/udp_endpoint.py`
- **Kết quả nghiệm thu:** Server phân biệt và định tuyến chính xác gói tin từ 3 Client khác nhau gửi tới đồng thời.

### A2: Truyền tin Tin cậy Stop-and-Wait trên UDP Thật (Mốc M1)
- **Thời hạn:** Cuối Giai đoạn 1 (Mốc M1)
- **Phụ thuộc:** Nhận `transport/lossy.py` từ Người C trong Giai đoạn 1.
- **Làm gì:** Cài đặt thuật toán Stop-and-Wait: Gửi 1 gói tin, chờ ACK; nếu hết thời gian RTO mà chưa có ACK thì truyền lại (tối đa `MAX_RETRIES = 15` lần; quá số lần thì báo ngắt kết nối). Bỏ qua các gói tin trùng lặp (duplicate seq).
  - *Lý do chọn 15:* với 20% mất gói ở cả hai chiều, một lần gửi thành công với xác suất 0,8 × 0,8 = 0,64. Nếu chỉ cho 5 lần, xác suất một gói thất bại hẳn ≈ 0,36⁶ ≈ 0,2%; 100KB ≈ 100 gói nên khoảng 20% số lần chạy test sẽ fail. Với 15 lần, xác suất này ≈ 0,36¹⁶ ≈ 10⁻⁷, coi như không xảy ra.
- **Tập tin tạo/sửa:** `transport/connection.py`, `transport/stream.py`
- **Kết quả nghiệm thu:** Truyền thành công 100KB dữ liệu qua `LossyTransport` với tỷ lệ mất gói 20% mà không bị hỏng hoặc mất dữ liệu. B và C bắt đầu chuyển sang dùng transport thật từ mốc M1.

### A3: Cửa sổ Trượt (Sliding Window) và Selective Repeat
- **Thời hạn:** Giai đoạn 2
- **Làm gì:** Nâng cấp từ Stop-and-Wait lên Sliding Window với kích thước cửa sổ W=16. Cho phép gửi đồng thời 16 gói tin chưa có ACK. Phía nhận lưu tạm thời các gói tin đến lệch thứ tự (out-of-order buffer), gửi danh sách SACK trong payload của gói ACK. Phía gửi đọc SACK và chỉ gửi lại duy nhất các gói tin bị thiếu. Tích hợp công thức ước lượng RTO động: `RTO = SRTT + 4 * RTTVAR`, giới hạn trong `[INITIAL_RTO… MAX_RTO]` khi chưa có mẫu.
  - **Karn's algorithm:** không lấy mẫu RTT từ gói đã gửi lại (không biết ACK trả lời cho lần gửi nào). Mỗi lần timeout thì `RTO = min(2 × RTO, MAX_RTO)`.
  - **Định nghĩa "duplicate ACK" (dùng ở A6):** gói ACK có cumulative `Ack` **không tăng** so với ACK trước, nhưng SACK báo thêm khoảng mới đã nhận.
  - Mỗi gói chưa được ACK có một timer riêng bằng `loop.call_later(RTO, ...)`; khi ACK đến thì `handle.cancel()`.
- **Tập tin tạo/sửa:** `transport/window.py`, `transport/connection.py`
- **Kết quả nghiệm thu:** Truyền thành công 1MB dữ liệu qua mạng mô phỏng (20% mất gói + 10% xáo trộn thứ tự + 5% lặp gói) với toàn vẹn dữ liệu 100%. Tốc độ truyền tải nhanh hơn Stop-and-Wait ít nhất 5 lần, đo trong cùng điều kiện cố định: 1MB, `delay_ms = 50`, `loss_pct = 0`, cùng một máy.

### A4: Đa luồng Độc lập (Multi-streaming) Khử Nghẽn HoL
- **Thời hạn:** Giai đoạn 2
- **Làm gì:** Duy trì số thứ tự (seq), bộ đệm gửi/nhận riêng biệt cho từng Stream ID. Phía gửi lập lịch theo **độ ưu tiên**: Stream 0 (control) > Stream 1 (chat) > Stream 2 (heartbeat) > Stream 3+ (file). Mỗi lượt gửi, stream có ưu tiên cao hơn và có gói chờ thì được gửi trước; các stream file cùng mức ưu tiên luân phiên Round-Robin với nhau.
  - *Lý do không dùng Round-Robin thuần:* `cwnd` tính chung cho cả kết nối (A6). Khi stream file mất nhiều gói, `cwnd` co lại; nếu chia lượt đều, chat phải chờ lượt trong cửa sổ hẹp mà file đang chiếm, nên vẫn bị chậm. Chat ít và nhỏ nên ưu tiên chat gần như không làm chậm file.
- **Tập tin tạo/sửa:** `transport/stream.py`, `transport/multiplex.py`
- **Kết quả nghiệm thu:** Kiểm thử HoL: Cố tình gây mất gói 50% trên Stream 3 (đang truyền file, dùng tham số `stream_loss` của `LossyTransport`, xem C2), kiểm tra thấy tin nhắn chat trên Stream 1 vẫn được nhận tức thời với độ trễ dưới 200ms.

### A5: Điều khiển Luồng (Flow Control qua Receive Window)
- **Thời hạn:** Cuối Giai đoạn 2
- **Làm gì:** Phía nhận tính toán dung lượng bộ đệm còn trống của từng stream (tính theo **số gói**) và ghi vào trường `Window` (rwnd) trong header gói ACK. Phía gửi duy trì `effective_window = min(cwnd, rwnd)`. Nếu `rwnd == 0`, phía gửi tạm ngừng truyền và gửi gói thăm dò (probe packet) mỗi giây một lần.
- **Tập tin tạo/sửa:** `transport/flow.py`, `transport/connection.py`
- **Kết quả nghiệm thu:** Khi máy nhận giả lập xử lý chậm (sleep 0.1s/gói), máy gửi tự động hãm tốc độ, không xảy ra hiện tượng tràn bộ đệm làm rớt gói phía nhận.

### A6: Kiểm soát Tắc nghẽn (Congestion Control: Reno & CUBIC)
- **Thời hạn:** Giai đoạn 3
- **Làm gì:** Quản lý cửa sổ tắc nghẽn `cwnd` ở cấp độ toàn kết nối (Connection-level):
  - Khởi đầu với Slow Start: `cwnd = 1`, nhân đôi sau mỗi RTT cho đến khi chạm `ssthresh`.
  - Chuyển sang Né tắc nghẽn (AIMD): tăng `+1/cwnd` cho mỗi ACK nhận được.
  - Xử lý mất gói (định nghĩa duplicate ACK ở A3):
    - Nhận 3 ACK trùng lặp -> Fast Retransmit gói thiếu, rồi `ssthresh = max(cwnd / 2, 2)`; `cwnd = ssthresh + 3` (Fast Recovery, không reset về 1). Khi có ACK mới thì `cwnd = ssthresh`.
    - Timeout -> **trước tiên** `ssthresh = max(cwnd / 2, 2)`, **sau đó** `cwnd = 1`. Thứ tự này bắt buộc: nếu đặt `cwnd = 1` trước thì `ssthresh` chỉ còn 0,5.
  - Triển khai CUBIC theo yêu cầu đề bài. Xuất lịch sử biến thiên `cwnd` ra tệp CSV để vẽ biểu đồ cho báo cáo.
- **Tập tin tạo/sửa:** `transport/congestion.py`
- **Kết quả nghiệm thu:** Biểu đồ `cwnd` vẽ ra dạng răng cưa (sawtooth) chuẩn mực của giao thức điều khiển tắc nghẽn kinh điển, hệ thống duy trì thông lượng ổn định.

### A7: Đóng Kết nối (FIN Handshake) và Ngắt kết nối do Quá hạn
- **Thời hạn:** Giai đoạn 3
- **Làm gì:** 
  - Đóng chủ động: Gửi gói tin FIN, chờ gói phản hồi FIN-ACK rồi giải phóng tài nguyên.
  - Ngắt thụ động (sự cố mạng): Theo dõi `IDLE_TIMEOUT = 15s`. Nếu quá 15 giây không nhận được bất kỳ dữ liệu hay gói Heartbeat nào, tự động đóng phiên và kích hoạt callback `on_disconnect`.
- **Tập tin tạo/sửa:** `transport/connection.py`
- **Kết quả nghiệm thu:** Tắt đột ngột Client bằng lệnh buộc dừng (kill -9), máy chủ tự động phát hiện và dọn sạch phiên kết nối trong khoảng 15–20 giây (15 giây timeout cộng tối đa một chu kỳ kiểm tra).

### A8: Soạn thảo Báo cáo Đặc tả Tầng Giao vận
- **Thời hạn:** Hoàn thành trong Giai đoạn 3
- **Làm gì:** Soạn thảo tài liệu kỹ thuật chi tiết: sơ đồ cấu trúc Packet Header, bảng mã trạng thái, nguyên lý hoạt động của Sliding Window + SACK, thuật toán RTO động, phân tích cơ chế chống tắc nghẽn kèm biểu đồ `cwnd`, và danh mục các lỗi kỹ thuật thực tế đã gặp và cách khắc phục.
- **Tập tin tạo/sửa:** `docs/protocol_spec.md`
- **Kết quả nghiệm thu:** Tài liệu đầy đủ, minh họa rõ ràng để đưa vào báo cáo kỹ thuật nộp giảng viên.

---

## 5. CHI TIẾT NHIỆM VỤ NGƯỜI B: TẦNG MÁY CHỦ VÀ AN TOÀN THÔNG TIN (SERVER & SECURITY)

### B1: Khung Thực thi Máy chủ Bất đồng bộ (Asyncio Server Core)
- **Thời hạn:** Giai đoạn 1
- **Làm gì:** Xây dựng điểm vào `server/main.py`. Cấu hình logging chuyên nghiệp, nạp tập trung `shared/config.py`. Dùng `asyncio.gather()` điều phối chạy đồng thời TCP Server (đăng nhập) và UDP Server (truyền tải dữ liệu). HTTP Server **không** chạy ở máy chủ mà chạy trong client agent (xem C4). Đón bắt tín hiệu `SIGINT` (Ctrl+C) để đóng kết nối an toàn.
  - Quy tắc chung cho toàn bộ code asyncio: **không được có lệnh chặn** trong event loop (không `time.sleep`, không tính PBKDF2 hay đọc file lớn trực tiếp). Việc tốn CPU đẩy sang `loop.run_in_executor`; chờ dùng `await asyncio.sleep`. Khi chạy test bật `asyncio.run(main(), debug=True)` để event loop cảnh báo bước nào chạy quá 0,1 giây.
- **Tập tin tạo/sửa:** `server/main.py`
- **Kết quả nghiệm thu:** Khởi chạy máy chủ in đầy đủ cổng lắng nghe, tắt máy chủ dọn sạch tài nguyên không văng lỗi.

### B2: Kênh TCP Bắt tay, Đóng khung và Trao đổi Khóa X25519
- **Thời hạn:** Giai đoạn 1
- **Làm gì:** Thiết lập máy chủ TCP trên cổng 9000. Xây dựng hàm đọc/ghi thông điệp có tiền tố độ dài 4 byte: `read_message(reader)`, `write_message(writer, msg)`. Tạo cặp khóa X25519: gửi khóa công khai của server cho client, nhận khóa công khai của client, tính toán khóa bí mật chung. Dùng hàm dẫn xuất HKDF để tạo ra **4 khóa** phiên AES-256 đối xứng, mỗi khóa một nhãn `info` riêng: `tcp_c2s`, `tcp_s2c` (cho kênh TCP đăng nhập) và `udp_c2s`, `udp_s2c` (cho UDP). Tách khóa TCP và UDP để hai kênh không bao giờ trùng nonce.
  - Nonce trên kênh TCP: bộ đếm thông điệp theo từng chiều (4B Big-Endian + 8 byte 0), tăng 1 sau mỗi thông điệp.
  - *(Tùy chọn, chống MITM)* Server có một cặp khóa danh tính Ed25519 dài hạn; khóa công khai được ghim sẵn trong config của client. Server ký lên khóa công khai X25519 của phiên; client kiểm chữ ký, sai thì ngắt kết nối. Nếu không làm thì ghi rõ hạn chế này trong báo cáo (B11).
- **Tập tin tạo/sửa:** `server/tcp_server.py`, `shared/crypto.py`
- **Kết quả nghiệm thu:** Quá trình bắt tay trao đổi khóa diễn ra thành công trong < 100ms trước khi thực hiện bước xác thực.

### B3: Xác thực Người dùng An toàn (PBKDF2 Authentication)
- **Thời hạn:** Giai đoạn 1
- **Làm gì:** Mọi thông điệp đăng ký/đăng nhập đều đi qua kênh TCP đã được mã hóa bằng khóa `tcp_c2s` / `tcp_s2c` sinh ở B2. Băm mật khẩu bằng `hashlib.pbkdf2_hmac` với thuật toán SHA-256, muối ngẫu nhiên 16 bytes và 100,000 vòng lặp. Lưu trữ trong `users.json`.
  - **PBKDF2 tốn khoảng 50–100ms CPU mỗi lần, phải chạy ngoài event loop:** `await loop.run_in_executor(None, hashlib.pbkdf2_hmac, 'sha256', pw, salt, 100_000)`. Gọi trực tiếp sẽ làm treo mọi client khác trong lúc băm. So sánh hash bằng `hmac.compare_digest`.
  - `REGISTER`: Kiểm tra trùng tên, lưu salt + hash, phản hồi kết quả.
  - `LOGIN`: Kiểm tra hash; nếu đúng sinh `conn_id` là số nguyên ngẫu nhiên 32-bit (`secrets.randbits(32)`, khớp với trường `ConnID` 4B trong header), kiểm tra không trùng với phiên đang hoạt động, rồi trả về cho client. Nếu tài khoản đang online ở nơi khác, thực hiện ngắt phiên cũ.
- **Tập tin tạo/sửa:** `server/auth.py`, `users.json`
- **Kết quả nghiệm thu:** Thử nghiệm đăng nhập sai mật khẩu bị từ chối; đúng mật khẩu nhận `conn_id`. Mật khẩu tuyệt đối không bao giờ xuất hiện dạng thô trên mạng và trong tệp lưu trữ.

### B4: Liên kết Địa chỉ UDP với Tài khoản (UDP Binding)
- **Thời hạn:** Cuối Giai đoạn 1 (đồng bộ với mốc M1)
- **Làm gì:** Sau khi nhận `conn_id` qua TCP, client gửi gói UDP HELLO chứa `conn_id` đến cổng UDP 9001. Máy chủ xác thực `conn_id`, lưu cặp ánh xạ `conn_id -> (Client_IP, Client_UDP_Port)` vào bộ nhớ. Sau khi liên kết UDP thành công, máy chủ chủ động đóng kết nối TCP tương ứng để tiết kiệm cổng kết nối.
- **Tập tin tạo/sửa:** `server/udp_bind.py`, `server/tcp_server.py`
- **Kết quả nghiệm thu:** Log máy chủ ghi nhận: Client chuyển đổi thành công từ kênh xác thực TCP sang kênh vận chuyển UDP thời gian thực; kết nối TCP đóng êm đẹp.

### B5: Quản lý Trạng thái Người dùng Trực tuyến (User Registry)
- **Thời hạn:** Giai đoạn 2
- **Làm gì:** Xây dựng bảng theo dõi người dùng trực tuyến `{username: {udp_addr, last_seen, conn_id}}`. Cập nhật `last_seen` mỗi khi nhận gói tin từ client hoặc gói Heartbeat (Stream 2). Chạy tác vụ nền (background task) định kỳ mỗi 5 giây quét bảng: Người dùng có `now - last_seen > 15s` sẽ bị đánh dấu offline và loại bỏ. Khi danh sách người dùng thay đổi, tự động phát sóng thông điệp `USER_LIST` qua Stream 1 đến toàn bộ client đang online. Đăng ký callback `on_disconnect` với tầng transport của Người A để loại bỏ ngay lập tức người dùng khi transport phát hiện ngắt kết nối.
- **Tập tin tạo/sửa:** `server/registry.py`
- **Kết quả nghiệm thu:** Tắt đột ngột một client, trong khoảng 15–20 giây (15 giây timeout cộng tối đa 5 giây chu kỳ quét) toàn bộ các client khác nhận được bản tin cập nhật danh sách người dùng mới mà không còn tên client vừa thoát. Client thoát bình thường (gửi FIN) thì cập nhật gần như ngay lập tức qua `on_disconnect`.

### B6: Cài đặt Module Mã hóa Giao vận (Cipher AES-256-GCM)
- **Thời hạn:** Giai đoạn 2
- **Làm gì:** Cài đặt lớp `AESGCMCipher` kế thừa interface `Cipher` của tầng transport (thay thế cho `NullCipher`). Thực hiện mã hóa/giải mã phần tải trọng (payload) bằng thuật toán AES-256-GCM:
  - Khóa mã hóa: Sử dụng `udp_c2s` và `udp_s2c` sinh từ HKDF ở bước B2. Hai chiều dùng hai khóa khác nhau nên hai chiều có thể dùng cùng giá trị `PktNum` mà không xung đột.
  - Vector khởi tạo (Nonce 12 bytes): `PktNum (4B BE) + 8 bytes số 0`. **Không dùng `stream_id + seq`**: khi gửi lại, `seq` giữ nguyên nhưng header (Ack, Window, Flags) có thể đã đổi, tức cùng nonce mà khác AAD → lộ khóa xác thực GCM, kẻ gian giả mạo được gói. Gói ACK và gói DATA cùng stream cũng có thể trùng `seq`. `PktNum` tăng sau mỗi lần gửi nên không bao giờ lặp lại trong một chiều.
  - Dữ liệu xác thực bổ sung (AAD): Sử dụng Header 31 bytes của gói tin **với trường Checksum = 0** làm AAD, đảm bảo nếu kẻ gian can thiệp sửa đổi trường nào trong header thì quá trình giải mã tại máy nhận sẽ lập tức báo lỗi xác thực.
  - Thứ tự xử lý khi gửi: (1) dựng header với Checksum = 0 → (2) mã hóa payload với AAD là header đó → (3) tính CRC32 trên header + ciphertext → (4) ghi CRC vào trường Checksum. Khi nhận làm ngược lại: kiểm CRC → đặt Checksum = 0 → giải mã.
  - **Mọi gói sau handshake đều đi qua `Cipher`**, kể cả gói ACK (có SACK), Heartbeat và FIN. Nếu ACK không được niêm phong, kẻ gian có thể giả ACK khiến bên gửi tưởng gói đã đến.
  - Interface: `encrypt(nonce, plaintext, aad) -> bytes` và `decrypt(nonce, ciphertext, aad) -> bytes` (ném lỗi khi thẻ sai).
- **Tập tin tạo/sửa:** `shared/crypto.py`, `transport/cipher.py`
- **Kết quả nghiệm thu:** Dùng phần mềm Wireshark bắt gói tin trên cổng 9001: Toàn bộ dữ liệu hiển thị dạng ngẫu nhiên, không thể đọc được nội dung chat hoặc file; cố tình chỉnh sửa 1 bit trong header dẫn đến gói tin bị từ chối giải mã.

### B7: Định tuyến Tin nhắn Văn bản (Broadcast & Direct Message)
- **Thời hạn:** Cuối Giai đoạn 2
- **Làm gì:** Tiếp nhận thông điệp qua UDP Stream 1.
  - `MSG_BCAST`: Đóng gói và chuyển tiếp đến Stream 1 của tất cả người dùng đang trực tuyến (ngoại trừ người gửi).
  - `MSG_DM`: Tra cứu địa chỉ người nhận trong User Registry, chuyển tiếp đến Stream 1 của người nhận. Nếu người nhận không online, gửi phản hồi `ERROR` (mã `USER_OFFLINE`) về cho người gửi.
- **Tập tin tạo/sửa:** `server/router.py`
- **Kết quả nghiệm thu:** Thử nghiệm 3 client: Tin nhắn chung hiển thị trên tất cả máy, tin nhắn riêng chỉ duy nhất người nhận xem được, gửi tin cho người offline lập tức nhận thông báo lỗi.

### B8: Trung chuyển Dữ liệu Tập tin (File Relay Engine)
- **Thời hạn:** Giai đoạn 3
- **Làm gì:** Xử lý việc chuyển tiếp các thông điệp truyền tập tin giữa 2 client:
  - Thông điệp thỏa thuận (`FILE_OFFER`, `FILE_ACCEPT`, `FILE_DONE`): Chuyển tiếp qua Stream 1.
  - Phân đoạn nhị phân (`FILE_CHUNK`): Chuyển tiếp qua Stream 3+ chuyên biệt cho phiên truyền đó.
  - Kiểm soát luồng chống tràn bộ nhớ (Back-pressure): Chuyển tiếp ngay lập tức từng chunk nhận được từ bên gửi sang bên nhận; nếu hàng đợi gửi tới bên nhận bị đầy, tạm ngừng nhận tiếp từ bên gửi để tránh máy chủ phải buffer toàn bộ tập tin vào RAM.
- **Tập tin tạo/sửa:** `server/file_relay.py`
- **Kết quả nghiệm thu:** Trung chuyển tập tin 10MB giữa 2 client qua máy chủ, bộ nhớ RAM máy chủ duy trì ổn định, dung lượng chiếm dụng tăng thêm không quá 5MB.

### B9: Xử lý Lỗi và Nâng cao Độ bền vững (Server Resilience)
- **Thời hạn:** Giai đoạn 3
- **Làm gì:** Bao bọc toàn bộ các hàm xử lý socket và luồng bằng các khối `try/except` đối với các lỗi mạng phổ biến: `ConnectionResetError`, `BrokenPipeError`, `asyncio.TimeoutError`, lỗi gói tin sai định dạng, dữ liệu JSON rác. Ghi log cảnh báo nhưng không làm dừng tiến trình máy chủ.
  - Lỗi trong một tác vụ nền asyncio thường **không** làm sập máy chủ mà làm tác vụ đó **chết âm thầm** (ví dụ tác vụ quét heartbeat chết thì không ai bị xóa khỏi danh sách online nữa). Vì vậy bọc thân vòng lặp của mỗi tác vụ nền (quét registry, heartbeat, gửi lại) bằng `try/except Exception` + ghi log, để lỗi một lượt không giết cả tác vụ.
- **Tập tin tạo/sửa:** `server/main.py`, `server/router.py`
- **Kết quả nghiệm thu:** Chạy script tấn công gửi 1000 gói tin rác ngẫu nhiên và ngắt kết nối đột ngột: Máy chủ vẫn hoạt động liên tục, phục vụ các client bình thường khác mà không bị crash.

### B10: Kiểm thử Tải Đồng thời (Concurrency Stress Test)
- **Thời hạn:** Giai đoạn 3
- **Làm gì:** Viết kịch bản tự động giả lập 20 client kết nối cùng một thời điểm: Bắt tay TCP, đăng nhập, gửi tin nhắn liên tục, truyền file và ngắt kết nối tuần tự. Đo đạc độ trễ xử lý thông điệp và theo dõi rò rỉ bộ nhớ.
- **Tập tin tạo/sửa:** `tests/test_concurrency_server.py`
- **Kết quả nghiệm thu:** 20 client thực hiện hơn 200 lượt đăng nhập/gửi tin mà không có thông điệp nào bị thất lạc. Độ trễ chuyển tiếp tin chat trung bình dưới 10ms (đo riêng, **không tính** đăng nhập vì PBKDF2 tự nó đã tốn 50–100ms). Trong lúc 20 client cùng đăng nhập, tin chat của các client đã online vẫn không bị trễ thêm.

### B11: Sơ đồ Kiến trúc và Báo cáo Tầng Máy chủ
- **Thời hạn:** Hoàn thành trong Giai đoạn 3
- **Làm gì:** Vẽ sơ đồ kiến trúc tổng thể toàn bộ hệ thống (Client ↔ TCP/UDP ↔ Server), hoàn thiện sơ đồ trạng thái đăng nhập, viết tài liệu giải trình mô hình phân quyền và bảo mật để đưa vào báo cáo tổng kết. Ghi rõ các giới hạn: mã hóa client↔server (không end-to-end), và MITM khi trao khóa nếu không làm phần chữ ký Ed25519 ở B2. Ghi lý do chọn asyncio thay vì multithreading.
- **Tập tin tạo/sửa:** `docs/architecture.md`, `docs/diagrams/login_state.png`
- **Kết quả nghiệm thu:** Tài liệu thiết kế kiến trúc chuẩn mực phục vụ bảo vệ đồ án.

---

## 6. CHI TIẾT NHIỆM VỤ NGƯỜI C: TẦNG CLIENT, GIAO DIỆN VÀ KIỂM THỬ (CLIENT, UI & TESTING)

### C1: Xây dựng Module Cấu trúc Gói tin (shared/packet.py)
- **Thời hạn:** Đầu Giai đoạn 1 (bàn giao cho A trước khi viết UDP Endpoint)
- **Làm gì:** Cài đặt lớp `Packet` với 11 trường theo thỏa thuận G1. Dùng `struct.pack('>BBBIHIIIIHI', ...)` và `struct.unpack` để đóng/giải mã header 31 bytes. Tích hợp tính toán và kiểm tra mã CRC32 bằng thư viện `zlib` theo đúng thứ tự ở G1 (tính trên header với Checksum = 0 + payload). Hỗ trợ đóng gói danh sách SACK ranges vào payload của gói ACK. Viết unit test kiểm thử độc lập.
- **Tập tin tạo/sửa:** `shared/packet.py`, `tests/test_packet.py`
- **Kết quả nghiệm thu:** Test round-trip thành công 100% **với giá trị lớn ở mọi trường** (ví dụ `checksum = 0xDEADBEEF`, `length = 1050`, `seq = 2**32 - 1`); test `struct.calcsize(fmt) == 31` chỉ là phụ, vì đảo thứ tự hai trường H/I vẫn cho cùng tổng kích thước nên `calcsize` không phát hiện được. Cố tình sửa 1 bit dữ liệu lập tức phát hiện mã kiểm tra checksum không hợp lệ. Bàn giao đúng hẹn cho Người A.

### C2: Xây dựng Bộ Giả lập Mạng Suy hao (LossyTransport)
- **Thời hạn:** Giai đoạn 1 (bàn giao cho A để kiểm thử Stop-and-Wait)
- **Làm gì:** Cài đặt lớp `LossyTransport` bao bọc bên ngoài bất kỳ transport nào. Hỗ trợ cấu hình các tham số suy hao mạng thực tế:
  - `loss_pct`: Tỷ lệ phần trăm làm rơi gói ngẫu nhiên.
  - `delay_ms` và `jitter_ms`: Độ trễ cơ sở kèm độ dao động ngẫu nhiên.
  - `dup_pct`: Tỷ lệ nhân đôi gói tin.
  - `reorder_pct`: Tỷ lệ đảo lộn thứ tự nhận gói.
  - `stream_loss`: tỷ lệ mất gói riêng theo Stream ID, ví dụ `{3: 0.5}` (đọc `StreamID` từ header trước khi quyết định bỏ gói). Cần cho test HoL ở A4 và C8.
  - `direction`: áp suy hao cho một chiều hay cả hai chiều.
- **Tập tin tạo/sửa:** `transport/lossy.py`, `tests/test_lossy.py`
- **Kết quả nghiệm thu:** Thử nghiệm truyền 1000 gói tin với cấu hình 20% mất gói: Số lượng gói bị hủy nằm trong khoảng sai số cho phép (18% - 22%). Bàn giao cho Người A để bắt đầu kiểm thử Stop-and-Wait.

### C3: Xây dựng ClientAgent và Giao diện Dòng lệnh (CLI)
- **Thời hạn:** Giai đoạn 1
- **Làm gì:** Cài đặt lớp `ClientAgent` đóng gói toàn bộ logic phía người dùng: `connect()`, `login(user, pwd)`, `send_chat(msg)`, `send_dm(to, msg)`, `send_file(path, to)`, và đăng ký lắng nghe sự kiện `on_event(cb)`. Ở giai đoạn đầu, kết nối qua `FakeTransport` để kiểm thử; sau mốc M1 chuyển sang gọi UDP Transport thật. Viết giao diện dòng lệnh `client/cli.py` cho phép người dùng gõ lệnh chat và gửi file trực tiếp từ Terminal.
- **Tập tin tạo/sửa:** `client/agent.py`, `client/cli.py`
- **Kết quả nghiệm thu:** Người dùng mở 2 cửa sổ terminal có thể đăng nhập, xem danh sách bạn bè và chat trực tiếp với nhau thông qua CLI.

### C4: Xây dựng Máy chủ Web HTTP Mini bằng Socket Thô (Raw HTTP Server)
- **Thời hạn:** Giai đoạn 2
- **Làm gì:** Tự lập trình máy chủ HTTP/1.1 chạy **bên trong client agent** (trình duyệt ↔ client agent ↔ server), cổng mặc định 8080, đổi được bằng `--http-port` để chạy nhiều agent trên cùng một máy. Sử dụng raw socket (không framework). Tự bóc tách chuỗi HTTP request: phương thức, đường dẫn URL, các trường Header và Body.
  - Phục vụ tệp tĩnh: `GET /` -> trả về `ui/static/index.html` kèm các tệp CSS, JS với đúng `Content-Type`.
  - Phục vụ REST API: `POST /api/login`, `POST /api/send`, `GET /api/users`.
  - Tải lên tệp tin: `POST /api/upload` nhận dữ liệu nhị phân thô (Raw Body) kèm tiêu đề `X-Filename` (không dùng multipart phức tạp).
  - Đẩy sự kiện thời gian thực (SSE): `GET /api/events` duy trì kết nối HTTP mở, gửi dữ liệu dạng `data: {...}\n\n` cho trình duyệt mỗi khi có tin nhắn mới hoặc danh sách người dùng thay đổi.
- **Tập tin tạo/sửa:** `ui/http_server.py`
- **Kết quả nghiệm thu:** Dùng lệnh `curl` gọi thử các endpoint API trả về kết quả chuẩn mã 200 OK và dữ liệu JSON chính xác; trình duyệt web tải được toàn bộ giao diện tĩnh.

### C5: Thiết kế Giao diện Web Người dùng Tương tác (Web UI)
- **Thời hạn:** Giai đoạn 2
- **Làm gì:** Thiết kế giao diện web hiện đại, phong cách tối giản, nền sáng thanh lịch sử dụng HTML/CSS/JS thuần:
  - Màn hình xác thực: Form Đăng ký / Đăng nhập với thông báo lỗi trực quan.
  - Thanh bên trái (Sidebar): Hiển thị danh sách người dùng đang online (tự động cập nhật tức thời qua SSE).
  - Khu vực trung tâm: Khung chat hiển thị lịch sử tin nhắn, tên người gửi và dấu thời gian (timestamp). Có tab chuyển đổi giữa "Phòng chat chung" và "Chat riêng với [User]".
  - Chức năng gửi tệp tin: Hộp thoại chọn tệp, thanh hiển thị tiến độ phần trăm tải lên/tải xuống (Progress bar) và thông báo tải file hoàn tất.
- **Tập tin tạo/sửa:** `ui/static/index.html`, `ui/static/css/style.css`, `ui/static/js/app.js`
- **Kết quả nghiệm thu:** Chạy 2 client agent trên cùng máy (`--http-port 8080` và `--http-port 8081`), mở 2 tab trình duyệt tới hai cổng đó, đăng nhập 2 tài khoản khác nhau, nhắn tin hiển thị qua lại tức thì dưới 1 giây, gửi tệp có thanh tiến độ chạy mượt mà. (Hai tab cùng trỏ vào một agent chỉ là một phiên đăng nhập.)

### C6: Truyền nhận Tập tin Nhị phân và Kiểm tra Toàn vẹn SHA-256
- **Thời hạn:** Cuối Giai đoạn 2
- **Làm gì:** Cài đặt module `client/file_transfer.py`:
  - Phía gửi: Đọc tệp tin dạng nhị phân **theo từng khối** (không `read()` cả tệp một lần trong event loop; tính SHA-256 trong `run_in_executor` hoặc cập nhật dần theo từng khối), tính mã băm SHA-256 toàn tệp. Gửi thông điệp `FILE_OFFER` (Stream 1). Khi nhận `FILE_ACCEPT`, mở Stream 3+ riêng và gửi lần lượt các chunk nhị phân `[16B transfer_id][4B offset][chunk_data]` (kích thước tối đa 1000B). Sau khi gửi hết, gửi thông điệp `FILE_DONE` mang mã SHA-256 gốc.
  - Phía nhận: Nhận `FILE_OFFER`, tự động gửi `FILE_ACCEPT`, tiếp nhận các chunk nhị phân ghi vào bộ đệm bộ nhớ theo đúng offset. Khi nhận `FILE_DONE`, ráp tệp, tính toán lại mã băm SHA-256. Nếu khớp 100%, ghi tệp ra đĩa vào thư mục `downloads/`; nếu sai lệch mã băm, lập tức xóa tệp hỏng và thông báo lỗi.
  - **Tệp rỗng (0 byte):** có 0 chunk. Nhận `FILE_DONE` ngay sau `FILE_ACCEPT` mà không có chunk nào là hợp lệ; bên nhận tạo tệp rỗng và so SHA-256 của chuỗi rỗng.
- **Tập tin tạo/sửa:** `client/file_transfer.py`, `server/file_relay.py`
- **Kết quả nghiệm thu:** Truyền thành công một tệp dung lượng 10MB qua mạng mô phỏng có 10% rớt gói: Tệp tải về có mã băm SHA-256 trùng khớp hoàn toàn với tệp gốc, mở tệp xem nội dung nguyên vẹn.

### C7: Điều phối Tích hợp Hệ thống Toàn diện (End-to-End Integration)
- **Thời hạn:** Bắt đầu từ mốc M1, chốt toàn diện trong Giai đoạn 3
- **Làm gì:** Điều phối chuyển đổi toàn bộ mã nguồn của B và C từ `FakeTransport` sang chạy trực tiếp trên UDP Transport thật của Người A từ mốc M1. Chạy kiểm thử smoke test end-to-end liên tục sau mỗi lần Người A hoàn thành một tính năng mới (Sliding Window, Multi-stream, Congestion Control). Phát hiện sớm các lỗi không tương thích giữa các tầng để nhóm cùng xử lý.
- **Tập tin tạo/sửa:** Cấu hình tích hợp hệ thống
- **Kết quả nghiệm thu:** Toàn bộ hệ thống chạy đồng bộ trên UDP Transport thật: Giao diện Web ↔ ClientAgent ↔ UDP Streaming ↔ Server Router ↔ Cipher AES-GCM.

### C8: Xây dựng Bộ Kiểm thử Tự động pytest cho Môi trường Mạng Xấu
- **Thời hạn:** Giai đoạn 3
- **Làm gì:** Viết bộ kịch bản kiểm thử tự động toàn diện bao quát các tiêu chí đánh giá của đề bài:
  - `tests/test_reliable.py`: Kiểm thử truyền 1MB qua mạng mất 20% gói và xáo trộn 10% thứ tự.
  - `tests/test_file.py`: Kiểm thử truyền tệp 10MB bảo toàn tính toàn vẹn SHA-256; thêm trường hợp tệp rỗng (0 byte) và tệp có kích thước không chia hết cho 1000.
  - `tests/test_crypto.py`: Kiểm thử tính hợp lệ của quá trình mã hóa/giải mã AES-256-GCM và bắt lỗi khi AAD bị thay đổi; kiểm tra gói gửi lại mang `PktNum` mới (không trùng nonce).
  - `tests/test_hol.py`: Kiểm thử chứng minh luồng chat không bị nghẽn khi luồng file bị mất gói (`stream_loss={3: 0.5}`), và một client đang gửi tệp lớn không làm chậm tin chat của các client khác.
  - `tests/test_disconnect.py`: Kiểm thử máy chủ dọn dẹp phiên khi client ngắt kết nối đột ngột.
- **Tập tin tạo/sửa:** Thư mục `tests/`
- **Kết quả nghiệm thu:** Chạy lệnh `pytest tests/ -v` cho kết quả tất cả các bài kiểm tra đều đạt (PASS) trong thời gian dưới 60 giây, với asyncio chạy ở chế độ debug và không có cảnh báo bước chạy chậm (> 0,1 giây).

### C9: Hoàn thiện Tài liệu README và Báo cáo Kỹ thuật PDF
- **Thời hạn:** Cuối Giai đoạn 3
- **Làm gì:**
  - Hoàn thiện `README.md`: Hướng dẫn chi tiết từ cài đặt môi trường ảo, cài thư viện phụ thuộc, lệnh chạy server, lệnh chạy client, cách mở giao diện web và cách chạy bộ test. Người ngoài đọc vào có thể chạy thành công ứng dụng trong vòng 5 phút.
  - Biên soạn Báo cáo Kỹ thuật PDF: Tổng hợp sơ đồ kiến trúc hệ thống (B11), đặc tả giao thức và cấu trúc gói tin (A8), sơ đồ tuần tự các luồng đăng nhập và truyền tệp (G6), và phần tổng kết các khó khăn thực tế cùng giải pháp (Challenges & Solutions).
- **Tập tin tạo/sửa:** `README.md`, `docs/challenges.md`, Báo cáo kỹ thuật PDF
- **Kết quả nghiệm thu:** Bộ hồ sơ dự án hoàn chỉnh, chuẩn mực, sẵn sàng nộp bài bảo vệ đồ án.

---

## 7. ĐỐI CHIẾU TIÊU CHÍ CHẤM ĐIỂM (RUBRIC MAPPING)

| Điểm | Tiêu chí Rubric | Phụ trách | Các nhiệm vụ bảo đảm đạt điểm |
| :---: | :--- | :---: | :--- |
| **1 pt** | Bước 1: Setup & Protocol Design | Cả nhóm | G1, G2, G3, G4, G6, G7 |
| **1 pt** | Bước 2: Client-Server Handshake | A, B | B2, B4, A1 |
| **1 pt** | Bước 3: Authentication & State | B | B3, B5 |
| **1 pt** | Bước 4: Concurrency Implementation | A, B | B1, B10, A1 |
| **1 pt** | Bước 5: Time-sensitive Streaming | A, B | A4, B7 |
| **1 pt** | Bước 6: Reliable File Transfer | A, C | A2, A3, C6 |
| **1 pt** | Bước 7: Network Resilience | A, B | A7, B9 |
| **1 pt** | Bước 8: Security Layer | B | B2, B6 |
| **1 pt** | Bước 9: HTTP-based UI with Client-side JS | C | C4, C5 |
| **1 pt** | Bước 10: Testing & Code Quality | Cả nhóm | C1, C2, C8, C9 |
| **TỔNG** | **10 Điểm Tối Đa** | | **35 Nhiệm vụ Hoàn chỉnh** |

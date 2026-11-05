# Bàn giao phần B – việc A và C cần biết

Đặc tả đầy đủ: **`docs/protocol_messages.md`**. File này chỉ tóm tắt những gì A và C phải làm để khớp với server.

## Chạy

```bash
pip install -r requirements.txt
python server/main.py            # TCP 9000; UDP 9001 khi A có transport/udp_endpoint.py
python -m pytest tests/ -v       # 53 test, khoảng 17 giây
```

Lần đầu chạy, server tạo khóa danh tính `server_identity.key` ở thư mục gốc dự án và in khóa công khai ra màn hình.
Client **bắt buộc** ghim khóa đó: dán chuỗi hex vào `config.SERVER_IDENTITY_PUB`. Chạy cùng máy thì client tự đọc `server_identity.pub`.

## Người A – yêu cầu đối với transport (protocol_messages.md §9)

| # | Việc | Ghi chú |
|---|---|---|
| T1 | Loại gói `HELLO`: `ConnID = conn_id`, `PktNum = 0`, payload rỗng mã hóa bằng `udp_c2s`. Server gọi `cipher_lookup(conn_id)`; giải mã được thì tạo kết nối và `create_task(on_connection(conn))`, không thì bỏ im lặng. Client gửi lại mỗi 1 s, tối đa 5 lần. | Bản giả `transport/fake.py` mô phỏng đúng việc này trong `FakeHub.connect`. |
| T2 | Cửa sổ chống phát lại theo `PktNum`, mỗi chiều một cửa sổ. | AES-GCM không tự chống phát lại. |
| T3 | Cập nhật địa chỉ UDP theo gói hợp lệ mới nhất. | Chống chiếm địa chỉ bằng HELLO phát lại; chịu được NAT đổi cổng. |
| T4 | `conn.accept_stream()`: trả về stream **tệp** mới (số ≥ 3) do bên kia mở, `None` khi kết nối đóng. | Server dùng để nhận chunk; client dùng để nhận tệp. |
| T5 | `stream.send()` chặn khi cửa sổ hoặc `rwnd` đầy; riêng stream 2 (heartbeat) thì bỏ gói, không chặn. | Back-pressure khi trung chuyển tệp. |
| T6 | Mọi gói sau HELLO đều qua `Cipher` (`transport/cipher.py:AESGCMCipher`, `overhead = 16`). | |
| T7 | Bit **EOM** trong trường `Flags` của header, bật ở gói chứa byte cuối của một thông điệp. | Đề R2 yêu cầu "End-of-Message flags"; xem protocol_messages.md §9. Đề xuất, chờ A quyết. |

A cũng cần viết hai phần còn thiếu: **G1** (header gói UDP) và **G3** (stream, đóng khung trên UDP), theo cùng khuôn với `protocol_messages.md`.

Interface còn lại giữ như bản giả: `UDPEndpoint.create(host, port)`, `endpoint.listen(cipher_lookup, on_connection)`, `conn.conn_id`, `conn.peer_addr`, `conn.open_stream(id)` (gọi lại cùng id trả cùng đối tượng), `await stream.recv()` (trả `b""` khi đóng), `conn.on_disconnect(cb)` (gọi đúng một lần), `conn.close()`.

## Người C – client

- `client/tcp_login.py`: `tcp_login(...)` → `LoginResult(conn_id, keys, …)`; tự đóng TCP sau `AUTH_OK`. Sau đó `transport.connect(conn_id, AESGCMCipher.for_client(keys))` (gửi HELLO) rồi `await_bind(conn)` chờ `USER_LIST` đầu tiên.
- **Gõ xong tên/mật khẩu mới mở TCP**: server chỉ chờ mỗi thông điệp 10 s.
- **Heartbeat**: gửi 1 byte trên stream 2 mỗi 5 s; server trả lại mỗi gói. 15 s không nhận gói nào thì coi là mất kết nối.
- **Mọi trường nhị phân là base64**, kể cả `transfer_id` (16 B) và `sha256` (32 B).
- `MSG_BCAST`/`MSG_DM` **bắt buộc** có `msg_id` (dùng `new_msg_id()`); lỗi trả về có `ref = msg_id`.
- **Gửi tệp**: `FILE_OFFER` (không có `stream_id`) → chờ `FILE_ACCEPT` → gửi chunk trên một stream ≥ 3 **tự chọn** → `FILE_DONE{sha256}`.
- **Nhận tệp (C6)**: nhận `FILE_OFFER` → gửi `FILE_ACCEPT` → `conn.accept_stream()` để lấy stream chunk (nhận ra phiên bằng `transfer_id` trong chunk) → chỉ kiểm SHA-256 khi **đủ `size` byte và đã có `FILE_DONE`**. Ghi chunk xuống đĩa theo offset, không giữ cả tệp trong RAM. **Tự lọc tên tệp** lần nữa trước khi ghi đĩa.
- Xử lý `ERROR` với các mã `FILE_ABORTED` (dừng gửi/nhận, xóa phần đã nhận) và `SESSION_REPLACED` (báo "tài khoản đăng nhập ở nơi khác").
- `tests/helpers.py:TestClient` là một client tối giản chạy được, tham khảo cho C3.

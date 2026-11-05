# Danh mục thông điệp

Bản rút gọn để A và C code theo: thông điệp nào, đi kênh nào, có trường gì, gửi sai thì nhận lại gì. Phần giải thích "vì sao" và nguồn tham khảo không nằm trong bài; sẽ đưa vào báo cáo.

Ký hiệu: C = client, S = server. `0x55` là số viết ở hệ 16 (= 85).

---

## 1. Quy ước chung

- Mọi thông điệp điều khiển là một **object JSON** (`{ … }`), mã hóa **UTF-8**, không có dấu cách thừa, chữ có dấu để nguyên (không viết dạng `à`).
- Mọi thông điệp có trường `type`, viết chữ in hoa.
- Mọi giới hạn độ dài tính theo **byte UTF-8**, không theo số ký tự. Ví dụ chữ `ệ` tốn 3 byte.
- Dữ liệu nhị phân (khóa, chữ ký, `transfer_id`, mã băm) viết bằng **base64 chuẩn, có dấu `=` đệm**.
- `from` và `ts` do **server** điền khi chuyển tiếp. `ts` là số mili-giây kể từ 1/1/1970 (UTC). Client có gửi hai trường này thì server bỏ qua.
- Trường lạ không có trong tài liệu: bên nhận bỏ qua, không báo lỗi.
- Thiếu trường, sai kiểu, sai loại thông điệp: server trả lỗi `BAD_MESSAGE`.

## 2. Kênh và luồng

```
C ── TCP 9000 ──> S   KEY_EXCHANGE ⇄, REGISTER / LOGIN → AUTH_OK / AUTH_FAIL, rồi đóng TCP
C ── UDP 9001 ──> S   gói HELLO, rồi:
                      stream 1: thông điệp JSON (tin nhắn, danh sách, lỗi, thỏa thuận tệp)
                      stream 2: heartbeat
                      stream 3+: dữ liệu tệp, mỗi lần truyền một stream
```

| Thông điệp | Kênh | Chiều | Mã hóa bằng khóa |
|---|---|---|---|
| `KEY_EXCHANGE` | TCP | C → S, rồi S → C | không (chưa có khóa) |
| `REGISTER`, `LOGIN` | TCP | C → S | `tcp_c2s` |
| `AUTH_OK`, `AUTH_FAIL` | TCP | S → C | `tcp_s2c` |
| gói `HELLO` (gói của transport, không phải JSON) | UDP | C → S | `udp_c2s` |
| `MSG_BCAST`, `MSG_DM`, `FILE_OFFER`, `FILE_ACCEPT`, `FILE_DONE` | UDP stream 1 | C → S → C | `udp_c2s` / `udp_s2c` |
| `USER_LIST`, `ERROR` | UDP stream 1 | S → C | `udp_s2c` |
| heartbeat | UDP stream 2 | C ⇄ S | như trên |
| `FILE_CHUNK` (nhị phân) | UDP stream 3+ | C → S → C | như trên |

---

## 3. Kênh TCP (đăng nhập)

### 3.1. Đóng khung

Mỗi thông điệp = **4 byte độ dài** (Big-Endian, tức byte lớn đứng trước) + nội dung.

```
00 00 00 55 {"type":"KEY_EXCHANGE","v":1,"pubkey":"…"}     ← 0x55 = 85 byte nội dung
```

| Trường hợp | Server làm gì |
|---|---|
| Độ dài > 16 KiB (16 384 byte) | Đóng kết nối, không đọc nội dung |
| Độ dài = 0 *(chờ nhóm quyết bỏ hay giữ)* | Đóng kết nối |
| Nội dung không phải object JSON | Đóng kết nối |
| Đứt kết nối giữa một thông điệp | Đóng kết nối |
| Ghi vào kết nối client đã đóng (broken pipe / connection reset / connection aborted) | Ngừng gửi, đóng kết nối |
| 10 giây chưa nhận đủ một thông điệp | Đóng kết nối |
| Cả giai đoạn TCP quá 60 giây | Đóng kết nối |

### 3.2. `KEY_EXCHANGE` (đi rõ)

```json
C → S: {"type":"KEY_EXCHANGE","v":1,"pubkey":"<32 byte, base64>"}
S → C: {"type":"KEY_EXCHANGE","v":1,"pubkey":"<32 byte, base64>","sig":"<64 byte, base64>"}
```

| Trường | Ý nghĩa |
|---|---|
| `v` | Phiên bản giao thức, phải bằng 1 *(chờ nhóm quyết bỏ hay giữ)* |
| `pubkey` | Khóa công khai **X25519**, tạo mới cho mỗi kết nối, đúng 32 byte |
| `sig` | Chữ ký **Ed25519** của server (khóa danh tính dài hạn) lên chuỗi transcript bên dưới |

**Client gửi trước.** Server ký lên:
```
transcript = "MMT-KX-v1" ‖ pubkey client (32 B) ‖ pubkey server (32 B) ‖ khóa công khai danh tính của server (32 B)
```
(`‖` = nối liền các chuỗi byte.) Client phải có sẵn khóa công khai danh tính của server, chép từ máy server trước khi chạy. Chữ ký sai thì client đóng kết nối ngay, **không gửi gì thêm**.

Sau đó hai bên tự tính 4 khóa:
```
bí mật chung = X25519(khóa riêng của mình, pubkey bên kia)
salt         = SHA-256(pubkey client ‖ pubkey server)
khóa         = HKDF-SHA256(bí mật chung, salt, info), info = "tcp_c2s" | "tcp_s2c" | "udp_c2s" | "udp_s2c"
```
Mỗi khóa 32 byte. `c2s` = chiều client → server, `s2c` = chiều ngược lại.

| Trường hợp | Server làm gì |
|---|---|
| Thiếu trường, `pubkey` không phải 32 byte | Đóng kết nối |
| `pubkey` làm bí mật chung ra toàn số 0 (ví dụ 32 byte 0) | Đóng kết nối |
| `v` ≠ 1 | Đóng kết nối |

### 3.3. Mã hóa từ thông điệp thứ 3

- Thuật toán **AES-256-GCM**. Nội dung = phần mã hóa ‖ thẻ xác thực 16 byte. 4 byte độ dài tính cả thẻ.
- Khóa: `tcp_c2s` cho C → S, `tcp_s2c` cho S → C.
- Nonce 12 byte = bộ đếm 4 byte (Big-Endian) ‖ 8 byte 0. Mỗi chiều một bộ đếm, bắt đầu từ 0, tăng 1 sau mỗi thông điệp, **không gửi lên dây**.
- Không có dữ liệu xác thực kèm (AAD rỗng).
- Giải mã thất bại (bị sửa, bị phát lại, sai khóa): đóng kết nối.

Ví dụ: `LOGIN` dài 58 byte → mã hóa thành 58 + 16 = 74 byte → trên dây là `00 00 00 4A` + 74 byte.

### 3.4. `REGISTER`

```json
{"type":"REGISTER","username":"alice","password":"mậtkhẩu"}
```

| Trường | Ràng buộc |
|---|---|
| `username` | 3–20 ký tự, chỉ `A–Z`, `a–z`, `0–9`, `_` |
| `password` | 6–128 byte UTF-8 |

Server lưu muối ngẫu nhiên 16 byte + băm **PBKDF2-HMAC-SHA256** 100 000 vòng. Không bao giờ lưu mật khẩu thô. Đăng ký thành công **không** tự đăng nhập: client gửi tiếp `LOGIN` trên cùng kết nối.

### 3.5. `LOGIN`

```json
{"type":"LOGIN","username":"alice","password":"mậtkhẩu"}
```

Sai tên và sai mật khẩu trả **cùng một** lỗi `BAD_CREDENTIALS`, không nói rõ sai cái nào. Tài khoản đang online ở máy khác vẫn đăng nhập được: khi máy mới gắn UDP xong, máy cũ nhận `ERROR SESSION_REPLACED` rồi bị đóng.

### 3.6. `AUTH_OK`

```json
{"type":"AUTH_OK","action":"REGISTER","username":"alice"}
{"type":"AUTH_OK","action":"LOGIN","username":"alice","conn_id":305419896,"udp_port":9001}
```

| Trường | Ý nghĩa |
|---|---|
| `action` | `REGISTER` hoặc `LOGIN` |
| `conn_id` | Chỉ có khi `LOGIN`. Số 32 bit ngẫu nhiên, khác 0, dùng làm `ConnID` trong gói HELLO |
| `udp_port` | Cổng UDP của server, mặc định 9001 |

Nhận `AUTH_OK` của `LOGIN` thì client đóng TCP và gửi HELLO.

### 3.7. `AUTH_FAIL`

```json
{"type":"AUTH_FAIL","action":"LOGIN","code":"BAD_CREDENTIALS","detail":"Sai tên hoặc mật khẩu"}
```

| `code` | Khi nào |
|---|---|
| `BAD_CREDENTIALS` | Sai tên hoặc mật khẩu |
| `USER_EXISTS` | Đăng ký tên đã có |
| `INVALID_INPUT` | Tên hoặc mật khẩu sai ràng buộc ở 3.4 |
| `BAD_MESSAGE` | Thiếu trường, sai kiểu, sai loại thông điệp |
| `SERVER_ERROR` | Lỗi phía server (ví dụ không ghi được file tài khoản) |
| `TOO_MANY_ATTEMPTS` | Thất bại lần thứ 5 trên cùng kết nối; server đóng kết nối ngay sau đó |

Mọi loại thất bại đều tính vào bộ đếm 5 lần. Chưa tới 5 lần thì kết nối vẫn mở để thử lại.

---

## 4. Gói `HELLO` (chuyển sang UDP)

- Gói của tầng transport: `ConnID` = `conn_id`, `PktNum` = 0, nội dung rỗng mã hóa bằng `udp_c2s` (sau mã hóa chỉ còn thẻ 16 byte).
- Client gửi lại mỗi 1 giây, tối đa 5 lần.
- Server giải mã được thì gắn địa chỉ IP và cổng UDP vào tài khoản, rồi gửi `USER_LIST` cho mọi người online, **kể cả client mới**. Client nhận `USER_LIST` đầu tiên nghĩa là đã online.

| Trường hợp | Server làm gì |
|---|---|
| Không giải mã được, hoặc `conn_id` không có | Bỏ gói, không trả lời |
| Quá 10 giây kể từ `AUTH_OK` mà chưa có HELLO | Hủy `conn_id` |
| HELLO gửi lại sau khi đã gắn (`conn_id` chỉ dùng một lần) | Bỏ gói |

---

## 5. UDP stream 1: thông điệp JSON

Mỗi thông điệp có **2 byte độ dài** (Big-Endian) đứng trước, nên dài tối đa 65 535 byte.

### 5.1. `MSG_BCAST`: tin nhắn chung

```json
C → S:   {"type":"MSG_BCAST","msg_id":"m-17","text":"Chào cả nhóm"}
S → các C khác: {"type":"MSG_BCAST","msg_id":"m-17","from":"alice","ts":1761660000123,"text":"Chào cả nhóm"}
```

| Trường | Ràng buộc |
|---|---|
| `msg_id` | Do client tự đặt, không rỗng, tối đa 64 byte, mỗi tin một giá trị; server giữ nguyên khi chuyển tiếp |
| `text` | Tối đa 4000 byte |

Server gửi cho mọi người online **trừ người gửi**.

| Trường hợp | Server trả |
|---|---|
| Thiếu hoặc sai `msg_id` | `ERROR BAD_MESSAGE` (không có `ref`) |
| `text` quá 4000 byte | `ERROR BAD_MESSAGE`, `ref` = `msg_id` |

### 5.2. `MSG_DM`: tin nhắn riêng

```json
C → S:  {"type":"MSG_DM","msg_id":"m-18","to":"bob","text":"Gửi riêng"}
S → bob: {"type":"MSG_DM","msg_id":"m-18","from":"alice","to":"bob","ts":1761660000456,"text":"Gửi riêng"}
```

Ràng buộc `msg_id`, `text` như 5.1. Chỉ người có tên trong `to` nhận được.

| Trường hợp | Server trả |
|---|---|
| `to` không online | `ERROR USER_OFFLINE`, `ref` = `msg_id` |

### 5.3. `USER_LIST`: danh sách người online

```json
{"type":"USER_LIST","users":["alice","bob","carol"],"ts":1761660001000}
```

Luôn là **toàn bộ** danh sách, sắp theo bảng chữ cái, có cả người nhận. Server gửi cho mọi người mỗi khi có người vào (cũng là xác nhận HELLO), ra, bị loại vì im lặng, hoặc bị thay phiên. Client chỉ việc thay danh sách cũ bằng danh sách mới.

### 5.4. `ERROR`

```json
{"type":"ERROR","code":"USER_OFFLINE","ref":"m-18","detail":"bob không online"}
```

`ref` là `msg_id` hoặc `transfer_id` của thông điệp gây lỗi; không xác định được thì không có. `detail` để người đọc, client không dựa vào nó để xử lý.

| `code` | Khi nào |
|---|---|
| `BAD_MESSAGE` | Thông điệp sai: JSON hỏng, thiếu trường, sai kiểu, sai loại, vượt giới hạn, tên tệp không hợp lệ |
| `USER_OFFLINE` | `MSG_DM` hoặc `FILE_OFFER` tới người không online |
| `UNKNOWN_TRANSFER` | `FILE_ACCEPT`, `FILE_DONE` hoặc chunk không thuộc lần truyền nào, hoặc không phải của người gửi |
| `FILE_ABORTED` | Lần truyền tệp bị hủy; gửi cho **cả hai** bên |
| `SESSION_REPLACED` | Tài khoản vừa đăng nhập ở máy khác; gửi cho máy cũ, sau 0,5 giây thì đóng |
| `SERVER_ERROR` | Lỗi phía server khi xử lý thông điệp; phiên vẫn giữ |

| Trường hợp | Server làm gì |
|---|---|
| Quá 50 thông điệp sai trong một phiên | Đóng phiên |
| Client nhận quá chậm, hàng đợi gửi cho client đó vượt 1000 thông điệp | Đóng phiên của client đó |

### 5.5. `FILE_OFFER`: mời nhận tệp

```json
C → S:  {"type":"FILE_OFFER","transfer_id":"3q2+78r+zv7erb7v3q2+7w==","to":"bob","name":"bao_cao.pdf","size":10485760}
S → bob: {"type":"FILE_OFFER","transfer_id":"3q2+78r+zv7erb7v3q2+7w==","from":"alice","to":"bob","name":"bao_cao.pdf","size":10485760,"ts":1761660002000}
```

| Trường | Ràng buộc |
|---|---|
| `transfer_id` | 16 byte ngẫu nhiên do người gửi tạo (base64 thành 24 ký tự) |
| `name` | Chỉ tên tệp: không rỗng, ≤ 255 byte, không chứa `/` `\` hay ký tự điều khiển, không phải `.` hay `..` |
| `size` | 0 đến 4 294 967 295 byte (2³² − 1) |

Bên nhận **vẫn phải tự lọc tên tệp lại** trước khi ghi đĩa.

| Trường hợp | Server trả |
|---|---|
| `to` không online | `ERROR USER_OFFLINE`, `ref` = `transfer_id` |
| Mời chính mình; `transfer_id` trùng lần truyền đang chạy; `name` hoặc `size` sai ràng buộc | `ERROR BAD_MESSAGE` |
| Người nhận không trả lời trong 120 giây | `ERROR FILE_ABORTED` cho cả hai bên |

### 5.6. `FILE_ACCEPT`: đồng ý nhận

```json
bob → S:  {"type":"FILE_ACCEPT","transfer_id":"3q2+78r+zv7erb7v3q2+7w=="}
S → alice: {"type":"FILE_ACCEPT","transfer_id":"3q2+78r+zv7erb7v3q2+7w==","from":"bob"}
```

Chỉ người được mời gửi được, và chỉ khi lời mời còn chờ. Người gửi nhận được thì bắt đầu gửi chunk. Chưa có thông điệp từ chối: không muốn nhận thì để lời mời hết hạn.

| Trường hợp | Server trả |
|---|---|
| Không phải người được mời, hoặc `transfer_id` không tồn tại | `ERROR UNKNOWN_TRANSFER` |

### 5.7. `FILE_DONE`: gửi xong

```json
{"type":"FILE_DONE","transfer_id":"3q2+78r+zv7erb7v3q2+7w==","sha256":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}
```

- `sha256`: mã băm **SHA-256** (32 byte) của toàn tệp, base64. Ví dụ trên là mã băm của tệp rỗng.
- Người gửi gửi sau chunk cuối. `FILE_DONE` có thể tới trước chunk cuối (khác stream), nên:
  - server chỉ chuyển `FILE_DONE` cho người nhận khi đã chuyển đủ `size` byte;
  - người nhận chỉ kiểm mã băm khi đã nhận đủ `size` byte **và** đã có `FILE_DONE`. Khớp thì lưu tệp, không khớp thì xóa và báo người dùng.

| Trường hợp | Server trả |
|---|---|
| Không phải người gửi, chưa được đồng ý, hoặc `transfer_id` không tồn tại | `ERROR UNKNOWN_TRANSFER` |
| `sha256` không phải 32 byte | `ERROR BAD_MESSAGE` |

---

## 6. UDP stream 2: heartbeat

- Client gửi 1 byte mỗi 5 giây. Server trả lại 1 byte cho mỗi heartbeat nhận được.
- Bên nào 15 giây không nhận được **gói nào** của bên kia (kể cả tin nhắn, chunk) thì coi bên kia đã mất.
- Server kiểm mỗi 5 giây, nên client tắt đột ngột bị loại sau 15–20 giây. Khi đó mọi người nhận `USER_LIST` mới, và các lần truyền tệp của người đó bị hủy.
- Heartbeat không được gửi lại khi mất.

---

## 7. UDP stream 3+: `FILE_CHUNK`

Nhị phân, không phải JSON, nằm sau 2 byte độ dài:
```
| transfer_id (16 byte) | offset (4 byte, Big-Endian) | dữ liệu (1–1000 byte) |
```

- Mỗi lần truyền dùng một stream riêng có số ≥ 3. Mỗi bên tự chọn số stream trên kết nối của mình; số stream ở chặng người gửi → server và server → người nhận có thể khác nhau. Bên nhận biết stream mới thuộc lần truyền nào nhờ `transfer_id` trong chunk đầu tiên.
- `offset` bắt đầu từ 0, liền mạch. Ví dụ tệp 10 MB (10 485 760 byte) = 10 486 chunk; chunk cuối có `offset` 10 485 000 và chứa 760 byte.
- Tệp 0 byte: không có chunk nào.
- Server chuyển từng chunk ngay khi nhận, và chưa đọc chunk tiếp khi chưa chuyển xong chunk trước. Người nhận chậm thì người gửi tự bị hãm lại.

| Trường hợp | Server làm gì |
|---|---|
| Chunk cho lần truyền chưa được đồng ý, hoặc không phải của người gửi | `ERROR UNKNOWN_TRANSFER` |
| Chunk đầu tiên ngắn hơn 21 byte | `ERROR BAD_MESSAGE` |
| `offset` không liền mạch, hoặc vượt `size` | `ERROR FILE_ABORTED` cho cả hai bên |
| Một bên rời mạng giữa chừng | `ERROR FILE_ABORTED` cho bên còn lại |

---

## 8. Khóa và nonce

- Mỗi lần đăng nhập: khóa X25519 mới, 4 khóa mới, `conn_id` mới.
- Bộ đếm nonce TCP và `PktNum` UDP bắt đầu từ 0 cho mỗi bộ khóa mới, mỗi chiều một bộ đếm, không bao giờ đặt lại khi còn dùng khóa đó.
- `PktNum` chạm 2³² − 1024 thì đóng kết nối, client đăng nhập lại.
- Gói UDP: nonce = `PktNum` (4 byte) ‖ 8 byte 0; header gói là dữ liệu xác thực kèm (AAD), sửa header thì giải mã thất bại.

## 9. Yêu cầu với tầng transport (Người A)

| # | Yêu cầu |
|---|---|
| T1 | Có loại gói `HELLO` như mục 4 |
| T2 | Chống phát lại theo `PktNum`, mỗi chiều riêng; gói gửi lại lấy `PktNum` mới |
| T3 | Cập nhật địa chỉ UDP theo gói hợp lệ mới nhất |
| T4 | Báo cho tầng trên khi bên kia mở stream tệp mới (số ≥ 3) |
| T5 | Việc gửi trên một stream phải chờ khi cửa sổ hoặc bộ đệm bên nhận đầy (trừ heartbeat) |
| T6 | Mọi gói sau HELLO đều được mã hóa, kể cả ACK, heartbeat, gói đóng kết nối |
| T7 | *(đề xuất)* Bit End-of-Message trong trường `Flags` của header |

A còn phải viết hai phần: header gói UDP (G1), stream và đóng khung trên UDP (G3).

## 10. Hằng số

| Tên | Giá trị |
|---|---|
| Cổng TCP / UDP | 9000 / 9001 |
| Khung TCP tối đa | 16 KiB |
| Hạn một thông điệp TCP / cả giai đoạn TCP | 10 giây / 60 giây |
| Số lần đăng nhập thất bại tối đa | 5 trên một kết nối |
| Hạn gắn UDP | 10 giây |
| Gửi lại HELLO | mỗi 1 giây, tối đa 5 lần |
| `msg_id` / `text` | ≤ 64 byte / ≤ 4000 byte |
| Thông điệp sai tối đa | 50 trên một phiên |
| Hàng đợi gửi mỗi client | 1000 thông điệp |
| Hạn chờ đồng ý nhận tệp | 120 giây |
| Heartbeat / hạn im lặng / chu kỳ kiểm | 5 / 15 / 5 giây |
| Dữ liệu một chunk | ≤ 1000 byte |

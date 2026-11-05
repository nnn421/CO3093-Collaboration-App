"""Bộ statechart cấp hệ thống: vòng đời MỘT người dùng trong Client-Server Collaboration Application.
  h0_overview.svg   Hình 0 - tổng quan
  h1_login.svg      Hình 1 - chi tiết "Đăng nhập"
  h2_online.svg     Hình 2 - chi tiết "Online" (3 vùng song song)
  h3_file.svg       Hình 3 - chi tiết một lần truyền tệp
Kiểu trình bày theo slide Sommerville: ô trắng viền xanh, tên + ngăn "do:".
Nhãn mũi tên: "điều xảy ra [điều kiện] / việc được làm", luôn ghi rõ client hay server.
Chạy trong thư mục này: python system_statecharts.py
"""
from html import escape

BLUE, INK, GREY = "#1a9be0", "#111", "#555"


class Fig:
    def __init__(self, w, h, title, subtitle=()):
        self.w, self.h, self.out = w, h, []
        self.text(w / 2, 36, title, size=19, bold=True)
        for i, s in enumerate(subtitle):
            self.text(w / 2, 62 + 18 * i, s, size=13, fill=GREY, italic=True)

    # ---------------------------------------------------------------- chữ
    def text(self, x, y, s, anchor="middle", size=13, bold=False, fill=None, italic=False):
        st = (' font-weight="bold"' if bold else "") + (f' fill="{fill}"' if fill else "") + \
             (' font-style="italic"' if italic else "")
        self.out.append(f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}"{st}>{escape(s)}</text>')

    def up(self, x, y_last, lines, anchor="middle", size=12.5, fill=None):
        for i, s in enumerate(lines):
            self.text(x, y_last - 16 * (len(lines) - 1 - i), s, anchor, size, fill=fill)

    def down(self, x, y_first, lines, anchor="start", size=12.5, fill=None):
        for i, s in enumerate(lines):
            self.text(x, y_first + 16 * i, s, anchor, size, fill=fill)

    # ---------------------------------------------------------------- hình
    def state(self, x, y, w, name, body=(), sub=False):
        h = 40 + 17 * len(body) + (10 if body else 0)
        self.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="#fff" '
                        f'stroke="{BLUE}" stroke-width="2.4"/>')
        self.text(x + w / 2, y + 25, name, size=14.5, bold=True)
        if sub:   # ký hiệu submachine (∞): trạng thái này có hình con riêng
            cx, cy = x + w - 26, y + 21
            self.out.append(f'<circle cx="{cx-6}" cy="{cy}" r="5" fill="none" stroke="{INK}" stroke-width="1.4"/>'
                            f'<circle cx="{cx+6}" cy="{cy}" r="5" fill="none" stroke="{INK}" stroke-width="1.4"/>')
        if body:
            self.out.append(f'<line x1="{x}" y1="{y+36}" x2="{x+w}" y2="{y+36}" stroke="{BLUE}" stroke-width="2"/>')
            for i, s in enumerate(body):
                self.text(x + w / 2, y + 56 + 17 * i, s, size=12.5)
        return {"l": x, "r": x + w, "t": y, "b": y + h, "cx": x + w / 2, "cy": y + h / 2, "w": w, "h": h}

    def arrow(self, pts, dash=False):
        d = " ".join(f"{'M' if i == 0 else 'L'}{px},{py}" for i, (px, py) in enumerate(pts))
        da = ' stroke-dasharray="6 4"' if dash else ""
        self.out.append(f'<path d="{d}" fill="none" stroke="{INK}" stroke-width="1.5"{da} marker-end="url(#a)"/>')

    def start(self, x, y):
        self.out.append(f'<circle cx="{x}" cy="{y}" r="12" fill="{BLUE}"/>')

    def end(self, x, y):
        self.out.append(f'<circle cx="{x}" cy="{y}" r="13" fill="#fff" stroke="{BLUE}" stroke-width="2.4"/>'
                        f'<circle cx="{x}" cy="{y}" r="7.5" fill="{BLUE}"/>')

    def entry_point(self, x, y):
        self.out.append(f'<circle cx="{x}" cy="{y}" r="9" fill="#fff" stroke="{INK}" stroke-width="1.6"/>')

    def exit_point(self, x, y):
        self.out.append(f'<circle cx="{x}" cy="{y}" r="9" fill="#fff" stroke="{INK}" stroke-width="1.6"/>'
                        f'<path d="M{x-6},{y-6} L{x+6},{y+6} M{x-6},{y+6} L{x+6},{y-6}" stroke="{INK}" stroke-width="1.6"/>')

    def choice(self, x, y):
        self.out.append(f'<path d="M{x},{y-13} L{x+13},{y} L{x},{y+13} L{x-13},{y} Z" fill="#fff" '
                        f'stroke="{INK}" stroke-width="1.6"/>')

    def frame(self, x, y, w, h, name, header=()):
        self.out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="22" fill="none" '
                        f'stroke="{BLUE}" stroke-width="2.4"/>')
        self.text(x + 22, y + 28, name, "start", 16, True)
        hb = y + 40
        if header:
            for i, s in enumerate(header):
                self.text(x + 22, y + 52 + 17 * i, s, "start", 12.5)
            hb = y + 52 + 17 * len(header)
            self.out.append(f'<line x1="{x}" y1="{hb}" x2="{x+w}" y2="{hb}" stroke="{BLUE}" stroke-width="2"/>')
        return hb

    def hline_dashed(self, x1, x2, y):
        self.out.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{BLUE}" stroke-width="1.6" '
                        f'stroke-dasharray="8 6"/>')

    def save(self, path):
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
               f'viewBox="0 0 {self.w} {self.h}" font-family="DejaVu Sans, Arial, sans-serif" fill="{INK}">'
               f'<defs><marker id="a" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" '
               f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{INK}"/></marker></defs>'
               f'<rect width="100%" height="100%" fill="#fff"/>' + "".join(self.out) + "</svg>")
        open(path, "w", encoding="utf-8").write(svg)
        print(path, self.w, self.h)


LEGEND = "Nhãn mũi tên: điều xảy ra [điều kiện] / việc được làm.   ∞ = trạng thái có hình chi tiết riêng."


# ====================================================================== Hình 0
def h0():
    f = Fig(1500, 680, "Hình 0 — Vòng đời một người dùng trong ứng dụng (tổng quan)", [LEGEND])
    T = 200
    f.start(50, T + 45)
    A = f.state(120, T, 270, "Chưa kết nối", ["do: client hiện màn hình đăng nhập"])
    B = f.state(590, T, 280, "Đăng nhập", ["do: trao khóa, kiểm tra mật khẩu,", "gắn kênh UDP (Hình 1)"], sub=True)
    C = f.state(1060, T, 330, "Online", ["do (song song, Hình 2):", "giữ kết nối bằng heartbeat;",
                                         "chuyển tin nhắn; truyền tệp (Hình 3)"], sub=True)
    D = f.state(1060, 500, 330, "Đã ngắt", ["do: server xóa khỏi danh sách online,",
                                            "báo cho người còn online;", "client báo mất kết nối"])
    ay = T + 45
    f.arrow([(62, ay), (A["l"], ay)]);         f.up(91, ay - 10, ["mở", "app"])
    f.arrow([(A["r"], ay), (B["l"], ay)]);     f.up((A["r"] + B["l"]) / 2, ay - 10, ["người dùng bấm", "Đăng nhập"])
    f.arrow([(B["r"], ay), (C["l"], ay)]);     f.up((B["r"] + C["l"]) / 2, ay - 10, ["client nhận", "USER_LIST đầu tiên"])
    # thất bại: vòng phía trên về lại "Chưa kết nối"
    f.arrow([(B["cx"], B["t"]), (B["cx"], 150), (A["cx"], 150), (A["cx"], A["t"])])
    f.up((A["cx"] + B["cx"]) / 2, 140, ["đăng nhập thất bại", "(sai mật khẩu, quá hạn chờ, lỗi giao thức)"])
    # online -> đã ngắt
    f.arrow([(C["cx"], C["b"]), (C["cx"], D["t"])])
    f.down(C["cx"] + 12, C["b"] + 26, ["client gửi FIN (người dùng đăng xuất)", "15 giây không nhận gói nào",
                                       "đăng nhập ở máy khác", "client nhận quá chậm",
                                       "client gửi quá 50 thông điệp sai"])
    # đã ngắt -> chưa kết nối
    f.arrow([(D["l"], D["cy"]), (A["r"] - 40, D["cy"]), (A["r"] - 40, A["b"])])
    f.up((A["r"] + D["l"]) / 2, D["cy"] - 8, ["client quay về màn hình đăng nhập"])
    # đóng app
    f.arrow([(A["l"] + 50, A["b"]), (A["l"] + 50, 602)])
    f.end(A["l"] + 50, 616)
    f.down(A["l"] + 62, A["b"] + 60, ["người dùng", "đóng app"])
    f.save("../h0_overview.svg")


# ====================================================================== Hình 1
def h1():
    f = Fig(1960, 600, "Hình 1 — Chi tiết trạng thái \"Đăng nhập\"", [LEGEND])
    FX, FY, FW, FH = 60, 110, 1790, 410
    f.frame(FX, FY, FW, FH, "Đăng nhập")
    T = 230
    S1 = f.state(250, T, 290, "Trao khóa (TCP)", ["do: client và server trao khóa", "X25519; server ký khóa của mình",
                                                   "bằng Ed25519"])
    S2 = f.state(780, T, 300, "Xác thực", ["do: server kiểm tra mật khẩu bằng", "PBKDF2; tối đa 5 lần thất bại",
                                            "trên một kết nối"])
    S3 = f.state(1320, T, 290, "Gắn kênh UDP", ["do: server giữ conn_id 10 giây,", "chờ gói HELLO ở cổng 9001"])
    ay = T + 45
    f.entry_point(FX, ay)
    f.text(FX, ay + 30, "từ Hình 0", "middle", 12, fill=GREY)
    f.arrow([(FX + 9, ay), (S1["l"], ay)]);    f.up((FX + S1["l"]) / 2, ay - 10, ["client mở TCP,", "gửi KEY_EXCHANGE"])
    f.arrow([(S1["r"], ay), (S2["l"], ay)])
    f.up((S1["r"] + S2["l"]) / 2, ay - 10, ["server trả KEY_EXCHANGE", "[chữ ký transcript đúng]", "/ hai bên tạo 4 khóa;", "client gửi LOGIN"])
    f.arrow([(S2["r"], ay), (S3["l"], ay)])
    f.up((S2["r"] + S3["l"]) / 2, ay - 10, ["LOGIN đúng / server cấp", "conn_id, trả AUTH_OK;",
                                             "client đóng TCP, gửi gói HELLO"])
    # vòng REGISTER
    x1, x2, top = S2["cx"] - 45, S2["cx"] + 45, T - 42
    f.arrow([(x1, S2["t"]), (x1, top), (x2, top), (x2, S2["t"])])
    f.up(S2["cx"], top - 10, ["lần đầu: client gửi REGISTER / server lưu tài khoản,",
                              "trả AUTH_OK; client gửi tiếp LOGIN"])
    # thành công
    xs = FX + FW
    f.arrow([(S3["r"], ay), (xs - 9, ay)])
    f.exit_point(xs, ay)
    f.up((S3["r"] + xs) / 2, ay - 10, ["server giải mã được gói", "HELLO / xóa conn_id khỏi",
                                       "bảng chờ, thêm vào danh sách", "online, gửi USER_LIST cho", "mọi người (= xác nhận)"])
    f.down(xs + 14, ay + 5, ["thành công", "→ Online"], fill=GREY)
    # thất bại: mỗi trạng thái một điểm thoát ở cạnh dưới
    fails = [(S1, ["quá 10 giây chưa có khóa", "chữ ký sai / khóa không hợp lệ", "/ đóng TCP"]),
             (S2, ["LOGIN sai / server trả AUTH_FAIL,", "client báo sai mật khẩu", "quá 10 giây không có thông điệp",
                   "thông điệp giải mã không được", "/ đóng TCP"]),
             (S3, ["server: quá 10 giây chưa có", "gói HELLO / hủy conn_id",
                   "client: gửi HELLO 5 lần (mỗi 1 giây)", "vẫn chưa có USER_LIST"])]
    yb = FY + FH
    for s, lab in fails:
        x = s["l"] + 40
        f.arrow([(x, s["b"]), (x, yb - 9)])
        f.exit_point(x, yb)
        f.down(x + 12, s["b"] + 24, lab)
        f.down(x - 30, yb + 30, ["thất bại → Chưa kết nối"], fill=GREY)
    f.save("../h1_login.svg")


# ====================================================================== Hình 2
def h2():
    f = Fig(1820, 790, "Hình 2 — Chi tiết trạng thái \"Online\"",
            [LEGEND, "Ba vùng ngăn bởi nét đứt chạy song song: người dùng ở cả ba cùng lúc."])
    FX, FY, FW, FH = 60, 110, 1330, 640
    hb = f.frame(FX, FY, FW, FH, "Online", [
        "entry: server thêm vào danh sách online, gửi USER_LIST cho mọi người đang online",
        "exit: server xóa khỏi danh sách online, gửi ERROR FILE_ABORTED cho bên kia của mọi tệp đang truyền,",
        "        gửi USER_LIST cho những người còn online"])
    R1, R2, R3 = hb, hb + 205, hb + 420
    f.hline_dashed(FX, FX + FW, R2)
    f.hline_dashed(FX, FX + FW, R3)
    DX = 1530
    Dn = f.state(DX, 420, 250, "Đã ngắt", ["(Hình 0)"])

    def region(top, label, name, body, loop, exit_lab=None):
        f.text(FX + 20, top + 26, label, "start", 13, True, fill=BLUE)
        f.start(FX + 50, top + 95)
        s = f.state(FX + 130, top + 50, 380, name, body)
        f.arrow([(FX + 62, top + 95), (s["l"], top + 95)])
        if loop:     # vòng bên phải ô
            y1, y2, xr = s["t"] + 30, s["t"] + 62, s["r"] + 45
            f.arrow([(s["r"], y1), (xr, y1), (xr, y2), (s["r"], y2)])
            f.down(xr + 14, y1 + 4, loop)
        if exit_lab:
            ye = s["b"] + 40
            f.arrow([(s["l"] + 60, s["b"]), (s["l"] + 60, ye), (FX + FW - 9, ye)])
            f.exit_point(FX + FW, ye)
            f.up(s["l"] + 74, ye - 8, exit_lab, "start")
            f.arrow([(FX + FW + 9, ye), (DX - 40, ye), (DX - 40, Dn["cy"] + (10 if ye > Dn["cy"] else -10)),
                     (Dn["l"], Dn["cy"] + (10 if ye > Dn["cy"] else -10))])
        return s

    region(R1, "Vùng 1 — giữ kết nối", "Còn liên lạc",
           ["do: client gửi heartbeat mỗi 5 giây;", "server trả lại mỗi heartbeat"],
           ["server nhận gói bất kỳ từ client", "/ ghi lại thời điểm nhận", "(đi vòng: hạn 15 giây đếm lại từ đầu)"],
           ["15 giây không nhận gói nào"])
    region(R2, "Vùng 2 — nhắn tin", "Sẵn sàng chuyển tin", ["do: server đọc Stream 1 của client"],
           ["client gửi MSG_BCAST / server chuyển cho mọi người online trừ người gửi",
            "client gửi MSG_DM [người nhận online] / server chuyển cho người nhận",
            "client gửi MSG_DM [người nhận offline] / server trả ERROR USER_OFFLINE",
            "client gửi thông điệp sai / server trả ERROR"],
           ["client gửi quá 50 thông điệp sai"])
    f.text(FX + 20, R3 + 26, "Vùng 3 — truyền tệp", "start", 13, True, fill=BLUE)
    s3 = f.state(FX + 130, R3 + 50, 380, "Truyền tệp", ["mỗi tệp đang gửi hoặc nhận chạy một bản", "Hình 3; nhiều tệp cùng lúc được"],
                 sub=True)
    f.start(FX + 50, R3 + 95)
    f.arrow([(FX + 62, R3 + 95), (s3["l"], R3 + 95)])

    # chuyển cấp trạng thái tổng hợp: từ viền khung
    yc = FY + 30
    f.arrow([(FX + FW, yc), (DX + 125, yc), (DX + 125, Dn["t"])])
    f.down(FX + FW + 14, yc + 24, ["client gửi FIN (đăng xuất)", "đăng nhập ở máy khác",
                                    "hàng đợi gửi của client đầy", "(client nhận quá chậm)"])
    f.save("../h2_online.svg")


# ====================================================================== Hình 3
def h3():
    f = Fig(2080, 760, "Hình 3 — Một lần truyền tệp (người gửi → server → người nhận)",
            [LEGEND, "Mỗi tệp chạy một bản riêng của hình này. Chunk đi trên stream riêng (số ≥ 3), thỏa thuận đi trên Stream 1."])
    T = 230
    ay = T + 45
    f.start(40, ay)
    f.arrow([(52, ay), (147, ay)]);  f.up(100, ay - 10, ["người gửi gửi", "FILE_OFFER"])
    f.choice(160, ay)
    T1 = f.state(400, T, 270, "Chờ người nhận đồng ý", ["do: server giữ đề nghị", "tối đa 120 giây"])
    T2 = f.state(880, T, 330, "Đang truyền", ["do: người gửi gửi chunk 1000 byte;", "server chuyển từng chunk; người",
                                              "nhận chậm thì server ngừng đọc"])
    T3 = f.state(1450, T, 270, "Người nhận kiểm tra", ["do: tính SHA-256", "của tệp đã nhận"])
    T4 = f.state(1820, T, 200, "Hoàn tất", ["do: lưu vào downloads/"])
    T5 = f.state(880, 560, 330, "Đã hủy", ["do: hai bên dừng gửi/nhận,", "người nhận xóa phần đã nhận"])

    f.arrow([(173, ay), (T1["l"], ay)])
    f.up((173 + T1["l"]) / 2, ay - 10, ["[người nhận online ∧", "tên tệp hợp lệ]", "/ server chuyển",
                                        "FILE_OFFER"])
    f.arrow([(160, ay + 13), (160, 600)]);  f.end(160, 614)
    f.down(172, ay + 60, ["[người nhận offline]", "/ server trả", "ERROR USER_OFFLINE"])
    f.arrow([(T1["r"], ay), (T2["l"], ay)])
    f.up((T1["r"] + T2["l"]) / 2, ay - 10, ["người nhận gửi FILE_ACCEPT", "/ server báo FILE_ACCEPT", "cho người gửi"])
    f.arrow([(T2["r"], ay), (T3["l"], ay)])
    f.up((T2["r"] + T3["l"]) / 2, ay - 10, ["server đã chuyển đủ byte", "VÀ đã nhận FILE_DONE",
                                            "/ chuyển FILE_DONE{sha256}", "cho người nhận"])
    f.arrow([(T3["r"], ay), (T4["l"], ay)]);  f.up((T3["r"] + T4["l"]) / 2, ay - 10, ["[SHA-256", "khớp]"])
    f.arrow([(T4["cx"], T4["b"]), (T4["cx"], 600)]);  f.end(T4["cx"], 614)
    # vòng chunk phía trên Đang truyền
    x1, x2, top = T2["cx"] - 45, T2["cx"] + 45, T - 42
    f.arrow([(x1, T2["t"]), (x1, top), (x2, top), (x2, T2["t"])])
    f.up(T2["cx"], top - 10, ["server nhận chunk trên stream người gửi tự chọn [đúng transfer_id, đúng offset]",
                              "/ chuyển cho người nhận trên stream server tự chọn"])
    # vào Đã hủy
    f.arrow([(T1["cx"], T1["b"]), (T1["cx"], T5["cy"]), (T5["l"], T5["cy"])])
    f.down(T1["cx"] + 12, T1["b"] + 26, ["quá 120 giây chưa trả lời", "một bên offline", "/ server gửi ERROR FILE_ABORTED", "cho cả hai bên"])
    f.arrow([(T2["cx"], T2["b"]), (T2["cx"], T5["t"])])
    f.down(T2["cx"] + 12, T2["b"] + 26, ["chunk sai offset hoặc transfer_id", "một bên offline",
                                          "/ server gửi ERROR FILE_ABORTED", "cho cả hai bên"])
    f.arrow([(T3["cx"], T3["b"]), (T3["cx"], T5["cy"]), (T5["r"], T5["cy"])])
    f.down(T3["cx"] + 12, T3["b"] + 26, ["[SHA-256 không khớp]", "/ người nhận báo lỗi"])
    f.arrow([(T5["cx"], T5["b"]), (T5["cx"], 695)]);  f.end(T5["cx"], 709)
    f.save("../h3_file.svg")


h0(); h1(); h2(); h3()

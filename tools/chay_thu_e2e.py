"""Chạy thử toàn hệ thống qua HTTP API của giao diện web: 1 server + 2 client agent (cổng 8080, 8081).

    python tools/chay_thu_e2e.py            # mạng tốt
    python tools/chay_thu_e2e.py --loss 10  # mỗi client bỏ ngẫu nhiên 10% gói ở cả hai chiều
    python tools/chay_thu_e2e.py --crash    # thêm: tắt đột ngột bob, rồi tắt đột ngột server, đo thời gian phát hiện

Dùng thư mục tạm riêng cho users.json, khóa server và downloads, nên không đụng dữ liệu đang có.
Cần các cổng 9000/9001/8080/8081 đang trống.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def post(port, path, obj, timeout=120):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", json.dumps(obj).encode(),
                                 {"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def get(port, path):
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10).read())


def check(name, ok, detail=""):
    print(f"[{'ĐẠT' if ok else 'HỎNG'}] {name}" + (f": {detail}" if detail else ""))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loss", default="0")
    ap.add_argument("--size", type=int, default=500_000)
    ap.add_argument("--crash", action="store_true")
    ap.add_argument("--log-dir", default=None, help="ghi log server/client vào thư mục này để xem khi có mục hỏng")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="e2e_")

    def out(name):
        if not args.log_dir:
            return subprocess.DEVNULL
        os.makedirs(args.log_dir, exist_ok=True)
        return open(os.path.join(args.log_dir, name + ".log"), "w", encoding="utf-8")
    srv_cmd = [PY, "-c",
               "import sys; sys.argv=['server/main.py','--users-file',sys.argv[1],'--identity-file',sys.argv[2],"
               "'--identity-pub-file',sys.argv[3]]; sys.path.insert(0,'.'); from server.main import main; main()",
               os.path.join(tmp, "users.json"), os.path.join(tmp, "id.key"), os.path.join(tmp, "id.pub")]
    procs = [subprocess.Popen(srv_cmd, cwd=ROOT, stdout=out("server"), stderr=subprocess.STDOUT)]
    key = ""
    for _ in range(100):                      # chờ server ghi xong khóa công khai (file có thể vừa tạo mà chưa có nội dung)
        try:
            key = open(os.path.join(tmp, "id.pub")).read().strip()
        except OSError:
            pass
        if len(key) == 64:
            break
        time.sleep(0.1)
    clients = {}
    for port in (8080, 8081):
        clients[port] = subprocess.Popen(
            [PY, "client/main.py", "--port", str(port), "--ui-host", "127.0.0.1", "--loss", args.loss,
             "--server-key", key, "--downloads", os.path.join(tmp, "downloads")],
            cwd=ROOT, stdout=out(f"client_{port}"), stderr=subprocess.STDOUT)
        procs.append(clients[port])
    time.sleep(1.5)

    events = {8080: [], 8081: []}

    def sse(port):
        try:
            for line in urllib.request.urlopen(f"http://127.0.0.1:{port}/api/events", timeout=300):
                line = line.decode().strip()
                if line.startswith("data:"):
                    events[port].append(json.loads(line[5:]))
        except Exception:
            pass

    ok = True
    try:
        r = post(8080, "/api/register", {"username": "alice", "password": "123"})
        ok &= check("mật khẩu 3 byte bị từ chối (INVALID_INPUT)", not r["ok"], r.get("error", ""))
        for port, user in ((8080, "alice"), (8081, "bob")):
            r = post(port, "/api/register", {"username": user, "password": "123456"})
            ok &= check(f"đăng ký + đăng nhập {user}", r["ok"], r.get("error", ""))
        for p in events:
            threading.Thread(target=sse, args=(p,), daemon=True).start()
        t = time.time()
        while get(8080, "/api/status")["online_users"] != ["alice", "bob"] and time.time() - t < 10:
            time.sleep(0.05)
        ok &= check("alice thấy USER_LIST [alice, bob]", get(8080, "/api/status")["online_users"] == ["alice", "bob"])

        post(8080, "/api/chat", {"content": "Chào cả nhóm"})
        post(8081, "/api/dm", {"to": "alice", "content": "Gửi riêng"})
        post(8081, "/api/dm", {"to": "carol", "content": "x"})
        def seen(port, want):
            return want in [(e["type"], e.get("from"), e.get("text") or e.get("code")) for e in events[port]]
        wants = [(8081, ("MSG_BCAST", "alice", "Chào cả nhóm"), "bob nhận MSG_BCAST của alice"),
                 (8080, ("MSG_DM", "bob", "Gửi riêng"), "alice nhận MSG_DM của bob"),
                 (8081, ("ERROR", None, "USER_OFFLINE"), "DM tới người offline -> ERROR USER_OFFLINE")]
        t = time.time()                       # mất gói thì tin tới muộn hơn (chờ gửi lại theo RTO): chờ tối đa 10 giây
        while not all(seen(p, w) for p, w, _ in wants) and time.time() - t < 10:
            time.sleep(0.05)
        for p, w, name in wants:
            ok &= check(name, seen(p, w))
        print(f"       (đủ cả 3 sau {time.time() - t:.2f} giây)")

        data = os.urandom(args.size)
        t = time.time()
        r = post(8080, "/api/upload", {"to": "bob", "filename": "tep thu.bin",
                                       "data": base64.b64encode(data).decode()})
        files = []
        for _ in range(600):
            files = get(8081, "/api/downloads")["files"]
            if files:
                break
            time.sleep(0.1)
        took = time.time() - t
        got = urllib.request.urlopen("http://127.0.0.1:8081/api/download/tep%20thu.bin").read() if files else b""
        ok &= check(f"gửi tệp {args.size} byte, mất gói {args.loss}%",
                    r.get("ok") and hashlib.sha256(got).hexdigest() == hashlib.sha256(data).hexdigest(),
                    f"{took:.2f} giây, SHA-256 khớp" if got else str(r))

        if args.crash:
            clients[8081].kill()
            t = time.time()
            while "bob" in get(8080, "/api/status")["online_users"] and time.time() - t < 30:
                time.sleep(0.5)
            ok &= check("bob tắt đột ngột -> alice thấy bob offline", time.time() - t < 21,
                        f"sau {time.time() - t:.1f} giây")
            procs[0].kill()
            t = time.time()
            while get(8080, "/api/status")["authenticated"] and time.time() - t < 30:
                time.sleep(0.5)
            ok &= check("server tắt đột ngột -> client biết mất kết nối", time.time() - t < 21,
                        f"sau {time.time() - t:.1f} giây")
        else:
            post(8081, "/api/logout", {})
            t = time.time()
            while get(8080, "/api/status")["online_users"] != ["alice"] and time.time() - t < 20:
                time.sleep(0.1)
            took = time.time() - t
            ok &= check("bob đăng xuất (FIN) -> alice thấy bob offline", took < 20,
                        f"sau {took:.1f} giây" + (" (FIN bị mất, phải chờ hạn im lặng 15 giây)" if took > 5 else ""))
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait()
        shutil.rmtree(tmp, ignore_errors=True)
    print("KẾT QUẢ:", "TẤT CẢ ĐẠT" if ok else "CÓ MỤC HỎNG")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

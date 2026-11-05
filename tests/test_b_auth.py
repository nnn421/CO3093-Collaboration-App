"""Nghiệm thu B3: PBKDF2, không lưu mật khẩu thô, không chặn event loop, đăng ký đồng thời."""
import asyncio
import json
import time

from server.auth import UserStore
from shared import config, messages


def test_register_verify_and_storage(tmp_path):
    async def go():
        path = tmp_path / "users.json"
        st = UserStore(str(path))
        assert await st.register("alice", "Pa55word!") == (True, "")
        assert await st.register("alice", "other123") == (False, messages.E_USER_EXISTS)
        assert await st.register("a", "Pa55word!") == (False, messages.E_INVALID_INPUT)
        assert await st.register("alice\n", "Pa55word!") == (False, messages.E_INVALID_INPUT)   # "\n" cuối tên
        assert await st.register("bob", "123") == (False, messages.E_INVALID_INPUT)              # < 6 byte
        assert await st.register("bob", "x" * 129) == (False, messages.E_INVALID_INPUT)          # > 128 byte
        assert await st.register("bob", "ệ" * 43) == (False, messages.E_INVALID_INPUT)           # 43 ký tự = 129 byte
        assert await st.register("bob_2", "x" * 128) == (True, "")
        assert await st.verify("alice", "Pa55word!")
        assert not await st.verify("alice", "Pa55word?")
        assert not await st.verify("nobody", "Pa55word!")

        raw = path.read_text(encoding="utf-8")
        assert "Pa55word" not in raw
        rec = json.loads(raw)["users"]["alice"]
        assert len(bytes.fromhex(rec["salt"])) == config.SALT_BYTES
        assert rec["iterations"] == 100_000 and len(bytes.fromhex(rec["hash"])) == 32

        assert await UserStore(str(path)).verify("alice", "Pa55word!")   # đọc lại từ đĩa
    asyncio.run(go())


def test_same_password_different_hash(tmp_path):
    async def go():
        st = UserStore(str(tmp_path / "u.json"), iterations=1000)
        await st.register("user1", "samepass")
        await st.register("user2", "samepass")
        u = st._users
        assert u["user1"]["salt"] != u["user2"]["salt"] and u["user1"]["hash"] != u["user2"]["hash"]
    asyncio.run(go())


def test_concurrent_register_same_name_only_one_wins(tmp_path):
    async def go():
        st = UserStore(str(tmp_path / "u.json"), iterations=20_000)
        res = await asyncio.gather(*(st.register("race", f"password{i}") for i in range(8)))
        assert sum(ok for ok, _ in res) == 1
    asyncio.run(go())


def test_pbkdf2_does_not_block_event_loop(tmp_path):
    """Trong lúc 4 lần PBKDF2 100k vòng chạy, một ticker 10ms vẫn chạy đều (khoảng hở lớn nhất < 50ms)."""
    async def go():
        st = UserStore(str(tmp_path / "u.json"))
        await st.register("alice", "Pa55word!")
        gaps, stop = [], False

        async def ticker():
            last = time.perf_counter()
            while not stop:
                await asyncio.sleep(0.01)
                now = time.perf_counter()
                gaps.append(now - last)
                last = now

        t = asyncio.create_task(ticker())
        t0 = time.perf_counter()
        await asyncio.gather(*(st.verify("alice", "Pa55word!") for _ in range(4)))
        elapsed = time.perf_counter() - t0
        stop = True
        await t
        return max(gaps), elapsed

    worst, elapsed = asyncio.run(go())
    print(f"\n4 x PBKDF2: {elapsed*1000:.0f} ms, khoảng hở event loop lớn nhất {worst*1000:.1f} ms")
    assert worst < 0.05

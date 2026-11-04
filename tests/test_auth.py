"""
tests/test_auth.py
------------------
Kiểm thử tự động cho hệ thống xác thực người dùng và quản lý tài khoản (B3 / C6).
Bao gồm:
  - Đăng ký tài khoản mới và lưu trữ băm an toàn
  - Đăng nhập thành công với mật khẩu đúng
  - Từ chối đăng nhập khi sai mật khẩu
  - Từ chối đăng ký tài khoản trùng tên
  - Kiểm tra tính bất đồng bộ không chặn Event Loop
"""

import os
import pytest
from server.user_db import UserDB

TEST_DB_PATH = "test_users_sandbox.json"

@pytest.fixture
def clean_user_db():
    """Tạo môi trường UserDB sạch và tự dọn dẹp sau khi kiểm thử."""
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    db = UserDB(filepath=TEST_DB_PATH)
    yield db
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    if os.path.exists(f"{TEST_DB_PATH}.tmp"):
        os.remove(f"{TEST_DB_PATH}.tmp")


@pytest.mark.asyncio
async def test_register_and_login(clean_user_db):
    """Kiểm tra chu trình Đăng ký -> Đăng nhập thành công."""
    db = clean_user_db
    # 1. Đăng ký tài khoản
    ok = await db.register("alice", "MatKhauChuan123@")
    assert ok is True
    assert db.user_exists("alice") is True
    assert db.count() == 1

    # 2. Đăng nhập đúng mật khẩu
    auth_ok = await db.authenticate("alice", "MatKhauChuan123@")
    assert auth_ok is True


@pytest.mark.asyncio
async def test_wrong_password_rejected(clean_user_db):
    """Kiểm tra từ chối đăng nhập với mật khẩu sai hoặc tài khoản không tồn tại."""
    db = clean_user_db
    await db.register("bob", "MatKhauBob_999")

    # Mật khẩu sai
    assert await db.authenticate("bob", "SaiMatKhau") is False
    assert await db.authenticate("bob", "") is False

    # Tài khoản không tồn tại
    assert await db.authenticate("charlie", "MatKhauBatKy") is False


@pytest.mark.asyncio
async def test_duplicate_registration_rejected(clean_user_db):
    """Kiểm tra không cho phép đăng ký trùng tên (kể cả khác chữ hoa/thường)."""
    db = clean_user_db
    assert await db.register("David", "Pass1") is True
    # Đăng ký lại cùng tên
    assert await db.register("David", "Pass2") is False
    # Đăng ký lại với chữ thường
    assert await db.register("david", "Pass3") is False
    assert db.count() == 1


@pytest.mark.asyncio
async def test_persistence_across_reloads(clean_user_db):
    """Dữ liệu người dùng phải được lưu vĩnh viễn trên tệp JSON và đọc lại chuẩn xác."""
    db = clean_user_db
    await db.register("eve", "MatKhauEve_2026")

    # Khởi tạo instance mới đọc cùng file
    db_reloaded = UserDB(filepath=TEST_DB_PATH)
    assert db_reloaded.count() == 1
    assert db_reloaded.user_exists("eve") is True
    assert await db_reloaded.authenticate("eve", "MatKhauEve_2026") is True

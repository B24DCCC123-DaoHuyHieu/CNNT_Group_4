import hashlib
import hmac
import base64
import json
import time

SECRET_KEY = b"NganHangSo_Nhom4_SecretKey_2026"

# Cơ sở dữ liệu giả lập (3 vai trò khớp với bảng phân quyền của B)
USERS_DB = {
    "khachhang01": {
        "password_hash": hashlib.sha256(b"PassKH@2026").hexdigest(),
        "role": "CUSTOMER",
        "otp": "111222",
        "failed_attempts": 0,
        "locked_until": 0
    },
    "nhanvien01": {
        "password_hash": hashlib.sha256(b"PassOfficer@2026").hexdigest(),
        "role": "OFFICER",
        "otp": "333444",
        "failed_attempts": 0,
        "locked_until": 0
    },
    "admin01": {
        "password_hash": hashlib.sha256(b"PassAdmin@2026").hexdigest(),
        "role": "SYSADMIN",
        "otp": "999888",
        "failed_attempts": 0,
        "locked_until": 0
    }
}

# Ma trận phân quyền RBAC 3 vai trò
ROLE_PERMISSIONS = {
    "CUSTOMER": ["VIEW_BALANCE", "TRANSFER_MONEY"],
    "OFFICER": ["VIEW_BALANCE", "TRANSFER_MONEY", "APPROVE_HIGH_VALUE", "VIEW_LOGS"],
    "SYSADMIN": ["SYSTEM_CONFIG", "VIEW_LOGS"]
}

def create_token(username, role, ttl=900):
    payload = json.dumps({"sub": username, "role": role, "exp": int(time.time()) + ttl}).encode()
    b64_payload = base64.urlsafe_b64encode(payload).decode()
    sig = hmac.new(SECRET_KEY, b64_payload.encode(), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"

def verify_token(token):
    try:
        b64_payload, sig = token.split(".")
        expected_sig = hmac.new(SECRET_KEY, b64_payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None, "Token bị giả mạo chữ ký!"
        payload = json.loads(base64.urlsafe_b64decode(b64_payload).decode())
        if time.time() > payload["exp"]:
            return None, "Phiên đăng nhập đã hết hạn (Timeout)!"
        return payload, "OK"
    except Exception:
        return None, "Token không hợp lệ!"

def login_mfa(username, password, otp_input):
    user = USERS_DB.get(username)
    if not user:
        return False, "Tài khoản không tồn tại."
    
    # Kiểm tra khóa tài khoản (chống Brute-force)
    if time.time() < user["locked_until"]:
        return False, f"Tài khoản đang bị khóa tạm thời do nhập sai quá 3 lần!"

    # Bước 1: Kiểm tra mật khẩu
    if hashlib.sha256(password.encode()).hexdigest() != user["password_hash"]:
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= 3:
            user["locked_until"] = time.time() + 60
            return False, "Sai mật khẩu 3 lần -> KHÓA TÀI KHOẢN trong 60 giây!"
        return False, f"Sai mật khẩu (Lần {user['failed_attempts']}/3)."

    # Bước 2: Kiểm tra MFA (OTP)
    if otp_input != user["otp"]:
        return False, "Xác thực MFA thất bại: Sai mã OTP!"

    user["failed_attempts"] = 0
    token = create_token(username, user["role"])
    return True, token

def check_access(token, action):
    payload, msg = verify_token(token)
    if not payload:
        return f"[TỪ CHỐI] {msg}"
    role = payload["role"]
    if action in ROLE_PERMISSIONS.get(role, []):
        return f"[CHO PHÉP] User '{payload['sub']}' ({role}) được thực hiện '{action}'."
    return f"[TỪ CHỐI] User '{payload['sub']}' ({role}) KHÔNG có quyền '{action}'."

if __name__ == "__main__":
    print("=== CA B01: KHÁCH HÀNG ĐĂNG NHẬP MFA & THỬ PHÂN QUYỀN ===")
    ok, res = login_mfa("khachhang01", "PassKH@2026", "111222")
    print("Login:", "Thành công" if ok else res)
    if ok:
        print(check_access(res, "TRANSFER_MONEY"))    # Cho phép
        print(check_access(res, "SYSTEM_CONFIG"))     # Từ chối

    print("\n=== CA B02: QUẢN TRỊ VIÊN (SYSADMIN) THỬ PHÂN QUYỀN ===")
    ok, res = login_mfa("admin01", "PassAdmin@2026", "999888")
    if ok:
        print(check_access(res, "SYSTEM_CONFIG"))     # Cho phép
        print(check_access(res, "TRANSFER_MONEY"))    # Từ chối (PoLP)

    print("\n=== CA B03: KIỂM THỬ SAI OTP (MFA) ===")
    print(login_mfa("nhanvien01", "PassOfficer@2026", "000000"))

    print("\n=== CA B04: KIỂM THỬ KHÓA TÀI KHOẢN KHI SAI MẬT KHẨU 3 LẦN ===")
    for i in range(3):
        print(f"Lần {i+1}:", login_mfa("khachhang01", "SaiPass", "111222"))
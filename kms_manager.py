#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script 2: Hệ thống Quản lý khóa mật mã (Envelope Encryption & NIST SP 800-57)
 và Đồng bộ đẩy Log UDP 514 về SYSLOG-SRV (192.168.20.40)
"""

import os
import stat
import socket
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = os.path.abspath("./bank_env")
KMS_VAULT_DIR = os.path.join(BASE_DIR, "etc_bank_kms")  # Mô phỏng /etc/bank_kms/
KEK_FILE_PATH = os.path.join(KMS_VAULT_DIR, "master.key")

SYSLOG_SERVER_IP = "192.168.20.40"
SYSLOG_UDP_PORT = 514
NTP_SERVER_IP = "192.168.20.30"
SOURCE_HOST = "DB_Server_192.168.20.10"

def send_syslog(event_code: str, severity: int, user_role: str, message: str):
    """
    Đẩy bản tin chuẩn Syslog (RFC 3164) qua UDP 514 về SYSLOG-SRV (192.168.20.40)
    và ghi nhận vào file syslog_local_mirror.log để chụp ảnh bằng chứng.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    # Facility 16 (local0): Priority = Facility * 8 + Severity
    pri = 16 * 8 + severity
    syslog_packet = (
        f"<{pri}>{timestamp} [NTP:{NTP_SERVER_IP}] {SOURCE_HOST} "
        f"Role={user_role} Event={event_code} Severity={severity}: {message}"
    )

    # 1. Ghi file log локаl để làm bằng chứng kiểm thử có dấu thời gian
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(os.path.join(BASE_DIR, "syslog_mirror_192_168_20_40.log"), "a", encoding="utf-8") as f:
        f.write(syslog_packet + "\n")

    # 2. Đẩy gói tin UDP 514 thực tế qua mạng (nếu chạy trong lab kết nối IP thật)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.sendto(syslog_packet.encode("utf-8"), (SYSLOG_SERVER_IP, SYSLOG_UDP_PORT))
        sock.close()
    except Exception:
        pass  # Bỏ qua nếu đang chạy độc lập trên máy cá nhân ngoài mạng 192.168.20.x

    print(f"📡 [SYSLOG -> {SYSLOG_SERVER_IP}:514] {syslog_packet}")

def init_master_kek(role: str = "Security_Admin"):
    """Giai đoạn 1 & 2: Khởi tạo KEK 256-bit bằng CSPRNG và thiết lập quyền 400"""
    if role != "Security_Admin":
        send_syslog("[KEY_ACCESS_DENIED]", 2, role, "Trái phép khởi tạo Master Key (KEK)!")
        raise PermissionError("RBAC Denied: Chỉ Security_Admin mới có quyền khởi tạo KEK.")

    os.makedirs(KMS_VAULT_DIR, exist_ok=True)
    kek_bytes = secrets.token_bytes(32)  # 256-bit AES Key

    # Nếu file cũ đang khóa quyền read-only thì mở tạm để ghi mới
    if os.path.exists(KEK_FILE_PATH):
        os.chmod(KEK_FILE_PATH, stat.S_IWRITE | stat.S_IREAD)

    with open(KEK_FILE_PATH, "wb") as f:
        f.write(kek_bytes)

    # Thiết lập quyền tương đương chmod 400 (Owner Read-Only)
    os.chmod(KEK_FILE_PATH, stat.S_IREAD)
    print(f"[+] Đã sinh Master Key (KEK 256-bit) an toàn tại: {KEK_FILE_PATH}")

def wrap_dek_with_kek(dek_bytes: bytes) -> bytes:
    """Mã hóa khóa phiên DEK bằng Master Key KEK (AES-256-GCM)"""
    if not os.path.exists(KEK_FILE_PATH):
        init_master_kek("Security_Admin")
    with open(KEK_FILE_PATH, "rb") as f:
        kek = f.read()
    aesgcm = AESGCM(kek)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, dek_bytes, b"ENVELOPE_DEK_V1")
    return nonce + ciphertext

def unwrap_dek_with_kek(encrypted_dek_blob: bytes, role: str, custom_kek: bytes = None) -> bytes:
    """Giải mã tệp .key.enc để lấy lại DEK trên RAM (Chỉ cho phép Security_Admin)"""
    if role != "Security_Admin":
        send_syslog("[KEY_ACCESS_DENIED]", 2, role, "Cố gắng truy cập KEK trái phép khi giải mã DEK!")
        raise PermissionError("RBAC Denied: Cần quyền Security_Admin để mở khóa KEK.")

    kek = custom_kek
    if kek is None:
        with open(KEK_FILE_PATH, "rb") as f:
            kek = f.read()

    nonce, ct = encrypted_dek_blob[:12], encrypted_dek_blob[12:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ct, b"ENVELOPE_DEK_V1")

if __name__ == "__main__":
    init_master_kek("Security_Admin")
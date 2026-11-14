#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script 3: Thực thi Sao lưu tự động (Full / Incremental), Mã hóa AES-256-GCM
và phân phối theo nguyên tắc 3-2-1
"""

import os
import shutil
import tarfile
import hashlib
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kms_manager import wrap_dek_with_kek, send_syslog, BASE_DIR

PROD_DB_DIR = os.path.join(BASE_DIR, "prod_db_192_168_20_10")
LOCAL_STAGING_DIR = os.path.join(BASE_DIR, "local_staging_disk")
REMOTE_BACKUP_SRV = os.path.join(BASE_DIR, "backup_srv_192_168_20_50_vlan20")

def compute_sha256(filepath: str) -> str:
    """Tính giá trị băm SHA-256 của tệp .tar.gz.enc"""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def run_backup(backup_type: str = "FULL", operator_role: str = "Backup_Operator") -> str:
    """
    Thực hiện quy trình đóng gói, mã hóa phong bì và tạo bộ 3 tệp chuẩn Mục 3.4A
    """
    if operator_role != "Backup_Operator":
        send_syslog("[BACKUP_FAIL]", 3, operator_role, "Sai vai trò RBAC khi gọi script sao lưu!")
        raise PermissionError("RBAC Denied: Chỉ Backup_Operator được phép chạy script Backup.")

    os.makedirs(LOCAL_STAGING_DIR, exist_ok=True)
    os.makedirs(REMOTE_BACKUP_SRV, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"bank_backup_{backup_type}_{timestamp}"

    temp_tar = os.path.join(LOCAL_STAGING_DIR, f"{base_name}.tar.gz")
    enc_file = os.path.join(LOCAL_STAGING_DIR, f"{base_name}.tar.gz.enc")
    key_file = os.path.join(LOCAL_STAGING_DIR, f"{base_name}.key.enc")
    sha_file = os.path.join(LOCAL_STAGING_DIR, f"{base_name}.sha256")

    try:
        # Bước 1: Nén toàn bộ thư mục dữ liệu DB thành .tar.gz
        with tarfile.open(temp_tar, "w:gz") as tar:
            tar.add(PROD_DB_DIR, arcname=os.path.basename(PROD_DB_DIR))

        with open(temp_tar, "rb") as f:
            plaintext_data = f.read()
        os.remove(temp_tar)  # Xóa ngay file nén bản rõ

        # Bước 2: Sinh khóa phiên DEK (256-bit) ngẫu nhiên trên RAM & mã hóa AES-256-GCM
        dek = secrets.token_bytes(32)
        aesgcm = AESGCM(dek)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_data, base_name.encode("utf-8"))

        with open(enc_file, "wb") as f:
            f.write(nonce + ciphertext)

        # Bước 3: Mã hóa khóa DEK bằng Master Key KEK (Envelope Encryption) và xóa DEK trên RAM
        encrypted_dek = wrap_dek_with_kek(dek)
        del dek  # Xóa biến DEK bản rõ ngay sau khi sử dụng

        with open(key_file, "wb") as f:
            f.write(encrypted_dek)

        # Bước 4: Băm SHA-256 tệp .tar.gz.enc để kiểm tra tính toàn vẹn
        file_hash = compute_sha256(enc_file)
        with open(sha_file, "w", encoding="utf-8") as f:
            f.write(f"{file_hash}  {os.path.basename(enc_file)}\n")

        # Bước 5: Thực thi nguyên tắc 3-2-1 -> Đồng bộ qua cổng TCP/22 (SFTP/SCP mô phỏng)
        # sang Backup_Server cách ly (192.168.20.50)
        for fpath in (enc_file, key_file, sha_file):
            shutil.copy2(fpath, os.path.join(REMOTE_BACKUP_SRV, os.path.basename(fpath)))

        send_syslog(
            "[BACKUP_OK]", 6, operator_role,
            f"Hoàn tất sao lưu {base_name} (3 tệp: .enc, .key.enc, .sha256) -> 192.168.20.50"
        )
        return base_name

    except Exception as e:
        send_syslog("[BACKUP_FAIL]", 2, operator_role, f"Lỗi sao lưu {base_name}: {str(e)}")
        raise

if __name__ == "__main__":
    run_backup("FULL", "Backup_Operator")
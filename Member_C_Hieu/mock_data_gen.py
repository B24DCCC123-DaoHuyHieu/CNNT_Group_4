#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script 1: Khởi tạo dữ liệu giả định Ngân hàng số (Mock Core Banking Data)
Phụ trách: Thành viên C (Đào Huy Hiệu)
"""

import os
import json
import hmac
import hashlib
import secrets
from datetime import datetime

BASE_DIR = os.path.abspath("./bank_env")
PROD_DB_DIR = os.path.join(BASE_DIR, "prod_db_192_168_20_10")
HMAC_SECRET = b"CORE_BANKING_LEDGER_HMAC_SECRET_KEY_2026"

def mask_pan(pan: str) -> str:
    """Che số thẻ (Masking): Chỉ hiện 6 số đầu (BIN) và 4 số cuối"""
    return f"{pan[:6]}******{pan[-4:]}"

def hash_password_salted(password: str) -> dict:
    """Băm mật khẩu 1 chiều kèm chuỗi Salt ngẫu nhiên 16 bytes"""
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return {
        "algorithm": "Argon2id/PBKDF2-SHA256",
        "salt_hex": salt.hex(),
        "hash_hex": pwd_hash.hex()
    }

def sign_ledger_record(account_id: str, balance: float, timestamp: str) -> str:
    """Ký HMAC-SHA256 cho mỗi bản ghi giao dịch/số dư để chống sửa đổi trái phép"""
    msg = f"{account_id}|{balance:.2f}|{timestamp}".encode('utf-8')
    return hmac.new(HMAC_SECRET, msg, hashlib.sha256).hexdigest()

def generate_mock_database():
    os.makedirs(PROD_DB_DIR, exist_ok=True)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Nhóm PII & CHD + 3. Nhóm Credentials
    customers = [
        {
            "customer_id": "CUST_001",
            "full_name": "Nguyen Van A",
            "cccd_encrypted_col": "ENC_AES256GCM_038206001234",
            "pan_masked": mask_pan("9704221234567890"),
            "credentials": hash_password_salted("Bank@Secure2026!")
        },
        {
            "customer_id": "CUST_002",
            "full_name": "Tran Thi B",
            "cccd_encrypted_col": "ENC_AES256GCM_001199005678",
            "pan_masked": mask_pan("9704229876543210"),
            "credentials": hash_password_salted("SmartOtp#998877")
        }
    ]

    # 2. Nhóm Tài chính & Lõi (Core Banking Ledger có gắn chữ ký HMAC-SHA256)
    ledgers = []
    raw_accounts = [("ACC_1001", 150000000.00), ("ACC_1002", 85500000.00)]
    for acc_id, bal in raw_accounts:
        ledgers.append({
            "account_id": acc_id,
            "balance_vnd": bal,
            "updated_at": now_str,
            "hmac_sha256": sign_ledger_record(acc_id, bal, now_str)
        })

    db_dump = {
        "db_host": "192.168.20.10",
        "vlan": "VLAN 20 (Internal)",
        "generated_at": now_str,
        "customers_pii_credentials": customers,
        "core_banking_ledger": ledgers
    }

    dump_file = os.path.join(PROD_DB_DIR, "core_banking_dump.json")
    with open(dump_file, "w", encoding="utf-8") as f:
        json.dump(db_dump, f, indent=4, ensure_ascii=False)

    # Tạo thêm file cấu hình giả lập & Transaction Log (WAL)
    wal_file = os.path.join(PROD_DB_DIR, "wal_binlog_current.log")
    with open(wal_file, "w", encoding="utf-8") as f:
        f.write(f"[{now_str}] TX_001: TRANSFER 5,000,000 VND FROM ACC_1001 TO ACC_1002 STATUS=COMMITTED\n")

    print(f"[+] Đã khởi tạo dữ liệu giả định tại: {PROD_DB_DIR}")

if __name__ == "__main__":
    generate_mock_database()
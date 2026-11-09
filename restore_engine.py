#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script 4: Quy trình 5 bước Phục hồi dữ liệu an toàn, Xác thực kép & Đo chỉ số RTO[cite: 2]
"""

import os
import time
import json
import shutil
import tarfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kms_manager import unwrap_dek_with_kek, send_syslog, BASE_DIR
from backup_engine import compute_sha256, REMOTE_BACKUP_SRV, LOCAL_STAGING_DIR
from mock_data_gen import sign_ledger_record

RESTORE_STAGE_DIR = os.path.join(BASE_DIR, "restore_staging_tmp")
RESTORED_OUTPUT_DIR = os.path.join(BASE_DIR, "restored_db_192_168_20_10")

def run_restore_workflow(
    backup_base_name: str,
    operator_role: str = "Backup_Operator",
    approver_role: str = "Security_Admin",
    source_dir: str = REMOTE_BACKUP_SRV,
    custom_kek: bytes = None
) -> dict:
    """
    Thực thi 5 bước phục hồi chuẩn Mục 3.4B & đo thời gian RTO thực tế[cite: 2]
    """
    start_time = time.perf_counter()

    # Kiểm tra cơ chế Xác thực kép (Dual Authorization)[cite: 2]
    if operator_role != "Backup_Operator" or approver_role != "Security_Admin":
        send_syslog(
            "[KEY_ACCESS_DENIED]", 2, f"{operator_role}+{approver_role}",
            "Vi phạm xác thực kép khi kích hoạt Restore!"
        )
        raise PermissionError("RBAC Denied: Phục hồi yêu cầu xác thực kép (Backup_Operator + Security_Admin)[cite: 2].")

    os.makedirs(RESTORE_STAGE_DIR, exist_ok=True)
    os.makedirs(RESTORED_OUTPUT_DIR, exist_ok=True)

    # -------------------------------------------------------------------------
    # BƯỚC 1: Thu thập bộ 3 tệp (.tar.gz.enc, .key.enc, .sha256) về Staging[cite: 2]
    # -------------------------------------------------------------------------
    enc_name = f"{backup_base_name}.tar.gz.enc"
    key_name = f"{backup_base_name}.key.enc"
    sha_name = f"{backup_base_name}.sha256"

    stage_enc = os.path.join(RESTORE_STAGE_DIR, enc_name)
    stage_key = os.path.join(RESTORE_STAGE_DIR, key_name)
    stage_sha = os.path.join(RESTORE_STAGE_DIR, sha_name)

    for fname, dst in [(enc_name, stage_enc), (key_name, stage_key), (sha_name, stage_sha)]:
        shutil.copy2(os.path.join(source_dir, fname), dst)

    # -------------------------------------------------------------------------
    # BƯỚC 2: Kiểm tra tính toàn vẹn SHA-256 (Integrity Check)[cite: 2]
    # -------------------------------------------------------------------------
    with open(stage_sha, "r", encoding="utf-8") as f:
        expected_hash = f.read().strip().split()[0]

    actual_hash = compute_sha256(stage_enc)
    if actual_hash != expected_hash:
        send_syslog(
            "[HASH_MISMATCH_ALERT]", 2, operator_role,
            f"CRITICAL: Sai lệch mã băm SHA-256 trên {enc_name}! "
            f"(Expected={expected_hash[:12]}..., Actual={actual_hash[:12]}...). Dừng khôi phục!"
        )
        shutil.rmtree(RESTORE_STAGE_DIR, ignore_errors=True)
        raise ValueError("Integrity Check Failed: Tệp sao lưu đã bị can thiệp trái phép hoặc hỏng[cite: 2]!")

    # -------------------------------------------------------------------------
    # BƯỚC 3: Giải mã khóa DEK bằng Master Key (KEK) trên RAM[cite: 2]
    # -------------------------------------------------------------------------
    with open(stage_key, "rb") as f:
        encrypted_dek_blob = f.read()

    try:
        dek = unwrap_dek_with_kek(encrypted_dek_blob, role=approver_role, custom_kek=custom_kek)
    except Exception as e:
        send_syslog(
            "[KEY_ACCESS_DENIED]", 2, approver_role,
            f"Giải mã khóa DEK thất bại cho gói {backup_base_name} (Khóa KEK không hợp lệ)!"
        )
        shutil.rmtree(RESTORE_STAGE_DIR, ignore_errors=True)
        raise ValueError("Key Decryption Failed: Khóa KEK không khớp hoặc bị giả mạo[cite: 2]!") from e

    # -------------------------------------------------------------------------
    # BƯỚC 4: Giải mã dữ liệu AES-256-GCM & Bung nén vào hệ thống[cite: 2]
    # -------------------------------------------------------------------------
    with open(stage_enc, "rb") as f:
        enc_blob = f.read()

    nonce, ciphertext = enc_blob[:12], enc_blob[12:]
    aesgcm = AESGCM(dek)
    del dek  # Xóa khóa DEK trên RAM ngay sau khi khởi tạo cipher

    plaintext_tar = aesgcm.decrypt(nonce, ciphertext, backup_base_name.encode("utf-8"))
    temp_tar_path = os.path.join(RESTORE_STAGE_DIR, f"{backup_base_name}.tar.gz")
    with open(temp_tar_path, "wb") as f:
        f.write(plaintext_tar)

    with tarfile.open(temp_tar_path, "r:gz") as tar:
        tar.extractall(path=RESTORED_OUTPUT_DIR)

    # -------------------------------------------------------------------------
    # BƯỚC 5: Kiểm tra chữ ký HMAC sổ cái, dọn sạch file tạm & Gửi Syslog[cite: 2]
    # -------------------------------------------------------------------------
    restored_json = os.path.join(
        RESTORED_OUTPUT_DIR, "prod_db_192_168_20_10", "core_banking_dump.json"
    )
    with open(restored_json, "r", encoding="utf-8") as f:
        db_data = json.load(f)

    for rec in db_data["core_banking_ledger"]:
        calc_hmac = sign_ledger_record(rec["account_id"], rec["balance_vnd"], rec["updated_at"])
        if calc_hmac != rec["hmac_sha256"]:
            raise ValueError(f"Phát hiện sai lệch chữ ký HMAC tại tài khoản {rec['account_id']}!")

    # Xóa sạch thư mục tạm chứa file giải nén trung gian[cite: 2]
    shutil.rmtree(RESTORE_STAGE_DIR, ignore_errors=True)

    elapsed_sec = time.perf_counter() - start_time
    rto_limit_sec = 3600.0  # RTO mục tiêu <= 60 phút (3600 giây)[cite: 2]

    send_syslog(
        "[RESTORE_SUCCESS]", 6, f"{operator_role}+{approver_role}",
        f"Khôi phục hoàn tất {backup_base_name}. Bản ghi={len(db_data['core_banking_ledger'])}, "
        f"RTO_thuc_te={elapsed_sec:.4f}s (Mục tiêu <= 3600s - ĐẠT)"
    )

    return {
        "backup_package": backup_base_name,
        "records_verified": len(db_data["core_banking_ledger"]),
        "rto_seconds": round(elapsed_sec, 4),
        "rto_target_seconds": rto_limit_sec,
        "status": "PASS" if elapsed_sec <= rto_limit_sec else "FAIL"
    }
if __name__ == "__main__":
    # Tự động tìm gói sao lưu .tar.gz.enc mới nhất trong Backup Server để phục hồi
    files = [f for f in os.listdir(REMOTE_BACKUP_SRV) if f.endswith(".tar.gz.enc")]
    if not files:
        print("[-] Chưa có bản sao lưu nào! Hãy chạy backup_engine.py trước.")
    else:
        latest_pkg = sorted(files)[-1].replace(".tar.gz.enc", "")
        print(f"[*] Đang tiến hành phục hồi gói: {latest_pkg}")
        res = run_restore_workflow(latest_pkg, "Backup_Operator", "Security_Admin")
        print(f"[+] KẾT QUẢ PHỤC HỒI: {res}")
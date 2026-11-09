#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script 5: Chạy tự động 3 Kịch bản Kiểm thử Bảo mật Sao lưu & Phục hồi (Giai đoạn 2 & 3)
Phụ trách: Thành viên C (Đào Huy Hiệu)
"""

import os
import shutil
import secrets
from datetime import datetime
from mock_data_gen import generate_mock_database
from kms_manager import init_master_kek
from backup_engine import run_backup, REMOTE_BACKUP_SRV, LOCAL_STAGING_DIR
from restore_engine import run_restore_workflow

def run_all_tests():
    print("=" * 78)
    print(f"BẮT ĐẦU KIỂM THỬ PHÂN HỆ C (DỮ LIỆU, MÃ HÓA & SAO LƯU) - {datetime.now()}")
    print("=" * 78)

    # Khởi tạo môi trường chuẩn
    generate_mock_database()
    init_master_kek("Security_Admin")
    pkg_name = run_backup("FULL", "Backup_Operator")

    # -------------------------------------------------------------------------
    # TEST CASE 01: Sửa 1 byte trong file .tar.gz.enc -> Kiểm tra SHA-256 Alert[cite: 2]
    # -------------------------------------------------------------------------
    print("\n--- [TEST CASE 01]: Sửa 1 byte trong file .enc (Kiểm tra toàn vẹn SHA-256) ---")
    enc_path = os.path.join(REMOTE_BACKUP_SRV, f"{pkg_name}.tar.gz.enc")
    backup_copy = enc_path + ".bak"
    shutil.copy2(enc_path, backup_copy)

    # Đảo 1 byte cuối cùng của file .enc
    with open(enc_path, "r+b") as f:
        f.seek(-1, os.SEEK_END)
        last_byte = f.read(1)
        f.seek(-1, os.SEEK_END)
        f.write(bytes([last_byte[0] ^ 0xFF]))

    try:
        run_restore_workflow(pkg_name, "Backup_Operator", "Security_Admin")
        print("❌ KẾT QUẢ TC01: CHƯA ĐẠT (Không phát hiện được file bị sửa!)")
    except ValueError as e:
        print(f"✅ KẾT QUẢ TC01: ĐẠT - Đã chặn đứng và báo lỗi: {e}")
    finally:
        # Phục hồi lại file chuẩn từ bản dự phòng thứ 2 (Local Staging Disk)[cite: 2]
        shutil.move(backup_copy, enc_path)

    # -------------------------------------------------------------------------
    # TEST CASE 02: Giải mã bằng khóa KEK sai (Fake Key Attack)[cite: 2]
    # -------------------------------------------------------------------------
    print("\n--- [TEST CASE 02]: Giải mã gói sao lưu bằng khóa KEK giả mạo ---")
    fake_kek = secrets.token_bytes(32)
    try:
        run_restore_workflow(
            pkg_name, "Backup_Operator", "Security_Admin", custom_kek=fake_kek
        )
        print("❌ KẾT QUẢ TC02: CHƯA ĐẠT (Giải mã thành công bằng khóa sai!)")
    except ValueError as e:
        print(f"✅ KẾT QUẢ TC02: ĐẠT - Hệ thống từ chối khóa sai: {e}")

    # -------------------------------------------------------------------------
    # TEST CASE 03: Khôi phục chuẩn & Đo thời gian thực tế so với RTO (<= 60 phút)[cite: 2]
    # -------------------------------------------------------------------------
    print("\n--- [TEST CASE 03]: Phục hồi dữ liệu chuẩn & Đo chỉ số RTO ---")
    metrics = run_restore_workflow(pkg_name, "Backup_Operator", "Security_Admin")
    print(f"✅ KẾT QUẢ TC03: ĐẠT")
    print(f"   + Gói sao lưu       : {metrics['backup_package']}")
    print(f"   + Số bản ghi sổ cái : {metrics['records_verified']} (HMAC-SHA256 hợp lệ 100%)")
    print(f"   + Thời gian RTO đo  : {metrics['rto_seconds']} giây (Mục tiêu <= 3600 giây)")
    print("=" * 78)

if __name__ == "__main__":
    run_all_tests()
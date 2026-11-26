# BTL CNNT – Nhóm 13 – Đề tài 16: Thiết kế hạ tầng CNTT an toàn cho ngân hàng số

Học phần: Nhập môn Công nghệ Nền tảng (RIPT1304-20261-01) · Phiên bản README: 1.0 (17/11/2026) · Mô hình: `BTL_V5.pkt`

Dự án mô phỏng hạ tầng của một ngân hàng số giả định trên Cisco Packet Tracer: mạng ba vùng có phân quyền truy cập bằng ACL, hệ thống giám sát tập trung (Syslog, NTP, quy tắc cảnh báo), cùng các script Python cho mã hóa, sao lưu và phân tích log. Toàn bộ địa chỉ IP, tài khoản, số thẻ và khóa trong dự án là **dữ liệu giả**.

**Phạm vi chứng minh:** Packet Tracer chứng minh cấu hình và kết nối của mô hình. Dự án không đưa ra kết luận về thông lượng, độ phủ Wi-Fi hay khả năng chịu tải của hệ thống thật. Các số đo thời gian (ví dụ RTO) là kết quả của script trên dữ liệu giả.

---

## 1. Thành viên và sản phẩm kỹ thuật

| Thành viên | Họ tên | Mảng | Sản phẩm kỹ thuật |
| --- | --- | --- | --- |
| A | Lữ Trọng Đại – B24DCCC045 | Kiến trúc và mạng | `BTL_V5.pkt`: VLAN, trunk, router-on-a-stick, ACL, bảng IP, sơ đồ hệ thống |
| B | [B bổ sung] | Xác thực và phân quyền (IAM, RBAC, phiên) | Thiết kế IAM, ma trận RBAC, chính sách xác thực và quản lý phiên |
| C | Đào Huy Hiệu - B24DCCC123 | Mã hóa, quản lý khóa, sao lưu, phục hồi | `backup_engine.py`, `restore_engine.py`, `kms_manager.py`, `mock_data_gen.py`, `test_scenarios.py` |
| D | Nguyễn Viết Vinh – B24DCCC290 | Giám sát, cảnh báo, kiểm thử | Cấu hình Syslog/NTP, bộ quy tắc cảnh báo A01–A13, `giam_sat_canh_bao.py`, `sample_syslog.log`, `Test_Cases_Monitoring.xlsx` |

---

## 2. Cấu trúc thư mục nộp

```
BTL_CNNT_Group_13/
├── README.md
├── 01_packet_tracer/
│   ├── BTL_V5.pkt
│   ├── so_do_he_thong.png
│   └── cau_hinh/              switch.txt, router.txt, acl.txt, syslog_ntp.txt
├── 02_iam_rbac/               (B) tài liệu và file mô phỏng
├── 03_ma_hoa_sao_luu/         (C) backup_engine.py, restore_engine.py, kms_manager.py,
│                              mock_data_gen.py, test_scenarios.py, bank_env/
├── 04_giam_sat/               (D) giam_sat_canh_bao.py, sample_syslog.log
├── 05_kiem_thu/               Test_Cases_Monitoring.xlsx, Evidence/
├── 06_bao_cao/                bao_cao.pdf, phu_luc_cau_hinh/
├── 07_video/                  video_demo.mp4 (5–7 phút)
└── 08_phieu_dong_gop/         phiếu cá nhân, khai báo nguồn và dùng AI
```

---

## 3. Phiên bản và yêu cầu

| Thành phần | Phiên bản |
| --- | --- |
| Cisco Packet Tracer | 9.0.1.0858 |
| Hệ điều hành | Windows |
| Python cho script của C | Python 3.13; chỉ dùng thư viện chuẩn (tùy chọn `pip install cryptography`) |
| Python cho script của D | Python 3.8 trở lên; chỉ dùng thư viện chuẩn, không cần cài thêm |
| Mô hình | `BTL_V5.pkt` |

---

## 4. Kiến trúc hệ thống

Ba vùng mạng, một router làm cổng trung tâm (router-on-a-stick) và một switch phân VLAN:

| Vùng | VLAN | Mạng | Gateway | Thiết bị |
| --- | --- | --- | --- | --- |
| Internet | – | 100.100.100.0/24 | 100.100.100.1 (Router_Core G0/1) | PC_KhachHang |
| DMZ | 10 | 192.168.10.0/24 | 192.168.10.1 (G0/0.10) | Web_Server |
| Internal | 20 | 192.168.20.0/24 | 192.168.20.1 (G0/0.20) | PC_Admin, Database_Server, NTP-SRV, SYSLOG-SRV, Backup_Server |

### Bảng tài nguyên và IP

| Thiết bị | Vùng | Cổng | IP | Gateway |
| --- | --- | --- | --- | --- |
| Router_Core (2911) | Internet | G0/1 tới PC_KhachHang | 100.100.100.1/24 | |
| | DMZ | G0/0.10 (dot1Q 10) | 192.168.10.1/24 | |
| | Internal | G0/0.20 (dot1Q 20) | 192.168.20.1/24 | |
| Switch_Central (2960) | – | Gig0/1 trunk tới Router_Core G0/0 | | |
| PC_KhachHang | Internet | Fa0 | 100.100.100.2/24 | 100.100.100.1 |
| Web_Server | DMZ (10) | Switch_Central Fa0/2 | 192.168.10.10/24 | 192.168.10.1 |
| Database_Server | Internal (20) | Switch_Central Fa0/3 | 192.168.20.10/24 | 192.168.20.1 |
| PC_Admin | Internal (20) | Switch_Central Fa0/4 | 192.168.20.20/24 | 192.168.20.1 |
| SYSLOG-SRV | Internal (20) | Switch_Central Fa0/5 | 192.168.20.40/24 | 192.168.20.1 |
| NTP-SRV | Internal (20) | Switch_Central Fa0/6 | 192.168.20.30/24 | 192.168.20.1 |
| Backup_Server | Internal (20) | Switch_Central Fa0/7 | 192.168.20.50/24 | 192.168.20.1 |

**Backup_Server (192.168.20.50)** nhận bản sao lưu từ Database_Server và lưu các bản backup phục vụ chức năng Backup/Restore của C. Thiết bị nằm trong VLAN 20, không truy cập trực tiếp từ Internet.

### Chính sách truy cập (ACL 100 trên Router_Core G0/1, chiều vào)

| Thứ tự | Luật | Ý nghĩa |
| --- | --- | --- |
| 10 | `permit tcp any host 192.168.10.10 eq 80` | Khách vào web (HTTP) |
| 20 | `permit tcp any host 192.168.10.10 eq 443` | Khách vào web (HTTPS) |
| 30 | `permit icmp any host 192.168.10.10 echo` | Khách ping Web_Server |
| 40 | `deny ip any any` | Chặn mọi lưu lượng còn lại từ Internet, gồm cả đường vào VLAN 20 |

Chính sách tập trung kiểm soát lưu lượng từ Internet vào hệ thống. Phân quyền chi tiết giữa DMZ và Internal nằm ngoài phạm vi bài tập này.

### Phân quyền (tóm tắt từ chương của B)

| Vai trò | Xem số dư | Chuyển khoản | Duyệt giao dịch lớn | Cấu hình hệ thống | Xem nhật ký |
| --- | --- | --- | --- | --- | --- |
| CUSTOMER | có | có | không | không | không |
| OFFICER | có | có | có | không | có |
| SYSADMIN | không | không | không | có | có |

Jump Server, Active Directory, FIDO2 và eKYC là các thành phần thiết kế trong báo cáo; mô hình Packet Tracer không dựng các thành phần này.

---

## 5. Dựng lại mô hình

### Cách nhanh

1. Cài Cisco Packet Tracer (phiên bản ở mục 3).
2. Mở `01_packet_tracer/BTL_V5.pkt`.
3. Đợi các cổng chuyển sang màu xanh, rồi chạy các bước kiểm tra ở mục 6.

### Dựng từ đầu

Thiết bị: 1 Router 2911 (`Router_Core`), 1 Switch 2960 (`Switch_Central`), 2 PC (`PC_KhachHang`, `PC_Admin`), 5 Server-PT (`Web_Server`, `Database_Server`, `SYSLOG-SRV`, `NTP-SRV`, `Backup_Server`). Nối cáp theo bảng IP ở mục 4, đặt IP tĩnh và gateway cho từng máy.

**Switch_Central (VLAN và trunk):**

```text
enable
configure terminal
vlan 10
 name DMZ
vlan 20
 name INTERNAL
interface fa0/2
 switchport mode access
 switchport access vlan 10
interface range fa0/3 - 7
 switchport mode access
 switchport access vlan 20
interface gi0/1
 switchport mode trunk
```

**Router_Core (router-on-a-stick):**

```text
enable
configure terminal
interface g0/0
 no shutdown
interface g0/0.10
 encapsulation dot1Q 10
 ip address 192.168.10.1 255.255.255.0
interface g0/0.20
 encapsulation dot1Q 20
 ip address 192.168.20.1 255.255.255.0
interface g0/1
 ip address 100.100.100.1 255.255.255.0
 no shutdown
```

**ACL:**

```text
access-list 100 permit tcp any host 192.168.10.10 eq 80
access-list 100 permit tcp any host 192.168.10.10 eq 443
access-list 100 permit icmp any host 192.168.10.10 echo
access-list 100 deny ip any any
interface g0/1
 ip access-group 100 in
```

Bản Packet Tracer đã dùng không chấp nhận từ khóa `log` trên extended ACL (báo `% Invalid input`, xem ca D04), vì vậy ACL được cấu hình không có `log`. Hiệu lực chặn vẫn được xác nhận qua kết quả ping và bộ đếm `matches` của `show access-lists`.

**Giám sát: Syslog và NTP:**

Trên SYSLOG-SRV (Services > SYSLOG) và NTP-SRV (Services > NTP), chọn On. Sau đó cấu hình thiết bị:

```text
! Router_Core
service timestamps log datetime msec
service timestamps debug datetime msec
ntp server 192.168.20.30
logging on
logging host 192.168.20.40
logging trap informational
username admin secret Matkhau@123        ! tài khoản giả cho mô phỏng
line vty 0 4
 login local
exit
login block-for 60 attempts 3 within 30
login on-failure log
login on-success log

! Switch_Central: cần IP quản lý trong VLAN 20 để gửi log
interface vlan 20
 ip address 192.168.20.2 255.255.255.0
 no shutdown
exit
ip default-gateway 192.168.20.1
service timestamps log datetime msec
ntp server 192.168.20.30
logging host 192.168.20.40
logging trap informational
```

Khi bật `login block-for`, thiết bị tự tạo ACL `sl_def_acl` để quản lý chế độ khóa đăng nhập; đây là hành vi bình thường.

---

## 6. Kiểm thử

Mỗi ca kiểm thử có mục tiêu, điều kiện, các bước thực hiện, kết quả mong đợi (viết trước khi chạy), kết quả thực tế, trạng thái và bằng chứng có dấu thời gian. Ảnh bằng chứng được lưu trong `05_kiem_thu/Evidence/` theo quy ước `<Mã ca>_YYYYMMDD_HHMM_<Mô tả>.png`.

Thứ tự thực hiện: mạng (A) → xác thực (B) → giám sát (D) → mã hóa và sao lưu (C) → kiểm tra cuối (nhóm).

### Nhóm A – Mạng, phân vùng, ACL

Mở Desktop > Command Prompt trên từng máy:

| Từ máy | Lệnh | Kết quả mong đợi |
| --- | --- | --- |
| PC_Admin | `ping 192.168.20.10` | Thông |
| PC_Admin | `ping 192.168.10.10` | Thông (gói đầu có thể timeout do ARP) |
| PC_KhachHang | `ping 192.168.10.10` | Thông (ACL cho phép) |
| PC_KhachHang | `ping 192.168.20.10` | Bị chặn (Destination host unreachable) |
| PC_KhachHang | `ping 192.168.20.20` | Bị chặn |
| Switch_Central | `show vlan brief`, `show interfaces trunk` | Đúng VLAN theo bảng IP; trunk mang VLAN 10 và 20 |
| Router_Core | `show access-lists`, `show ip interface brief` | Số `matches` của luật deny tăng; các interface up |

Gói đầu tiên khi ping giữa hai VLAN có thể timeout do router cần hỏi ARP; đây là hiện tượng bình thường.

### Nhóm B – Xác thực và phân quyền

[B bổ sung: cách chạy kiểm thử đăng nhập, khóa tài khoản, phân quyền và MFA mô phỏng.]

### Nhóm D – Giám sát và cảnh báo

File ca: `05_kiem_thu/Test_Cases_Monitoring.xlsx` (sheet `Test_Cases`, `Test_Execution`, `Evidence_Log`).

| Mã | Nội dung kiểm thử | Kết quả | Bằng chứng | Thời điểm |
| --- | --- | --- | --- | --- |
| D03 | Đồng bộ giờ NTP: NTP-SRV (192.168.20.30) bật, Router_Core báo `Clock is synchronized` | Đạt | EV001, EV002 | 14/11/2026 17:06–17:12 |
| D01 | Router_Core gửi log về SYSLOG-SRV (192.168.20.40), nhận sự kiện `%SYS-5-CONFIG_I` | Đạt | EV003, EV004 | 14/11/2026 17:24–17:25 |
| D02 | Đăng nhập Telnet sai 3 lần từ PC_Admin sinh `LOGIN_FAILED`, kích hoạt `QUIET_MODE_ON/OFF` | Đạt | EV005, EV006 | 14/11/2026 17:36–17:38 |
| D04 | ACL 100 chặn ping từ PC_KhachHang (100% loss, bộ đếm `matches` tăng); ghi log ACL về Syslog không khả dụng vì Packet Tracer không hỗ trợ `log` trên extended ACL | Chặn đạt; ghi log ACL: Blocked (giới hạn công cụ, DEF-01) | EV007, EV008, EV009 | 14/11/2026 18:07–18:11 |
| D05 | Tắt dịch vụ SYSLOG: server ngừng nhận log và không nhận bù sau khi bật lại, đúng đặc tính UDP | Đạt | EV010, EV011 | 14/11/2026 18:12–18:14 |
| D06 | Script phân tích 31 dòng `sample_syslog.log`, xuất 14 cảnh báo ra CSV | Đạt | EV012, EV013 | 16/11/2026 22:04–22:05 |

Chạy script phân tích:

```text
cd 04_giam_sat
python giam_sat_canh_bao.py sample_syslog.log
python giam_sat_canh_bao.py sample_syslog.log --csv bao_cao_canh_bao.csv
```

Kết quả đúng với `sample_syslog.log` là **14 cảnh báo** (10 mức Cao, 3 Trung bình, 1 Thấp): A01 ×1, A02 ×1, A03 ×2, A04 ×1, A05 ×2, A06 ×3, A07 ×2, A08 ×1, A09 ×1.

Khi chạy trên log trích từ SYSLOG-SRV, tên thiết bị trong `EXPECTED_DEVICES`, `ALIASES` và `CRITICAL_PORTS` ở đầu script phải khớp với tên trong `BTL_V5.pkt` (`Router_Core`, `Switch_Central`).

### Nhóm C – Mã hóa, sao lưu, phục hồi

```text
cd 03_ma_hoa_sao_luu
python test_scenarios.py
```

Script chạy 4 kịch bản: TC-C00 (sao lưu 3-2-1 có mã hóa phong bì), TC-C01 (phát hiện sửa 1 byte trong file `.enc`), TC-C02 (giải mã bằng khóa KEK sai), TC-C03 (phục hồi 5 bước và đo RTO), đồng thời ghi log gửi sang `syslog_mirror_192_168_20_40.log`. Kết quả mong đợi: cả 4 kịch bản báo ĐẠT và RTO nhỏ hơn 2 giây.

### Kiểm tra cuối (cả nhóm)

Trên một máy khác và thư mục sạch: mở `BTL_V5.pkt`, làm theo README, chạy lại các ca chính; đối chiếu bảng IP trong báo cáo với từng thiết bị; đối chiếu mỗi mã ca với file bằng chứng; xem video và kiểm tra độ dài (5–7 phút).

---

## 7. Kết quả kiểm thử hiện có (tính đến 17/11/2026)

| Nhóm | Tình trạng |
| --- | --- |
| A (mạng) | Đã kiểm thử định tuyến liên VLAN, trunk, router-on-a-stick, ACL và kết nối Backup_Server; theo báo cáo của A, các ca đều đạt và bằng chứng đã lưu trong thư mục `Evidence` |
| B (xác thực) | [B bổ sung] |
| C (sao lưu) | Bốn kịch bản TC-C00 đến TC-C03 đã chạy; dữ liệu đo RTO gốc nộp kèm |
| D (giám sát) | Sáu ca D01–D06: năm ca đạt; D04 xác nhận ACL chặn thành công, phần ghi log ACL bị giới hạn bởi Packet Tracer. Script đã chạy đúng trên log mẫu (14 cảnh báo) và trên log trích từ SYSLOG-SRV theo báo cáo của D. Mười ba ảnh bằng chứng có dấu thời gian |

---

## 8. Phạm vi và giả định

- Packet Tracer chứng minh cấu hình và kết nối; không dùng để nêu hiệu năng hay khả năng chịu tải thực tế.
- **Cảnh báo:** hệ thống thu log tập trung bằng Syslog và dùng script phát hiện sự kiện bất thường trên file log đã xuất. Đây là phân tích theo lô, không phải cảnh báo thời gian thực. Việc chuyển log từ bảng của SYSLOG-SRV sang file là bước thủ công.
- **Ghi log ACL:** bản Packet Tracer đã dùng không hỗ trợ `log` trên extended ACL, nên các quy tắc A03, A04, A05 được kiểm chứng trên log mẫu; chặn lưu lượng vẫn được xác nhận qua ping và bộ đếm `matches`.
- **Quy tắc A10–A13** (sao lưu, khóa, phục hồi, sự kiện máy chủ) là phần thiết kế, do Packet Tracer không sinh log ứng dụng.
- Các ngưỡng cảnh báo (3 lần/30 giây, 5 gói/60 giây, 15 phút, giờ làm 08:00–18:00) là giả định thiết kế, chưa hiệu chỉnh bằng dữ liệu vận hành.
- Jump Server, Active Directory, FIDO2, eKYC, TLS/mTLS, HSM/KMS là thiết kế trong báo cáo, không dựng trong mô hình.
- Syslog dùng UDP, không xác thực và không bảo đảm toàn vẹn; NTP chưa bật xác thực. Đây là đặc điểm của thiết kế hiện tại.
- Kết quả đo RPO/RTO là của script trên dữ liệu giả.

---

## 9. Nguồn tham khảo và khai báo dùng AI

**Nguồn tham khảo:**

- NIST SP 800-92, Guide to Computer Security Log Management.
- NIST SP 800-57, Recommendation for Key Management.
- PCI DSS (yêu cầu về quản lý khóa, ghi log và theo dõi truy cập).
- ISO/IEC 27001, Phụ lục A (ghi log và giám sát).
- Tài liệu Cisco IOS / Packet Tracer cho các lệnh `logging`, `ntp`, `login block-for`, ACL.

**Khai báo sử dụng AI:**

| Thành viên | Công cụ AI | Phần được hỗ trợ | Cách kiểm tra và chỉnh |
| --- | --- | --- | --- |
| A | Microsoft Copilot | Giải thích kiến trúc mạng, VLAN, trunk, router-on-a-stick, ACL; rà soát bảng IP, README; đề xuất cấu hình | Trực tiếp cấu hình trên Packet Tracer, kiểm tra bằng `show vlan brief`, `show interfaces trunk`, `show ip interface brief`, `show access-lists` và ping giữa các thiết bị; chỉnh IP, cổng và tên thiết bị cho khớp mô hình |
| B | [B bổ sung] | [B bổ sung] | [B bổ sung] |
| C | Gemini (Google) | Chuẩn hóa bảng báo cáo, gợi ý khung script mô phỏng mã hóa/sao lưu | Chỉnh IP/VLAN 20 theo `BTL_V5.pkt`, tự chạy 4 kịch bản TC-C00 đến TC-C03 và kiểm tra dữ liệu đo RTO |
| D | Claude (Anthropic) | Bản đầu của `giam_sat_canh_bao.py`, bảng quy tắc cảnh báo, khung kế hoạch kiểm thử, README | Đọc và chạy lại script trên máy cá nhân, tự thực hiện các ca D01–D06 trên Packet Tracer và lưu bằng chứng |

Mỗi thành viên giải thích được và chạy lại được phần mình nộp.

---

## 10. Danh mục nộp

- [x] Mô hình `BTL_V5.pkt` và sơ đồ hệ thống
- [x] Bảng tài nguyên, IP, quyền
- [x] Script và mã nguồn của A, C, D
- [x] Bảng kiểm thử nhóm D kèm bằng chứng có dấu thời gian
- [ ] Phần xác thực, phân quyền và kiểm thử của B
- [ ] Báo cáo 12–18 trang nội dung chính
- [x] Dữ liệu đo gốc RPO/RTO của C
- [ ] Video demo 5–7 phút
- [ ] Phiếu đóng góp cá nhân
- [ ] Khai báo nguồn tham khảo và việc dùng AI (đủ bốn thành viên)

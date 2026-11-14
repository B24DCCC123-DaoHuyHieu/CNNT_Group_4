# BTL CNNT – Nhóm 4 – Đề tài 16: Thiết kế hạ tầng CNTT an toàn cho ngân hàng số

Phiên bản README: 0.1 (bản chính, 14/11/2026). File mô hình: `BTL_V4.pkt`.

Dự án mô phỏng hạ tầng của một ngân hàng số giả định bằng Cisco Packet Tracer, kết hợp các script Python chạy trên **dữ liệu giả** cho phần mã hóa, sao lưu và giám sát. Mọi địa chỉ IP, tài khoản, số thẻ, khóa trong dự án đều là dữ liệu giả phục vụ bài tập.

> Giới hạn quan trọng: Packet Tracer chỉ chứng minh cấu hình và kết nối trong mô hình. Dự án **không** khẳng định thông lượng, độ phủ Wi-Fi hay khả năng chịu tải của hệ thống thật. Các số đo thời gian (ví dụ RTO) chỉ là kết quả của script trên dữ liệu giả.

Các chỗ ghi `[điền ...]` là thông tin README này chưa biết; thành viên phụ trách điền trước khi nộp.

---

## 1. Thành viên và sản phẩm kỹ thuật riêng

| Thành viên | Họ tên | Mảng | Sản phẩm kỹ thuật riêng |
| --- | --- | --- | --- |
| A | [điền] | Kiến trúc và mạng | `BTL_V4.pkt`: VLAN, trunk, router-on-a-stick, ACL, bảng IP, sơ đồ hệ thống |
| B | [điền] | Xác thực và phân quyền (IAM, RBAC, phiên) | Thiết kế IAM, ma trận RBAC, chính sách xác thực và quản lý phiên; [điền file/script mô phỏng MFA nếu có] |
| C | Đào Huy Hiếu | Mã hóa, quản lý khóa, sao lưu, phục hồi | `backup_engine.py`, `restore_engine.py`, `kms_manager.py`, `mock_data_gen.py`, `test_scenarios.py` (nhánh `Dao_Huy_Hieu/Member_C_Hieu` trên GitHub) |
| D | Nguyễn Viết Vinh - B24DCCC290 | Giám sát, cảnh báo, kiểm thử | Cấu hình Syslog/NTP, bảng quy tắc cảnh báo A01–A13, `giam_sat_canh_bao.py`, `sample_syslog.log`, `ke_hoach_kiem_thu.xlsx` |

---

## 2. Cấu trúc thư mục nộp (đề xuất, chỉnh theo thư mục thật)

```
BTL_CNNT_Group_4/
├── README.md
├── 01_packet_tracer/
│   ├── BTL_V1.pkt
│   ├── so_do_he_thong.png
│   └── cau_hinh/              switch.txt, router.txt, acl.txt, syslog_ntp.txt
├── 02_iam_rbac/               (B) tài liệu và file mô phỏng
├── 03_ma_hoa_sao_luu/         (C) backup_engine.py, restore_engine.py, kms_manager.py,
│                              mock_data_gen.py, test_scenarios.py, du_lieu_do_goc/
├── 04_giam_sat/               (D) giam_sat_canh_bao.py, sample_syslog.log
├── 05_kiem_thu/               ke_hoach_kiem_thu.xlsx, bang_chung/
├── 06_bao_cao/                bao_cao.pdf, phu_luc_cau_hinh/
├── 07_video/                  video_demo.mp4 (5–7 phút)
└── 08_phieu_dong_gop/         4 phiếu cá nhân, khai báo nguồn và dùng AI
```

---

## 3. Phiên bản và yêu cầu

| Thành phần | Phiên bản |
| --- | --- |
| Cisco Packet Tracer | [điền, xem Help > About Packet Tracer] |
| Hệ điều hành đã dùng | Windows (theo ảnh chụp màn hình) |
| Python cho script của C | [C điền phiên bản Python đã dùng]; thư viện cần cài: [C điền, xem repo] |
| Python cho script của D | Python 3.8 trở lên; chỉ dùng thư viện chuẩn, không cần cài thêm |
| Mô hình | `BTL_V4.pkt` |

---

## 4. Kiến trúc hệ thống

Ba vùng mạng, một router làm cổng trung tâm (router-on-a-stick) và một switch phân VLAN:

| Vùng | VLAN | Mạng | Gateway | Thiết bị |
| --- | --- | --- | --- | --- |
| Internet | – | 100.100.100.0/24 | 100.100.100.1 (Router_Core G0/1) | PC_KhachHang |
| DMZ | 10 | 192.168.10.0/24 | 192.168.10.1 (G0/0.10) | Web_App_Server |
| Internal | 20 | 192.168.20.0/24 | 192.168.20.1 (G0/0.20) | PC_IT_Admin, Database_Server, NTP-SRV, SYSLOG-SRV |

### Bảng tài nguyên và IP

| Thiết bị | Vùng | Cổng | IP | Gateway |
| --- | --- | --- | --- | --- |
| Router_Core (2911) | – | G0/1 tới PC_KhachHang | 100.100.100.1/24 | |
| | DMZ | G0/0.10 (dot1Q 10) | 192.168.10.1/24 | |
| | Internal | G0/0.20 (dot1Q 20) | 192.168.20.1/24 | |
| Switch (2960) | – | Gig0/1 trunk tới Router_Core G0/0 | | |
| PC_KhachHang | Internet | Fa0 | 100.100.100.2/24 | 100.100.100.1 |
| Web_App_Server | DMZ (10) | Switch Fa0/2 | 192.168.10.10/24 | 192.168.10.1 |
| Database_Server | Internal (20) | Switch Fa0/3 | 192.168.20.10/24 | 192.168.20.1 |
| PC_IT_Admin | Internal (20) | Switch Fa0/4 | 192.168.20.20/24 | 192.168.20.1 |
| SYSLOG-SRV | Internal (20) | Switch Fa0/5 | 192.168.20.40/24 | 192.168.20.1 |
| NTP-SRV | Internal (20) | Switch Fa0/6 | 192.168.20.30/24 | 192.168.20.1 |

### Chính sách truy cập (ACL 100 trên Router_Core G0/1, chiều vào)

| Thứ tự | Luật | Ý nghĩa |
| --- | --- | --- |
| 10 | `permit tcp any host 192.168.10.10 eq 80` | Khách vào web (HTTP) |
| 20 | `permit tcp any host 192.168.10.10 eq 443` | Khách vào web (HTTPS) |
| 30 | `permit icmp any host 192.168.10.10 echo` | Khách ping Web_App_Server (phục vụ quay video) |
| 40 | `deny ip any any` | Chặn mọi thứ còn lại, gồm cả đường vào VLAN 20 |

### Phân quyền (tóm tắt từ chương của B)

| Vai trò | Xem số dư | Chuyển khoản | Duyệt giao dịch lớn | Cấu hình hệ thống | Xem nhật ký |
| --- | --- | --- | --- | --- | --- |
| CUSTOMER | có | có | không | không | không |
| OFFICER | có | có | có | không | có |
| SYSADMIN | không | không | không | có | có |

Jump Server, Active Directory, FIDO2 và eKYC trong chương của B là **thiết kế**; mô hình Packet Tracer không có các thành phần này.

---

## 5. Dựng lại mô hình

### Cách nhanh

1. Cài Cisco Packet Tracer (bản ghi ở mục 3).
2. Mở `01_packet_tracer/BTL_V1.pkt`.
3. Đợi các cổng chuyển sang xanh, rồi chạy các bước kiểm tra ở mục 6.

### Dựng từ đầu

Thiết bị: 1 Router 2911 (đặt tên `Router_Core`), 1 Switch 2960, 1 PC (`PC_KhachHang`), 1 PC (`PC_IT_Admin`), 4 Server-PT (`Web_App_Server`, `Database_Server`, `SYSLOG-SRV`, `NTP-SRV`). Nối cáp theo bảng IP ở mục 4, đặt IP tĩnh và gateway cho từng máy.

**Switch (VLAN và trunk):**

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
interface range fa0/3 - 6
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
access-list 100 deny ip any any log
interface g0/1
 ip access-group 100 in
```

Dòng cuối của ACL có từ khóa `log` (khác bản trước) để Router sinh log mỗi khi chặn gói; phần giám sát cần log này.

**Giám sát: Syslog và NTP (phần của D):**

Trên SYSLOG-SRV (Services > SYSLOG) và NTP-SRV (Services > NTP), chọn On. Rồi cấu hình thiết bị:

```text
! Router_Core
service timestamps log datetime msec
service timestamps debug datetime msec
ntp server 192.168.20.30
logging on
logging host 192.168.20.40
logging trap informational
username admin secret Matkhau@123
line vty 0 4
 login local
exit
login block-for 60 attempts 3 within 30
login on-failure log
login on-success log

! Switch: cần IP quản lý trong VLAN 20 mới gửi log được (đổi IP nếu đã có thiết bị dùng)
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

Nếu `show running-config` còn các dòng cũ `logging host 10.10.99.10`, `ntp server 10.10.99.20`, interface `Gi0/0.99` hay VLAN 99 từ thời thử nghiệm đầu, hãy xóa (`no logging host 10.10.99.10`, `no ntp server 10.10.99.20`, `no interface g0/0.99`) để log không gửi đi địa chỉ cũ.

Một số lệnh có thể khác trên bản Packet Tracer của bạn. Lệnh nào báo lỗi thì ghi lại vào mục 8.

---

## 6. Chạy kiểm thử

Toàn bộ 42 ca nằm trong `05_kiem_thu/ke_hoach_kiem_thu.xlsx` (sheet "Ca kiểm thử": cột Mã, Mục tiêu, Đầu vào, Thao tác, Mong đợi, Thực tế, Đạt?, Bằng chứng). Sheet "Tổng hợp" tự đếm kết quả.

| Nhóm | Phần kiểm thử | Phụ trách | Số ca |
| --- | --- | --- | --- |
| N | Mạng, phân vùng, ACL | A | 11 |
| X | Xác thực, phân quyền | B | 8 |
| C | Mã hóa, sao lưu, phục hồi, RPO/RTO | C | 9 |
| D | Log, NTP, cảnh báo | D | 9 |
| I | Chạy lại, dựng lại từ README, bằng chứng, video | cả nhóm | 5 |

Thứ tự chạy: **N, X, D, C, I**. Nhóm N phải đạt trước vì các nhóm khác dựa vào kết nối.

### Quy tắc bằng chứng

- Chụp cả màn hình để thấy đồng hồ Windows, hoặc dùng log có cột giờ.
- Tên file: `<Mã ca>_YYYYMMDD_HHMM.png`, ví dụ `N06_20261116_0930.png`; lưu vào `05_kiem_thu/bang_chung/`.
- Chụp ngay khi chạy, không làm bù. Ca chưa đạt: ghi nguyên nhân, sửa, chạy lại và giữ cả hai bằng chứng.

### Nhóm N, kiểm tra mạng (trong Packet Tracer)

Mở Desktop > Command Prompt trên từng máy:

| Từ máy | Lệnh | Kết quả mong đợi |
| --- | --- | --- |
| PC_IT_Admin | `ping 192.168.20.10` | Thông |
| PC_IT_Admin | `ping 192.168.10.10` | Thông (gói đầu có thể timeout do ARP) |
| PC_KhachHang | `ping 192.168.10.10` | Thông (ACL cho phép) |
| PC_KhachHang | `ping 192.168.20.10` | Destination host unreachable (bị ACL chặn) |
| PC_KhachHang | `ping 192.168.20.20` | Destination host unreachable |
| Switch | `show vlan brief`, `show interfaces trunk` | Đúng VLAN theo bảng IP; trunk mang VLAN 10 và 20 |
| Router_Core | `show access-lists`, `show ip interface brief` | Số `matches` của luật deny tăng; các interface up |

Gói đầu tiên khi ping giữa hai VLAN có thể bị timeout vì router cần hỏi ARP; đó là hiện tượng bình thường (xem giải thích "25% loss" trong báo cáo).

### Nhóm D, giám sát và cảnh báo

1. Tạo sự kiện thử (đăng nhập sai 3 lần vào Router_Core, `ping` bị ACL chặn từ PC_KhachHang, đổi cấu hình, tắt một cổng Switch rồi bật lại).
2. Mở SYSLOG-SRV > Services > SYSLOG, chụp bảng log (có cột giờ).
3. Chép các dòng log vào file `log_that.txt` theo định dạng `YYYY-MM-DD HH:MM:SS <tên thiết bị hoặc IP> <nội dung>`.
4. Chạy script phân tích:

```text
cd 04_giam_sat
python giam_sat_canh_bao.py sample_syslog.log
python giam_sat_canh_bao.py log_that.txt --csv bao_cao_canh_bao.csv
```

Với `sample_syslog.log` kết quả đúng là **14 cảnh báo** (10 mức Cao, 3 Trung bình, 1 Thấp): A01 ×1, A02 ×1, A03 ×2, A04 ×1, A05 ×2, A06 ×3, A07 ×2, A08 ×1, A09 ×1. Nếu log thật có định dạng khác file mẫu, chỉnh các biểu thức chính quy ở đầu script, và chỉnh `EXPECTED_DEVICES`, `ALIASES`, `CRITICAL_PORTS` cho khớp tên thiết bị và cổng thật.

### Nhóm C, mã hóa, sao lưu, phục hồi

```text
cd 03_ma_hoa_sao_luu
python test_scenarios.py
```

Script chạy 4 kịch bản (TC-C00 sao lưu 3-2-1 có mã hóa phong bì; TC-C01 phát hiện sửa 1 byte trong file `.enc`; TC-C02 giải mã bằng khóa KEK sai; TC-C03 phục hồi 5 bước và đo RTO) và ghi log gửi sang `syslog_mirror_192_168_20_40.log`. [C điền: cách cài thư viện và kết quả mong đợi chi tiết.]

### Nhóm X, xác thực và phân quyền

[B điền: cách chạy kiểm thử phần đăng nhập, khóa tài khoản, phân quyền và MFA mô phỏng.]

### Nhóm I, kiểm tra cuối

Trên một máy khác và thư mục sạch: mở `BTL_V1.pkt`, làm theo README, chạy lại các ca chính; đối chiếu bảng IP trong báo cáo với từng thiết bị; đối chiếu mỗi mã ca với file bằng chứng; xem video và đo độ dài (5–7 phút).

---

## 7. Kết quả hiện có (tính đến 14/11/2026)

| Nhóm | Tình trạng |
| --- | --- |
| N | Đã có ảnh chụp ping và `show access-lists` trong báo cáo nháp: khách vào được Web_App_Server, bị chặn khỏi Database_Server và PC_IT_Admin. Chưa ghi vào bảng kiểm thử chung |
| X | [B điền] |
| C | Báo cáo nháp ghi TC-C00 đến TC-C03 đạt; RTO đo được 1,5328 giây so với mục tiêu 3.600 giây. Dữ liệu đo gốc cần nộp kèm (xem mục 8, điểm 6) |
| D | Script đã chạy đúng trên log mẫu; chưa chạy trên log thật từ SYSLOG-SRV |
| I | Chưa chạy |

---

## 8. Vấn đề đã biết cần nhóm thống nhất trước khi nộp

1. **Địa chỉ Syslog/NTP:** bản thử nghiệm đầu dùng 10.10.99.10 và 10.10.99.20 (VLAN 99), mô hình cuối dùng 192.168.20.40 và 192.168.20.30 (VLAN 20). Kiểm tra `show running-config` của Router_Core và Switch xem còn cấu hình cũ không.
2. **ACL 100 chưa có `log`:** nếu không thêm `log` ở dòng deny (mục 5), Router không sinh log ACL và các ca D04, A03 không có dữ liệu.
3. **DMZ sang VLAN 20 chưa bị lọc:** ACL chỉ đặt ở G0/1 chiều vào, nên Web_App_Server vẫn ping được cả Database_Server lẫn PC_IT_Admin. A cần quyết định: thêm ACL ở `g0/0.10` (chỉ cho Web_App_Server tới Database_Server theo cổng cần thiết) hoặc ghi rõ đây là phạm vi chưa làm. Quyết định này ảnh hưởng ca N08, D07 và quy tắc A04.
4. **Backup_Server 192.168.20.50:** báo cáo của C ghi VLAN 20 ở chỗ này và VLAN 30 ở chỗ khác, và thiết bị này **không có** trong `BTL_V1.pkt` (chỉ là thư mục mô phỏng trong script). Cần thống nhất và ghi vào phần giả định.
5. **Bảng IP và cổng:** bảng của A ghi Switch cắm F0/1 và PC_KhachHang vào G0/0; sơ đồ và cấu hình thực tế là Switch Gig0/1 ↔ Router G0/0 (trunk), PC_KhachHang ↔ Router G0/1. README này dùng theo cấu hình thực tế.
6. **Bằng chứng của C không khớp nhau:** Hình 1 ghi thời điểm 19:49:10 và văn bản ghi RTO 1,5328 giây, nhưng ảnh console trong hình hiển thị 2026-11-12 20:28:48 và RTO 0,0141 giây. Cần chạy lại một lần, rồi dùng cùng một lần chạy cho ảnh, log và bảng kết quả, và nộp kèm dữ liệu đo gốc.
7. **Tên thiết bị chưa thống nhất:** Switch1 và Switch_Central, Web_Server và Web_App_Server, PC_Admin và PC_IT_Admin. Chọn một bộ tên theo `.pkt` và dùng thống nhất ở báo cáo, bảng IP, script.
8. **Log của C chưa đưa vào script của D:** log của C có dạng `<134>2026-11-12 ... Event=[BACKUP_OK] Severity=6` nên script giám sát hiện bỏ qua. Quy tắc cảnh báo sao lưu (A10, A11) mới là thiết kế.
9. **Cổng quan trọng trong script D:** `CRITICAL_PORTS` cần thêm Switch Fa0/3 (Database_Server), Fa0/5 (SYSLOG-SRV), Fa0/6 (NTP-SRV).

---

## 9. Giới hạn của dự án

- Packet Tracer chỉ chứng minh cấu hình và kết nối; không dùng để nói về hiệu năng hay khả năng chịu tải thực tế.
- Packet Tracer không tự gửi thông báo cảnh báo. "Cảnh báo" của dự án gồm Syslog server thu log và script phát hiện sự kiện bất thường trên file log đã xuất, không phải cảnh báo thời gian thực.
- Log của máy chủ (cơ sở dữ liệu, ứng dụng, sao lưu) không có thật trong Packet Tracer; các quy tắc A10 đến A13 là thiết kế.
- Các thành phần như Jump Server, Active Directory, FIDO2, eKYC, TLS/mTLS, HSM/KMS là thiết kế trong báo cáo, không được dựng trong mô hình.
- Kết quả đo RPO/RTO là của script trên dữ liệu giả, không đại diện hệ thống ngân hàng thật.
- Toàn bộ dữ liệu (tài khoản, mật khẩu, số thẻ, CCCD, khóa) là dữ liệu giả.

---

## 10. Nguồn tham khảo và khai báo dùng AI

**Nguồn tham khảo (theo báo cáo nháp, cần mở bản chính thức để xác nhận số hiệu và mục trước khi nộp):**

- NIST SP 800-92, Guide to Computer Security Log Management.
- NIST SP 800-57, Recommendation for Key Management.
- PCI DSS (yêu cầu về quản lý khóa, ghi log và theo dõi truy cập).
- ISO/IEC 27001 (Phụ lục A, mục ghi log và giám sát).

**Khai báo sử dụng AI (mỗi thành viên sửa cho đúng sự thật):**

| Thành viên | Công cụ AI | Phần được hỗ trợ | Cách bạn đã kiểm tra và chỉnh |
| --- | --- | --- | --- |
| A | [điền] | [điền] | [điền] |
| B | [điền] | [điền] | [điền] |
| C | [điền] | [điền] | [điền] |
| D | Claude (Anthropic) | Bản đầu của `giam_sat_canh_bao.py`, bảng quy tắc cảnh báo, kế hoạch kiểm thử, README | [D điền: đã đọc, chỉnh, chạy lại như thế nào] |

Mỗi thành viên phải giải thích được và chạy lại được phần mình nộp.

---

## 11. Danh mục nộp (đối chiếu trước khi nộp)

- [ ] Báo cáo 12–18 trang nội dung chính (phụ lục cấu hình không tính)
- [ ] Sơ đồ hệ thống, bảng tài nguyên, IP, quyền
- [ ] `BTL_V4.pkt` và file cấu hình
- [ ] Script, mã nguồn của từng thành viên
- [ ] README này (đã điền các chỗ `[điền ...]`)
- [ ] Bảng kiểm thử có bằng chứng và dấu thời gian
- [ ] Dữ liệu đo gốc (RPO/RTO của C)
- [ ] Video demo 5–7 phút
- [ ] 4 phiếu đóng góp cá nhân
- [ ] Khai báo nguồn tham khảo và việc dùng AI

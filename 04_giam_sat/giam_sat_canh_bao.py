#!/usr/bin/env python3
"""Phân tích log Syslog (dữ liệu giả) và in cảnh báo theo bảng quy tắc A01–A09.

Chạy:
    python3 giam_sat_canh_bao.py sample_syslog.log
    python3 giam_sat_canh_bao.py sample_syslog.log --csv bao_cao_canh_bao.csv

Mỗi dòng log có dạng:   YYYY-MM-DD HH:MM:SS <tên thiết bị hoặc IP> <nội dung>
Cũng đọc được dạng syslog thường:   Nov 16 17:35:02 <thiết bị> <nội dung>   (thêm --year nếu cần)

Chỉ dùng thư viện chuẩn của Python 3. Toàn bộ dữ liệu là dữ liệu giả phục vụ bài tập.
Định dạng log thật xuất từ Packet Tracer có thể khác: nếu có dòng bị bỏ qua, hãy chỉnh
các biểu thức chính quy ở phần "DẠNG DÒNG LOG" cho khớp rồi chạy lại.
"""
import argparse
import csv
import ipaddress
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, time, timedelta


ADMIN_IPS = {"192.168.20.20"}                      
WEB_HOST = "192.168.10.10"                          
DB_HOST = "192.168.20.10"                           
ALLOWED_TO_DB = {WEB_HOST} | ADMIN_IPS              

NET_INTERNET = ipaddress.ip_network("100.100.100.0/24")   
NET_DMZ = ipaddress.ip_network("192.168.10.0/24")        
NET_INTERNAL = ipaddress.ip_network("192.168.20.0/24")  

FAIL_THRESHOLD = 3                                 
FAIL_WINDOW = timedelta(seconds=30)                
ACL_REPEAT = 5                                     
ACL_WINDOW = timedelta(seconds=60)                 
SILENCE_LIMIT = timedelta(minutes=15)            
BUSINESS_START, BUSINESS_END = time(8, 0), time(18, 0)   


EXPECTED_DEVICES = {"Router_Core", "Switch"}
ALIASES = {
    "192.168.20.1": "Router_Core",
    "192.168.20.2": "Switch",    
}

CRITICAL_PORTS = {
    ("Switch", "GigabitEthernet0/1"): "trunk tới Router_Core",
    ("Switch", "FastEthernet0/2"): "Web_App_Server (DMZ)",
    ("Router_Core", "GigabitEthernet0/0"): "trunk xuống Switch",
    ("Router_Core", "GigabitEthernet0/1"): "đường ra PC_KhachHang",
}

RULES = {
    "A01": ("Đăng nhập quản trị sai nhiều lần", "kiểm tra IP nguồn, khóa tạm thời"),
    "A02": ("Đăng nhập quản trị từ IP lạ", "xác minh người đăng nhập, đổi mật khẩu nếu không nhận ra"),
    "A03": ("Gói từ Internet bị ACL chặn", "xác định nguồn, đối chiếu quy tắc ACL"),
    "A04": ("Gói từ DMZ vào VLAN 20 bị chặn", "coi Web_App_Server nghi bị xâm nhập: cách ly, kiểm tra"),
    "A05": ("Truy cập CSDL từ nguồn không được phép", "chặn nguồn, kiểm tra dữ liệu có bị đọc không"),
    "A06": ("Cấu hình thiết bị bị thay đổi", "đối chiếu với yêu cầu thay đổi đã duyệt"),
    "A07": ("Cổng mạng chuyển sang down", "kiểm tra cáp và thiết bị đầu cuối"),
    "A08": ("Thiết bị mất đồng bộ giờ NTP", "kiểm tra show ntp status và kết nối tới NTP-SRV"),
    "A09": ("Thiết bị ngừng gửi log", "kiểm tra thiết bị và đường tới SYSLOG-SRV; có thể log bị tắt"),
}


LINE_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$")
LINE_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$")

FAILED = re.compile(r"LOGIN_FAILED.*?\[user: (?P<user>[^\]]*)\].*?\[Source: (?P<src>[\d.]+)\]")
SUCCESS = re.compile(r"LOGIN_SUCCESS.*?\[user: (?P<user>[^\]]*)\].*?\[Source: (?P<src>[\d.]+)\]")
ACL = re.compile(
    r"IPACCESSLOGP: list (?P<acl>\S+) (?P<action>denied|permitted) (?P<proto>\w+) "
    r"(?P<src>\d+\.\d+\.\d+\.\d+)(?:\(\d+\))? -> (?P<dst>\d+\.\d+\.\d+\.\d+)"
)
CONFIG = re.compile(r"SYS-5-CONFIG_I: Configured from (?P<where>\S+) by (?P<user>\S+)")
LINK_DOWN = re.compile(r"LINEPROTO-5-UPDOWN: Line protocol on Interface (?P<ifc>\S+), changed state to down")
NTP_LOST = re.compile(r"%NTP-\d-(?P<kind>UNSYNC|PEERUNREACH)")

LEVEL_ORDER = {"CAO": 0, "TRUNG BÌNH": 1, "THẤP": 2}


def parse_line(raw, year):
    """Trả về (thời điểm, thiết bị, nội dung) hoặc None nếu dòng không đúng định dạng."""
    m = LINE_ISO.match(raw)
    try:
        if m:
            return datetime.fromisoformat(m["ts"].replace("T", " ")), m["host"], m["msg"]
        m = LINE_SYSLOG.match(raw)
        if m:
            text = re.sub(r"\s+", " ", m["ts"])      # gộp khoảng trắng, ví dụ "Nov  6" thành "Nov 6"
            ts = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
            return ts, m["host"], m["msg"]
    except ValueError:
        return None
    return None


class Window:
    """Đếm số sự kiện cùng khóa trong một cửa sổ thời gian trượt."""

    def __init__(self, span):
        self.span = span
        self.q = defaultdict(deque)

    def add(self, key, ts):
        q = self.q[key]
        q.append(ts)
        while q and ts - q[0] > self.span:
            q.popleft()
        return len(q)


def analyze(path, year, now_text=None):
    alerts = []

    def emit(ts, level, rule, device, text):
        alerts.append({
            "thoi_diem": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "muc": level,
            "quy_tac": rule,
            "thiet_bi": device,
            "noi_dung": text,
            "hanh_dong": RULES[rule][1],
        })

    entries, skipped = [], []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            parsed = parse_line(raw, year)
            if parsed:
                entries.append(parsed)
            else:
                skipped.append(raw)
    entries.sort(key=lambda e: e[0])         

    fails, acl_win, dedup = Window(FAIL_WINDOW), Window(ACL_WINDOW), Window(ACL_WINDOW)
    last_seen = {}
    ignored = 0

    for ts, host, msg in entries:
        host = ALIASES.get(host, host)

        prev = last_seen.get(host)
        if prev and ts - prev > SILENCE_LIMIT:
            mins = int((ts - prev).total_seconds() // 60)
            emit(ts, "CAO", "A09", host,
                 f"không có log suốt {mins} phút (từ {prev:%H:%M:%S} đến {ts:%H:%M:%S})")
        last_seen[host] = ts

        m = FAILED.search(msg)
        if m:
            n = fails.add((host, m["src"]), ts)
            if n == FAIL_THRESHOLD:             
                emit(ts, "CAO", "A01", host,
                     f"{FAIL_THRESHOLD} lần đăng nhập sai từ {m['src']} trong "
                     f"{int(FAIL_WINDOW.total_seconds())} giây (user: {m['user']})")
            continue

        m = SUCCESS.search(msg)
        if m:
            if m["src"] not in ADMIN_IPS:
                emit(ts, "CAO", "A02", host,
                     f"đăng nhập thành công (user: {m['user']}) từ IP lạ {m['src']}")
            continue

        m = ACL.search(msg)
        if m:
            src, dst, action = m["src"], m["dst"], m["action"]
            a_src, a_dst = ipaddress.ip_address(src), ipaddress.ip_address(dst)
            if action == "denied" and a_src in NET_DMZ and a_dst in NET_INTERNAL:
                if dedup.add(("A04", src, dst), ts) == 1:
                    emit(ts, "CAO", "A04", host,
                         f"ACL {m['acl']} chặn {m['proto']} từ DMZ {src} vào VLAN 20 ({dst})")
            elif action == "denied" and a_src in NET_INTERNET and a_dst in NET_INTERNAL:
                n = acl_win.add(src, ts)
                if n == 1:
                    emit(ts, "TRUNG BÌNH", "A03", host,
                         f"ACL {m['acl']} chặn {m['proto']} từ Internet {src} vào VLAN 20 ({dst})")
                elif n == ACL_REPEAT:
                    emit(ts, "CAO", "A03", host,
                         f"{ACL_REPEAT} gói từ {src} bị chặn trong "
                         f"{int(ACL_WINDOW.total_seconds())} giây, nghi dò quét")
            elif dst == DB_HOST and src not in ALLOWED_TO_DB:
                if dedup.add(("A05", src, dst, action), ts) == 1:
                    verb = "chặn" if action == "denied" else "CHO PHÉP"
                    emit(ts, "CAO", "A05", host,
                         f"ACL {m['acl']} {verb} {m['proto']} từ {src} tới CSDL {dst} "
                         f"(nguồn không thuộc danh sách được phép)")
            else:
                ignored += 1
            continue
        m = CONFIG.search(msg)
        if m:
            in_hours = BUSINESS_START <= ts.time() < BUSINESS_END
            text = f"cấu hình được thay đổi từ {m['where']} bởi {m['user']}"
            if in_hours:
                emit(ts, "TRUNG BÌNH", "A06", host, text)
            else:
                emit(ts, "CAO", "A06", host, text + " (ngoài giờ làm việc)")
            continue

        m = LINK_DOWN.search(msg)
        if m:
            desc = CRITICAL_PORTS.get((host, m["ifc"]))
            if desc:
                emit(ts, "CAO", "A07", host, f"cổng {m['ifc']} ({desc}) chuyển sang down")
            else:
                emit(ts, "THẤP", "A07", host, f"cổng {m['ifc']} chuyển sang down")
            continue

        m = NTP_LOST.search(msg)
        if m:
            emit(ts, "TRUNG BÌNH", "A08", host, f"mất đồng bộ giờ NTP ({m['kind']})")
            continue

        ignored += 1

    if entries:
        now = datetime.fromisoformat(now_text) if now_text else entries[-1][0]
        for dev in sorted(EXPECTED_DEVICES):
            seen = last_seen.get(dev)
            if seen is None:
                emit(now, "CAO", "A09", dev, "không nhận được log nào trong file")
            elif now - seen > SILENCE_LIMIT:
                mins = int((now - seen).total_seconds() // 60)
                emit(now, "CAO", "A09", dev,
                     f"không có log từ {seen:%H:%M:%S}, đã {mins} phút so với mốc {now:%H:%M:%S}")
    return alerts, len(entries), ignored, skipped


def main():
    ap = argparse.ArgumentParser(description="Phân tích log Syslog giả và in cảnh báo A01–A09.")
    ap.add_argument("logfile", nargs="?", default="sample_syslog.log", help="file log đã xuất từ SYSLOG-SRV")
    ap.add_argument("--csv", help="ghi các cảnh báo ra file CSV (mở được bằng Excel)")
    ap.add_argument("--year", type=int, default=datetime.now().year, help="năm cho log dạng 'Nov 16 17:35:02'")
    ap.add_argument("--now", help="mốc 'hiện tại' cho A09, dạng YYYY-MM-DD HH:MM:SS (mặc định: dòng log cuối)")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    alerts, total, ignored, skipped = analyze(args.logfile, args.year, args.now)

    for a in alerts:
        print(f"[{a['muc']}] {a['thoi_diem']} | {a['quy_tac']} | {a['thiet_bi']}: "
              f"{a['noi_dung']} -> hành động: {a['hanh_dong']}")

    print("\n--- Tổng kết ---")
    print(f"Số dòng log đọc được: {total}")
    print(f"Số dòng không khớp quy tắc nào (bỏ qua): {ignored}")
    by_rule, by_level = Counter(a["quy_tac"] for a in alerts), Counter(a["muc"] for a in alerts)
    for code in sorted(RULES):
        if by_rule[code]:
            print(f"  {code} {RULES[code][0]}: {by_rule[code]}")
    for level in sorted(by_level, key=LEVEL_ORDER.get):
        print(f"  Mức {level}: {by_level[level]}")
    print(f"Tổng số cảnh báo: {len(alerts)}")
    if skipped:
        print(f"\nCHÚ Ý: {len(skipped)} dòng sai định dạng nên bị bỏ qua, ví dụ:")
        for line in skipped[:3]:
            print(f"  {line[:90]}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["thoi_diem", "muc", "quy_tac", "thiet_bi", "noi_dung", "hanh_dong"])
            w.writeheader()
            w.writerows(alerts)
        print(f"\nĐã ghi {len(alerts)} cảnh báo vào {args.csv}")


if __name__ == "__main__":
    main()

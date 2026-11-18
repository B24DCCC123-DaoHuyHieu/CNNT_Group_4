XÁC THỰC VÀ PHÂN QUYỀN (IAM, RBAC & SESSION MANAGEMENT)
1. Thiết kế mô hình IAM (Identity and Access Management)
Hệ thống quản lý danh tính và truy cập (IAM) trong ngân hàng số được kiến trúc theo mô hình phân tách độc lập thành hai phân vùng nhằm đảm bảo tiêu chuẩn bảo mật phân đoạn mạng (DMZ và Internal):
CIAM (Customer IAM - Quản lý định danh khách hàng):
Phục vụ đối tượng khách hàng cá nhân/doanh nghiệp truy cập từ Internet (PC_KhachHang) vào ứng dụng qua giao diện Web_Server đặt tại vùng DMZ (VLAN 10).
Quy trình Onboarding & Định danh: Tích hợp công nghệ eKYC (Electronic Know Your Customer) cho phép định danh trực tuyến bằng cách chụp ảnh CCCD gắn chip và quét sinh trắc học khuôn mặt đối chiếu với cơ sở dữ liệu quốc gia.
WIAM (Workforce IAM - Quản lý định danh nhân sự & quản trị):
Phục vụ cán bộ nhân viên, giao dịch viên, kiểm soát viên và quản trị hệ thống thao tác từ PC_Admin đặt tại vùng mạng nội bộ Internal (VLAN 20).
Cơ chế bảo vệ: Yêu cầu định danh qua Active Directory (AD) nội bộ kết hợp xác thực phần cứng nâng cao. Mọi kết nối quản trị đặc quyền vào DB_Server hoặc thiết bị mạng đều bắt buộc đi qua Jump Server (Bastion Host) với nguyên tắc cấp quyền theo thời gian thực (JIT - Just-In-Time 
2. Ma trận phân quyền RBAC (Role-Based Access Control)
Hệ thống áp dụng mô hình phân quyền dựa trên vai trò kết hợp nguyên tắc Đặc quyền tối thiểu (PoLP) và Tách 

Viết thêm phần tính năng của từng role
Sửa lại ma trận phân quyền
 I,Khách hàng (CUSTOMER)
Dấu đầu dòng Chức năng & Quyền hạn:
Dấu đầu dòng Được phép (\checkmark): Xem số dư tài khoản cá nhân và thực hiện các lệnh chuyển khoản thông thường.
Dấu đầu dòng Từ chối (\times): Không có quyền tự duyệt các giao dịch có giá trị lớn, không được can thiệp vào cấu hình hệ thống và không thể xem nhật ký hoạt động (logs) của hệ thống.  
Dấu đầu dòng Luồng hoạt động (Workflow):
1. Đăng nhập vào ứng dụng/hệ thống và kiểm tra số dư khả dụng.
2. Khởi tạo lệnh chuyển khoản đến người nhận.
3. Rẽ nhánh xử lý:
Dấu đầu dòng Nếu giao dịch nằm trong hạn mức thông thường: Hệ thống thực thi lệnh chuyển tiền ngay lập tức.
Dấu đầu dòng Nếu giao dịch vượt hạn mức (Giao dịch lớn): Hệ thống chuyển lệnh sang trạng thái "Chờ duyệt" (Pending) và đẩy thông báo sang hàng đợi của Nhân viên nghiệp vụ.
II. Nhân viên nghiệp vụ (OFFICER)
Dấu đầu dòng Chức năng & Quyền hạn:
Dấu đầu dòng Được phép (\checkmark): Xem số dư, thực hiện chuyển khoản (hỗ trợ tại quầy hoặc giao dịch nội bộ), Duyệt giao dịch lớn, và Xem nhật ký để đối soát, tra soát giao dịch.
Dấu đầu dòng Từ chối (\times): Không có quyền thay đổi các thiết lập kỹ thuật hay cấu hình cốt lõi của hệ thống.  
Dấu đầu dòng Luồng hoạt động (Workflow):
1. Tiếp nhận các yêu cầu giao dịch giá trị lớn do Khách hàng khởi tạo (hoặc hỗ trợ khách hàng thực hiện giao dịch trực tiếp).
2. Kiểm tra thông tin tài khoản, số dư và đối chiếu lịch sử/nhật ký giao dịch để đảm bảo tính hợp lệ, phòng chống gian lận.
3. Ra quyết định: Chọn Phê duyệt (Approve) để hệ thống giải ngân/hoàn tất giao dịch, hoặc Từ chối (Reject) nếu phát hiện rủi ro/sai sót.
III. Quản trị hệ thống (SYSADMIN)
Dấu đầu dòng Chức năng & Quyền hạn:
Dấu đầu dòng Được phép (\checkmark): Cấu hình hệ thống (thiết lập tham số, hạn mức, phân quyền, bảo mật) và Xem nhật ký (giám sát hoạt động toàn hệ thống, phát hiện lỗi hoặc truy cập bất thường).
Dấu đầu dòng Từ chối (\times): Hoàn toàn không có quyền xem số dư, chuyển khoản hay duyệt giao dịch tài chính.  
Dấu đầu dòng Luồng hoạt động (Workflow):
1. Thiết lập và duy trì các tham số vận hành của hệ thống (ví dụ: định nghĩa ngưỡng thế nào là "giao dịch lớn", cấu hình bảo mật, quản lý tài khoản người dùng).
2. Thường xuyên theo dõi nhật ký hệ thống (System/Audit Logs) để giám sát hiệu năng, xử lý sự cố kỹ thuật và phát hiện các hành vi bất thường từ cả Khách hàng lẫn Nhân viên nghiệp vụ.                                          
3,Nguyên tắc bảo mật thể hiện qua luồng trên
Mô hình này áp dụng chặt chẽ nguyên tắc Phân tách nhiệm vụ (Separation of Duties - SoD) và Đặc quyền tối thiểu (Least Privilege):
Dấu đầu dòng Người quản lý kỹ thuật (SYSADMIN) có toàn quyền cấu hình hạ tầng nhưng bị chặn hoàn toàn khỏi các thao tác liên quan đến dòng tiền (không thể tự tạo hay duyệt giao dịch) để chống gian lận nội bộ.
Dấu đầu dòng Người xử lý nghiệp vụ (OFFICER) có quyền duyệt tiền nhưng không thể sửa cấu hình hệ thống hay xóa dấu vết trong nhật ký.

                          
3. Chính sách Xác thực & Quản lý phiên (Authentication & Session Policies)
A. Chính sách Xác thực (Authentication Policy)
Mật khẩu mạnh (Strong Password):
Độ dài tối thiểu từ 12 ký tự trở lên.
Bắt buộc bao gồm sự kết hợp của chữ hoa, chữ thường, chữ số và ký tự đặc biệt.
Vô hiệu hóa tài khoản tạm thời trong vòng 15 phút nếu nhập sai mật khẩu quá 5 lần liên tiếp.
Xác thực đa yếu tố (MFA - Multi-Factor Authentication):
Bắt buộc kích hoạt cho toàn bộ giao dịch tài chính, thay đổi hạn mức hoặc chỉnh sửa thông tin bảo mật.
Sử dụng hình thức Soft OTP gửi qua Push Notification ứng dụng di động hoặc mã xác thực sinh trắc học.
Đối với nhóm quản trị viên hệ thống, bắt buộc sử dụng khóa xác thực phần cứng FIDO2 / WebAuthn.
B. Chính sách Quản lý phiên làm việc (Session Management Policy)
Sử dụng chuẩn OAuth 2.0 / OpenID Connect (OIDC):
Phiên đăng nhập được quản lý thông qua mã thông báo bảo mật Access Token (JWT) với thời gian sống ngắn (tối đa 15 phút) nhằm giảm thiểu rủi ro bị đánh cắp phiên (Session Hijacking).
Cơ chế Refresh Token Rotation:
Mỗi khi Access Token hết hạn, hệ thống sử dụng Refresh Token để cấp mới mã thông báo, đồng thời thay thế luôn Refresh Token cũ nhằm ngăn chặn việc tái sử dụng token độc hại.
Tự động hủy phiên (Session Timeout):
Phiên làm việc của khách hàng trên ứng dụng/Web sẽ tự động kết thúc (Logout) sau 5 phút không có hoạt động tương tác (Idle Timeout).


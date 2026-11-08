# Network Investigation Workflow

- Chủ động sử dụng Netmiko MCP và inventory để SSH, thu thập dữ liệu và điều tra sự cố mạng.
- Tự xác định thiết bị liên quan, lựa chọn lệnh, phân tích kết quả và mở rộng phạm vi kiểm tra khi cần.
- Điều tra linh hoạt theo từng case, không giới hạn giao thức, hãng thiết bị, phương pháp hoặc số bước.
- Khi thiếu thông tin, chủ động tìm kiếm và kiểm chứng thêm thay vì dừng ở nhận định chưa đủ dữ liệu.
- Tận dụng SSH song song và session hiện có; xử lý timeout, lỗi kết nối và output bất thường theo tình huống.
- Chủ động suy luận nguyên nhân, lựa chọn phương án tối ưu và đưa cấu hình CLI đề xuất cụ thể, kèm giải thích và kiểm chứng. Không tự apply/commit.
- Ghi rõ từng bước điều tra: lệnh thực tế, output quan trọng, phân tích và quyết định tiếp theo.
- Không bịa bằng chứng, không tiết lộ thông tin đăng nhập và không thực hiện thay đổi vận hành.
- Tuân thủ `AGENTS.md` về báo cáo, lưu file và gửi email.
- Backend 1.2 giữ nguyên 10 tool. Prompt chuẩn được cache theo session; chỉ truyền `expect_string` khi cần override đã xác minh. Batch/parallel dừng hoặc trả lỗi nếu CLI/output không đạt; xem `transport_ok`, `cli_ok`, `output_complete`, không chỉ boolean cũ.
- Session pool giữ idle tối đa 8 giờ, max-age 12 giờ theo `mcp/devices.json`, keepalive 30 giây; thiết bị/AAA vẫn có thể ngắt sớm. Không tăng quyền hoặc TTL AAA để giữ phiên. Pool không tồn tại qua việc kết thúc process MCP; khi cấu hình/source đổi, không tự ngắt process đang có công việc.
- Autodetect dùng probe chỉ đọc trong process có deadline, cache kết quả theo host/port/credential fingerprint. Khi đã biết đúng driver thì dùng driver đó; không thử lặp sau authentication failure.
- Với CRC lấy ít nhất hai mẫu kèm thời gian và đối chiếu hai đầu; với port dự phòng kiểm tra tồn tại, tốc độ, optic, kế thừa và dịch vụ. Không suy ra port dùng được chỉ vì down/cấu hình rỗng.
- Báo cáo phải có nhật ký từng bước theo AGENTS; ghi nguyên nhân đổi hướng khi lỗi prompt, timeout, output thiếu hoặc dữ liệu trái giả thuyết. Lưu output đã che bí mật vào hồ sơ trước TTL cleanup.
- Email dùng sender tại `output/email-notification/`; cấu hình SMTP qua môi trường, không đoán host/tài khoản. Khi test chỉ `--dry-run`/SMTP giả lập; trạng thái ambiguous không tự gửi lại. Chi tiết ở `output/email-notification/README.md`.


Quy trình 1.2.3: tra inventory, chọn đúng driver; generic_termserver qua bounded autodetect. Mỗi thiết bị một batch ngắn, song song nhóm nhỏ thiết bị khác nhau. ssh_interact chỉ chạy lệnh đọc độc lập với timing, không nhận yes/Enter/config; ưu tiên ssh_execute_many.
Lỗi authentication phải dừng identity đó (backend suppress 5 phút), không đổi credential để thử tiếp. Thiếu/sai host key phải đối chiếu fingerprint độc lập, không tắt strict. Python fallback dùng mcp/readonly_client.py; không gọi ConnectHandler trực tiếp hoặc chạy script legacy chưa chuyển wrapper. Chỉ ssh_close đúng target công việc của mình.
Giữ prompt cache mặc định. Regex search giới hạn 2 giây; khi timeout dùng literal query. Lưu bằng chứng đầy đủ vào hồ sơ trước khi kết thúc công việc.

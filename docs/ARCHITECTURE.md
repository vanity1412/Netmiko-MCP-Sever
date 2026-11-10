# Hiểu và sửa Netmiko MCP

## Đọc theo thứ tự

1. README.md: danh sách source và dependency.
2. docs/ARCHITECTURE.md: luồng chạy và điểm sửa (file này).
4. docs/SCAN.md: job runner, retry, bằng chứng và resume.
5. CHANGELOG.md: lịch sử thay đổi.

Regression và integration SSH localhost nằm trong tests; chạy `python -m unittest discover -s tests -v`.

## Ba đường gọi

MCP client → STDIO JSON-RPC → bootstrap.py → Collector trong collector_backend.py → Netmiko → Paramiko → SSH thiết bị.

Python fallback → ReadOnlyConnection trong readonly_client.py → cùng Collector → cùng policy SSH/CLI.

Scanner CLI → scan.py → Collector → kết quả từng task + bằng chứng + summary. Scanner không phải tool MCP thứ 11.

bootstrap.py nạp environment, cấu hình JSON và inventory CSV. Khi thiếu cặp NETWORK_SSH_USER/PASSWORD, fallback input/ssh.txt; hiện chỉ chọn cặp đầu tiên, không tự thử tất cả cặp. File devices.example.json chỉ có tham chiếu environment, không có credential thật.

## Trách nhiệm và điểm cần tìm trong source

| File / hàm | Vai trò |
|---|---|
| bootstrap.py / prepare_environment, main | Credential precedence, đường dẫn root và bật private host-key file |
| collector_backend.py / load_config, load_inventory_csv | Nạp JSON, expand environment, merge alias/IP/driver |
| Collector._get_settings | Ghép defaults → profile → device → override; chấp nhận host key và chọn file persistence riêng |
| Collector._session_key | Identity cho session cache; thay policy phải tránh tái dùng transport cũ |
| Collector._resolve_platform, detection_worker | Autodetect bằng probe đọc trong process riêng, có ngân sách thời gian |
| Collector._open, lease/session helpers | Mở SSH, xác minh prompt, giới hạn số phiên và reuse |
| readonly_command, cli_pipeline | Grammar lệnh chỉ đọc, chặn pipeline/lệnh không được duyệt |
| Collector._send, read_cli_output | Đọc Netmiko channel, chờ prompt cuối, chuyển trang, giữ partial output và kiểm soát timeout |
| Collector._result | Kiểm tra echo, prompt cuối, dấu CLI error và pager/confirmation |
| classify_error | Phân loại lỗi SSH/TCP/auth/host key, quyết định retryable |
| TOOLS, make_tool_list, run_stdio | 10 tool MCP, schema và dispatcher JSON-RPC |
| readonly_client.py / send_command | Wrapper Python, hiện lỗi CLI chỉ ném RuntimeError theo tên lỗi |
| scan.py / prepare_tasks, _attempt, run_scan | Kiểm tra plan, fast/slow lanes, retry có chọn lọc, export/checkpoint |

## 10 tool đang có

- ssh_execute: một lệnh đọc.
- ssh_execute_many: nhiều lệnh trên cùng thiết bị.
- ssh_interact: các bước lệnh đọc; không nhận yes/Enter/confirmation tùy ý.
- ssh_parallel: nhiều task độc lập.
- ssh_read_output, ssh_read_output_bytes: đọc output lớn theo dòng/byte.
- ssh_search_output: tìm trong output đã lưu.
- ssh_inventory: tra inventory.
- ssh_status: trạng thái collector/session.
- ssh_close: đóng session.

## Dữ liệu triển khai (đã sao chép dữ liệu thật từ bộ gốc)

- input/device.csv: tối thiểu name,ip,netmiko_device_type.
- input/ssh.txt: nguồn credential fallback, không đưa lên Git.
- mcp/devices.json: cấu hình triển khai tạo từ devices.example.json.
- mcp/ssh/known_hosts: trust store. Bootstrap/scanner/fallback trỏ tới file này.
- runtime/data/netmiko/: dữ liệu local/session evidence theo cấu hình.
- output/<job>/: manifest, task result, bằng chứng và summary của scanner.

Đường dẫn dùng root tương đối từ vị trí source. MCP client cần working directory là thư mục Netmiko-MCP; command python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv. Có client cần đường dẫn tuyệt đối trong cấu hình.

Inventory, credential, known_hosts, runtime và output được cung cấp riêng tại môi trường triển khai, không được theo dõi trong Git. Dữ liệu lịch sử không đại diện cho phiên SSH hoặc trạng thái thiết bị hiện tại.

## Chính sách hiện tại — 1.5.0

- Backend, Python fallback và subprocess autodetect cùng chấp nhận host key mới/đổi, lưu theo SSH client dưới khóa file liên tiến trình. Lỗi ghi store tạo warning và không chặn kết nối.
- Không patch AutoAddPolicy toàn cục; mỗi Netmiko client có policy giữ đường dẫn store riêng. File được đọc/merge lại khi đang giữ lock rồi atomic replace.
- Output cần prompt cuối của phiên và không có CLI error/confirmation/pager chưa xử lý; echo không bắt buộc. Chỉ có echo không đủ để báo thành công.
- Reader không gửi lại lệnh khi thiếu output; tự gửi Space cho phân trang. Timeout/cancel giữ partial output; batch dừng và đóng transport trước driver cleanup để tránh gửi exit vào confirmation.
- EOF/closed channel được phát hiện ngay. Chỉ các footer pager thực sự được xử lý mới bị loại khỏi output; chuỗi giống pager trong dữ liệu vẫn giữ nguyên. Câu hỏi password/confirmation dừng thu thập mà không gửi phản hồi.
- global_cmd_verify mặc định false cho session preparation; wrapper terminal-width đọc tới prompt thay vì đợi echo. Kiểm chứng output lệnh thu thập vẫn dựa vào prompt cuối.
- CLI error thật khác lỗi xác minh output. Chưa đọc account không có nghĩa account rỗng.
- Scanner có fast/slow lanes; retry tối đa một lần cho TCP/banner/read/auth timeout. Authentication rejected/auth_method vẫn cooldown 5 phút và không retry. Resume bỏ qua failed/partial đã lưu.

CSV hỗ trợ profile tùy chọn; thiếu dùng default. Mapping thật cần khai báo theo thiết bị, không tự đoán hoặc thử tất cả credential. Bootstrap không bắt cặp credential toàn cục khi profile đã có credential riêng.

Các tùy chọn tối ưu 1.4.0 (quiet, health check định kỳ, redaction, store theo process, cooldown và ưu tiên driver inventory) được mô tả trong README.md. Output redaction có thể tắt; thông báo lỗi và audit command vẫn được che.

1.5.0: SQLite lưu driver đã xác minh theo hash endpoint/auth/route và TTL; tách cache driver khỏi location known_hosts để các job dùng cùng cache. Output exclusive có index RAM, quota check mỗi ghi và reconcile định kỳ; shared vẫn đối soát file. Không chuyển transport qua process: probe còn giữ hard deadline riêng.

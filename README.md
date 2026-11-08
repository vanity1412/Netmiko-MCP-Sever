# Netmiko-MCP-Sever — OpenCode Network

## Source 1.2.2 trên Git

Repository chỉ chứa mã nguồn, test và cấu hình mẫu. Tài khoản, inventory thật,
SSH host keys, executable, báo cáo vận hành và runtime được giữ riêng tại máy.
Giữ nguyên các file cục bộ hiện có khi cập nhật source.

Máy mới: cài Python 3.10+, chạy `python -m pip install -r requirements.txt`,
chép `mcp/devices.example.json` thành `mcp/devices.json` và
`opencode.example.json` thành `opencode.json`. Cung cấp inventory riêng tại
`input/device.csv` với header `name,ip,netmiko_device_type`; cung cấp tài khoản
qua biến môi trường `NETWORK_SSH_USER` và `NETWORK_SSH_PASSWORD`.
Tạo `mcp/ssh/known_hosts` từ fingerprint đã xác minh theo quy trình quản trị;
không tắt strict để bỏ qua lỗi host key. Launcher cần `app/opencode.exe` được
cài riêng từ nguồn OpenCode đã xác minh.

Kiểm thử offline: `python -m unittest discover -s mcp/tests -v` và
`python -m unittest discover -s output/email-notification/tests -v`.
Các test dùng mock/SSH localhost, không đăng nhập thiết bị production.
Chi tiết sửa lỗi: [CHANGELOG.md](CHANGELOG.md).

## Sử dụng

1. Mở `OpenCode-Web.cmd` để dùng trình duyệt, hoặc `OpenCode-Terminal.cmd` để dùng terminal.
   Giữ cửa sổ launcher mở. Nếu Web yêu cầu mật khẩu server, dùng mật khẩu do OpenCode hiển thị trong cửa sổ này; không chia sẻ mật khẩu đó. Đây không phải mật khẩu SSH.
2. Làm việc tại chính thư mục `OpenCode-Network`. Nếu giao diện Web yêu cầu chọn project, chọn thư mục này.
3. Kết nối/đăng nhập nhà cung cấp AI trong OpenCode nếu được yêu cầu. Bản mới không sao chép database đang mở hoặc lịch sử phiên của bản cũ.
   Trước khi dùng MCP, điền hai trường `NETWORK_SSH_USER` và `NETWORK_SSH_PASSWORD` tại `mcp.servers.netmiko.environment` trong `opencode.json`. Sau khi lưu, OpenCode tự nạp lại cấu hình; nếu cần dùng `/reload`.
4. Gửi yêu cầu kiểm tra mạng; agent dùng Netmiko MCP, tự thu thập và lưu báo cáo ở `output/<tên-sự-cố>/`.

Chạy `Check.cmd` để kiểm tra Python, inventory, credential profiles và kết nối MCP.

## Cấu trúc

| Đường dẫn | Vai trò |
|---|---|
| `opencode.json` | Cấu hình duy nhất của bộ mới |
| `AGENTS.md` | Nguyên tắc AI Network Engineer |
| `app/opencode.exe`, `app/Start.ps1` | Chương trình và script khởi chạy |
| `mcp/bootstrap.py` | Nạp tài khoản vào bộ nhớ, khởi chạy MCP |
| `mcp/collector_backend.py` | Code SSH/Netmiko MCP, bản chép từ GooseNet |
| `mcp/devices.json`, `mcp/ssh/known_hosts` | Cấu hình kết nối, SSH host keys |
| `mcp/WORKFLOW.md` | Hướng dẫn điều tra, kiểm chứng và báo cáo |
| `input/` | Bản chép input; gồm device.csv và tài khoản SSH |
| `output/` | Báo cáo/bằng chứng, đã có bài SC24102600707 |
| `temp/` | Script tạm, đã có script thu thập bài CRC |
| `runtime/` | Dữ liệu, cache, trạng thái và log mới |

## Quản lý và bảo mật

- Bản này không cần code/config trong GooseNet hay hai thư mục OpenCode cũ. Các bản cũ vẫn giữ nguyên; không tự xóa khi chưa kiểm tra đủ.
- Vẫn dùng Python/Netmiko đã cài trên Windows. Chuyển sang máy khác cần cài lại runtime/dependencies; không phải bộ đóng gói kèm Python.
- Có thể di chuyển cả thư mục khi đã đóng bộ mới; launcher và bootstrap tính đường dẫn tương đối.
- Tài khoản điền trực tiếp trong `opencode.json` là văn bản thường, không mã hóa. Có thể thay giá trị bằng `{env:NETWORK_SSH_USER}` và `{env:NETWORK_SSH_PASSWORD}` nếu muốn sử dụng biến môi trường bên ngoài thay vì lưu trực tiếp. Không chia sẻ cấu hình có mật khẩu.
- Tài khoản JSON là nguồn chính: khi hai biến đầy đủ, bootstrap không đọc `input/ssh.txt`. Nếu thiếu, bootstrap dùng tài khoản đầu tiên trong file này. Nếu SSH qua MCP không thành công, Agent vẫn được tham khảo file và dùng Python/Netmiko trực tiếp khi cần, theo AGENTS.md. File input/ssh.txt được giữ nguyên; nó vẫn chứa thông tin nhạy cảm. `runtime/` có thể chứa dữ liệu xác thực AI và output mạng. Không công khai/chia sẻ nguyên thư mục, không đưa lên Git.
- Bản mới dùng bản chép của input. Cập nhật inventory/tài khoản tại input của bộ mới; thay đổi input ở bộ cũ không tự đồng bộ.
- Chỉ sao chép input, báo cáo SC24102600707 và script liên quan trong lần gom này; các hồ sơ sự cố khác ở bộ cũ không bị di chuyển hoặc xóa.
- Agent chỉ điều tra khi nhận yêu cầu, không tự đọc hộp thư hay thực hiện thay đổi vận hành. Gửi báo cáo theo phạm vi cho phép và AGENTS.md; trong kiểm thử dùng `--dry-run`. Sender/retry/chống trùng được mô tả ở `output/email-notification/README.md`.

## Backend 1.2

- Giữ nguyên 10 tool và lời gọi cũ; bổ sung trường kiểm chứng output, trạng thái partial failure, tùy chọn prompt cho batch/parallel.
- Sửa Junos/BEL bằng prompt đã xác minh, không dò lại prompt trên từng lệnh. Autodetect dùng tối đa ba lệnh đọc với process deadline mặc định 20 giây và cache theo credential fingerprint.
- Pool tối đa 64 phiên; cấu hình hiện tại idle 8 giờ, max-age 12 giờ, keepalive 30 giây; reaper không đụng phiên đang được mượn. Không bảo đảm một login cả ngày vì AAA/thiết bị có thể ngắt phiên.
- `mcp/devices.json` giữ nguyên profile/tài khoản và các host-key flags; việc fingerprint/AAA cần triển khai riêng có kiểm soát. Lệnh nhiều dòng/control characters bị từ chối, nhưng backend không thay cho command authorization read-only.
- Source Python thay đổi không cập nhật module đã được process MCP cũ import. Khi không có công việc đang chạy, reconnect riêng Netmiko qua `/mcps`; không cần restart toàn bộ OpenCode Web. Không tự reload/ngắt phiên đang làm việc.
- Regression offline: `python -m unittest discover -s mcp/tests -v`. SSH smoke-test có quyền: `python mcp/check.py --ssh`; không dùng credential trong CLI. Kiểm thử nâng cấp và rollback ở `output/UPGRADE-MCP-OPENCODE/`.

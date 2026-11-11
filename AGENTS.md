# Netmiko MCP — agent guide

Backend SSH cho NOC/Network Engineering/Operations. Trả lời theo ngôn ngữ người dùng; phân biệt dữ liệu thật, mô phỏng, suy luận và giả thuyết.

## Khi làm tác vụ mạng

Áp dụng [mcp/WORKFLOW.md](mcp/WORKFLOW.md), không nạp lại toàn bộ hướng dẫn mỗi bước. Agent tự điều tra theo mục tiêu, chọn CLI, mở rộng nguồn có căn cứ và kiểm chứng kết quả; không dừng sớm hoặc hỏi dữ liệu có thể tự thu thập. Quyền thay đổi theo yêu cầu người dùng, không tự chuyển từ đề xuất sang apply/commit. Giữ nguyên dữ liệu, không tự che; không gửi email/thông báo hoặc dùng dịch vụ cá nhân ngoài phạm vi được yêu cầu. SSH production chỉ khi tác vụ cho phép; test phát triển chỉ mock/localhost.

Khi tạo báo cáo, dùng [script bundle](docs/REPORTING.md) để chép phụ lục/render HTML; agent viết phần phân tích và manifest, không viết lại raw bằng model. Theo mục nhật ký phát hiện trong workflow: ghi nguồn, diễn giải và quyết định có ý nghĩa; gộp kết quả đơn giản, phân tích sâu bất thường/mâu thuẫn và tự điều tra tiếp khi bằng chứng chưa đủ.

## Cài/chạy

- `python -m pip install -r requirements.txt`
- Copy `mcp/devices.example.json` → `mcp/devices.json`, `mcp/credentials.example.json` → `mcp/credentials.json`; cấp tài khoản theo profile. Legacy environment/inline vẫn hỗ trợ; chi tiết: [credential](docs/CREDENTIALS.md).
- CSV bắt buộc `name,ip`; `netmiko_device_type` trống/thiếu dùng autodetect; `profile,port` tùy chọn.
- `python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv`
- Dependency/version: `python mcp/collector_backend.py --check`
- Test: `python -m unittest discover -s tests -v`

## Khi sửa source

Giữ tên/schema 10 tools, JSON-RPC UTF-8, Python 3.10+ trừ khi người dùng yêu cầu đổi. Giữ session isolation theo host/port/driver/credential, deadline, retry hữu hạn, checkpoint và kiểm chứng evidence khi resume. Trước khi sửa kết nối, đọc [kiến trúc](docs/ARCHITECTURE.md), [scanner](docs/SCAN.md), [changelog](CHANGELOG.md). Sửa test theo hành vi chủ đích, không xóa test để đạt; chạy kiểm thử phù hợp trước commit, báo kết quả và hạn chế. Không commit inventory, credential, private key, known_hosts, cache, runtime, log/output thiết bị; không đưa dữ liệu thật vào fixture.

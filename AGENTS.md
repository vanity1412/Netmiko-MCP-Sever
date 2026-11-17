# Netmiko MCP — agent guide

Backend SSH cho NOC/Network Engineering/Operations. Trả lời theo ngôn ngữ người dùng; phân biệt dữ liệu thật, mô phỏng, suy luận và giả thuyết.

## Khi làm tác vụ mạng

Áp dụng [mcp/WORKFLOW.md](mcp/WORKFLOW.md) một lần đầu tác vụ. Agent tự chọn giả thuyết, CLI và thiết bị liên quan từ evidence; không giới hạn vào use case hoặc bộ lệnh có sẵn. Quyền theo yêu cầu người dùng: không tự chuyển điều tra/đề xuất sang apply/commit production, gửi thông báo hoặc dùng dịch vụ cá nhân ngoài phạm vi. SSH production chỉ khi tác vụ cho phép; test phát triển chỉ mock/localhost.

Workflow là nguồn chính cho suy luận/topology/cấu hình/kiểm chứng; chỉ nạp tài liệu sâu khi cần. Giữ chốt quyền/raw/kiểm chứng, không nạp toàn docs/transcript mặc định. Kết luận/delta quan trọng phải truy xuất được nguồn, không bịa tham số. Giữ nguyên raw, không tự che. Báo cáo theo [REPORTING.md](docs/REPORTING.md).

## Cài/chạy

- `python -m pip install -r requirements.txt`
- Copy `mcp/devices.example.json` → `mcp/devices.json`, `mcp/credentials.example.json` → `mcp/credentials.json`; cấp tài khoản theo profile. Legacy environment/inline vẫn hỗ trợ; chi tiết: [credential](docs/CREDENTIALS.md).
- CSV bắt buộc `name,ip`; `netmiko_device_type` trống/thiếu dùng autodetect; `profile,port` tùy chọn.
- `python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv`
- Dependency/version: `python mcp/collector_backend.py --check`
- Test: `python -m unittest discover -s tests -v`

## Khi sửa source

Giữ tên/schema 10 tools, JSON-RPC UTF-8, Python 3.10+ trừ khi người dùng yêu cầu đổi. Giữ session isolation theo host/port/driver/credential, deadline, retry hữu hạn, checkpoint và kiểm chứng evidence khi resume. Trước khi sửa kết nối, đọc [kiến trúc](docs/ARCHITECTURE.md), [scanner](docs/SCAN.md), [changelog](CHANGELOG.md). Sửa test theo hành vi chủ đích, không xóa test để đạt; chạy kiểm thử phù hợp trước commit, báo kết quả và hạn chế. Không commit inventory, credential, private key, known_hosts, cache, runtime, log/output thiết bị; không đưa dữ liệu thật vào fixture.

# Netmiko MCP Server

MCP server SSH chỉ đọc dùng Netmiko, có session pool, autodetect và helper quét inventory. Backend hiện tại: **1.3.0**, giữ nguyên **10 MCP tool**.

## File trong repository

| File/thư mục | Vai trò |
|---|---|
| `mcp/collector_backend.py` | Backend MCP STDIO, SSH pool, kiểm tra lệnh/output và phân loại lỗi |
| `mcp/bootstrap.py` | Nạp cấu hình/inventory và môi trường tài khoản, bật private known_hosts |
| `mcp/readonly_client.py` | Python fallback dùng cùng policy; bắt buộc device_type |
| `mcp/scan.py` | Quét theo job, fast/slow lanes, bằng chứng tăng dần và resume |
| `mcp/*.example.json` | Cấu hình và kế hoạch quét mẫu, không chứa thông tin truy cập thật |
| `mcp/tests/` | Regression offline/mock và SSH localhost |
| `mcp/SCAN.md`, `mcp/HARDENING.md` | Hướng dẫn quét và giới hạn vận hành |
| `AGENTS.md`, `mcp/WORKFLOW.md` | Hướng dẫn cho agent trong môi trường sử dụng |
| `requirements.txt`, `CHANGELOG.md` | Dependency và lịch sử thay đổi |

Launcher/executable OpenCode, sender email, báo cáo, credential, inventory thật, host keys và runtime không thuộc source MCP trong Git. Các tích hợp có sẵn trên máy vẫn được giữ riêng. Hướng dẫn email trong AGENTS/WORKFLOW áp dụng khi môi trường triển khai có sender tương ứng; backend/scanner không phụ thuộc sender để chạy.

## Cài và cấu hình

Dùng Python 3.10+, cài dependency:

```powershell
python -m pip install -r requirements.txt
```

Trên máy mới, copy `mcp/devices.example.json` thành `mcp/devices.json`; cung cấp inventory riêng tại `input/device.csv` với các cột `name,ip,netmiko_device_type`. Đặt `NETWORK_SSH_USER` và `NETWORK_SSH_PASSWORD` trong môi trường của process MCP. Bootstrap hỗ trợ nguồn tài khoản cục bộ `input/ssh.txt` khi thiếu cặp môi trường; không đưa file này lên Git.

Cung cấp `mcp/ssh/known_hosts` từ fingerprint đã được xác minh độc lập. Không tắt strict để vượt lỗi host key. Giữ nguyên cấu hình và dữ liệu riêng khi cập nhật source từ Git.

## Chạy MCP STDIO

Cấu hình MCP client gọi từ thư mục gốc repository:

```text
python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv
```

Không cần launcher hoặc executable OpenCode để chạy server. MCP client chịu trách nhiệm cấp environment và working directory đúng.

Kiểm tra dependency/version, không SSH:

```powershell
python mcp/collector_backend.py --check
python mcp/collector_backend.py --version
```

## Quét inventory

Preview, không SSH:

```powershell
python mcp/scan.py --all --output output/SCAN-VERSION
```

Thêm `--execute` khi thực hiện quét thật với credential/fingerprint đã xác minh. Mặc định chỉ lấy version. Kế hoạch riêng, fast/slow lanes, profile, checkpoint và resume: [mcp/SCAN.md](mcp/SCAN.md).

## Kiểm thử

```powershell
python -m unittest discover -s mcp/tests -v
```

Tests dùng fake transport và SSH server localhost, không đăng nhập thiết bị production. Giới hạn và cách triển khai: [mcp/HARDENING.md](mcp/HARDENING.md). Lịch sử: [CHANGELOG.md](CHANGELOG.md).

# Netmiko MCP Server

MCP server SSH chỉ đọc dùng Netmiko, có session pool, autodetect và helper quét inventory. Backend hiện tại: **1.3.3**, giữ nguyên **10 MCP tool**.

## Cấu trúc

- `mcp/`: backend, bootstrap, Python client, scanner và cấu hình mẫu.
- `tests/`: bộ kiểm thử phát triển, không cần khi chạy MCP.
- `docs/`: kiến trúc và hướng dẫn quét inventory.
- `AGENTS.md`: hướng dẫn agent thực thi và sửa source.

Inventory, credential, host keys và output được cung cấp riêng tại môi trường triển khai và không đưa lên Git.

## Cài và cấu hình

Dùng Python 3.10+, cài dependency:

```powershell
python -m pip install -r requirements.txt
```

Trên máy mới, copy `mcp/devices.example.json` thành `mcp/devices.json`; cung cấp inventory riêng tại `input/device.csv` với các cột `name,ip,netmiko_device_type`. Đặt `NETWORK_SSH_USER` và `NETWORK_SSH_PASSWORD` trong môi trường của process MCP. Bootstrap hỗ trợ nguồn tài khoản cục bộ `input/ssh.txt` khi thiếu cặp môi trường; không đưa file này lên Git.

Host key mới/đổi được chấp nhận và lưu atomic dưới khóa liên tiến trình. Lỗi ghi known_hosts tạo warning, không chặn SSH. Thành công cần prompt cuối và CLI không báo lỗi; echo không bắt buộc. Giữ nguyên cấu hình và dữ liệu riêng khi cập nhật source từ Git.

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

Thêm `--execute` khi thực hiện quét thật với credential/fingerprint đã xác minh. Mặc định chỉ lấy version. Kế hoạch riêng, fast/slow lanes, profile, checkpoint và resume: [docs/SCAN.md](docs/SCAN.md).

## Kiểm thử

```powershell
python -m unittest discover -s tests -v
```

Tests dùng fake transport và SSH server localhost, không đăng nhập thiết bị production. Kiến trúc: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Lịch sử: [CHANGELOG.md](CHANGELOG.md).

## Kiểm chứng 1.3.3

Có thêm `mcp/validate_fleet.py`, replay 2.000 cách chia chunk, stress 500 thiết bị ảo, kiểm tra bằng chứng/resume và SSH localhost cho Cisco IOS/XR/NXOS, Huawei, Junos, Linux. Dữ liệu production và báo cáo riêng không được đưa lên Git. Xem `docs/ARCHITECTURE.md` và `docs/SCAN.md`.

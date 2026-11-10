# Netmiko MCP Server

MCP server SSH chỉ đọc dùng Netmiko, có session pool, autodetect và helper quét inventory. Backend hiện tại: **1.5.0**, giữ nguyên **10 MCP tool**.

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

## Tối ưu 1.4.0

| defaults option | Constructor default | Cấu hình mẫu |
|---|---|---|
| prefer_inventory_driver | true | true |
| health_check_interval_seconds | 30 | 30 |
| prompt_quiet_seconds | 0.03 | 0.03 |
| timing_quiet_seconds | 0.1 | 0.1 |
| redaction_enabled | true | false |
| auth_failure_cooldown_seconds | 300 | 30 |
| host_key_store_mode | shared | process |

Cấu hình mẫu ưu tiên tốc độ và trả/lưu output không che bí mật. Đặt redaction_enabled=true nếu muốn che dữ liệu output. Error và audit command luôn được che. Mode process ghi known_hosts.<PID>, không tự hợp nhất sang file chung; dùng shared nếu cần một store thống nhất. Prompt được cache trong phiên, không tái sử dụng mù qua kết nối mới. Đặt prefer_inventory_driver=false để yêu cầu dò lại dù inventory đã có driver. Quiet ngắn có thể cần tăng lại trên thiết bị gửi dữ liệu bất thường; điều kiện prompt cuối và kiểm tra CLI vẫn được giữ.

## Lưu output và cache driver — 1.5.0

- `output_storage_mode`: `shared` mặc định, đối soát thư mục khi lưu; `exclusive` dùng index dung lượng trong RAM cho thư mục do một Collector sở hữu. Scanner/validator tự dùng exclusive với scratch riêng của job.
- `output_cleanup_interval_seconds`: mặc định 30s. Exclusive không glob mỗi lần ghi; quota vẫn kiểm tra trước mọi lần ghi, cleanup ngay khi thiếu chỗ. Reconcile định kỳ hoặc khi gọi cleanup tường minh; restart đọc lại index từ file. File đang được đọc hoặc đang pin được bảo vệ. Không dùng exclusive nếu nhiều Collector/process cùng ghi một thư mục. Shared vẫn cần thư mục riêng nếu yêu cầu quota cứng giữa nhiều process; không có global quota transaction.
- `autodetect_persistent_cache`: mặc định true. Bootstrap/scanner/validator dùng chung `runtime/data/netmiko/autodetect.sqlite3`; `autodetect_cache_file` cho phép đổi đường dẫn. Direct Collector dùng APP_HOME nếu không khai báo path.
- SQLite chỉ lưu hash identity, driver và thời điểm; không lưu credential rõ. Cache theo host/port/credential/route options, hết hạn theo TTL autodetect (mặc định 8 giờ). Chỉ ghi sau probe thành công. Cache lỗi/khóa/bị hỏng sẽ fallback dò thật; không chặn SSH vì lỗi cache. Driver chỉ định rõ vẫn ưu tiên và không cần disk lookup. Cache không tự sửa inventory và có thể cũ nếu thiết bị bị thay trong khoảng TTL; tắt cache persistent và khởi động Collector mới hoặc chỉ định driver đúng khi cần kiểm chứng lại.
- Probe vẫn ở process riêng để giữ hard deadline. Chưa chia sẻ transport probe sang process thu thập; tái sử dụng cùng session đòi hỏi thiết kế ownership/cancellation khác.

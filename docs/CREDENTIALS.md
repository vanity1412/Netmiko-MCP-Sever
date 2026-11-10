# Credential dùng chung — 1.9.0

Mô hình triển khai:

```text
Codex / Claude / OpenCode / Goose / MCP client khác
    → khởi chạy backend với cùng --config hoặc --credentials-file
    → devices.json: driver, timeout, worker và thiết lập profile
    → device.csv: thiết bị → tên profile
    → credentials.json: tên profile → tài khoản SSH
    → session pool của từng tiến trình → thiết bị
```

Chia sẻ file tài khoản không chia sẻ session pool giữa các tiến trình. Không cần thêm tool, dịch vụ credential hay framework. File được đọc một lần khi khởi động; thay credential thì restart các MCP đang dùng. Không tự thử tuần tự nhiều profile khi xác thực thất bại.

## File cần chuẩn bị

Copy `mcp/credentials.example.json` thành `mcp/credentials.json` rồi điền tài khoản. File thực tế nằm ngoài Git; chỉ file example được publish. Có thể để file ở một đường dẫn ngoài repository để nhiều checkout/client dùng chung. Checkout phát triển có thể có file private trống `{"profiles": {}}`; file trống chưa cung cấp tài khoản nào và vẫn cho phép cấu hình cũ hoạt động.

```json
{
  "profiles": {
    "default": {"username": "noc-user", "password": "YOUR_PASSWORD"},
    "site_b": {"username": "site-user", "password": "YOUR_SITE_PASSWORD"},
    "key_login": {"username": "automation", "key_file": "keys/site.key", "passphrase": "YOUR_KEY_PASSPHRASE"},
    "agent_login": {"username": "automation", "allow_agent": true}
  }
}
```

Chỉ chấp nhận `username`, `password`, `secret` (enable), `key_file`, `passphrase`, `use_keys`, `allow_agent` trong từng credential profile. Username cùng password hoặc phương thức key/agent phải đầy đủ; không mượn password từ nguồn khác. Nếu cần enable, khai báo `secret` trong chính profile. Không bắt buộc `secret` cho đăng nhập SSH thông thường.

File hỗ trợ `${VARIABLE}` cho toàn bộ giá trị, giống config hiện có. Password literal có `$` hoặc ký tự đặc biệt được giữ nguyên. File example dùng biến môi trường; nếu muốn các client hoàn toàn độc lập environment, thay bằng giá trị trong file private. Profile có biến chưa được cấp giá trị sẽ báo thiếu credential khi khởi động. Key file tương đối được tính từ thư mục chứa credentials.json.

`devices.json` giữ cấu hình kết nối:

```json
{
  "credentials_file": "credentials.json",
  "defaults": {"device_type": "autodetect", "max_workers": 8},
  "profiles": {"default": {}, "site_b": {"conn_timeout": 20}},
  "devices": {}
}
```

Inventory chọn tài khoản bằng tên profile:

```csv
name,ip,netmiko_device_type,profile
SW-A,192.0.2.1,cisco_ios,default
SW-B,192.0.2.2,huawei,site_b
```

Agent vẫn có thể truyền `profile` vào các tool hiện có. Thứ tự chọn: profile truyền trong tool → profile thiết bị/CSV → default. Profile chỉ có trong credentials.json cũng được sử dụng, không cần khai báo lặp trong devices.json.

## Dùng chung giữa các client

Cho mỗi client chạy cùng backend và trỏ tới cùng file:

```powershell
python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv --credentials-file "D:/NetworkPrivate/credentials.json"
```

Dùng đường dẫn tuyệt đối tới Python, bootstrap, config và inventory trong launcher của client nếu working directory khác repository. Client chỉ cần khai báo command/args, không cần chứa username/password. Cách đặt command/args phụ thuộc client; giao diện stdio và 10 tool không thay đổi.

Có thể cấu hình `NETWORK_MCP_CREDENTIALS_FILE` cho mọi tiến trình, hoặc chỉ đặt `credentials_file` trong config chung để không phụ thuộc environment từng client. Bootstrap, backend trực tiếp, scanner và validate_fleet đều hỗ trợ `--credentials-file`.

Thứ tự tìm file: `--credentials-file` → `NETWORK_MCP_CREDENTIALS_FILE` → `credentials_file` trong config → tự tìm credentials.json cạnh config. Các đường dẫn tương đối tính từ thư mục config, không theo working directory của client. Không có config thì dùng thư mục backend. File được chỉ định rõ mà thiếu/sai sẽ báo lỗi; không âm thầm dùng tài khoản khác. Không có file tự tìm thì giữ nguyên luồng legacy.

Credential ngoài thay trọn bộ auth của profile cùng tên trong config; giữ driver/port/timeout của profile đó. Credential riêng khai báo trực tiếp tại device vẫn là override để tương thích. Muốn quản lý tập trung hoàn toàn, chuyển auth khỏi defaults/profiles/device vào credentials.json và giữ tên profile trong CSV. Config/environment/input/ssh.txt cũ tiếp tục dùng được với các profile chưa chuyển. Không tự chuyển dữ liệu triển khai riêng hoặc sửa launcher của client khi chưa có file triển khai tương ứng.

## Kiểm tra không SSH

```powershell
python mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv --credentials-file "D:/NetworkPrivate/credentials.json" --check
```

`--inventory-csv` có thể bỏ khi dùng bootstrap với target động hoặc chỉ có thiết bị trong config. Check kiểm tra credential của các thiết bị đã nạp, không xác nhận password đúng trên thiết bị. Nếu không có thiết bị, kết quả check không kiểm chứng credential của target động tương lai. Chỉ xuất số lượng/profile, không xuất password. Không commit file private; không cần dán tài khoản vào chat. Resume vẫn kiểm chứng identity hiện có; đổi tài khoản có thể làm identity của kế hoạch khác đi.

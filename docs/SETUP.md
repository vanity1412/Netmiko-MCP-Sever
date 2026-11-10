# Cài mới và kiểm tra không SSH

Yêu cầu Python 3.10+ và mạng để tải dependency. Tải ZIP từ GitHub rồi giải nén hoặc clone repository. Các file inventory, credential và known_hosts thật không được phát hành; mỗi người tự cấp thông tin của mình. Không cần Node/OpenCode để dùng backend với Codex.

## Windows PowerShell

Mở terminal tại thư mục source vừa tải:

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
Copy-Item mcp/devices.example.json mcp/devices.json
Copy-Item mcp/credentials.example.json mcp/credentials.json
```

Không copy đè file private đã có khi nâng cấp. Sửa `mcp/credentials.json`, thay hai tham chiếu môi trường bằng tài khoản của bạn, ví dụ cấu trúc:

```json
{"profiles":{"default":{"username":"YOUR_SSH_USER","password":"YOUR_SSH_PASSWORD"}}}
```

Hoặc giữ file mẫu và đặt `$env:NETWORK_SSH_USER` và `$env:NETWORK_SSH_PASSWORD` trong môi trường khởi chạy MCP. Mẫu chỉ có `default`, không cần cấp biến cho một site không sử dụng. Xem [credential nhiều profile](CREDENTIALS.md) nếu cần.

```powershell
./.venv/Scripts/python.exe mcp/check_install.py --config mcp/devices.json
```

## Linux/macOS

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
cp mcp/devices.example.json mcp/devices.json
cp mcp/credentials.example.json mcp/credentials.json
# Sửa mcp/credentials.json theo hướng dẫn trên trước khi kiểm tra.
./.venv/bin/python mcp/check_install.py --config mcp/devices.json
```

Linux cần gói venv của bản phân phối nếu `python3 -m venv` chưa có. Các lệnh copy phía trên chỉ dùng khi cài mới.

## Có CSV hoặc không có CSV

Không cần CSV nếu agent nhận target/driver theo yêu cầu. Nếu dùng CSV, tự tạo `input/device.csv`:

```csv
name,ip,netmiko_device_type
LAB-JUNOS,192.0.2.1,juniper_junos
LAB-UNKNOWN,192.0.2.2,
```

Đây là địa chỉ ví dụ, không phải thiết bị truy cập được. `name,ip` bắt buộc; `netmiko_device_type` tùy chọn, nên điền đúng driver khi biết. Ô trống/thiếu cột dùng autodetect khi thực sự kết nối, không dò trong lúc nạp CSV. `profile,port` tùy chọn; mặc định profile `default`, port 22. Giữ nguyên driver đã điền; backend không tự sửa driver tường minh khi bị lỗi.

Thêm `--inventory-csv input/device.csv` vào lệnh kiểm tra và command MCP nếu muốn nạp inventory. Không truyền cờ này nếu chưa tạo CSV.

## Kiểm tra đạt chứng minh điều gì?

`check_install.py` kiểm tra cấu hình bằng bootstrap, sau đó thực hiện initialize, tools/list và ssh_status qua STDIO. Kết quả đạt có `mcp_connected=true`, `tools=10`, `ssh_tested=false`. Nó không gửi lệnh SSH, không thử password lên thiết bị, không gửi email. Khi lỗi, exit code là 1 và không in stderr chứa thông tin private.

Chạy `python mcp/collector_backend.py --check` chỉ kiểm tra dependency/version; không chứng minh MCP client kết nối được. Chạy `bootstrap.py --check` chỉ kiểm tra cấu hình, không kiểm chứng giao thức MCP hoặc xác thực thiết bị. Nếu dùng target động, các kiểm tra cài đặt không xác minh profile của mọi target tương lai.

Sau khi đăng ký MCP trong client, kiểm tra client thấy 10 tools và gọi được ssh_status. Chỉ thử SSH trên target người dùng đã cho phép; SUCCESS cần CLI không lỗi và output đầy đủ. Thiếu quyền, auth reject, TCP timeout và output thiếu là các kết quả khác nhau. Tài khoản đúng trên file chưa chứng minh đúng trên thiết bị; cần đường mạng/VPN/bastion phù hợp.

Nếu chạy bootstrap thủ công rồi thấy nó chờ, đây là server STDIO chờ JSON-RPC, không phải treo. Hãy để MCP client khởi chạy nó. Dùng đường dẫn tuyệt đối tới Python trong venv, bootstrap, config và CSV để tránh lỗi working directory. Sau khi đổi credential/code phải restart MCP.

Mặc định redaction_enabled=false: output, structured result, evidence và lỗi/audit giữ nguyên dữ liệu credential nếu thiết bị trả về. Chỉ che khi người triển khai chủ động bật true.

# Dùng Netmiko MCP với Codex

Hoàn tất [cài đặt và check không SSH](SETUP.md) trước. Codex và Netmiko chạy trên cùng máy có quyền truy cập thiết bị; cần tài khoản Codex hoạt động. Repository này cung cấp backend, không chứa Codex, tài khoản model hay credential SSH thật.

Theo [tài liệu MCP chính thức của OpenAI](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), cấu hình server ở `~/.codex/config.toml` hoặc `.codex/config.toml` của project được tin cậy. Có thể dùng giao diện MCP của client hoặc `codex mcp add`. Không dán mẫu MCP JSON của client khác vào TOML.

## Windows

Ví dụ source đặt ở `C:/NetmikoMCP`; thay bằng đường dẫn tuyệt đối thật, kể cả khi có khoảng trắng:

```toml
[mcp_servers.netmiko]
command = "C:/NetmikoMCP/.venv/Scripts/python.exe"
args = ["-u", "C:/NetmikoMCP/mcp/bootstrap.py", "--config", "C:/NetmikoMCP/mcp/devices.json"]
```

Hoặc chạy trong PowerShell đã cài Codex CLI:

```powershell
codex mcp add netmiko -- 'C:/NetmikoMCP/.venv/Scripts/python.exe' -u 'C:/NetmikoMCP/mcp/bootstrap.py' --config 'C:/NetmikoMCP/mcp/devices.json'
```

## Linux/macOS

Ví dụ source ở `/home/your-user/NetmikoMCP`, thay đường dẫn theo máy:

```toml
[mcp_servers.netmiko]
command = "/home/your-user/NetmikoMCP/.venv/bin/python"
args = ["-u", "/home/your-user/NetmikoMCP/mcp/bootstrap.py", "--config", "/home/your-user/NetmikoMCP/mcp/devices.json"]
```

```sh
codex mcp add netmiko -- /home/your-user/NetmikoMCP/.venv/bin/python -u /home/your-user/NetmikoMCP/mcp/bootstrap.py --config /home/your-user/NetmikoMCP/mcp/devices.json
```

Chọn một cách đăng ký, không tạo hai server trùng tên. Có CSV thì thêm `--inventory-csv` và đường dẫn tuyệt đối tới CSV vào cuối args/command. Không có CSV thì bỏ cờ đó. Username/password lấy từ credentials.json thông qua devices.json, không cần đặt vào config Codex.

Restart/kết nối lại MCP sau khi đổi cấu hình. Đợi server khởi tạo rồi xác nhận 10 tools; gọi ssh_status kiểm tra backend version. Với Codex mở repository như workspace, đọc AGENTS.md và mcp/WORKFLOW.md; nếu workspace khác, yêu cầu agent đọc các file đó bằng đường dẫn đầy đủ trước khi thao tác mạng. Kết nối MCP không tự chèn mọi Markdown vào context.

Ví dụ yêu cầu đầu tiên: “Chỉ kiểm tra ssh_status và inventory, chưa SSH và không gửi email.” Khi cần SSH thật, chỉ định target, mục tiêu/lệnh đọc và phạm vi được phép; backend không lọc nội dung CLI. Không coi MCP connected là SSH thành công.

Nếu server không khởi động: kiểm tra Python trỏ đúng venv có Netmiko, đường dẫn tồn tại, credential đủ, CSV hợp lệ và project được tin cậy khi dùng cấu hình project. Dùng cùng Python/args chạy check_install.py bên ngoài Codex để tách lỗi cài đặt backend khỏi lỗi cấu hình client. Chỉ định Python của máy đang chạy MCP (Windows hoặc Linux/WSL tương ứng), không trộn đường dẫn hai môi trường.

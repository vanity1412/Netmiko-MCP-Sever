# Agent guide

## Mục tiêu

Netmiko MCP là backend SSH phục vụ kỹ sư NOC và agent: thực thi CLI, cấu hình và thu thập nhiều thiết bị và xử lý dữ liệu. Trả lời theo ngôn ngữ người dùng. Chủ động kiểm chứng, phân biệt dữ liệu thật, mô phỏng và nhận định chưa xác minh.

## Chạy dự án

- Cài dependency: `python -m pip install -r requirements.txt`.
- Cấu hình riêng: copy `mcp/devices.example.json` thành `mcp/devices.json`; copy `mcp/credentials.example.json` thành `mcp/credentials.json` và cấp tài khoản theo profile; environment/inline legacy vẫn được hỗ trợ. Xem `docs/CREDENTIALS.md`. Inventory CSV dùng `name,ip,netmiko_device_type`, tùy chọn `profile`.
- MCP: `python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv`.
- Kiểm tra version/dependency: `python mcp/collector_backend.py --check`.
- Test: `python -m unittest discover -s tests -v`. Chỉ dùng mock và SSH localhost; không cần inventory/credential production.
- Xem `docs/ARCHITECTURE.md`, `docs/SCAN.md` và `CHANGELOG.md` trước khi đổi luồng kết nối.

## Khi thao tác thiết bị

- Đọc và áp dụng [mcp/WORKFLOW.md](mcp/WORKFLOW.md) khi xử lý kết quả, phục hồi lỗi và kiểm chứng mục tiêu. Workflow không tự chạy trong backend; giữ nguyên 10 tools.

- Dùng alias/IP/hostname do người dùng yêu cầu. Chọn driver từ inventory hoặc autodetect; không cần thêm target vào CSV.
- Tận dụng session, dùng batch và song song có giới hạn. Tool không lọc nội dung lệnh. Agent quyết định lệnh đọc/cấu hình theo yêu cầu người dùng; không tự chạy production trong test phát triển.
- Chỉ coi thu thập thành công khi CLI không báo lỗi và output có prompt cuối. Echo không bắt buộc. Thiếu output hoặc không truy cập được không đồng nghĩa dịch vụ down.
- Giữ output dở dang và lỗi theo từng đích. Không đoán credential, không tự thử nhiều tài khoản. Host key mới/đổi được backend chấp nhận và lưu; lỗi persistence có warning.
- Chỉ SSH production khi yêu cầu công việc có phạm vi tương ứng. Các test phát triển không tự truy cập production.

## Khi sửa source

- Giữ tên/schema 10 MCP tool, JSON-RPC UTF-8 và tương thích Python 3.10+ trừ khi người dùng yêu cầu đổi.
- Giữ session isolation theo host/port/driver/credential, timeout, retry có giới hạn, checkpoint và kiểm chứng bằng chứng khi resume.
- Sửa test khi hành vi chủ đích thay đổi; không xóa test chỉ để làm bộ kiểm thử đạt. Chạy kiểm thử phù hợp trước commit.
- Không commit inventory, credential, private key, known_hosts, cache, runtime, log hoặc output thiết bị. Không đưa dữ liệu thật vào fixture.
- Báo rõ thay đổi, kết quả kiểm thử và hạn chế. Không tự gửi email/thông báo hoặc phụ thuộc dịch vụ cá nhân ngoài yêu cầu của người dùng.

# Netmiko MCP 1.3.0

1.2.2 cho phép `/` và `:` trong đối số interface/prefix và regex có pipe trong dấu nháy. Pipeline ngoài dấu nháy vẫn phải thuộc whitelist; không hỗ trợ escape/backslash hoặc lệnh ghi file. Nhóm RSVP/BFD/multicast Junos được bổ sung. Autodetect khóa theo identity thay vì khóa toàn collector. Không sửa trust store, inventory hoặc tài khoản.

Giữ nguyên 10 tên tool, schema, STDIO JSON-RPC và session pool. Bản này siết chính sách đầu vào: API cũ vẫn gọi được, nhưng CLI không nằm trong grammar chỉ đọc sẽ trả lỗi. Không có cách bỏ policy qua tool argument.

## Chính sách

- Junos: các nhóm `show` được duyệt; Cisco: các nhóm `show`; Huawei: các nhóm `display`. Linux chỉ có danh sách nhỏ lệnh quan sát cố định. Driver chưa được duyệt bị chặn; generic_termserver được chuyển qua autodetect trước khi chọn grammar. Autodetect vẫn giữ nguyên probe/cache/deadline trước khi chọn policy.
- Chặn lệnh viết, viết tắt, chuỗi lệnh, shell expansion, redirection, pipeline không được duyệt và đường dẫn file. Đây là lớp giảm rủi ro, không thay cho tài khoản AAA chỉ đọc. Khi thêm cú pháp hãng/phiên bản mới phải review và thêm regression.
- `ssh_interact` chỉ nhận chuỗi lệnh đọc độc lập, xác minh từng bước; không nhận Enter/yes/password hay phiên cấu hình. Fail sớm khi CLI lỗi, thiếu echo, prompt thay đổi hoặc có confirmation/pager.
- Mọi kết nối mới cưỡng chế strict host key; cả profile cũ đặt false cũng không được bỏ strict. Bootstrap dùng `mcp/ssh/known_hosts` tuyệt đối. Không tự thêm hoặc thay key. Không sửa trust store trong lần nâng cấp này.
- Read-only là ngoại trừ setup session Netmiko có thể gửi lệnh terminal/session-local (ví dụ Junos set cli screen-length), không phải cấu hình persistent.

## Triển khai có kiểm soát

1. Không reconnect/reload process đang có công việc. Source mới không tự thay module đã import trong process cũ.
2. So fingerprint file với nguồn quản trị độc lập; coverage hiện chỉ 1793/3222 alias có key, không đồng nghĩa 1793 key đã được xác nhận nguồn gốc.
3. Thiết bị thiếu/sai key sẽ bị từ chối ở process mới. Hoàn tất xác nhận/enroll key qua quy trình quản trị trước khi quét diện rộng; không dùng ssh-keyscan làm bằng chứng danh tính độc lập.
4. Chạy test và smoke ở process riêng. Khi sẵn sàng, operator reconnect riêng MCP trong cửa sổ không có công việc; xác nhận version bằng ssh_status. Không tự kill OpenCode/Web.

## Concurrency và deadline

STDIO có tối đa max_workers request chạy và max_workers request chờ; quá tải trả lỗi rõ. Ping/initialize/list/status/inventory không phải xếp hàng sau SSH. Responses có thể khác thứ tự request, JSON-RPC id giữ nguyên. Parallel dùng executor chung thay vì nhân một pool cho mỗi request; semaphore toàn collector chặn vượt số lease đồng thời. Session lock vẫn serialize IO từng transport.

`request_timeout_seconds` mặc định 120 giây, tính từ nhận request; chờ lease/slot, autodetect process và send kiểm tra thời hạn. `notifications/cancelled` dùng params.requestId. Cancellation mang tính cooperative: không cưỡng bức kill thread/socket từ dispatcher; lệnh đang I/O có thể chờ đến Netmiko timeout. Session preparation và regex Python chưa có hard wall deadline. EOF chờ worker hoàn tất rồi đóng riêng session của process đó.

## Test

`python -m unittest discover -s mcp/tests -v`

Tests dùng fake connection và SSH server localhost sinh key tạm; không gửi lệnh nguy hiểm tới thiết bị thật. `python mcp/check.py --ssh` dùng thiết bị Junos cố định theo script; chỉ chạy khi được phép. Không in credential trong CLI.

Redaction dùng chung `redact_text` cho output, audit/error và sender email hiện có. Structured output dùng recursive sanitizer để không hỏng JSON framing. Đây vẫn là best-effort; bảo vệ ACL credential/output, không công khai dữ liệu thô. Không có thay đổi sender/dedup hoặc email thật trong nâng cấp.

1.2.3: generic_termserver được autodetect trước policy, regex search chạy process riêng tối đa 2 giây, auth failure suppress 5 phút theo identity. Entry host key vẫn cần xác minh độc lập; coverage cũ là snapshot, không phải cam kết kết nối.

## Scanner 1.3

Xem SCAN.md về ngân sách fast/slow, loại lỗi, resume và giới hạn thực tế. Detection/collection cùng dùng semaphore SSH. Python execute/batch/interact/parallel có request budget dù không gọi qua STDIO. Regex search vẫn dùng process riêng. Không hạ kiểm chứng echo/prompt, không thay trust provisioning để tăng tỷ lệ thành công. Session preparation/network I/O còn cooperative, không cam kết hard deadline hoặc SSH thành công mọi thiết bị.

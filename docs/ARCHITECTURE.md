# Cải tiến storage, evidence và đo hiệu năng

Shared output dùng output_storage.py: transaction OS liên tiến trình bao quanh quota/cleanup/publish; pin 300 giây được lưu xuống đĩa, 64 stripe lock bảo vệ reader/search/export. Atomic publish không để lộ file .txt ghi dở. Scanner retire scratch qua cùng khóa, chỉ sau khi evidence đã được lưu. Exclusive vẫn dành cho một Collector. Cần restart mọi process dùng chung thư mục và dùng cùng quota/TTL; process bản cũ không tham gia khóa mới.

Mặc định redaction_enabled=false, giữ username/password/hash/secret/token trong dữ liệu CLI, structured result, evidence và lỗi/audit. Cấu hình true tường minh vẫn hỗ trợ như trước. Khi persistence thất bại, giữ toàn bộ output đã nhận trong lỗi, không tự SSH lại; việc này có thể tăng kích thước response lỗi.

telemetry.py giữ 128 mẫu gần nhất mỗi pha và tổng count/failures/total_ms; status có phase_metrics, kết quả có timings_ms/connection_timings_ms/session_reused. Đo Paramiko connect và _auth, Netmiko _try_session_preparation để không làm mất dispatch vendor khi redispatch. Các pha có thể lồng nhau. Không thêm lệnh SSH để đo, không thay timeout/worker, không suy diễn timing bị thiếu thành 0. Test 500/2.500 thiết bị dùng mock transport, theo dõi tài nguyên process; không đại diện cho tải AAA/SSH thực.

# Permission diagnostics and agent workflow — 1.9.1

CLI response classification adds error_reason=permission_denied/syntax_error/command_failed while retaining CLI_ERROR and error_category=cli_error. Normalization removes stale reasons on success or non-CLI failure. Existing batch stop, session retention and retry behavior stay unchanged. Permission classification uses recognized diagnostic lines and access-denied RPC error tags, not arbitrary payload words; it remains heuristic.

[mcp/WORKFLOW.md](../mcp/WORKFLOW.md) guides agents through evidence, fault status, recovery limits and post-command checks; AGENTS.md links it. This Markdown is agent guidance, not a new backend execution stage or runtime orchestrator. No new tool/input schema or connection architecture changes.

# Shared credentials — 1.9.0

load_config is the shared credential loading boundary for bootstrap, direct backend, scanner and fleet validator. External profile auth replaces inline auth atomically while preserving connection-only fields. Credential files stay local/ignored, are read once at startup and never appear in MCP tool schemas. Each process owns its own session pool. See [credential setup](CREDENTIALS.md).

# Reliability 1.8.2

Pool capacity waits now obey the request deadline/cancellation without holding the registry lock or SSH semaphore. Probe adoption waits after releasing its SSH slot; leased entries are never evicted.

Reader retains late data after a prompt candidate and marks an ambiguous transcript as incomplete (output_verification, not automatically retryable). Prompt candidates settle for at least 300 ms; structured XML/JSON/banner guards remain. A quiet period cannot prove completion against an arbitrarily delayed device that emits an exact prompt as data. Partial output is preserved; no sentinel commands or implicit confirmation responses are injected.

Scanner --device-timeout defaults to --slow-timeout (240 seconds). Fast and slow attempts share this budget, including pool wait, execution, export and time between attempts after the first dispatch. Initial fleet queue time and time while the process is stopped are excluded. Checkpoints preserve consumed time for retry_pending; explicit --retry-status starts a new authorized cycle. Exhaustion prevents another SSH attempt and retains evidence/prefix. Configuration with uncertain effects is never automatically replayed.

Deadlines are cooperative for direct Netmiko connections: a blocking library/OS call may return late. Late completion is recorded with device_budget_exceeded; verified output remains available. Probe subprocesses retain their existing hard timeout. This change does not promise hard preemption of an in-flight direct connection.

# Cập nhật 1.8.1

Result normalization recalculates pending summaries from current results. Parallel/batch pending tasks are identified at all positions by task_id or response index plus target. Interact only leaves its last question pending while retaining historical steps. Successful complete results clear obsolete error diagnostics.

Credential merge separates auth fields from connection settings. A profile/device defining auth selects its own complete password/key/agent bundle; a connection-only profile inherits the whole prior bundle. Explicit boolean inherit_credentials opts into field merging. No separate credential loader is added; use a private config path shared by clients. Existing retry/resume and all ten schemas remain unchanged.

# Kiến trúc hiện tại — 1.8.0

result_status.py chuẩn hóa kết quả thực thi theo status/fault_status/data_state/execution_state, không thay schema tool hoặc trạng thái checkpoint cũ. Reader dùng OutputBuffer (spool) và metadata pager spans; worker queue hữu hạn và không gửi lại toàn text ở gói cuối. Sau I/O vẫn tạo string cho verification/redaction/parse. Các lỗi file buffer được phân loại persistence.

Lease wrapper chỉ refresh driver suy ra từ cache/session khi lỗi preparation xảy ra trước yield, sau khi lease cũ đã được giải phóng. Nó invalidate RAM/SQLite, bỏ qua stale disk entry trong lần probe cưỡng bức và chỉ thử một lần. TCP/auth/CLI lỗi và driver tường minh không kích hoạt fallback này. Session đang hoạt động được ưu tiên hơn cache và không bị probe vào câu hỏi đang chờ.

Execute đơn có một recovery cho truy vấn đọc mất transport; dữ liệu cũ giữ trong previous_attempt hoặc response hiện tại nếu không còn budget. Scanner dùng execute_many và tự sở hữu retry để không retry chồng. Metadata command_sent/replay_safe và lỗi thật được giữ; cấu hình chưa rõ kết quả không tự chạy lại. Xem README cho bảng trạng thái và giới hạn.

# Luồng nền tảng — 1.7.0

MCP giữ nguyên 10 schema. Agent chọn CLI đọc/cấu hình; backend kiểm tra framing, identity, lease và kết quả, không áp policy nội dung. Cập nhật này không benchmark hoặc đổi pool/storage.

Reader theo prompt family khi đổi mode, giữ pending input để agent trả lời, giữ unattributed preceding output. Worker trả prompt/command_sent về proxy. Custom expect không thay thế identity prompt. Config banner và XML/JSON được kiểm tra đóng container trước completion.

Scanner lưu next_command_index và cycle_attempts. Task đọc retry từ prefix đã hoàn tất, success được giữ; explicit retry_statuses mở một chu kỳ mới cho failed/partial/unknown. Replay lệnh không chắc chắn cần agent chủ động replay_uncertain; toàn batch được chạy lại để không mất context mode. Export pending được phục hồi không qua SSH. Kiểm chứng hash/identity/lock không bị bỏ.

Phần bên dưới mô tả luồng và lịch sử; các ràng buộc read-only cũ đã được thay thế bởi 1.7.0 và README hiện tại.

## Đọc theo thứ tự

1. README.md: danh sách source và dependency.
2. docs/ARCHITECTURE.md: luồng chạy và điểm sửa (file này).
4. docs/SCAN.md: job runner, retry, bằng chứng và resume.
5. CHANGELOG.md: lịch sử thay đổi.

Regression và integration SSH localhost nằm trong tests; chạy `python -m unittest discover -s tests -v`.

## Ba đường gọi

MCP client → STDIO JSON-RPC → bootstrap.py → Collector trong collector_backend.py → Netmiko → Paramiko → SSH thiết bị.

Python fallback → ReadOnlyConnection trong readonly_client.py → cùng Collector → cùng policy SSH/CLI.

Scanner CLI → scan.py → Collector → kết quả từng task + bằng chứng + summary. Scanner không phải tool MCP thứ 11.

bootstrap.py nạp environment, cấu hình JSON và inventory CSV tùy chọn. Khi thiếu cặp NETWORK_SSH_USER/PASSWORD, fallback input/ssh.txt; hiện chỉ chọn cặp đầu tiên, không tự thử tất cả cặp. Credential mẫu dùng tham chiếu environment trong credentials.example.json, không có credential thật.

## Trách nhiệm và điểm cần tìm trong source

| File / hàm | Vai trò |
|---|---|
| bootstrap.py / prepare_environment, main | Credential precedence, đường dẫn root và bật private host-key file |
| collector_backend.py / load_config, load_inventory_csv | Nạp JSON, expand environment, merge alias/IP/driver |
| Collector._get_settings | Ghép defaults → profile → device → override; chấp nhận host key và chọn file persistence riêng |
| Collector._session_key | Identity cho session cache; thay policy phải tránh tái dùng transport cũ |
| Collector._resolve_platform, detection_worker | Autodetect bằng probe đọc trong process riêng, có ngân sách thời gian |
| probe_session.py / ProbeSession, main | Worker giữ SSH từ probe qua redispatch và thu thập; parent kiểm soát deadline, truyền partial output qua pipe |
| Collector._open, lease/session helpers | Mở SSH, xác minh prompt, giới hạn số phiên và reuse |
| readonly_command, cli_pipeline | Tên compatibility cho kiểm tra framing; từ 1.7.0 không lọc nội dung lệnh |
| Collector._send, read_cli_output | Đọc Netmiko channel, chờ prompt cuối, chuyển trang, giữ partial output và kiểm soát timeout |
| Collector._result | Kiểm tra echo, prompt cuối, dấu CLI error và pager/confirmation |
| classify_error | Phân loại lỗi SSH/TCP/auth/host key, quyết định retryable |
| TOOLS, make_tool_list, run_stdio | 10 tool MCP, schema và dispatcher JSON-RPC |
| readonly_client.py / send_command | Wrapper Python, hiện lỗi CLI chỉ ném RuntimeError theo tên lỗi |
| scan.py / prepare_tasks, _attempt, run_scan | Kiểm tra plan, fast/slow lanes, retry có chọn lọc, export/checkpoint |

## 10 tool đang có

- ssh_execute: một lệnh CLI do agent chọn, có thể đọc hoặc cấu hình.
- ssh_execute_many: nhiều lệnh đọc/cấu hình trên cùng thiết bị.
- ssh_interact: chuỗi lệnh/phản hồi rõ ràng; nhận yes/Enter do agent cung cấp, không tự trả lời.
- ssh_parallel: nhiều task độc lập.
- ssh_read_output, ssh_read_output_bytes: đọc output lớn theo dòng/byte.
- ssh_search_output: tìm trong output đã lưu.
- ssh_inventory: tra inventory.
- ssh_status: trạng thái collector/session.
- ssh_close: đóng session.

## Dữ liệu triển khai riêng (không đi kèm source công khai)

- input/device.csv: tối thiểu name,ip,netmiko_device_type.
- input/ssh.txt: nguồn credential fallback, không đưa lên Git.
- mcp/devices.json: cấu hình triển khai tạo từ devices.example.json.
- mcp/ssh/known_hosts: trust store. Bootstrap/scanner/fallback trỏ tới file này.
- runtime/data/netmiko/: dữ liệu local/session evidence theo cấu hình.
- output/<job>/: manifest, task result, bằng chứng và summary của scanner.

Đường dẫn dùng root tương đối từ vị trí source. MCP client cần working directory là thư mục Netmiko-MCP; command python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv. Có client cần đường dẫn tuyệt đối trong cấu hình.

Inventory, credential, known_hosts, runtime và output được cung cấp riêng tại môi trường triển khai, không được theo dõi trong Git. Dữ liệu lịch sử không đại diện cho phiên SSH hoặc trạng thái thiết bị hiện tại.

## Lịch sử chính sách đến 1.6.1

- Backend, Python fallback và subprocess autodetect cùng chấp nhận host key mới/đổi, lưu theo SSH client dưới khóa file liên tiến trình. Lỗi ghi store tạo warning và không chặn kết nối.
- Không patch AutoAddPolicy toàn cục; mỗi Netmiko client có policy giữ đường dẫn store riêng. File được đọc/merge lại khi đang giữ lock rồi atomic replace.
- Output cần prompt cuối của phiên và không có CLI error/confirmation/pager chưa xử lý; echo không bắt buộc. Chỉ có echo không đủ để báo thành công.
- Reader không gửi lại lệnh khi thiếu output; tự gửi Space cho phân trang. Timeout/cancel giữ partial output; batch dừng và đóng transport trước driver cleanup để tránh gửi exit vào confirmation.
- EOF/closed channel được phát hiện ngay. Chỉ các footer pager thực sự được xử lý mới bị loại khỏi output; chuỗi giống pager trong dữ liệu vẫn giữ nguyên. Câu hỏi password/confirmation dừng thu thập mà không gửi phản hồi.
- global_cmd_verify mặc định false cho session preparation; wrapper terminal-width đọc tới prompt thay vì đợi echo. Kiểm chứng output lệnh thu thập vẫn dựa vào prompt cuối.
- CLI error thật khác lỗi xác minh output. Chưa đọc account không có nghĩa account rỗng.
- Scanner có fast/slow lanes; retry tối đa một lần cho TCP/banner/read/auth timeout. Authentication rejected/auth_method dùng auth_failure_cooldown_seconds và không retry. Resume bỏ qua failed/partial đã lưu.

CSV hỗ trợ profile tùy chọn; thiếu dùng default. Mapping thật cần khai báo theo thiết bị, không tự đoán hoặc thử tất cả credential. Bootstrap không bắt cặp credential toàn cục khi profile đã có credential riêng.

Các tùy chọn tối ưu 1.4.0 (quiet, health check định kỳ, redaction, store theo process, cooldown và ưu tiên driver inventory) được mô tả trong README.md. Ở các bản cũ thông báo lỗi và audit command luôn được che; hiện redaction_enabled=false giữ nguyên dữ liệu ở cả các đường này.

1.5.0: SQLite lưu driver đã xác minh theo hash endpoint/auth/route và TTL; tách cache driver khỏi location known_hosts để các job dùng cùng cache. Output exclusive có index RAM, quota check mỗi ghi và reconcile định kỳ; shared vẫn đối soát file.

1.6.0: `ProbeSession` sở hữu worker từ lúc SSH bắt đầu đến khi session đóng. Worker dùng `detection_worker(connection_sink=...)` và redispatch cùng Netmiko object; parent đưa proxy vào pool theo đúng identity driver/credential/endpoint. Không serialize hay chuyển SSH socket giữa process. Session lease vẫn tuần tự hóa CLI; semaphore giới hạn công việc SSH đang hoạt động. Cache hit không probe và mở phiên thu thập trực tiếp khi pool chưa có phiên.

Worker truyền chunk ngay khi reader nhận được, rồi trả output đã xử lý pager và failure. Parent chỉ nhận kết quả cuối khi vẫn còn request budget; EOF/hard timeout/cancel trả partial kèm failure dù partial chứa prompt. Thời gian kill/reap process là phần cleanup có giới hạn. TTL/eviction/close/shutdown đóng worker qua cùng lifecycle của session pool. Mỗi phiên probe giữ một process + receiver thread, cần cân nhắc RAM khi tăng max_sessions. `--detect-worker` một lần và custom detect factory vẫn tương thích; custom factory không hỗ trợ giữ lại phiên.

1.6.1: chế độ compatible mặc định hoặc strict chủ động; profile CLI options tách khỏi kwargs SSH, auto_enable Cisco tùy chọn. Reader kiểm tra banner configuration trước khi chấp nhận prompt. Parser/persistence chỉ giữ session đã đồng bộ; slow-lane transient retry tối đa hai attempt. Xem README cho phạm vi và giới hạn.

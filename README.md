# Netmiko MCP Server

Giấy phép: [MIT](LICENSE).

Backend **1.9.1**: thực thi CLI và cấu hình nhiều thiết bị qua Netmiko, giữ **10 MCP tools**; `ssh_execute_many` thêm tùy chọn `continue_on_error` không bắt buộc.

## Batch: tiếp tục sau lỗi CLI và lệnh chưa gửi

`ssh_execute_many` mặc định `continue_on_error=false`: dừng ở lệnh không thành công. Kết quả giữ các lệnh đã thực thi và thêm một entry `SKIPPED` cho từng lệnh còn lại chưa gửi, có `command_index` (zero-based), `blocked_by_command_index`, `command_sent=false`, `execution_state=NOT_SENT`, `data_state=NONE`. Lỗi validation/kết nối trước khi vào batch vẫn trả lỗi khởi tạo, không tạo transcript giả cho các lệnh.

Agent có thể bật `continue_on_error=true` cho các lệnh độc lập:

```json
{"target":"LAB-A","commands":["show version","show clock","show interfaces"],"continue_on_error":true}
```

Chỉ chạy tiếp nếu lỗi thuộc CLI, transport còn khỏe, output đã đầy đủ, không chờ câu trả lời và reader không có lỗi. Timeout, disconnect, dữ liệu chưa hoàn tất, lỗi storage và câu hỏi tương tác vẫn dừng, phần chưa gửi là SKIPPED. Cấu hình có tác động không chắc chắn không được tự replay. Tham số này không phân tích tính độc lập của câu lệnh: agent phải xác định context/phạm vi; mặc định dừng vẫn phù hợp chuỗi cấu hình phụ thuộc.

Có SUCCESS và CLI_ERROR thì batch là PARTIAL, không phải SUCCESS; tất cả lỗi CLI thì là CLI_ERROR. SKIPPED không thay thế nguyên nhân lỗi của lệnh đã chạy. Lỗi CLI đã đọc đủ vẫn có thể giữ session để dùng tiếp. `ssh_parallel` cũng chuyển tiếp tùy chọn này cho task có `commands`. Scanner chưa bật tùy chọn này; vẫn dừng theo prefix, checkpoint/resume bỏ qua các entry SKIPPED và giữ lỗi thật. Không thay đổi mặc định không che dữ liệu.

## Thực thi do agent quyết định

Không còn allowlist/denylist nội dung lệnh. Agent có thể gửi show/display, configure, set, commit, save, shell command và pipeline do agent lựa chọn. Server không tự đổi abbreviation, sửa lệnh hoặc thêm count cho ping.

Chỉ kiểm tra framing: mỗi command là string một dòng, không rỗng, tối đa 8192 ký tự, không có ký tự điều khiển. Dùng execute_many cho batch tối đa 1000 lệnh; interact nhận tối đa 1000 bước, có thể dùng chuỗi rỗng hoặc newline làm Enter rõ ràng. Parallel tối đa 100 task mỗi lời gọi; scanner --all không có giới hạn số thiết bị này. Số kết nối đang làm việc vẫn theo max_workers để bảo vệ tài nguyên; không đổi pool/storage hoặc benchmark trong bản này.

Agent chịu trách nhiệm phạm vi lệnh và thay đổi cấu hình mà người dùng yêu cầu. Các test phát triển chỉ dùng mock/SSH localhost.

## Bắt đầu nhanh cho người mới

Xem [cài mới Windows/Linux và kiểm tra không SSH](docs/SETUP.md), [kết nối Codex](docs/CODEX.md) và [credential nhiều profile](docs/CREDENTIALS.md). File mẫu mặc định chỉ có profile `default`.

CSV bắt buộc `name,ip`; cột `netmiko_device_type` được khuyến nghị để tránh dò driver. Thiếu cột hoặc ô driver trống dùng `autodetect`; driver có sẵn được giữ nguyên. Không tự chạy các lệnh mẫu scanner chỉ để kết nối thiết bị đã biết driver.

## Cài và chạy

Python 3.10+, cài `python -m pip install -r requirements.txt`. Copy mcp/devices.example.json thành mcp/devices.json và mcp/credentials.example.json thành mcp/credentials.json; nếu dùng inventory CSV, cung cấp file riêng input/device.csv với name,ip và tùy chọn netmiko_device_type,profile,port; driver trống/thiếu dùng autodetect.

Khuyến nghị điền tài khoản theo profile trong file private credentials.json để mọi MCP client dùng chung. Cấu hình cũ qua NETWORK_SSH_USER/NETWORK_SSH_PASSWORD hoặc inline profiles vẫn được hỗ trợ. Bootstrap fallback cặp đầu tiên trong input/ssh.txt khi thiếu cặp môi trường. Không đưa credential, inventory, known_hosts, runtime hoặc output lên Git.

```powershell
python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv
python mcp/collector_backend.py --check
```

`--inventory-csv` là tùy chọn: bỏ tham số này để dùng thiết bị trong config hoặc target động qua MCP; thiết bị đã khai báo trong config vẫn được giữ. Nếu cung cấp CSV, bootstrap merge theo cơ chế backend hiện có và vẫn báo lỗi nếu file sai/không tồn tại.

Bootstrap chỉ đặt mặc định khi chưa có cấu hình: `NETWORK_MCP_DATA_DIR=runtime/data/netmiko`, `alt_key_file=mcp/ssh/known_hosts`, `alt_host_keys=true`. Giá trị environment và `defaults` do người dùng đặt được giữ nguyên tại bootstrap, kể cả `alt_host_keys=false`. Khi kết nối, backend suy ra các cờ kiểm tra host key từ `ssh_mode` theo bảng dưới.

Cập nhật toàn bộ mcp/ và restart MCP. Giữ devices.json cùng dữ liệu triển khai riêng; giữ launcher OpenCode Web và refresh tool catalog để nhận optional continue_on_error. Kiểm tra ssh_status.version=1.9.1.

## Cài mới không có inventory và kết nối MCP client

Ví dụ PowerShell, chạy tại thư mục source đã tải:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item mcp/devices.example.json mcp/devices.json
Copy-Item mcp/credentials.example.json mcp/credentials.json
```

Sửa file private `mcp/credentials.json` để chỉ giữ những profile thực sự dùng và cấp đủ tài khoản cho chúng. Ví dụ tối thiểu (thay placeholder trên máy của bạn):

```json
{"profiles":{"default":{"username":"YOUR_SSH_USER","password":"YOUR_SSH_PASSWORD"}}}
```

Giữ `devices: {}` và `credentials_file: "credentials.json"` trong config nếu dùng target động. Không cần tạo CSV. Nếu giữ các profile dùng `${ENV}` trong file example, phải cấp đủ biến môi trường cho từng profile; xem [cấu hình credential](docs/CREDENTIALS.md).

```powershell
.\.venv\Scripts\python.exe -u mcp/bootstrap.py --config mcp/devices.json
```

Đây là server stdio: khi chạy thủ công, tiến trình chờ JSON-RPC từ stdin. Trong MCP client, chọn transport stdio và cho client khởi chạy server. Mẫu command/args dưới đây cần thay đường dẫn tuyệt đối theo máy; vị trí đặt các trường tùy client:

```json
{
  "command": "C:/NetmikoMCP/.venv/Scripts/python.exe",
  "args": ["-u", "C:/NetmikoMCP/mcp/bootstrap.py", "--config", "C:/NetmikoMCP/mcp/devices.json"]
}
```

Client thực hiện initialize rồi tools/list; cần thấy 10 tools. Gọi ssh_status để kiểm tra version 1.9.1. Sau khi được cấp phạm vi thiết bị thật, gọi ssh_execute với target, command, device_type và profile phù hợp. Việc khởi động/stdin thành công chưa chứng minh SSH thiết bị thật hoạt động.

## Permission Detection và Agent Workflow — 1.9.1

Lỗi CLI giữ `status=CLI_ERROR` và `error_category=cli_error`, bổ sung `error_reason`: `permission_denied` (thiếu quyền), `syntax_error` (cú pháp được nhận diện), `command_failed` (lỗi CLI khác). Lỗi auth SSH vẫn là AUTH_ERROR. Phân loại dựa trên diagnostic CLI/RPC đã nhận diện, vẫn mang tính heuristic và giữ evidence để agent đối chiếu. Lỗi thiếu quyền có prompt hoàn tất không tự đóng session hoặc retry.

Agent áp dụng [mcp/WORKFLOW.md](mcp/WORKFLOW.md), được liên kết từ AGENTS.md: đọc từng kết quả, tránh retry chồng, xử lý câu hỏi/evidence và kiểm chứng mục tiêu sau cấu hình. Client không tự đọc AGENTS.md cần đưa hai file này vào instructions/context của agent. Backend không tự chạy workflow và không thay schema 10 tools, Reader, pool, semaphore hay cơ chế retry hiện có.

## Credential dùng chung — 1.9.0

`devices.json` giữ tham số kết nối, `device.csv` chọn profile, `credentials.json` giữ tài khoản. Backend tự tìm file cạnh config; có thể dùng `--credentials-file` hoặc `NETWORK_MCP_CREDENTIALS_FILE` để chỉ tới file dùng chung ngoài repository. Profile ngoài thay trọn bộ auth, giữ cấu hình driver/timeout; file được chỉ định sai sẽ báo rõ, không dùng nhầm global. Các client giữ session pool riêng và cùng đọc một nguồn credential khi khởi động. Xem [hướng dẫn đầy đủ](docs/CREDENTIALS.md).

## Session, driver và profile

Driver inventory/cache được ưu tiên. Cold autodetect dùng worker probe và redispatch trên cùng kết nối, không đăng nhập lần hai. Autodetect nhận sáu driver Junos, IOS, XR, NX-OS, Huawei, Linux; driver Netmiko khác có thể chỉ định trực tiếp. Không có grammar theo hãng để chặn lệnh nữa.

Các lệnh trong một lease chạy tuần tự; thiết bị khác chạy song song. Dùng execute_many hoặc interact khi cần một chuỗi không bị yêu cầu khác chen vào. Giữ cùng target/profile/driver khi gửi phản hồi cho phiên đang chờ.

ssh_mode mặc định compatible: nhận key mới/đổi, lưu atomic, ghi nhận thay đổi fingerprint; lỗi lưu key không chặn SSH. strict là lựa chọn chủ động: phải có trusted key trong alt_key_file; dùng host_key_store_mode shared nếu muốn một file chung thay vì file theo PID.

| `ssh_mode` nội bộ | `ssh_strict` gửi Netmiko | `alt_host_keys` | `system_host_keys` |
|---|---|---|---|
| `compatible` | `false` | `false` | `false` |
| `strict` | `true` | `true` | `true` |

Các cờ trên không hoạt động độc lập với `ssh_mode`; `false` không vô hiệu hóa strict. Compatible dùng policy tiếp nhận/lưu key riêng, nên `alt_host_keys=false` không tắt persistence. `ssh_mode` không truyền trực tiếp cho Netmiko. `alt_key_file` tùy chỉnh được giữ và chuẩn hóa thành đường dẫn tuyệt đối; `host_key_store_mode=process` thêm hậu tố PID chỉ trong compatible.

Lỗi đọc/xác minh phản hồi trong các bước preparation Junos và terminal-width Cisco trả `error_stage=preparation`, `ssh_authenticated=true`, `cli_ready=false`, `command_sent=false` cho lệnh nghiệp vụ chưa gửi. `output` giữ phản hồi preparation dở dang; chỉ che credential khi bật `redaction_enabled=true`; `preparation_command` chỉ rõ lệnh setup. Timeout và chính sách retry không thay đổi.

Profile/device hỗ trợ read_timeout, prompt_quiet_seconds, timing_quiet_seconds; tham số tool tường minh ưu tiên. Connection options gồm conn_timeout, auth_timeout, banner_timeout, key_file, passphrase, encoding, disable_sha2_fix, disabled_algorithms và ssh_config_file. Credential literal giữ nguyên; chuỗi ${ENV_NAME} nguyên vẹn lấy từ environment. auto_enable=true chủ động gọi enable cho Cisco bằng secret backend; mặc định false.

Request deadline mặc định 120s, read timeout mặc định 40s. Batch dài cần request_timeout_seconds phù hợp; tăng read_timeout không tăng request deadline. Đường worker có hard deadline; connect trực tiếp vẫn cooperative theo timeout thư viện.

## Reader và verification

Reader xử lý paging, giữ partial khi timeout/cancel/EOF, nhận mode prompt trong cùng thiết bị cho Cisco/Junos/Huawei. Banner Cisco chưa đóng và output XML/JSON chưa hoàn chỉnh không được kết thúc chỉ vì gặp một dòng giống prompt. Custom expect chỉ là ranh giới đọc; không được biến prompt thiết bị khác thành thành công.

Dữ liệu đã có trước khi gửi lệnh tiếp theo được giữ trong preceding_output hoặc preceding_output_id, gắn association unattributed, thay vì bị xóa âm thầm. Output dài được lưu theo output_id, đọc bằng các tool dòng/byte/search hiện có. Redaction output tùy chọn; error và audit command vẫn scrub credential.

Kết quả có prompt không chứng minh cấu hình đúng ý định: validation vẫn là heuristic CLI. Agent cần đọc phản hồi và dùng lệnh kiểm tra trạng thái để xác minh thay đổi thực tế. Prompt/firmware tùy biến ngoài các họ đã hỗ trợ có thể cần expect rõ ràng.

## Prompt hỏi và phản hồi rõ ràng

Thiết bị hỏi yes/no, confirm, password hoặc destination/source filename trả ok=false, awaiting_input=true và giữ session. Không tự gửi yes/Enter, không gửi driver cleanup vào câu hỏi. Lỗi CLI có prompt đầy đủ khác với phiên còn đang chờ input.

Dùng ssh_interact với các bước rõ ràng, ví dụ ["write memory", "yes"]. Chuỗi rỗng là Enter, chỉ được gửi khi agent cung cấp. Hoặc gọi ssh_execute để xem câu hỏi rồi gửi phản hồi ở lời gọi tiếp theo, cùng identity. expect_string có thể chỉ định prompt tương tác khác; match custom expect chưa phải hoàn tất lệnh. Execute_many mặc định dừng ở lỗi, và luôn dừng ở câu hỏi để agent kiểm tra; không coi lệnh tiếp theo là câu trả lời ngầm.

## Retry và resume

```powershell
python mcp/scan.py --plan plan.json --output output/JOB
python mcp/scan.py --plan plan.json --output output/JOB --execute
python mcp/scan.py --plan plan.json --output output/JOB --execute --retry-status failed partial
```

Giữ cùng plan/identity và thư mục job. Resume mặc định giữ các kết quả đã có. --retry-status chọn failed/partial/unknown để chạy lại, không chạy lại thiết bị success. Lệnh đọc đã hoàn tất được bỏ qua bằng command index; lịch sử và hash evidence được giữ. Retry transient tối đa hai attempt mỗi chu kỳ, không retry auth reject.

Không lọc lệnh cấu hình khi thực thi. Tuy nhiên, lệnh có thể đã thay đổi thiết bị mà bị timeout không được tự replay. Job trả unknown/needs_reconciliation khi resume không thể xác định tác động. Sau khi agent đối soát, --replay-uncertain cùng --retry-status cho phép chủ động chạy lại toàn batch không an toàn để replay, kể cả phần đã hoàn tất, nhằm dựng lại mode context. Không dùng flag này như retry mặc định.

Lỗi export evidence giữ raw output và export_pending. --retry-status unknown thử lại export trước, không gửi SSH lần nữa nếu chỉ thiếu export. Evidence đã hỏng hoặc thiếu vẫn làm resume thất bại; không xóa kiểm chứng để ép success.

## Storage và giới hạn

`output_storage_mode=shared` dùng khóa OS liên tiến trình để đồng bộ kiểm tra quota, ghi file và cleanup. File được ghi tạm rồi publish bằng atomic replace. Thời hạn bảo vệ output mới 300 giây được lưu trong `.storage/`; lease OS bảo vệ file đang đọc/search/export kể cả khi process khác cleanup. Process chết sẽ nhả khóa OS. Khóa chờ tối đa 5 giây và tuân theo request deadline/cancel; lỗi lưu được báo riêng, không tự gửi lại CLI.

Các process dùng chung thư mục cần cùng quota/TTL và cùng phiên bản có cơ chế khóa này. `exclusive` dùng index RAM cho một Collector sở hữu thư mục; không dùng cho nhiều process cùng ghi. Scanner có scratch riêng, quota/TTL và checksum checkpoint vẫn giữ. Khóa lease dùng 64 stripe cố định để giới hạn số file khóa; va chạm stripe có thể trì hoãn cleanup hoặc serialize lượt đọc. Không xóa file khóa khi process còn chạy. Quota áp dụng cho output `.txt`, không gồm audit log và metadata khóa.

Mặc định `redaction_enabled=false`: nội dung CLI, evidence, structured output, preparation evidence và nội dung lỗi/audit được giữ nguyên, kể cả username/password/hash/secret/token. Cấu hình cũ đặt rõ `redaction_enabled=true` vẫn có thể chủ động bật che dữ liệu. Khi ghi file thất bại, response lỗi giữ toàn bộ output đã nhận thay vì cắt thành preview; response lỗi lớn vì vậy có thể tốn RAM/băng thông. Reader vẫn chuẩn hóa ANSI/pager như trước; dữ liệu là transcript CLI đã chuẩn hóa, không phải bản chụp byte của SSH transport.

## Tương thích override redaction và báo cáo

Dùng `redaction_enabled=false` để giữ dữ liệu; không cần monkey-patch `redact_output`. Backend giữ keyword tùy chọn `force` cho caller cũ, nhưng các đường lỗi CLI/preparation nội bộ chỉ truyền message để tương thích override một tham số. Nếu có override tùy biến, nên giữ chữ ký `redact_output(self, message, *, force=False)`; traceback và đường dẫn module đang nạp giúp xác định code ngoài repository gây lỗi.

Các script tạo báo cáo/email riêng phải tự tuân theo cùng cấu hình. Gọi thẳng `redact_text()` luôn thực hiện redaction, không kiểm tra `redaction_enabled`. Backend trả đủ output không bảo đảm agent hoặc renderer bên ngoài sẽ giữ nguyên dữ liệu. Báo cáo đã thay nội dung bằng `[redacted]` phải dựng lại từ evidence còn đầy đủ, không tự đoán phần bị mất.

## Đo hiệu năng SSH

`ssh_status.phase_metrics` trả count, failures, total_ms và p50/p95 của tối đa 128 mẫu gần nhất mỗi pha. Kết quả thực thi có `timings_ms`, `connection_timings_ms`, `session_reused`; phần đo không thêm tool hoặc input schema. Có các pha chờ slot/session, pool reservation, connect+prepare, autodetect, command và output_save. `ssh_connect` đo lời gọi Paramiko connect (gồm handshake và auth); `authentication` đo `_auth`; `preparation` đo Netmiko preparation, kể cả sau redispatch. Các pha lồng nhau, không cộng chúng để suy ra tổng thời gian. Phương thức tùy biến/mock không có hook thì không có số đo auth; không suy diễn bằng 0. Thống kê `failures` đếm exception của pha, không thay thế trạng thái CLI.

`connection_timings_ms` mô tả lần tạo transport, vẫn được đính kèm khi reuse; `timings_ms` đo công việc trong request hiện tại. Không phát sinh SSH để đo và không tăng worker/timeout. Mỗi session probe giữ thêm process/thread; max_sessions mặc định 64. Chưa có số đo để kết luận tăng tốc trên thiết bị production.

## Kiểm thử và tài liệu

```powershell
python -m unittest discover -s tests -v
```

Tests gồm protocol, phiên SSH localhost, chế độ cấu hình, câu hỏi/phản hồi, partial output, retry/resume, evidence, tranh chấp storage bằng subprocess thật và stress 500/2.500 thiết bị ảo. Stress đo RAM, CPU, thread/handle, số session/connection và cleanup; kiểm tra timeout, resume, SHA-256 và dữ liệu không lẫn đích. Đây là mock SSH qua scanner thật, không phải benchmark handshake/AAA của hàng nghìn thiết bị thật. Đặt `SSH_STRESS_REPORT` tới file JSON ngoài repository để lưu báo cáo cả hai quy mô. Chưa chạy production.

Python wrapper: CLIConnection là tên mới, ReadOnlyConnection giữ để tương thích import cũ nhưng không còn lọc lệnh. Xem docs/ARCHITECTURE.md, docs/SCAN.md, AGENTS.md và CHANGELOG.md.

## Trạng thái và độ tin cậy — 1.8.0

Kết quả thực thi thêm status chuẩn; giữ nguyên ok, error_category, output_complete và schema 10 tool. Các tool inventory/status/read-output không phải thao tác CLI nên giữ cấu trúc metadata hiện có. Checkpoint scanner vẫn dùng status chữ thường để tương thích job cũ; mỗi attempt có result_status chuẩn.

| status | Ý nghĩa |
|---|---|
| SUCCESS | CLI response đầy đủ và không có lỗi được nhận diện |
| PARTIAL | Có dữ liệu hoặc một phần batch thành công, chưa đầy đủ |
| CONNECT_ERROR | Lỗi DNS/TCP/banner/transport/key exchange/host key |
| AUTH_ERROR | Xác thực bị từ chối hoặc phương thức không phù hợp |
| CLI_ERROR | Response có lỗi CLI theo envelope/driver |
| PARSE_ERROR | Không phân tích được dữ liệu đã thu thập |
| TIMEOUT | Hết thời gian; xem error_stage và error_category để biết pha |
| STORAGE_ERROR | Lỗi buffer/archive; không coi là SSH thành công |
| AWAITING_INPUT | Chờ phản hồi rõ ràng từ agent |
| CANCELLED | Request bị hủy |
| UNKNOWN | Không thể kết luận kết quả, đặc biệt lệnh cấu hình có thể đã chạy |

fault_status giữ nguyên nhóm nguyên nhân khi status=UNKNOWN. data_state=FULL/PARTIAL/NONE mô tả dữ liệu của attempt hiện tại; execution_state=COMPLETED/AWAITING_INPUT/NOT_SENT/UNCERTAIN/UNKNOWN mô tả độ chắc chắn trao đổi CLI. COMPLETED/SUCCESS không chứng minh cấu hình đã áp dụng đúng ý định; agent vẫn kiểm tra trạng thái thiết bị. previous_attempt giữ bằng chứng trước recovery. Storage failure có thể chỉ trả preview với output_truncated=true nếu không thể lưu dữ liệu lớn.

Verification bổ sung envelope Junos/Cisco/Huawei và RPC error XML; Error: trong nội dung config/log có header không tự thành lỗi CLI. Vẫn là heuristic, cần kiểm chứng firmware/định dạng cụ thể, không tuyên bố nhận diện mọi CLI error.

MCP execute đơn tự recovery tối đa một lần khi mất transport và lệnh được nhận diện là truy vấn đọc. Cấu hình không tự replay. Execute_many không có recovery lồng: scanner sở hữu retry batch như trước. Nếu recovery hết budget/cancel hoặc reconnect tiếp theo thất bại, dữ liệu lần đầu vẫn được giữ. Session chết được nhận diện bằng trạng thái local/worker process trước reuse; không thêm health probe mỗi lệnh.

Session đã xác minh được ưu tiên trước driver cache. Nếu cache dẫn tới lỗi preparation/prompt trước khi gửi command, backend bỏ entry RAM/SQLite và probe lại tối đa một lần trong request budget, sau khi nhả lease/semaphore cũ. Khi DB không xóa được entry, lần refresh vẫn bỏ qua entry cũ. Không đổi driver inventory/chỉ định rõ, không refresh vì lỗi auth, TCP, algorithm hoặc lỗi CLI sau khi đã gửi command. ssh_status.driver_cache_refreshes và result.driver_refreshed cung cấp bằng chứng refresh.

Reader dùng spool 1 MiB rồi chuyển xuống temporary file. Worker truyền chunk tối đa 64 Ki ký tự qua queue hữu hạn và chỉ trả metadata/pager spans ở cuối, không gửi lặp cả output. Hỗ trợ thêm footer Press any key to continue (Q to quit) và --More-- or (q)uit; không gửi phím cho câu hỏi xác nhận thông thường. API cuối vẫn materialize text để normalize/verify/redact/parse, nên đây không phải bảo đảm RAM hằng số cho mọi kích thước output. Lỗi temporary storage được báo là lỗi lưu trữ. Không benchmark hoặc tự tăng worker.

Copy toàn bộ mcp/ khi cập nhật, gồm result_status.py; restart MCP. Kiểm thử phát triển chỉ dùng mock và SSH localhost, chưa cấu hình production.

## Reliability — 1.8.2

Pool đầy sẽ chờ theo deadline/cancel, không đẩy session đang được sử dụng ra ngoài. Reader chờ prompt ổn định tối thiểu 300 ms; dữ liệu tiếp tục sau prompt nghi ngờ được giữ lại và báo chưa xác nhận đầy đủ. ANSI/pager được chuẩn hóa trước khi so sánh. Với `show logging`, `show log ...` và `display logbuffer`, prompt cộng quiet time đơn thuần không đủ chứng minh hoàn tất: reader trả `output_verification`, `output_complete=false`, giữ dữ liệu đã nhận và không tự retry. Log đã đủ cũng có thể bị đánh dấu chưa xác minh. Kênh đóng sau prompt cho phép xác nhận điểm kết thúc; các kiểm tra lỗi/ambiguity còn lại vẫn áp dụng. Không tăng quiet time hoặc timeout. Phần dữ liệu đến sau lúc reader kết thúc chưa được thu thập; không coi dữ liệu partial là toàn bộ log. Quy tắc này không bảo đảm phát hiện prompt giả trong mọi loại CLI khác.

Scanner thêm `--device-timeout 240`: ngân sách chung cho fast và retry slow, mặc định bằng `--slow-timeout`. Resume giữ thời gian đã dùng; explicit retry mở chu kỳ mới. Không tự replay cấu hình chưa rõ kết quả. Timeout trực tiếp vẫn phụ thuộc lời gọi Netmiko/OS trả về; metadata `device_budget_exceeded` ghi nhận vượt trần. Xem [chi tiết và giới hạn](docs/SCAN.md).

## Status và credential — 1.8.1

Normalize tính lại awaiting_input và các trường tổng hợp theo kết quả hiện tại, không giữ cờ task chờ/error cũ sau success đã hoàn tất. ok=true cùng output_complete=false không thể thành SUCCESS. Batch có status_counts, awaiting_task_ids và awaiting_tasks (task_id/index/target). Nếu không có ID ổn định, index chỉ xác định task trong response hiện tại. Task trùng target vẫn phân biệt bằng index. UNKNOWN/UNCERTAIN vẫn được giữ khi một task cấu hình chưa rõ tác động, đồng thời danh sách chờ vẫn hiện đủ.

Với interact, các bước chờ đã được trả lời vẫn nằm trong lịch sử steps/status_counts; awaiting_tasks chỉ biểu thị bước cuối đang chờ. Không xem câu hỏi lịch sử là task còn chờ. Schema đầu vào của 10 tool không đổi; các field mới chỉ được bổ sung trong output.

Credential của profile/device là một bộ độc lập khi nguồn đó khai báo thông tin xác thực: phải có username và password hoặc key_file/use_keys/allow_agent. Key/agent không bắt buộc password và không tự lấy password global. Nguồn chỉ thay timeout/driver/port không thay credential và vẫn kế thừa nguyên bộ hiện có. secret của enable là tham số riêng.

Muốn chủ động kế thừa credential từng trường, đặt inherit_credentials=true tại profile hoặc device. Flag phải là boolean. Profile/device thiếu thông tin và chưa chọn kế thừa sẽ báo lỗi có tên nguồn trước khi SSH, thay vì ghép username/password âm thầm. Các field không thuộc xác thực vẫn kế thừa defaults → profile → device bình thường. Thay nguồn xác thực có thể đổi identity job; không bỏ kiểm chứng manifest để ép resume.

Ví dụ profile đầy đủ: {"username":"${SITE_SSH_USER}","password":"${SITE_SSH_PASSWORD}"}; key: {"username":"site-user","key_file":"/private/site-key"}; kế thừa chủ động: {"username":"site-user","inherit_credentials":true}.

Từ 1.9.0 có loader credentials.json dùng chung cho mọi client. Xem [cấu trúc, ưu tiên và chuyển đổi credential](docs/CREDENTIALS.md). Không đưa credential vào Git hoặc launcher client công khai. Restart MCP sau khi thay file tài khoản.

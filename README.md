# Netmiko MCP Server

Backend **1.8.2**: thực thi CLI và cấu hình nhiều thiết bị qua Netmiko, giữ nguyên **10 MCP tools** và schema OpenCode Web.

## Thực thi do agent quyết định

Không còn allowlist/denylist nội dung lệnh. Agent có thể gửi show/display, configure, set, commit, save, shell command và pipeline do agent lựa chọn. Server không tự đổi abbreviation, sửa lệnh hoặc thêm count cho ping.

Chỉ kiểm tra framing: mỗi command là string một dòng, không rỗng, tối đa 8192 ký tự, không có ký tự điều khiển. Dùng execute_many cho batch tối đa 1000 lệnh; interact nhận tối đa 1000 bước, có thể dùng chuỗi rỗng hoặc newline làm Enter rõ ràng. Parallel tối đa 100 task mỗi lời gọi; scanner --all không có giới hạn số thiết bị này. Số kết nối đang làm việc vẫn theo max_workers để bảo vệ tài nguyên; không đổi pool/storage hoặc benchmark trong bản này.

Agent chịu trách nhiệm phạm vi lệnh và thay đổi cấu hình mà người dùng yêu cầu. Các test phát triển chỉ dùng mock/SSH localhost.

## Cài và chạy

Python 3.10+, cài `python -m pip install -r requirements.txt`. Copy mcp/devices.example.json thành mcp/devices.json; cung cấp inventory riêng input/device.csv với name,ip,netmiko_device_type và tùy chọn profile,port.

Đặt NETWORK_SSH_USER và NETWORK_SSH_PASSWORD trong môi trường MCP, hoặc credential profiles. Bootstrap fallback cặp đầu tiên trong input/ssh.txt khi thiếu cặp môi trường. Không đưa credential, inventory, known_hosts, runtime hoặc output lên Git.

```powershell
python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv
python mcp/collector_backend.py --check
```

Cập nhật toàn bộ mcp/ và restart MCP. Giữ devices.json cùng dữ liệu triển khai riêng; không cần thay schema 10 tool hay launcher OpenCode Web. Kiểm tra ssh_status.version=1.8.2.

## Session, driver và profile

Driver inventory/cache được ưu tiên. Cold autodetect dùng worker probe và redispatch trên cùng kết nối, không đăng nhập lần hai. Autodetect nhận sáu driver Junos, IOS, XR, NX-OS, Huawei, Linux; driver Netmiko khác có thể chỉ định trực tiếp. Không có grammar theo hãng để chặn lệnh nữa.

Các lệnh trong một lease chạy tuần tự; thiết bị khác chạy song song. Dùng execute_many hoặc interact khi cần một chuỗi không bị yêu cầu khác chen vào. Giữ cùng target/profile/driver khi gửi phản hồi cho phiên đang chờ.

ssh_mode mặc định compatible: nhận key mới/đổi, lưu atomic, ghi nhận thay đổi fingerprint; lỗi lưu key không chặn SSH. strict là lựa chọn chủ động: phải có trusted key trong alt_key_file; dùng host_key_store_mode shared nếu muốn một file chung thay vì file theo PID.

Profile/device hỗ trợ read_timeout, prompt_quiet_seconds, timing_quiet_seconds; tham số tool tường minh ưu tiên. Connection options gồm conn_timeout, auth_timeout, banner_timeout, key_file, passphrase, encoding, disable_sha2_fix, disabled_algorithms và ssh_config_file. Credential literal giữ nguyên; chuỗi ${ENV_NAME} nguyên vẹn lấy từ environment. auto_enable=true chủ động gọi enable cho Cisco bằng secret backend; mặc định false.

Request deadline mặc định 120s, read timeout mặc định 40s. Batch dài cần request_timeout_seconds phù hợp; tăng read_timeout không tăng request deadline. Đường worker có hard deadline; connect trực tiếp vẫn cooperative theo timeout thư viện.

## Reader và verification

Reader xử lý paging, giữ partial khi timeout/cancel/EOF, nhận mode prompt trong cùng thiết bị cho Cisco/Junos/Huawei. Banner Cisco chưa đóng và output XML/JSON chưa hoàn chỉnh không được kết thúc chỉ vì gặp một dòng giống prompt. Custom expect chỉ là ranh giới đọc; không được biến prompt thiết bị khác thành thành công.

Dữ liệu đã có trước khi gửi lệnh tiếp theo được giữ trong preceding_output hoặc preceding_output_id, gắn association unattributed, thay vì bị xóa âm thầm. Output dài được lưu theo output_id, đọc bằng các tool dòng/byte/search hiện có. Redaction output tùy chọn; error và audit command vẫn scrub credential.

Kết quả có prompt không chứng minh cấu hình đúng ý định: validation vẫn là heuristic CLI. Agent cần đọc phản hồi và dùng lệnh kiểm tra trạng thái để xác minh thay đổi thực tế. Prompt/firmware tùy biến ngoài các họ đã hỗ trợ có thể cần expect rõ ràng.

## Prompt hỏi và phản hồi rõ ràng

Thiết bị hỏi yes/no, confirm, password hoặc destination/source filename trả ok=false, awaiting_input=true và giữ session. Không tự gửi yes/Enter, không gửi driver cleanup vào câu hỏi. Lỗi CLI có prompt đầy đủ khác với phiên còn đang chờ input.

Dùng ssh_interact với các bước rõ ràng, ví dụ ["write memory", "yes"]. Chuỗi rỗng là Enter, chỉ được gửi khi agent cung cấp. Hoặc gọi ssh_execute để xem câu hỏi rồi gửi phản hồi ở lời gọi tiếp theo, cùng identity. expect_string có thể chỉ định prompt tương tác khác; match custom expect chưa phải hoàn tất lệnh. Execute_many dừng ở lỗi/câu hỏi để agent kiểm tra; không coi lệnh tiếp theo là câu trả lời ngầm.

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

output_storage_mode=shared mặc định đối soát thư mục; exclusive dùng index RAM cho một Collector sở hữu thư mục. Scanner dùng scratch riêng, quota/TTL và checksum checkpoint vẫn giữ. Không dùng exclusive cho nhiều process cùng ghi. Quota shared chưa có transaction toàn cục. Mỗi session probe giữ thêm process/thread; max_sessions mặc định 64, không tự tăng concurrency hoặc thay ownership worker.

## Kiểm thử và tài liệu

```powershell
python -m unittest discover -s tests -v
```

Tests gồm protocol, phiên SSH localhost, chế độ cấu hình, câu hỏi/phản hồi, partial output, retry/resume, evidence và stress chức năng thiết bị ảo. Không có benchmark trong đợt thay đổi này và chưa chạy cấu hình trên firmware production.

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

Pool đầy sẽ chờ theo deadline/cancel, không đẩy session đang được sử dụng ra ngoài. Reader chờ prompt ổn định tối thiểu 300 ms; dữ liệu tiếp tục sau prompt nghi ngờ được giữ lại và báo chưa xác nhận đầy đủ. ANSI/pager được chuẩn hóa trước khi so sánh.

Scanner thêm `--device-timeout 240`: ngân sách chung cho fast và retry slow, mặc định bằng `--slow-timeout`. Resume giữ thời gian đã dùng; explicit retry mở chu kỳ mới. Không tự replay cấu hình chưa rõ kết quả. Timeout trực tiếp vẫn phụ thuộc lời gọi Netmiko/OS trả về; metadata `device_budget_exceeded` ghi nhận vượt trần. Xem [chi tiết và giới hạn](docs/SCAN.md).

## Status và credential — 1.8.1

Normalize tính lại awaiting_input và các trường tổng hợp theo kết quả hiện tại, không giữ cờ task chờ/error cũ sau success đã hoàn tất. ok=true cùng output_complete=false không thể thành SUCCESS. Batch có status_counts, awaiting_task_ids và awaiting_tasks (task_id/index/target). Nếu không có ID ổn định, index chỉ xác định task trong response hiện tại. Task trùng target vẫn phân biệt bằng index. UNKNOWN/UNCERTAIN vẫn được giữ khi một task cấu hình chưa rõ tác động, đồng thời danh sách chờ vẫn hiện đủ.

Với interact, các bước chờ đã được trả lời vẫn nằm trong lịch sử steps/status_counts; awaiting_tasks chỉ biểu thị bước cuối đang chờ. Không xem câu hỏi lịch sử là task còn chờ. Schema đầu vào của 10 tool không đổi; các field mới chỉ được bổ sung trong output.

Credential của profile/device là một bộ độc lập khi nguồn đó khai báo thông tin xác thực: phải có username và password hoặc key_file/use_keys/allow_agent. Key/agent không bắt buộc password và không tự lấy password global. Nguồn chỉ thay timeout/driver/port không thay credential và vẫn kế thừa nguyên bộ hiện có. secret của enable là tham số riêng.

Muốn chủ động kế thừa credential từng trường, đặt inherit_credentials=true tại profile hoặc device. Flag phải là boolean. Profile/device thiếu thông tin và chưa chọn kế thừa sẽ báo lỗi có tên nguồn trước khi SSH, thay vì ghép username/password âm thầm. Các field không thuộc xác thực vẫn kế thừa defaults → profile → device bình thường. Thay nguồn xác thực có thể đổi identity job; không bỏ kiểm chứng manifest để ép resume.

Ví dụ profile đầy đủ: {"username":"${SITE_SSH_USER}","password":"${SITE_SSH_PASSWORD}"}; key: {"username":"site-user","key_file":"/private/site-key"}; kế thừa chủ động: {"username":"site-user","inherit_credentials":true}.

Không thêm loader credentials.json trong phiên bản này. Có thể đặt toàn bộ config private ngoài repository rồi cho các client MCP cùng trỏ --config tới đó. Không đưa credential vào Git hoặc cấu hình client công khai. Cập nhật mcp/ và restart MCP.

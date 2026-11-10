# Netmiko MCP Server

Backend **1.7.0**: thực thi CLI và cấu hình nhiều thiết bị qua Netmiko, giữ nguyên **10 MCP tools** và schema OpenCode Web.

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

Cập nhật toàn bộ mcp/ và restart MCP. Giữ devices.json cùng dữ liệu triển khai riêng; không cần thay schema 10 tool hay launcher OpenCode Web. Kiểm tra ssh_status.version=1.7.0.

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

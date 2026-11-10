# Scanner — Netmiko MCP 1.9.1

Các mục phiên bản bên dưới mô tả hành vi kế thừa vẫn áp dụng; hướng dẫn chạy đã được đối chiếu với 1.9.1.

# Reliability 1.8.2

Pool capacity waits now obey the request deadline/cancellation without holding the registry lock or SSH semaphore. Probe adoption waits after releasing its SSH slot; leased entries are never evicted.

Reader retains late data after a prompt candidate and marks an ambiguous transcript as incomplete (output_verification, not automatically retryable). Prompt candidates settle for at least 300 ms; structured XML/JSON/banner guards remain. A quiet period cannot prove completion against an arbitrarily delayed device that emits an exact prompt as data. Partial output is preserved; no sentinel commands or implicit confirmation responses are injected.

Scanner --device-timeout defaults to --slow-timeout (240 seconds). Fast and slow attempts share this budget, including pool wait, execution, export and time between attempts after the first dispatch. Initial fleet queue time and time while the process is stopped are excluded. Checkpoints preserve consumed time for retry_pending; explicit --retry-status starts a new authorized cycle. Exhaustion prevents another SSH attempt and retains evidence/prefix. Configuration with uncertain effects is never automatically replayed.

Deadlines are cooperative for direct Netmiko connections: a blocking library/OS call may return late. Late completion is recorded with device_budget_exceeded; verified output remains available. Probe subprocesses retain their existing hard timeout. This change does not promise hard preemption of an in-flight direct connection.

# Scanner 1.8.0

Giữ status checkpoint chữ thường (success/partial/failed/unknown) và toàn bộ evidence/resume. Attempt thêm result_status chuẩn hóa từ kết quả CLI; export pending là STORAGE_ERROR. Kết quả command có data_state và execution_state để agent phân biệt dữ liệu dở dang với tác động cấu hình chưa chắc chắn. Không thêm retry lồng vào execute_many. README hiện tại mô tả status và cơ chế refresh driver trước command.

# Scanner 1.7.0 — cập nhật hành vi

Không lọc nội dung lệnh; plan có thể chứa cấu hình. Agent chịu trách nhiệm phạm vi thay đổi. Dùng tool interact cho chuỗi câu hỏi/phản hồi, scanner execute_many dừng ở awaiting_input, không gửi phản hồi ngầm.

--retry-status failed partial cho phép chạy lại riêng các trạng thái được chọn trên cùng plan/job, bỏ qua success và prefix lệnh đọc đã hoàn tất. Giữ toàn bộ attempts và evidence. --retry-status unknown phục hồi export_pending trước mà không SSH lại.

Lệnh có tác động chưa rõ không tự replay: cần đối soát rồi chủ động --replay-uncertain. Khi dùng flag này cho task không replay-safe, toàn batch được chạy lại để tái lập config mode. Gián đoạn running chuyển unknown. Retry tự động chỉ dành cho lỗi transient trước khi gửi lệnh hoặc chuỗi đọc được nhận diện, tối đa hai attempt mỗi chu kỳ. Đây là phân loại replay, không phải bộ lọc thực thi.

Không benchmark và không thay fast/slow pool trong bản này. Các mục read-only trong lịch sử bên dưới được thay bởi hành vi 1.7.0 và README.

## Chạy từ thư mục gốc

Scanner vẫn mặc định đọc `input/device.csv`, khác bootstrap cho phép bỏ CSV. Chuẩn bị file riêng trước khi chạy; các ví dụ không tự cung cấp inventory/credential production. Dùng `--config`, `--inventory-csv` và `--credentials-file` để chỉ định file riêng. Xem [credential](CREDENTIALS.md).

Xem kế hoạch toàn inventory, **không SSH**:

```powershell
python mcp/scan.py --all --output output/SCAN-VERSION
```

Khi đã sẵn sàng, chạy thật bằng cùng lệnh thêm `--execute`:

```powershell
python mcp/scan.py --all --output output/SCAN-VERSION --workers 16 --slow-workers 4 --execute
```

Mặc định chỉ lấy version (Linux: uname -s). Để lấy dữ liệu khác, dùng `--commands-file mcp/scan-commands.example.json` hoặc plan có `commands` riêng. Nội dung lệnh do agent quyết định; chỉ kiểm tra framing. `--all` lấy alias từ config sau khi merge CSV; các task cùng identity và cùng lệnh được loại trùng. Cùng IP nhưng khác driver/profile kết nối vẫn là task riêng khi tham số thực tế khác.

Dùng `--plan mcp/scan-plan.example.json` thay `--all` cho danh sách cụ thể. Sửa các target ví dụ thành target thật đã xác minh. CSV thiếu cột netmiko_device_type hoặc ô driver trống sẽ dùng autodetect; driver đã điền được giữ nguyên. Plan chỉ nhận target, commands, device_type, profile, read_timeout, lane. Target ngoài inventory được gọi bằng IP/hostname và driver tường minh/autodetect; không tự thêm CSV.

`lane: slow` đưa thiết bị đã biết chậm vào lượt chậm ngay từ đầu, tránh phải thử đăng nhập hai lần. `profile` chọn một profile đã có trong devices.json hoặc credentials.json, không chứa username/password trong plan. Có thể chọn profile qua cột CSV `profile`; bỏ trống dùng `default`. Profile khai báo credential riêng hoạt động khi không có credential toàn cục. Environment và cặp đầu tiên trong input/ssh.txt vẫn là nguồn fallback; không tự thử lần lượt các cặp credential.

Ví dụ mapping (thay giá trị mẫu và đặt biến môi trường tương ứng):

```json
{"profiles":{"default":{"username":"${NETWORK_SSH_USER}","password":"${NETWORK_SSH_PASSWORD}"},"branch":{"username":"${BRANCH_SSH_USER}","password":"${BRANCH_SSH_PASSWORD}"}}}
```

```csv
name,ip,netmiko_device_type,profile
BRANCH-01,192.0.2.1,cisco_ios,branch
```

## Nhanh nhưng không làm đẹp tỷ lệ giả

- Tổng worker mặc định16, tối đa32 và không vượt max_workers của collector; gồm lượt chậm mặc định4. Tối thiểu2 slot để có hai lane. Detection và collection cùng dùng semaphore SSH toàn collector. Một transport vẫn serialize từng lệnh.
- Mỗi thiết bị lấy đủ batch trước khi chuyển sang đích tiếp. Kết quả và bằng chứng được ghi tăng dần, không chờ toàn nhóm hoặc lượt chậm hoàn tất.
- Fast: deadline90s/thiết bị; TCP10s, banner15s, auth30s, read45s. Slow: deadline240s; TCP30s, banner45s, auth60s, read120s. Probe autodetect trong scanner được phép tối đa min(deadline,120s), thay vì trần20s của lời gọi MCP thông thường. Nếu probe hết hard deadline mà chưa xác định được pha auth, không tự retry mù; target đã biết chậm nên đặt lane slow ngay từ đầu. Đây là ngân sách của job, không phải cam kết thời gian thực tế; Netmiko I/O cancellation vẫn cooperative. Điều chỉnh deadline qua --fast-timeout/--slow-timeout, read timeout riêng trong plan. Chúng không sửa config thiết bị hoặc config cục bộ.
- Chỉ retry tối đa một lần ở lane chậm (kể cả task bắt đầu tại slow lane) cho connect_timeout/banner_timeout/read_timeout/auth_timeout/connection_lost/handshake_incomplete đã phân loại. Auth timeout không kích hoạt cooldown 5 phút; xác thực bị từ chối/auth_method dùng auth_failure_cooldown_seconds và không retry. Không retry algorithm_mismatch, CLI error hoặc lỗi không rõ nguyên nhân. Deadline chưa rõ pha không bị coi là TCP timeout để retry mù.
- Thiết bị chậm vẫn có kết quả riêng: success, partial, failed hoặc unknown; pending là chưa chạy, không phải thành công. Không biến timeout/auth thành interface down hoặc số đo0.
- Host key mới/đổi được chấp nhận và lưu atomic dưới khóa liên tiến trình. Lỗi persistence tạo warning và không làm SSH thất bại. Không tự đổi credential hoặc bật thuật toán cũ toàn mạng.
- Luồng đọc Netmiko channel không chờ echo; chỉ kết thúc thành công khi có prompt cuối. Tự gửi Space tại pager, không gửi phản hồi confirmation. Timeout giữ output dở dang làm bằng chứng và dừng batch. Session đầy đủ không echo vẫn được reuse.
- Không lọc nội dung CLI, không tự thêm count cho ping hoặc giới hạn số gói. Agent chọn lệnh và tham số trong phạm vi công việc; chỉ kiểm tra framing. Plan có thể chứa cấu hình; cấu hình chưa rõ kết quả không được tự replay.

## Output và resume

- scan-manifest.json: hash của kế hoạch/identity, không lưu credential.
- results/<task_id>.json: trạng thái, các lần thử, lỗi có category/stage, duration và đường dẫn chứng cứ. elapsed_ms của attempt đo từ bắt đầu thu thập tới trước export evidence (gồm chờ slot/detection/connect/CLI); không phải RTT hoặc thời gian riêng auth. Thời gian toàn job đo riêng khi benchmark, gồm cả ghi checkpoint/evidence.
- bang-chung/: output CLI đã chuẩn hóa ANSI/pager, có SHA256. Mặc định không che username/password/hash/secret/token; chỉ sanitize nếu chủ động bật redaction_enabled=true.
- scan-summary.json: tổng đích/loại trùng/thành công/lỗi/một phần/chưa rõ/chưa chạy.
- raw-output/: scratch riêng của CLI, được dọn theo từng output sau khi kết quả/bằng chứng đã lưu. Không dọn output của MCP hay job khác. Dùng các đường dẫn bang-chung trong kết quả, không phụ thuộc output_id của scratch.

Chạy lại cùng lệnh/output để resume. Job bỏ qua success/failed/partial đã lưu; retry_pending tiếp tục lane chậm. Kế hoạch/identity đổi, JSON lỗi hoặc evidence thiếu/sai checksum thì từ chối resume. Trạng thái running sau gián đoạn chuyển unknown, không tự xác thực lại. Đối soát trước khi tạo job mới cho những đích này.

scan.lock chặn hai process dùng cùng thư mục; crash có thể để lại lock. Chỉ gỡ lock thủ công sau khi xác minh process cũ đã dừng và đối soát checkpoint, không xóa outbox hay hồ sơ để ép chạy lại. Đĩa đầy/không ghi được không được báo success. Với thao tác replace checkpoint bị khóa file tạm thời trên Windows, chỉ retry thao tác file, không lặp SSH.

Scanner thực thi plan do agent cung cấp, có thể gồm lệnh đọc hoặc cấu hình. Agent đọc summary/evidence để kiểm chứng mục tiêu. Scanner không tự gửi email/thông báo; chỉ thực hiện nếu người dùng yêu cầu riêng.

## Cập nhật bộ công ty

Copy toàn bộ thư mục mcp/, gồm probe_session.py, output_storage.py và telemetry.py; giữ cấu hình devices.json riêng. Restart tất cả process dùng chung output để cùng áp dụng khóa storage mới. Các process chung thư mục phải cùng quota/TTL. Có thể copy kèm các file scan ví dụ/tài liệu/tests. Không thay opencode.json, devices.json, input/, known_hosts, SMTP settings hoặc runtime.

Source mới cần process MCP mới; kiểm tra ssh_status.version=1.9.1. Thay đổi tham số identity có thể khiến job cũ không resume được; dùng thư mục output mới thay vì ép bỏ kiểm chứng manifest.

## Kiểm tra diện rộng và tình huống lỗi

```powershell
python -u mcp/validate_fleet.py --output output/FLEET-NEW --execute --ssh-limit 128
python -m unittest discover -s tests -v
```

Validator kiểm tra TCP và banner trên từng endpoint host/port duy nhất trong toàn inventory (mặc định 64 probe, timeout 2s), rồi chọn tối đa 128 identity reachable, phân bổ theo driver. Bỏ --execute chỉ chạy census, không xác thực SSH. Mẫu SSH lấy version và bảng interface bằng lệnh đọc; retry dùng scanner hiện có. TCP mở không đồng nghĩa SSH thành công. Không có banner vẫn được thử SSH trong mẫu để ghi nhận lỗi handshake thực tế. Log transport nằm trong ssh-transport.log.

Tests có fault injection, replay 2.000 cách chia chunk, 500 và 2.500 thiết bị ảo qua scanner/persistence/resume và SSH localhost với driver thật. Stress cố tình tạo auth reject/timeout, EOF, CLI error và partial output; kiểm tra kết quả đúng oracle, không lấy tỷ lệ success của fixture làm tỷ lệ production. Dữ liệu --More--/[confirm] ở giữa config/log phải được giữ nguyên. Lỗi ghi output là storage_error và không gây retry SSH. EOF được phát hiện sớm; channel chưa hoàn chỉnh không được tái sử dụng.

Scanner dùng output index exclusive cho scratch riêng và thông báo khi xóa scratch. Các entry driver đã dò thành công được cache tại runtime/data/netmiko/autodetect.sqlite3 để lần chạy sau tái sử dụng trong TTL; lỗi cache quay về probe thật.

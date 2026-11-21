# Hợp đồng tool và đọc kết quả

Tài liệu tham chiếu khi cần tham số/giới hạn. Vòng điều tra và quyền theo
[WORKFLOW.md](../mcp/WORKFLOW.md); lỗi/pending/resume theo [RECOVERY.md](RECOVERY.md).
Schema thực do tools/list trả về; ví dụ dưới là params của tools/call, dùng dữ
liệu mô phỏng. Không SSH chỉ để kiểm tra ví dụ. Mọi lệnh thay đổi cần đúng quyền.
LAB-A/LAB-B và output_id trong ví dụ là dữ liệu mẫu; thay bằng đích được phép và
output_id thực do kết quả CLI trả về, không tự dựng ID cho dữ liệu chưa thu thập.

## Định danh và trạng thái

ssh_inventory.query tìm alias/host, không tìm profile/tag. Mặc định limit=100;
offset từ 0, limit=0 lấy toàn match có chủ đích; summary_only=true chỉ trả đếm.
devices có name, host, device_type, tags, profile, port. Profile mặc định default;
port theo defaults → profile → device. Đây là metadata cấu hình, không chứng nhận
auth/driver hay SSH thành công; device_type lấy từ device/defaults, không phải
kết quả autodetect mới hay xác minh driver hiệu lực từ profile.
Đọc resolution/warnings nếu alias/host không duy nhất. Không đoán credential.

```json
{"name":"ssh_inventory","arguments":{"query":"LAB-A","limit":10}}
```

ssh_status có giới hạn/session, phase_metrics và parallel_queue. Queue chỉ thuộc
executor ssh_parallel của process này; không gồm STDIO, scanner hay process khác.
queued/running là snapshot; submitted/completed/cancelled là tổng từ khi tạo
Collector. completed gồm cả task lỗi; running có thể chờ session/SSH slot.
Worker telemetry là trần concurrency, không phải số SSH thực tế. Không poll status
sau mỗi lệnh; xem [kiến trúc](ARCHITECTURE.md) khi cần ý nghĩa timing chi tiết.

```json
{"name":"ssh_status","arguments":{}}
```

## Lệnh và tương tác

ssh_execute nhận command là một chuỗi CLI; schema cho phép device_type, profile,
read_timeout, expect_string, use_timing, save_output, use_textfsm. Chỉ dùng override
khi có căn cứ. Custom expect không thay identity prompt. use_timing không biến
partial/quiet time thành bằng chứng hoàn tất. Parser lỗi phải giữ raw.

```json
{"name":"ssh_execute","arguments":{"target":"LAB-A","command":"show version","save_output":true}}
```

ssh_execute_many.commands là mảng 1–1000 chuỗi trên cùng phiên. Mặc định dừng;
continue_on_error=true chỉ cho lệnh độc lập và CLI error đã đọc đủ, session đồng
bộ. Không tiếp tục timeout/disconnect/storage/pending; suffix chưa gửi là SKIPPED,
không phải thành công hoặc output rỗng. Batch không có use_textfsm trong schema.

```json
{"name":"ssh_execute_many","arguments":{"target":"LAB-A","commands":["show version","show interfaces"],"continue_on_error":false,"save_output":true}}
```

ssh_parallel.tasks có 1–100 object. Mỗi task cần target và đúng một trong command
hoặc commands. Backend kiểm tra XOR này dù schema chỉ bắt buộc target. Task batch
hỗ trợ continue_on_error; không áp tùy chọn đó cho task command đơn. Results giữ
thứ tự task; xem từng kết quả và queue_wait_ms. tasks_requested/worker_limit/
effective_worker_limit không bảo đảm từng request được dùng toàn pool cùng lúc.
Các trường của command như use_textfsm không được áp cho commands dù task schema
chung có khai báo trường đó.

```json
{"name":"ssh_parallel","arguments":{"tasks":[{"target":"LAB-A","command":"show version"},{"target":"LAB-B","commands":["show version","show interfaces"],"continue_on_error":false,"save_output":true}]}}
```

ssh_interact.steps là mảng 1–1000 chuỗi, không phải object command/response.
Chuỗi rỗng hoặc newline là Enter tường minh. Không có expect_string trong input
schema của interact. Chỉ gửi câu trả lời đã biết/được phép cho đúng target/profile,
mode và phiên đang chờ. Khi phiên đang chờ, gửi phản hồi qua ssh_interact.
ssh_execute, ssh_execute_many và các tác vụ ssh_parallel trả lỗi nếu phiên đang chờ.
Ví dụ Enter dưới chỉ minh họa cấu trúc, không phải chỉ thị thực thi:

```json
{"name":"ssh_interact","arguments":{"target":"LAB-A","steps":["\n"],"save_output":true}}
```

## Evidence đã lưu

ssh_search_output nhận query (không phải pattern), regex=false và ignore_case=true
mặc định. Nó duyệt hết file nếu thành công; total_matches đếm **dòng có match**,
không đếm số lần xuất hiện hoặc số đối tượng mạng. max_matches (1–100, mặc định
30) giới hạn match được chọn làm excerpt, context_lines từ 0–5. Search không có
offset/next_offset/more để phân trang match; muốn đổi phép tìm phải đổi query hoặc
dùng readers/parse độc lập có kiểm chứng, không lặp cùng search để lấy trang sau.
excerpt.line tính từ 1; reader.offset tính từ 0. Muốn đọc từ dòng L trong excerpt,
dùng offset=L-1, không đưa thẳng L vào offset.

```json
{"name":"ssh_search_output","arguments":{"output_id":"20261117T000000Z_0123456789abcdef0123456789abcdef","query":"VRF-A","regex":false,"max_matches":30,"context_lines":2}}
```

shown_matches=min(total_matches,max_matches) không bảo đảm excerpt chứa đầy đủ các
dòng đó: mỗi dòng excerpt tối đa 3000 ký tự, tổng ngân sách khoảng 120000 ký tự.
truncated chỉ theo ngân sách tổng, không báo mọi trường hợp cắt từng dòng hoặc
vượt max_matches. Vì vậy truncated=false vẫn có thể thiếu text cần đọc thêm.
Regex chạy trong worker có deadline tối đa 2 giây/request budget; lỗi/timeout
không phải zero match. Search thành công không trả output_complete/hash/phạm vi
byte đã quét: lấy trạng thái từ kết quả CLI gốc và ghi nguồn/phạm vi/hash bằng
công cụ phù hợp khi kết luận toàn bộ. Không bịa các trường này trong tool response.

ssh_read_output.offset là chỉ số dòng từ 0; limit mặc định 200, tối đa 1000.
Đi tiếp bằng next_offset. more báo còn nội dung; oversized_line có thể khiến
next_offset không tăng, không lặp mãi cùng offset: dùng byte reader cho dòng dài.
Không coi text trả về là toàn raw khi more=true.

```json
{"name":"ssh_read_output","arguments":{"output_id":"20261117T000000Z_0123456789abcdef0123456789abcdef","offset":0,"limit":200}}
```

ssh_read_output_bytes đi theo next_byte_offset, không tự cộng length: chunk có thể
nới tối đa ba byte để hoàn tất UTF-8. Mặc định length=64000, tối đa 150000;
total_bytes và more mô tả byte đã tiêu thụ. Bắt đầu từ 0 rồi dùng offset trả về
để không rơi vào giữa code point. Offset tùy ý có thể tạo replacement character;
đây là text decode best-effort, không phải API binary/base64 để export mọi byte
tùy ý. Giữ file gốc và dùng script copy/hash khi cần evidence byte-exact.

```json
{"name":"ssh_read_output_bytes","arguments":{"output_id":"20261117T000000Z_0123456789abcdef0123456789abcdef","byte_offset":0,"length":64000}}
```

Giảm phần đọc vào context, không giảm raw đã lưu. Output ngắn inline có thể đủ;
không ép mọi lệnh phải save rồi search. Kết luận không tồn tại/toàn bộ cần cả
thu thập đủ, query/parse đúng ngữ nghĩa và phạm vi đầy đủ: xem [EVIDENCE.md](EVIDENCE.md).

## Đóng phiên và host key

ssh_close có target tùy chọn, không có profile/port selector. Target được resolve
về host rồi đóng mọi session cùng host, kể cả profile/port khác. Omit hoặc chuỗi
rỗng đóng toàn pool. MCP trả lỗi tham số nếu target được truyền với giá trị null hoặc kiểu khác chuỗi.
Chỉ gọi nếu các phiên bị ảnh hưởng thuộc phạm vi được phép;
không dùng để dọn phiên chung theo thói quen.

```json
{"name":"ssh_close","arguments":{"target":"LAB-A"}}
```

Host key tuân ssh_mode trong cấu hình: compatible chấp nhận key mới/đổi và lưu
khi có thể, lỗi persistence có warning; strict xác minh trust store và từ chối
key chưa tin cậy/khác. Tool không có tham số đổi ssh_mode. Không tự đổi policy hoặc
xóa known_hosts để chữa lỗi. Xem [README](../README.md) và [credentials](CREDENTIALS.md)
chỉ khi cần setup/profile. Inventory/status không xác nhận trust/auth production.

# Junos optional preparation fallback

Bản sửa cho phép bỏ qua prep tùy chọn khi CLI operational đã đồng bộ. Phiên không
tắt được complete-on-space phải xác minh chính xác dòng nhập trước Enter. Guard
prompt/output chung vẫn giữ nguyên. Không truy cập production trong đợt này.

## Nguyên nhân đã xác minh

Baseline là `2d483e0`, đồng bộ với origin/main trước khi sửa. Reader lưu hash của
prompt candidate. Nếu có body sau candidate, reader trả `prompt_candidate_continuation`.
Chỉ preamble không có body và echo khớp mới được reset candidate. Echo bị biến đổi,
ack xuất hiện trước repaint hoặc dữ liệu muộn đều có thể giữ candidate cũ.

Junos session_preparation hiện coi mọi reader failure là lỗi bắt buộc. Vì vậy SSH
đã auth vẫn bị chặn trước lệnh nghiệp vụ. Reproducer synthetic trên source HEAD cũ
thất bại ở width prep. Cùng tình huống trên bản sửa chạy qua probe đồng bộ rồi gửi
show, không gửi lại width prep.

Permission/syntax error có prompt trọn vẹn vốn đã được vòng prep cũ bỏ qua, nhưng
không ghi nhận rằng complete-on-space có thể còn bật. Echo nghiệp vụ cũ là tùy chọn
và phép so echo gộp whitespace. Cách so đó chưa bảo vệ được nội dung quoted/repeated
spaces khi prep bị bỏ qua.

Đây là nguyên nhân trong backend đã tái hiện. Chưa có transcript raw từ MX bị ảnh
hưởng để khẳng định permission, autocomplete hay repaint cụ thể gây ra lỗi thực tế.
Không diễn giải prompt_candidate_continuation thành permission denied tự động.

## Thay đổi

- `mcp/collector_backend.py`: phân loại diagnostic prep permission/syntax/other
  và echo biến đổi. Chỉ bỏ qua khi prompt operational đúng identity, không pending
  và transport còn sống. Lỗi timeout/disconnect hoặc prompt khác vẫn dừng.
- Width/prep có continuation ambiguity cần một probe đọc `show cli` để xác lập
  boundary mới. Probe xác minh input trước Enter và prompt kết thúc. Response CLI
  error vẫn có thể chứng minh boundary, không chứng minh setting đã được áp dụng.
  Không gửi lại prep lỗi và không nới guard chung.
- Khi bỏ qua complete-on-space hoặc phải resync, gửi nguyên command chưa kèm Enter.
  So chính xác echo, kể cả whitespace/quotes/Unicode. Chỉ gửi Enter nếu dòng nhập
  đã xác minh. Không tự sửa abbreviation, xóa khoảng trắng hay gõ lại command.
- Guard echo chỉ hiểu CR, backspace và ANSI màu/erase-to-end đã định nghĩa. Netmiko
  giữ nguyên các control này trong bước kiểm input rồi khôi phục các cờ normalize.
  Echo wrap/control không hỗ trợ, mismatch hoặc timeout đều fail closed và đóng
  transport trước cleanup. Raw CLI chuẩn hóa vẫn được giữ theo hợp đồng hiện có.
- Khi bỏ qua screen-length, dùng pager reader hiện có. Thiếu trang/prompt hoặc
  timeout không thành SUCCESS. `junos_preparation` giữ diagnostic/raw của prep đã
  bỏ qua. Đây là metadata bổ sung, không đổi 10 input schema.
- Prep Junos thất bại không kích hoạt refresh driver suy ra từ cache. Cơ chế retry
  transport của lệnh đọc và retry của scanner giữ nguyên.
- `mcp/probe_session.py`: chuyển diagnostic prep từ worker về parent. Echo guard
  tiếp tục chạy trong worker đang sở hữu chính kết nối đó.
- `tests/test_junos_fallback.py`: thêm ca mock/localhost cho prep bình thường,
  permission/syntax, ambiguity/resync, echo sai/mất dấu cách, quoted whitespace,
  Unicode, CR repaint, pager, timeout và reuse direct/probe.

Đường bình thường giữ ba prep và cách gửi command cũ. Guard pre-Enter chỉ thêm
khoảng settle 300 ms khi phiên cần fallback. Không thay credential, host-key policy,
worker limit hoặc cấu hình persistent. Cần restart MCP để nạp source mới.

## Kiểm thử và thời gian

Toàn suite đạt **434/434 test trong 536,428 giây**, không failure hoặc skip.
16 regression mới đạt trong 41,550 giây ở lượt focused. 52 file Python đạt kiểm
tra cú pháp Python 3.10. Schema 10 tool khớp bản đóng băng, diff check đạt.
Log full suite nằm ngoài Git tại TEMP, tên `junos-fallback-full-dlltgkli.log`.

Các regression prep/prompt cũ đã đạt 21 test. Các regression mới được chạy bằng
mock clock và SSH server chỉ bind 127.0.0.1. Server echo bytes trước Enter, cho phép
kiểm tra lệnh sai không được submit. Direct và probe dùng một authentication khi
reuse. Thử pager kiểm cả trang cuối nhận đủ và trường hợp không có trang cuối.

Đo normal cold connection dùng cùng Python/Netmiko, localhost server và ba ack prep
chuẩn. Mỗi bản có năm kết nối mới, lấy median. Cold execute gồm connect/prep và một
show version. Không bao gồm RSA key generation. Source baseline/current và JSON
số đo nằm ngoài Git trong TEMP, thư mục `junos-fallback-bench-0rzmu9_s`.

| Median, 5 cold connections mỗi bản | HEAD trước sửa | Bản sửa |
| --- | ---: | ---: |
| Cold execute | 1440,661 ms | 1449,657 ms |
| Connect + prepare | 1124,904 ms | 1133,590 ms |
| Riêng Netmiko preparation | 1108,818 ms | 1108,089 ms |

Cold execute tăng khoảng 9 ms, tương đương 0,62% trong fixture. Mỗi lượt chỉ có
ba prep và một show version, một authentication. Bản source được đo khớp byte với
backend dùng cho kiểm thử cuối. Không thêm probe hoặc echo settle ở đường bình thường.

Số đo localhost chỉ phát hiện overhead ở fixture bình thường. Không đại diện cho
RTT, AAA, tải MX hoặc thời gian trên production. Các lượt trước/sau chạy tuần tự,
không pin CPU. Chênh lệch nhỏ có thể do scheduler. Không suy percentile từ năm mẫu.

## Giới hạn

Bản này giữ phạm vi của mốc 434 test. Chưa bao gồm cơ chế "setting chưa xác nhận"
cho mọi phản hồi lạ hoặc bản địa hóa; phần tổng quát hóa sau mốc đó đã được bỏ.

Quiet period không chứng minh thiết bị sẽ không gửi dữ liệu trễ tùy ý. Guard
không phải terminal emulator đầy đủ. Phiên fallback có echo bị wrap, control không
hỗ trợ hoặc không echo sẽ bị từ chối an toàn. Chưa kiểm chứng firmware MX thật,
quyền của tài khoản noc-net hoặc transcript lỗi thực. Không tự đổi driver, nâng
quyền, apply cấu hình hoặc gửi thông báo để xử lý các trường hợp chưa rõ.

Chạy lại:

```text
python -m unittest discover -s tests -p test_junos_fallback.py -v
python -m unittest discover -s tests -v
```

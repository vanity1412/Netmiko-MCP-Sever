# Junos optional preparation fallback

Bản bổ sung trên `ceb1fc7` giữ echo guard của mốc 434 test. Phạm vi chỉ là
Junos preparation, capability theo SSH session và regression/benchmark offline.
Không SSH production, apply cấu hình, đổi driver, commit hoặc push.

## Bằng chứng và nguyên nhân

Backend cũ chưa đọc capability từ `show cli`, vẫn gửi cả ba prep và có thể coi
phản hồi không có diagnostic quen thuộc là complete-on-space đã tắt. Probe bị
sai echo dừng preparation ngay, chưa có cách hủy dòng nhập dở rồi tiếp tục an toàn.
Echo đúng nhưng bị chia chunk cách nhau hơn 300 ms cũng có thể bị kết luận sai
là mismatch trước khi hết deadline.

Transcript width bị cắt hoặc dính token kèm syntax error và prompt sạch đã qua
được ở cả mốc 434 lẫn bản bổ sung trong mock. Nó chưa đủ để chứng minh nguyên
nhân của `junos_echo_mismatch` trên MX204. Các số liệu 590/595 và kết quả generic
là bằng chứng người dùng cung cấp; chưa được chạy lại hoặc xác nhận độc lập.

## Hành vi

- Giữ đường bình thường: ba prep theo thứ tự cũ, cùng deadline, không thêm
  `show cli` hoặc echo settle khi ACK chuẩn xác nhận từng setting.
- Khi prep lỗi hoặc ACK chưa xác nhận, probe `show cli` một lần sau boundary
  operational sạch. Không gửi lại prep đã lỗi. Các prep còn lại được bỏ qua
  bằng capability đã biết hoặc thay bằng exact echo guard và pager reader.
  Width chưa biết vẫn được thử một lần trên phiên mới; cách probe sau lỗi
  tránh thêm round-trip vào mọi phiên Junos bình thường.
- Chỉ ACK chuẩn, đơn nghĩa hoặc đủ ba trường capability không mâu thuẫn mới
  xác nhận setting. Bare prompt, phản hồi lạ/bản địa hóa, ACK trộn nội dung,
  field thiếu/lặp hoặc CLI error không xác nhận setting. Diagnostic chỉ giúp
  gắn nhãn; quyết định an toàn không phụ thuộc danh sách chuỗi lỗi.
- `screen-length 1000` vẫn có paging. Complete-on-space còn bật hoặc chưa rõ
  luôn giữ kiểm echo chính xác trước Enter, kể cả khoảng trắng, quote và pipe.
  Prefix echo chưa đủ được chờ đến deadline cũ; mismatch thật không gửi Enter.
- Prep/probe chưa đồng bộ chỉ được hủy bằng tối đa một Ctrl-C cho cả lần prep.
  Cần cancel echo rõ ràng, đúng operational prompt, không question và ổn định
  ít nhất 300 ms. Prompt cũ đến trễ hoặc chuỗi `^C` trong payload không đủ.
  Không có bằng chứng thì dừng; không retry prep hay gửi Enter để chữa mismatch.
- Syntax error hoàn chỉnh cùng prompt được reader xử lý sau quiet period hiện
  có, không chờ echo deadline 5 giây. Syntax chưa có prompt vẫn chờ dữ liệu
  trong ngân sách cũ. Không đổi verifier/deadline chung cho lệnh nghiệp vụ.
- Probe không xác nhận capability nhưng kết thúc ở boundary an toàn vẫn cho
  phép lệnh chính đi qua strict echo guard. Lỗi lệnh chính vẫn là CLI_ERROR;
  prep advisory không biến output thiếu, pager thiếu hoặc echo sai thành SUCCESS.
- Cache gắn với connection đang sống, gồm width/length/complete-on-space và
  trạng thái đã prep. Reuse không probe/prep lại; đóng/lỗi reconnect tạo trạng
  thái mới. Worker chuyển capability về proxy. Lệnh `set cli` tường minh của
  người dùng invalidate capability và bật guard cho lệnh sau.
- Giữ nguyên lệnh có `| no-more` do người dùng cung cấp. Không tự nối pipe vì
  không chứng minh được cú pháp mọi lệnh/quote/pipeline. Các lệnh có match,
  count, display set, nhiều pipe và lệnh cấu hình giữ nguyên byte; pager reader
  hiện có tiếp tục thu đủ trang hoặc trả incomplete.

Không sửa authentication, session key/isolation, retry transport, driver selection,
10 tool schema hoặc cấu hình persistent. Ba lệnh prep chỉ đổi tùy chọn CLI của
phiên. Transcript prep/probe/resync được giữ trong diagnostic hiện có.

## Mở lại phiên khi đồng bộ thất bại

Đặt `"junos_minimal_recovery": true` trong cấu hình thiết bị hoặc profile để
thử tính năng này trên Junos đã xác định driver `juniper_junos`. Mặc định tắt.
Collector chỉ mở lại một lần cho batch lệnh đọc `show` hoặc `display` đủ điều
kiện chạy lại, khi bước đồng bộ của phiên đầu thất bại trước lệnh đầu tiên.
Lần mở lại dùng cùng tham số kết nối và deadline của yêu cầu.
Collector giữ pool riêng cho phiên của cấu hình Junos đã bật tùy chọn, để
profile tắt tùy chọn dùng phiên chuẩn. Trong scanner, lần mở lại dùng lượt
thử còn lại của chu kỳ. Nếu scanner đã chuyển sang lượt retry, batch không
mở thêm phiên minimal.

Phiên mới xác minh prompt, bật kiểm tra echo và dùng `show cli` để xác minh
reader. Collector giữ phân trang và dòng output xuống hàng theo phản hồi thiết
bị. Nếu echo của chính lệnh nhập bị xuống dòng theo cách reader chưa xác minh
được, Collector dừng trước khi gửi Enter.

Kết quả ghi lần đầu trong `previous_attempt` và phản hồi kiểm tra phiên mới
trong `junos_preparation` hoặc trong lỗi chuẩn bị. `continue_on_error` vẫn điều
khiển việc chạy tiếp sau lỗi CLI khi batch đã bắt đầu.

## Kiểm thử và benchmark

Kết quả của mốc 434: 434/434 PASS trong 536,428 giây; localhost cold execute
1440,661 → 1449,657 ms, tăng 0,62%. Đây là số đo lịch sử, không phải kết quả của
bản bổ sung.

Benchmark bản bổ sung so với `ceb1fc7`, năm cold connection localhost mỗi bản:

| Median | Mốc 434 | Bản bổ sung |
| --- | ---: | ---: |
| Cold execute | 1444,293 ms | 1437,464 ms |
| Connect + prepare | 1129,910 ms | 1116,120 ms |
| Riêng preparation | 1109,328 ms | 1106,610 ms |

Cold execute chênh −0,47%; chưa đủ để kết luận tăng tốc. Mỗi mẫu giữ một auth,
ba prep và một show, không probe. Chạy tuần tự, không pin CPU; suite offline
cũng chạy cùng máy nên có nhiễu scheduler. SHA-256 backend sau benchmark khớp
source được dùng cho lượt suite cuối.

Mock clock, năm mẫu mỗi tình huống (prep + một show): đường bình thường giữ
1200 → 1200 ms; width bị cắt/dính token với syntax + prompt sạch giữ 5/5 ở cả
hai bản, 1200 → 1500 ms do probe/echo guard bổ sung. Ca tiêm lỗi echo của probe
sau prompt continuation: mốc 434 dừng an toàn 0/5 ở 650 ms; bản bổ sung hủy input
rồi chạy show đúng 5/5 ở 1550 ms. Đây là thời gian ảo và lỗi tiêm tổng hợp,
không phải kết quả của năm MX204 thật hay benchmark cả 595 thiết bị.

Hai kiểm chứng SSH localhost bổ sung đạt với cả `juniper_junos` và worker
`autodetect`: tiêm echo sai cho `show cli` trước Enter, hủy bằng Ctrl-C, xác nhận
prompt sạch, chạy hai show đúng và reuse một authentication. Probe sai chưa hề
được submit. Log của hai ca này cũng nằm trong thư mục TEMP trên.

Suite cuối đạt **452/452 test trong 546,032 giây**, không failure hoặc skip:
giữ toàn bộ 434 ca của baseline và bổ sung 18 ca. Trong đó 34 ca mock/timing
đạt riêng trước lượt full; các ca localhost direct/worker đều đạt trong suite.
Schema của cả 10 tool khớp hợp đồng đóng băng và 52 file Python đạt kiểm tra
cú pháp Python 3.10. Diff check đạt. Test/log/JSON benchmark nằm
ngoài Git trong TEMP (`junos-adaptive-20261118-_t_lups6`); log suite là
`junos-adaptive-full-final-20261118.log`. Fixture chỉ dùng dữ liệu tổng hợp và SSH
server bind 127.0.0.1. ACK trong fixture Junos bình thường được làm rõ theo
phản hồi chuẩn; bare/unknown/mixed ACK có test từ chối riêng.

Chạy lại:

```text
python -m unittest discover -s tests -p test_junos_fallback.py -v
python -m unittest discover -s tests -p test_preparation_timing.py -v
python -m unittest discover -s tests -v
```

Sau lượt full 452 test, bổ sung hai regression lâu dài cho rủi ro resync/cache:
continuation hoặc question đến trong cửa sổ chờ sau cancel/prompt phải bị từ
chối; lệnh sau `set cli` trên session reuse phải qua exact echo guard, echo sai
không được Enter. Toàn nhóm mock/timing hiện tại đạt **36/36 trong 0,644 giây**.
Không đổi backend trong lượt kiểm tra này; chưa chạy lại full suite 454 test.
Các test dữ liệu muộn chỉ kiểm chứng lịch phát đã mô phỏng, không bảo đảm không
có dữ liệu đến sau cửa sổ quan sát.

## Giới hạn

Chưa nghiệm thu 5 MX204 bằng juniper_junos hoặc benchmark 595 thiết bị thật.
Quiet period không chứng minh thiết bị sẽ không gửi dữ liệu trễ tùy ý. Guard
không phải terminal emulator đầy đủ; echo wrap/control không hỗ trợ hoặc mất
cancel echo có thể khiến phiên bị từ chối an toàn. Phản hồi bản địa hóa chưa
được xác nhận giữ guard, không được suy là prep thành công.

Probe/cancel không phản hồi có thể dùng hết deadline riêng hiện có; chỉ lỗi đã
hoàn chỉnh mới fail-fast. Nhánh fallback có thêm chi phí kiểm chứng an toàn.
Số đo localhost/mock không đại diện RTT, AAA, firmware hoặc tải MX production.

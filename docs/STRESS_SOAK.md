# Stress/soak mock và localhost — 2026-11-17

Runtime được kiểm tra: commit `94c3094`, Python 3.14.6, Netmiko 4.7.0,
Windows 11. Không sửa backend, schema, dependency, timeout/retry/session policy
hoặc cấu hình triển khai. Giới hạn worker/session bên dưới chỉ thuộc fixture test.
Harness mới: [soak_collector.py](../tests/soak_collector.py);
regression: [test_soak_harness.py](../tests/test_soak_harness.py).

## Phạm vi và cách đo

- Fleet 500/2.500 dùng test hiện có, mỗi cỡ chạy trong process mới; socket connect
  và connect_ex bị chặn trong lượt đo. Không có SSH/AAA thật ở fleet mock.
- Soak mock dùng cùng collector/pool trong 180 giây, tám alias, hai credential
  fixture; hai alias cùng host nhưng khác credential. Tối đa bốn worker/tám
  session. Mỗi mười chu kỳ có một job scanner riêng, bốn worker/bốn session,
  gây lỗi xác định trước và kiểm tra retry/resume/evidence.
- Soak localhost dùng SSH server chỉ bind 127.0.0.1, credential/key tự sinh cho
  fixture; không có tham số target/inventory production. Một collector Linux trực
  tiếp và một collector autodetect giữ probe worker, mỗi pool giới hạn bốn session.
  Thử EOF rồi recovery trên collector trực tiếp; probe giữ khỏe để đo worker.
- CPU là process CPU seconds (mọi thread), phần trăm quy về một core nên có thể
  vượt 100%. Fleet chỉ đo pha scan; hash/resume/negative checks còn chạy sau đó.
  Fleet lấy mẫu parent RSS mỗi 25 ms; soak lấy mẫu mỗi 200 ms, tối đa 2.000 mẫu.
- Parent soak gồm harness, ghi/copy evidence và SSH test server nếu là localhost.
  Worker được đo riêng bằng API OS trên Windows/Linux. CPU worker là giá trị cuối
  quan sát trước khi process thoát, có thể thiếu phần cuối. RSS tổng là tổng các
  resident set, có thể đếm trùng trang shared; không phải RAM vật lý duy nhất.
- Một smoke đầu thiếu driver đã bị dừng: checkpoint chỉ có connect_timeout trên
  địa chỉ tài liệu 192.0.2.x, không có output thu thập thành công. Lượt này bị loại
  khỏi số đo. Harness sau sửa có driver tường minh, reject_detection và test chặn
  socket/probe để ngăn discovery ngoài nhánh mock.

## Tài nguyên đo được

RSS là đỉnh lấy mẫu của parent, không phải peak allocation chính xác:

| Kịch bản | Wall đo (s) | CPU parent (s) | CPU một core | RSS parent (MiB) |
|---|---:|---:|---:|---:|
| Fleet 500, process riêng | 5.255 | 6.703 | 127.55% | 55.56 |
| Fleet 2.500, process riêng | 36.543 | 32.734 | 89.58% | 72.98 |
| Soak mock, 584 chu kỳ | 180.146 | 108.375 | 60.16% | 54.75 |
| Soak localhost, 87 chu kỳ | 121.242 | 5.062 | 4.18% | 58.06 |

Localhost có một probe worker: sampled RSS đỉnh khoảng 51.66 MiB, CPU quan sát
1.625 s; RSS parent+worker đồng thời đỉnh khoảng 108.57 MiB. Không cộng hai đỉnh
riêng để suy ra đỉnh tổng hoặc so trực tiếp CPU này với thiết bị production.
Worker sample unavailable=0 trong lượt đo này.

## Session, retry/resume và evidence

| Fleet | Success | Partial | Failed | Factory calls | File hash đã kiểm tra |
|---|---:|---:|---:|---:|---:|
| 500 | 300 | 50 | 150 | 650 | 800 |
| 2.500 | 1.500 | 250 | 750 | 3.250 | 4.000 |

Các lỗi trong bảng được bơm có chủ đích, không phải 40% lỗi ngoài dự kiến. Phân bố
khớp yêu cầu test; chưa gặp trạng thái ngoài dự kiến. Fleet cached fake connections
đỉnh 32, không phải 32 SSH handshake đồng thời. Resume không mở lại kết nối, hash
sai bị từ chối, shutdown không còn session/fake connection.

Soak mock đạt:

- 584 chu kỳ, 9.344 kết quả command ở pool warm, chỉ tám lần tạo kết nối; dữ liệu
  từng alias/credential khớp byte mong đợi, kể cả hai credential cùng host.
- 59 job lỗi, 472 target và 649 attempt. Mỗi job: bốn success, hai partial, hai
  failed đúng kịch bản; transient chỉ retry một lần, không chạy lại prefix đã đủ.
  Lệnh cấu hình giả có tác động chưa rõ giữ UNCERTAIN và không tự replay.
- 59 resume không phát sinh kết nối/lệnh mới; 59 lần sửa evidence cố ý bị từ chối
  trước SSH. File test được phục hồi bằng byte gốc trước khi đóng manifest.
- 10.052 file/29.419.483 byte raw được giữ và tái kiểm tra hash. Kiểm tra độc lập
  thêm 118 file CLI error/partial xác nhận đúng từng byte, không chỉ hash tự sinh.
- Warm pool không vượt tám session; fault pool không vượt bốn connection, đo riêng
  với warm pool. Queue/lease trả về 0 sau mỗi chu kỳ, scratch chỉ retire sau copy
  và kiểm chứng evidence bền vững.

Soak localhost đạt:

- 87 chu kỳ, năm EOF injection và năm recovery đúng một lần; partial đầu tiên được
  giữ nguyên. Bảy lần auth = hai phiên ban đầu + năm reconnect được chờ đợi.
- Chín câu hỏi giữ AWAITING_INPUT, chỉ Enter tường minh mới tiếp tục; không reconnect
  để trả lời. Một probe worker được tạo và giữ qua lượt soak; không spawn lặp.
- 385 file/2.072.103 byte evidence, tất cả hash khớp. Sau shutdown: 0 session,
  0 worker sống, pool threads dừng và test server transport đều inactive.

## Bộ nhớ và giới hạn kết luận

Sau warm-up 10 giây, lấy median 25 mẫu đầu/cuối: mock RSS khoảng 53.53 → 53.84 MiB,
private bytes tăng khoảng 0.59 MiB; thread giữ mức 6, handles 179 → 177. Sau shutdown
chỉ còn một Python thread. Không thấy tăng handle/thread theo số chu kỳ ở lượt này.

Localhost RSS khoảng 55.07 → 56.68 MiB; handles 207 → 220, thread giữ mức 9 khi còn
hoạt động. Fixture cố ý giữ danh sách transport đã đóng để cleanup. Chẩn đoán riêng
20 chu kỳ xác nhận ba transport đều inactive; bỏ tham chiếu fixture và GC làm
handles 216 → 210, rồi 209 sau khi hàm trả về. Đây không phải session SSH còn sống
và không cần sửa backend để dọn các tham chiếu của test server.

RSS không giảm ngay sau GC trong chẩn đoán; chưa đủ bằng chứng tách hết allocator,
trace buffer và fixture khỏi mức tăng nhỏ. Soak 2–3 phút không chứng nhận leak-free
nhiều giờ/ngày, mọi firmware, tải AAA, nhiều MCP process hay hàng nghìn SSH thật.
Raw các soak được giữ ngoài Git; các test fleet kiểm tra hash trước khi cleanup
TemporaryDirectory như thiết kế unittest, chỉ JSON số đo được giữ cho fleet.

## Chạy lại

Kiểm chứng cuối: **415/415 test pass trong 481.408 giây, không skip**, gồm bốn
regression harness mới, schema/JSON-RPC, reader, mock fleet, SSH localhost và
shared-storage/scanner crash recovery. Python 3.10 syntax và diff check đạt.

Chọn output mới; CLI từ chối đè artifact. Không truyền inventory/credential thật:

```powershell
python -m unittest discover -s tests -p test_soak_harness.py -v
python tests/soak_collector.py --mode mock --seconds 180 --output "$env:TEMP\soak-mock-new.json"
python tests/soak_collector.py --mode localhost --seconds 120 --output "$env:TEMP\soak-localhost-new.json"
$env:SSH_STRESS_REPORT = "$env:TEMP\fleet-isolated-new.json"
python -m unittest discover -s tests -p test_fleet_stress.py -k test_500_ -v
python -m unittest discover -s tests -p test_fleet_stress.py -k test_2500_ -v
Remove-Item Env:SSH_STRESS_REPORT
python -m unittest discover -s tests -v
```

Mỗi lệnh fleet là process riêng; không dùng RSS của hai cỡ chạy nối tiếp trong
cùng process để suy quy luật scale. Artifact phiên này ở TEMP/netmiko-stage6-20261117:
JSON metric, trace lấy mẫu, manifest và raw soak. Có thể dùng report_bundle.py
--mode FULL để copy raw/metadata bằng script; không viết lại raw bằng model, không
ZIP hoặc gửi email trong kiểm thử này. Không commit các artifact/key/cache này.

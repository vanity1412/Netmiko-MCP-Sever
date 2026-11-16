# Reader baseline — 2026-11-16

Đo reader hiện tại trước tối ưu, trên commit `10e8d9083e9d1ff0e2248ffcbcaad15b575b20a8`.
Không sửa source backend, schema, timeout, quiet period, retry hoặc session policy.
Harness: [tests/benchmark_reader.py](../tests/benchmark_reader.py).

Kiểm chứng cuối: toàn bộ 398 test pass trong 469.650 giây, không skip. Bốn test
harness mới kiểm tra fixture, UTF-8 bị chia byte, profile, pager và prompt ambiguity.
Kiểm tra cú pháp Python 3.10 và diff đều đạt; không SSH production.

## Phạm vi và cách đo

- Python 3.14.6, Netmiko 4.7.0, Windows 11 build 26200, một process/case.
- Channel mô phỏng cấp chunk UTF-8 theo byte; decoder incremental giữ ký tự bị
  chia tại biên chunk. Không SSH, socket, AAA, worker IPC hay thiết bị production.
- Sweep 36 case: khoảng 1/10/100 MiB × chunk 4 KiB/64 KiB/1 MiB × text/JSON/XML/banner.
  Text và JSON chunk 64 KiB được đo thêm ba lần/kích thước (18 case).
- Clock accelerated bỏ thời gian sleep thực, nhưng monotonic vẫn cộng thời gian
  xử lý thật và sleep đã bỏ. Các kiểm tra quiet/deadline của reader vẫn chạy;
  không dùng clock đứng yên trong lúc parse. Ghi riêng requested_sleep_seconds.
  Đây là thời gian xử lý có instrumentation, không phải latency production.
- Đối chiếu clock thật: 1/10 MiB, chunk 64 KiB, text/JSON, hai lần mỗi case (8 case).
  Prompt giả/pager: 1/10 MiB × chunk 4/64 KiB (8 case). XML chứa prompt: 1/10 MiB,
  chunk 64 KiB (2 case). Hai profile riêng 10 MiB text/JSON bằng cProfile.
- Tổng 74 lượt, kể cả hai lượt profile; tất cả giữ đúng hash mong đợi và phản hồi
  đúng kịch bản. Prompt giả phải trả output_verification; pager chỉ thêm Space.
  Hash so với fixture độc lập; pager thay đúng marker đã xử lý bằng khoảng trắng.
- ResourceMonitor lấy mẫu RSS 25 ms trong process. Baseline đã chứa wire fixture;
  RSS gồm interpreter, fixture, buffer và các bản sao xử lý. Peak lấy mẫu có thể
  bỏ lỡ đỉnh; delta không phải phép đo chính xác từng allocation. CPU gồm thread
  lấy mẫu. cProfile và wrapper cũng có overhead; không cộng các thời gian inclusive
  của hàm lồng nhau và không dùng một sample để khẳng định percentile production.
- Đơn vị read amplification là tổng ký tự trả bởi OutputBuffer.value chia số ký
  tự transcript cuối; không phải số byte đọc vật lý từ đĩa. Spool/OS cache có thể
  làm I/O vật lý khác xa con số này. Fixture được tạo trước vùng timing của reader.

## Kết quả chính

Median ba lần, chunk 64 KiB; chỉ thời gian reader accelerated, không gồm tạo fixture,
hash kết quả hoặc khởi động process:

| Dung lượng xấp xỉ | Text — wall / CPU (s) | JSON — wall / CPU (s) |
|---|---:|---:|
| 1 MiB | 0.109 / 0.109 | 0.236 / 0.234 |
| 10 MiB | 0.760 / 0.766 | 1.059 / 1.062 |
| 100 MiB | 6.288 / 6.297 | 9.189 / 9.172 |

Clock thật, median hai lần: 10 MiB text 2.465 s, JSON 2.724 s; CPU lần lượt
0.844 s và 1.132 s. Reader yêu cầu khoảng 1.6 s sleep để đi qua các chunk này.
Số đo minh họa chi phí polling trên channel luôn sẵn dữ liệu; Netmiko thực có thể
gộp chunk khác nhau và có thời gian chờ thiết bị/mạng riêng.

Sweep 100 MiB, mỗi ô một lần (không phải median):

| Loại | Xử lý chunk 4 KiB (s) | 64 KiB (s) | 1 MiB (s) | RSS lấy mẫu ở 64 KiB / delta từ baseline (MiB) |
|---|---:|---:|---:|---:|
| Text | 26.613 | 6.327 | 5.384 | 500 / 370 |
| JSON | 30.066 | 9.528 | 8.405 | 864 / 733 |
| XML | 30.434 | 10.577 | 9.396 | 874 / 743 |
| Banner | 27.004 | 7.363 | 5.867 | 501 / 370 |

Với khoảng 100 MiB, reader yêu cầu thêm khoảng 256/16/1 giây sleep tương ứng
chunk 4/64/1024 KiB. Chỉ 1/10 MiB có đối chiếu clock thật trong đợt này; không
trình bày tổng thời gian dự phóng cho 100 MiB như kết quả đo thực.

## Bottleneck có bằng chứng

1. **Polling và xử lý tail theo từng chunk.** Text 100 MiB chunk 4 KiB tốn xử lý
   nhiều hơn khoảng bốn lần chunk 64 KiB, ngoài số sleep yêu cầu lớn hơn 16 lần.
   Profile text 10 MiB/4 KiB cho thấy ending_matches, regex chuẩn hóa terminal,
   splitlines và spool là các điểm đáng chú ý; profile cũng có overhead lấy mẫu.
2. **Materialize/normalize/verify toàn transcript.** 100 MiB text bình thường
   chỉ có bốn lần value(), không tăng theo hàng nghìn chunk. JSON/XML còn có
   nhiều lượt clean_terminal và parse container, đồng thời tạo nhiều bản sao RAM.
   Vì vậy chưa thể gọi đường bình thường là bậc hai chỉ từ sự hiện diện value().
   Với 1 MiB text/64 KiB, một lượt sweep đọc toàn buffer 27 lần trong thời gian
   settle; ở 100 MiB chỉ bốn lần vì bản thân xử lý đã vượt quiet period.
3. **XML có prompt giả kích hoạt phân tích lại các prefix đang lớn dần.** Fixture
   đặt một dòng router# khoảng mỗi 64 KiB bên trong root XML còn mở; channel dừng
   chunk đúng sau marker. Đây là tình huống bất lợi có chủ đích, không đại diện
   mọi output XML hoặc mọi cách chia chunk của Netmiko.

| XML có prompt bên trong | Xử lý wall / CPU (s) | value() | Read amplification |
|---|---:|---:|---:|
| Khoảng 1 MiB | 0.419 / 0.422 | 31 | 23.500× |
| Khoảng 10 MiB | 16.303 / 16.000 | 165 | 85.444× |

Ở 10 MiB, container_check có inclusive time 12.752 s và nhận tổng khoảng 772
triệu ký tự; nó gọi normalize/parse nên không cộng thêm clean_terminal như một
khoản độc lập. XML thường cùng kích thước/chunk mất 1.093 s trong sweep.
Tất cả case XML chứa prompt vẫn giữ đủ SHA-256 và không báo hoàn tất trước root
đóng. Cơ chế bảo vệ đang đúng, chi phí thực thi cần cải thiện. Khi số marker tăng
cùng dung lượng, việc parse lại mỗi prefix tạo cấu trúc chi phí có nguy cơ bậc hai;
hai kích thước đo được chưa đủ xác định hệ số hoặc dự báo latency 100 MiB.

## Thứ tự tối ưu đề xuất sau baseline

1. Cache kết quả container/normalization theo phiên bản dữ liệu: khi không có dữ
   liệu mới trong settle loop, không đọc/parse lại cùng transcript. Giữ nguyên
   quiet period, checkpoint, cancel, EOF và so sánh ambiguity khi có dữ liệu mới.
2. Tách guard XML/JSON/banner thành trạng thái incremental, xử lý phần mới thay
   vì parse lại prefix. Đây là thay đổi nhạy cảm: phải bảo vệ prompt giả, XML chưa
   đóng, banner delimiter, ANSI bị chia chunk, JSON escape và lỗi parse. Không chỉ
   kiểm tra suffix/brace count rồi bỏ cơ chế xác minh hiện tại.
3. Đo riêng thử nghiệm đọc liên tục khi channel còn dữ liệu và chỉ sleep khi idle;
   luôn có checkpoint/deadline và xử lý pager. Không bỏ 10 ms sleep trong bản này
   vì thay đổi đó có thể đổi hành vi scheduling và xác minh prompt.
4. Giảm số bản sao toàn transcript trong normalize/hash/final verification; đo
   thêm peak allocation riêng và đường worker IPC trước khi hứa RAM hằng số.

Mỗi thay đổi phải so cùng fixture/chunk/clock, giữ nguyên hash và status, không
false SUCCESS, không thêm command write/replay. Sau đó chạy toàn suite và test
SSH localhost. Chỉ cân nhắc tối ưu tiếp khi có cải thiện đo được; không tăng worker,
timeout hoặc rút gọn raw output để làm đẹp benchmark.

## Chạy lại

Chọn file JSON mới ngoài repository; mỗi case có timeout subprocess hữu hạn.
Ví dụ PowerShell:

```powershell
python tests/benchmark_reader.py --output "$env:TEMP\reader-matrix-new.json"
python tests/benchmark_reader.py --sizes-mib 1 10 100 --chunks 65536 --kinds plain json --repeats 3 --output "$env:TEMP\reader-repeat-new.json"
python tests/benchmark_reader.py --sizes-mib 1 10 --chunks 65536 --kinds plain json --clock real --repeats 2 --output "$env:TEMP\reader-real-new.json"
python tests/benchmark_reader.py --sizes-mib 1 10 --chunks 65536 --kinds xml_prompt --output "$env:TEMP\reader-xml-prompt-new.json"
python tests/benchmark_reader.py --sizes-mib 1 10 --chunks 4096 65536 --kinds fake_prompt pager --output "$env:TEMP\reader-adversarial-new.json"
python tests/benchmark_reader.py --child --sizes-mib 10 --chunks 4096 --kinds plain --profile "$env:TEMP\reader-plain-new.prof"
python -m unittest discover -s tests -v
```

Raw JSON đo trong phiên này ở TEMP với prefix reader-matrix/reader-repeat/reader-real/
reader-adversarial/reader-xml-prompt và ngày 20261116. Chúng chỉ chứa số đo synthetic,
không có output thiết bị. Clock accelerated/real và scope luôn phải đi cùng số liệu
khi dùng để so sánh; không so RSS này với một benchmark process đã có sẵn fixture
hoặc workload khác mà không xét baseline.

# Reader optimization — 2026-11-17

Baseline đã commit/push: `04d6449` (runtime reader giống đợt đo trước).
So sánh theo [harness](../tests/benchmark_reader.py) và phạm vi của
[baseline](READER_BENCHMARK.md). Bản tối ưu được đo trong working tree; SHA-256
của source cuối dùng trong bảng là
`cbe1b9458fdef60d44c8608b48f41deaba1c80313ca3a1b26dc6212132384a8b`.
Các case chốt ghi reader_sha256 riêng và đã đối chiếu với file thực tế.

## Thay đổi và các ràng buộc giữ nguyên

- Cache raw snapshot và kết quả output_container_open theo revision dữ liệu.
  Settle loop không đọc/parse lại cùng buffer khi chưa có chunk mới. Tail đã
  normalize cũng được tái sử dụng khi không có dữ liệu mới.
- Invalidate snapshot trước append/callback: nếu ghi một phần rồi lỗi, final
  evidence vẫn đọc được phần mới thay vì dùng snapshot cũ.
- XMLPrefixGuard dùng XMLParser target không tạo cây; xử lý các dòng mới để chứng
  minh root còn mở. Dòng cuối được giữ lại vì có thể là prompt mà verifier cũ loại
  khỏi XML. CRLF bị chia chunk được hỗ trợ. Guard chỉ có quyền veto completion;
  root đóng và trường hợp không chứng minh được vẫn qua verifier cũ.
- ANSI/backspace/control, bare CR, Unicode line separators, pending line quá
  64 Ki ký tự, lệnh banner hoặc lỗi parser ngoài ParseError dùng đường cũ.
  JSON và banner chỉ nhận cache, chưa có parser incremental riêng.
  Format được chọn từ match pipeline đầu tiên, đúng như verifier cũ.
- Final verification chỉ dùng lại kết quả container nếu canonical output bằng
  đúng raw snapshot đã kiểm tra. Pager/terminal rewrite làm text khác đi thì
  kiểm tra lại. Parser/target cycle được giải phóng sau command.
- Giữ nguyên mười input schema, credential/session isolation, retry/replay,
  deadline/cancel/checkpoint, quiet tối thiểu 300 ms, sleep polling 10 ms,
  command echo/prompt-family/ambiguity, pager và raw output. Không gửi thêm CLI.

## Phương pháp so sánh

Python 3.14.6, Netmiko 4.7.0, Windows 11 build 26200; một process/case, channel
synthetic UTF-8. Không benchmark SSH/AAA, worker IPC hoặc thiết bị production.
Baseline nạp từ source commit 04d6449 bằng READER_BENCHMARK_BACKEND; bản sau dùng
source workspace. Cùng harness, fixture và chunk size. Các nhóm chạy tuần tự.

158 lượt tổng cộng gồm thăm dò, lặp, profile và 15 lượt chốt trên source cuối:

- Trước/sau: mỗi bản có 24 case thường (1/10/100 MiB × bốn format × hai lượt),
  sáu case XML chứa prompt (1/10 MiB × ba lượt), bốn case clock thật 10 MiB và
  tám case prompt giả/pager. Tổng 84.
- Sweep bản tối ưu: 36 case (ba kích thước × ba chunk size × bốn format).
- Sáu lượt bổ sung RSS text 100 MiB và hai profile riêng: tổng tới 128.
- Chốt lại source cuối: tám case 100 MiB, ba XML-prompt 10 MiB và bốn clock thật.
  Có 15 lượt kiểm tra bổ sung trước đó; bảng không dùng các lượt này làm số đo
  của source cuối sau khi bổ sung regression chọn format pipeline.

Tất cả 158 case khớp hash mong đợi và status mong đợi. Prompt giả vẫn báo
output_verification; pager chỉ gửi Space cần thiết. Bảng dưới chỉ dùng các lượt
chốt cuối và baseline tương ứng. Không chọn lượt nhanh nhất.

Clock accelerated bỏ sleep thực nhưng vẫn tính thời gian xử lý vào monotonic;
đây là thời gian xử lý có instrumentation. Không gọi là latency production.
Các lượt trước và sau không xen kẽ và không pin CPU; chênh lệch nhỏ vẫn có thể bị
ảnh hưởng bởi scheduler/load. Không suy percentile từ hai hoặc ba mẫu.

## Kết quả xử lý, chunk 64 KiB

Median hai lượt cho mỗi case thường; XML có prompt là median ba lượt:

| Case | Trước (s) | Sau (s) | Giảm thời gian | value() trước → sau |
|---|---:|---:|---:|---:|
| Text khoảng 100 MiB | 6.481 | 5.378 | 17.0% | 4 → 1 |
| JSON khoảng 100 MiB | 9.475 | 6.351 | 33.0% | 4 → 1 |
| XML khoảng 100 MiB | 10.904 | 7.926 | 27.3% | 4 → 1 |
| Banner khoảng 100 MiB | 7.247 | 5.601 | 22.7% | 4 → 1 |
| XML-prompt khoảng 10 MiB | 15.443 | 0.811 | 94.7% (~19.0×) | 164 → 1 |

Read amplification XML-prompt giảm từ median 84.5× xuống 1× theo ký tự. Hash và
completion guard vẫn đúng: không dùng prompt bên trong XML để kết thúc sớm.
Guard incremental tránh parse lại các prefix tăng dần; ở điểm đóng vẫn dùng
output_container_open cũ, nên không thay verifier đầy đủ bằng đếm dấu ngoặc/tag.

CPU process của XML-prompt: 15.359 → 0.812 s. Ở 100 MiB JSON: 9.422 → 6.383 s;
XML thường: 10.891 → 7.891 s. Đây không phải tốc độ xử lý hàng nghìn thiết bị.

## Đối chiếu clock thật và bộ nhớ

Median hai lượt, 10 MiB/chunk 64 KiB:

| Case | Wall trước → sau (s) | CPU trước → sau (s) |
|---|---:|---:|
| Text | 2.521 → 2.364 | 0.860 → 0.562 |
| JSON | 2.827 → 2.379 | 1.235 → 0.641 |

Polling vẫn chiếm thời gian đáng kể nên mức giảm wall thực nhỏ hơn mức giảm CPU.
Không bỏ sleep hoặc tăng timeout để làm đẹp số đo. Output chunk 4 KiB vẫn là case
chậm; tối ưu scheduling/polling cần một thử nghiệm riêng.

RSS lấy mẫu mỗi 25 ms không phải peak allocation chính xác. Baseline đã chứa wire
fixture. Với 100 MiB text, năm lượt trước/sau cho median khoảng 499.7/499.5 MiB;
từng sample dao động khoảng 406–500 MiB, thể hiện nguy cơ bỏ lỡ đỉnh ngắn.
Trong lượt chốt JSON, sampled RSS median khoảng 864 → 681 MiB; XML khoảng
874 → 875 MiB, không giảm đáng kể. Không hứa RAM hằng số hoặc RSS giảm cho mọi
format. Raw/canonical output cuối vẫn materialize để normalize/hash/verify.

## Kiểm chứng hành vi

Toàn suite cuối: **408/408 test pass trong 493.289 giây, không skip**. Bao gồm
JSON-RPC/10 schema, fleet mô phỏng, SSH localhost, worker lifecycle, reader và
storage/scanner crash recovery. Python 3.10 syntax và diff check đạt. Lượt full
trước được dừng để bổ sung tương thích pipeline; số liệu này là lượt chạy lại
đầy đủ trên source cuối. Không SSH production.

Đối chiếu source cuối với baseline trên 1.440 replay seeded: output, failure dict,
phím gửi, pager spans và prompt cuối trùng nhau. Bao gồm text/log/banner, JSON/XML,
CRLF, CDATA, malformed XML, ANSI/backspace, prompt trong payload, EOF và pending
confirmation và thứ tự JSON/XML trong pipeline. Đây là replay synthetic, không
chứng minh mọi firmware.

Mười regression mới kiểm tra cache/invalidation, prefix mở, timeout/EOF, custom
expect trên dòng cuối, partial spool write, callback lỗi, input dài/control và
fallback khi parser incremental không hỗ trợ. Guard veto cũng được đối chiếu với
verifier toàn transcript trên các prefix chia ngẫu nhiên.

## Chạy lại

Mỗi output phải là đường dẫn mới. Ví dụ PowerShell; các file source baseline và
JSON đo được đặt ngoài repository:

```powershell
$baselineReader = Join-Path $env:TEMP 'reader-baseline-04d6449.py'
python -c "import pathlib,subprocess,sys; pathlib.Path(sys.argv[1]).write_bytes(subprocess.check_output(['git','show','04d6449:mcp/collector_backend.py']))" $baselineReader
$env:READER_BENCHMARK_BACKEND = $baselineReader
python tests/benchmark_reader.py --sizes-mib 100 --chunks 65536 --kinds plain json xml banner --repeats 2 --output "$env:TEMP\reader-before-new.json"
python tests/benchmark_reader.py --sizes-mib 10 --chunks 65536 --kinds xml_prompt --repeats 3 --output "$env:TEMP\reader-before-xml-new.json"
Remove-Item Env:READER_BENCHMARK_BACKEND
python tests/benchmark_reader.py --sizes-mib 100 --chunks 65536 --kinds plain json xml banner --repeats 2 --output "$env:TEMP\reader-after-new.json"
python tests/benchmark_reader.py --sizes-mib 10 --chunks 65536 --kinds xml_prompt --repeats 3 --output "$env:TEMP\reader-after-xml-new.json"
python -m unittest discover -s tests -v
```

Artifact phiên này ở TEMP với prefix reader-opt-before/after (20261116),
reader-opt-final-after và reader-opt-final2-after (20261117), memory-repeat và
profile. Bảng dùng final2-after. Chỉ chứa số đo và hash
synthetic, không có output thiết bị. Hướng tiếp theo: đo riêng scheduling/idle
polling và giảm bản sao final transcript, giữ nguyên bộ replay và hash/status gates.

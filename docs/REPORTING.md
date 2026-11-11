# Báo cáo đầy đủ, ít token

Backend/10 tools không đổi. Raw đầy đủ lưu ở file; agent chỉ nạp phần cần để suy luận. Với kiểm kê toàn bộ, kết luận không tồn tại hoặc tính đầy đủ, vẫn phải xét hết phạm vi dữ liệu. Search/preview giới hạn không đủ cho kết luận toàn cục.

## Tạo bundle

Agent viết summary.md gồm bốn mục Kết luận/Bằng chứng/Hướng xử lý/Chưa xác minh và dẫn evidence ID; không chép lại raw hay tự viết HTML. Lưu raw MCP thành file bền vững trước khi output_id hết TTL. Giữ nguyên lỗi/partial, không đổi status thành SUCCESS. Tính SHA-256 bằng công cụ local, không yêu cầu model tính/nhớ hash.

Manifest.json mẫu (thay path/hash bằng file thật):

```json
{"evidence":[{"id":"e1","path":"raw/device-a.txt","target":"LAB-A","command":"show interfaces","status":"PARTIAL","sha256":"SHA256_CUA_FILE"}]}
```

Path tương đối tính cạnh manifest; status do kết quả MCP cung cấp, không phải script suy đoán. SUMMARY giữ mọi byte, kể cả file nhị phân/encoding khác; summary phải UTF-8. FULL yêu cầu raw UTF-8 và không tự bỏ ký tự lỗi. sha256 đầu vào tùy chọn: script tự tính khi thiếu, đối chiếu khi được cung cấp. Hash tự tính xác nhận byte đã đóng gói, không chứng minh nguồn trước đó chưa đổi. Empty file được giữ nguyên, không chứng minh dữ liệu không tồn tại. Không đưa credential/config riêng lên Git.

```powershell
python scripts/report_bundle.py --mode SUMMARY --summary summary.md --manifest manifest.json --output bundle-001
```

### SUMMARY (mặc định CLI)

Email tổ chức theo bốn mục **Kết luận / Bằng chứng / Hướng xử lý / Chưa xác minh**. Liệt kê toàn bộ raw CLI, nhật ký, cấu hình và evidence liên quan trong manifest, mỗi file một ID; có thể thêm kind, output_complete, phạm vi, thời điểm hoặc metadata phép tìm kiếm. Script không tự tìm file bỏ sót và không tự xác nhận trạng thái thiết bị.

Bundle gồm summary.md, report.md/report.html chứa phần phân tích cần thiết, bundle.json và evidence.zip. ZIP chứa mỗi nguồn đúng một lần tại evidence/<id>.raw, source_manifest.json, manifest.json có hash/kích thước tự tạo và summary.md. Raw không nằm lại trong thân Markdown/HTML. Nguồn được đọc theo khối 1 MiB, hỗ trợ Zip64; không cần nạp toàn raw vào RAM. Mọi byte được giữ nguyên, không redaction. Bản gốc không sửa.

### Từ nhật ký phát hiện đến báo cáo

Dùng các phát hiện đã ghi theo mcp/WORKFLOW.md làm nguồn biên soạn, không sao transcript thao tác. Bắt đầu bằng kết luận theo mục tiêu; phần bằng chứng giải thích các quan sát, quan hệ giữa thiết bị và cơ chế kỹ thuật dẫn tới kết luận. Hướng xử lý phải gắn với nguyên nhân/giả thuyết và nêu cách kiểm chứng; phần chưa xác minh chỉ nêu khoảng trống thật cùng tác động lên nhận định.

Kết quả đơn giản được gộp; bất thường/mâu thuẫn phải có đủ diễn giải, nguồn và lý do của bước tiếp. Không đưa raw dài thay cho phân tích, cũng không đẩy phần lập luận cần thiết vào ZIP để người nhận tự tìm hiểu. Chỉ trích dữ kiện quan trọng và dẫn evidence ID/file/vị trí. Nhật ký đầy đủ được liệt kê trong manifest cùng raw.

Bốn mục là khung tổ chức, không phải giới hạn độ dài. SUMMARY tách raw khỏi email chứ không lược giả thuyết, nguyên nhân, phụ thuộc, tác động hoặc kiểm chứng cần thiết. Trước render, kiểm tra từng nhận định có bằng chứng và diễn giải; nếu chưa đủ, truy xuất thêm/điều tra tiếp. Hash chỉ kiểm chứng việc truyền nội dung, không chứng nhận chất lượng phân tích.

### FULL (tương thích báo cáo cũ)

Chọn `--mode FULL` khi thực sự cần toàn raw inline: evidence/<id>.txt, report.md và report.html đều chứa raw. Chế độ này còn nhân bản nội dung và dùng RAM theo tổng raw; không phù hợp file lớn. Mặc định hàm Python build() vẫn FULL để tương thích client cũ; CLI mặc định SUMMARY. Không tự chuyển SUMMARY sang FULL vì preview thiếu.

`--renderer <trusted-local-renderer.py>` dùng renderer Python đã tin cậy cho summary, không dùng đường dẫn renderer lấy từ CLI thiết bị. Script không gọi model/SSH/SMTP. Output phải là thư mục mới; file thiếu/hash sai/ID sai hoặc trùng làm hủy bundle đang dựng, không xóa nguồn hoặc dừng các phần điều tra độc lập. SHA-256 phát hiện thay đổi so với manifest đang dùng, không phải chữ ký xác thực. ZIP không mã hóa; chỉ gửi theo phạm vi đã được yêu cầu. HTML escape dữ liệu, không che nội dung.

## OpenCode1 và SMTP

Sender riêng của OpenCode1 nhận `bundle-001/report.md`, tự dùng report.html sau kiểm tra hash Markdown/HTML/evidence; với SUMMARY phải đính kèm evidence.zip đã kiểm chứng và đưa hash ZIP vào khóa dedup để phân biệt evidence thay đổi dù summary giống nhau. Report bình thường vẫn đi đường render hiện có. Nội dung bundle bị đổi hoặc cấu hình trình bày làm đổi body thì từ chối trước gửi; dựng bundle mới thay vì bỏ kiểm tra. Không thay recipient, credential SMTP, chính sách dedup, retry hoặc trạng thái unknown/sending.

Kiểm tra không gửi thật:

```powershell
python output/email-notification/send_report.py bundle-001/report.md --dry-run --preview preview.eml --html-preview preview.html
```

Module gửi email là thành phần triển khai riêng, không đi kèm repository backend công khai. Có thể dùng hàm verified_html(report) trong scripts/report_bundle.py để tích hợp sender khác. Chỉ gửi thật trong phạm vi đã được cho phép. Đóng gói streaming không có nghĩa sender MIME streaming: sender hiện có thể giữ ZIP/base64 trong RAM. Bundle lớn vẫn chịu giới hạn dung lượng SMTP/client; không tự cắt phụ lục để vượt giới hạn. Integrity verified chỉ nói về file, không xác nhận SSH hoặc mục tiêu nghiệp vụ.

## Kiểm tra và đo token

Chạy `python -m unittest discover -s tests -p test_report_bundle.py -v`. Kiểm tra hash/metadata và vài vùng render cần thiết, không đưa toàn email trở lại context chỉ để kiểm việc chép. Nếu cần đánh giá nội dung thì đọc đủ các vùng liên quan, không thay bằng bản tóm tắt.

Đo trước/sau phải dùng cùng raw, summary và tokenizer. Tách input evidence (toàn raw so với đoạn liên quan) khỏi output model (viết lại report/HTML so với summary/manifest). Đây là phép đo payload tham chiếu, không phải hóa đơn model, chứng nhận suy luận đầy đủ, hay bảo đảm tỷ lệ tiết kiệm cho mọi tác vụ; cache, reasoning và công việc phải đọc toàn bộ sẽ khác.

### Phép đo tham chiếu 11/11/2026

Cùng fixture UTF-8/CRLF 10.000 dòng (1.017.910 byte), cùng summary/manifest và tokenizer o200k_base. Baseline giả định model nhận toàn raw rồi viết lại cả report Markdown và HTML; phương án mới model nhận 11 dòng quanh một câu hỏi cụ thể cùng metadata, chỉ sinh summary/manifest. Input: 240.082 → 346 token; output: 480.557 → 106 token. Đây là tổng payload lý thuyết của công việc sao chép/render, có thể phải chia nhiều request; không phải phép chạy model thật, không bao gồm reasoning/cache và không bảo đảm mức giảm đó cho điều tra cần đọc toàn bộ. Byte raw trong bundle khớp hash gốc; phép đo cũ dùng FULL và sender dry-run giữ đủ 10.000 dòng ở plain/HTML. Với SUMMARY, raw chuyển vào ZIP, thân email không chứa raw; không dùng số liệu cũ để tuyên bố hiệu năng SUMMARY.

### SUMMARY so với FULL (fixture mô phỏng)

20.000 dòng lặp, 1.060.000 byte raw, cùng summary và manifest: tổng bundle FULL 3.181.369 byte → SUMMARY 5.289 byte; Markdown+HTML 2.120.474 → 320 byte. Peak cấp phát Python đo bằng tracemalloc: 8.620.635 → 2.717.698 byte (không phải RSS). ZIP được nén tốt vì fixture lặp; không suy tỷ lệ nén cho thiết bị thật. Kiểm tra MIME local giữ attachment đúng byte, raw không vào thân email; hash ZIP tham gia dedup kể cả cùng summary/subject. Không SSH hoặc gửi SMTP.

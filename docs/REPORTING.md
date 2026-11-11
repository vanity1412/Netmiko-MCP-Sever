# Báo cáo đầy đủ, ít token

Backend/10 tools không đổi. Raw đầy đủ lưu ở file; agent chỉ nạp phần cần để suy luận. Với kiểm kê toàn bộ, kết luận không tồn tại hoặc tính đầy đủ, vẫn phải xét hết phạm vi dữ liệu. Search/preview giới hạn không đủ cho kết luận toàn cục.

## Tạo bundle

Agent viết summary.md gồm bốn mục Kết luận/Bằng chứng/Hướng xử lý/Chưa xác minh và dẫn evidence ID; không chép lại raw hay tự viết HTML. Lưu raw MCP thành file bền vững trước khi output_id hết TTL. Giữ nguyên lỗi/partial, không đổi status thành SUCCESS. Tính SHA-256 bằng công cụ local, không yêu cầu model tính/nhớ hash.

Manifest.json mẫu (thay path/hash bằng file thật):

```json
{"evidence":[{"id":"e1","path":"raw/device-a.txt","target":"LAB-A","command":"show interfaces","status":"PARTIAL","sha256":"SHA256_CUA_FILE"}]}
```

Path tương đối tính cạnh manifest; status do kết quả MCP cung cấp, không phải script suy đoán. UTF-8 được yêu cầu; encoding khác phải chuyển đổi có kiểm chứng sang file dẫn xuất riêng và giữ bản gốc. Không tự bỏ ký tự lỗi. Empty file được giữ nguyên, không chứng minh dữ liệu không tồn tại. Không đưa credential/config riêng lên Git.

```powershell
python scripts/report_bundle.py --summary summary.md --manifest manifest.json --output bundle-001
```

Tùy chọn `--renderer output/email-notification/report_html.py` dùng renderer đã có cho phần summary. Raw luôn được escape vào pre block riêng, không bị Markdown/HTML diễn giải. Không redaction, không gọi model, SSH hay SMTP. Output phải là thư mục mới; evidence thiếu/hash đổi/ID trùng hoặc sai thì không xuất bundle hoàn chỉnh. Script in metadata gọn, không in toàn raw.

Bundle chứa summary.md, source_manifest.json, report.md, report.html, bundle.json và evidence/<id>.txt. Các bản evidence là byte-copy; bản gốc không sửa. Report Markdown chứa toàn raw bằng fence không va chạm backtick. SHA-256 trong bundle.json kiểm tra phần summary/report/HTML và từng raw. Toàn bộ raw vẫn vào phụ lục và thân email nếu sender dùng bundle; việc giữ ngoài context không có nghĩa rút gọn báo cáo.

## OpenCode1 và SMTP

Sender riêng của OpenCode1 nhận `bundle-001/report.md`, tự dùng report.html sau kiểm tra hash Markdown/HTML/evidence. Report bình thường vẫn đi đường render hiện có. Nội dung bundle bị đổi hoặc cấu hình trình bày làm đổi body thì từ chối trước gửi; dựng bundle mới thay vì bỏ kiểm tra. Không thay recipient, credential SMTP, dedup, retry hoặc trạng thái unknown/sending.

Kiểm tra không gửi thật:

```powershell
python output/email-notification/send_report.py bundle-001/report.md --dry-run --preview preview.eml --html-preview preview.html
```

Module gửi email là thành phần triển khai riêng, không đi kèm repository backend công khai. Có thể dùng hàm verified_html(report) trong scripts/report_bundle.py để tích hợp sender khác. Chỉ gửi thật trong phạm vi đã được cho phép. Bundle lớn vẫn chịu giới hạn dung lượng SMTP/client; không tự cắt phụ lục để vượt giới hạn. Integrity verified chỉ nói về file, không xác nhận SSH hoặc mục tiêu nghiệp vụ.

## Kiểm tra và đo token

Chạy `python -m unittest discover -s tests -p test_report_bundle.py -v`. Kiểm tra hash/metadata và vài vùng render cần thiết, không đưa toàn email trở lại context chỉ để kiểm việc chép. Nếu cần đánh giá nội dung thì đọc đủ các vùng liên quan, không thay bằng bản tóm tắt.

Đo trước/sau phải dùng cùng raw, summary và tokenizer. Tách input evidence (toàn raw so với đoạn liên quan) khỏi output model (viết lại report/HTML so với summary/manifest). Đây là phép đo payload tham chiếu, không phải hóa đơn model, chứng nhận suy luận đầy đủ, hay bảo đảm tỷ lệ tiết kiệm cho mọi tác vụ; cache, reasoning và công việc phải đọc toàn bộ sẽ khác.

### Phép đo tham chiếu 11/11/2026

Cùng fixture UTF-8/CRLF 10.000 dòng (1.017.910 byte), cùng summary/manifest và tokenizer o200k_base. Baseline giả định model nhận toàn raw rồi viết lại cả report Markdown và HTML; phương án mới model nhận 11 dòng quanh một câu hỏi cụ thể cùng metadata, chỉ sinh summary/manifest. Input: 240.082 → 346 token; output: 480.557 → 106 token. Đây là tổng payload lý thuyết của công việc sao chép/render, có thể phải chia nhiều request; không phải phép chạy model thật, không bao gồm reasoning/cache và không bảo đảm mức giảm đó cho điều tra cần đọc toàn bộ. Byte raw trong bundle khớp hash gốc; sender dry-run giữ đủ 10.000 dòng ở cả plain và HTML.

# Báo cáo đầy đủ, tối ưu token khi đọc evidence

## Nội dung và luồng mặc định

Agent viết phần phân tích kỹ thuật và manifest; script chép nguyên raw và render HTML. Email chứa đầy đủ phân tích cùng output CLI trong thân thư (plain UTF-8 và HTML), không đính kèm ZIP. Giảm token bằng đọc evidence có mục tiêu, tìm/parse toàn phạm vi khi cần và không dùng model viết lại raw hoặc HTML; không rút ngắn lập luận cần thiết.

Biên soạn từ nhật ký phát hiện theo mcp/WORKFLOW.md: câu hỏi/giả thuyết, nguồn thiết bị/lệnh, bằng chứng, phân tích và quyết định/bước tiếp. Gộp kết quả đơn giản; giải thích bất thường/mâu thuẫn, nguyên nhân/phụ thuộc/tác động và kiểm chứng. Bốn mục Kết luận/Bằng chứng/Hướng xử lý/Chưa xác minh là khung tổ chức, không giới hạn độ dài. Trích dữ kiện quan trọng trong phân tích; toàn output được script chèn tiếp thành các khối CLI có target/command/status/evidence ID.

## Dựng báo cáo

Lưu toàn raw MCP thành file bền vững trước khi output_id hết TTL; giữ cả partial/lỗi. Agent viết analysis.md và manifest, không chép lại raw. Ví dụ manifest (path tương đối cạnh manifest):

```json
{"evidence":[{"id":"e1","path":"raw/device-a.txt","target":"LAB-A","command":"show interfaces","status":"PARTIAL"}]}
```

Liệt kê đủ raw CLI, cấu hình và nhật ký liên quan; script không tự tìm nguồn bị bỏ sót. status/output_complete là dữ liệu thu thập, không phải script suy đoán. sha256 tùy chọn: tự tính bằng script khi thiếu, đối chiếu khi có. Hash chỉ xác nhận byte đóng gói, không chứng minh nguồn trước đó chưa đổi hay kết luận mạng đúng.

```powershell
python scripts/report_bundle.py --summary analysis.md --manifest manifest.json --output output/INC-001/bundle
```

CLI và hàm build() mặc định FULL. scripts/report_html.py mặc định render tiêu đề, chữ đậm, bảng và khối CLI; không cần truyền --renderer để có định dạng. --renderer chỉ dành cho renderer Python local đã tin cậy. Dòng # tiêu đề đầu tiên trong analysis.md dùng làm tên báo cáo/email; nếu thiếu, sender lấy tên thư mục sự cố thay vì tên bundle.

Bundle mới chứa summary.md (phân tích), source_manifest.json, report.md, report.html, bundle.json và evidence/<id>.txt. Raw gốc giữ nguyên byte, không redaction; Markdown và HTML đều chứa toàn output. HTML escape raw để CLI không bị diễn giải thành markup. Không tạo evidence.zip trong FULL. Nguồn/summary cần UTF-8; encoding khác phải chuyển đổi có kiểm chứng vào file dẫn xuất riêng, giữ bản gốc và không bỏ ký tự lỗi. FULL và MIME hiện dùng RAM theo tổng nội dung; không tự cắt output để vượt giới hạn RAM/SMTP/client.

Đích phải là thư mục mới; file thiếu/hash sai/ID sai hoặc trùng làm hủy lần dựng, không sửa nguồn. Sau render, xác minh hash/metadata và vùng trình bày cần thiết; không nạp lại toàn thư vào AI để kiểm sao chép. Kiểm tra chất lượng phân tích riêng trước render, truy xuất thêm evidence khi luận cứ chưa đủ.

## Gửi email ở OpenCode

Sender triển khai nhận bundle/report.md, xác minh Markdown/HTML/raw rồi tạo MIME plain + HTML không attachment. SMTP settings/recipient/credential và retry/outbox vẫn theo triển khai; không đổi hoặc xóa trạng thái unknown/sending. Dedup ràng buộc recipient, subject và toàn body. Chỉ gửi thật theo quyền đã có; test dùng dry-run:

```powershell
python output/email-notification/send_report.py output/INC-001/bundle/report.md --dry-run --preview preview.eml --html-preview preview.html
```

SUMMARY còn là chế độ lưu trữ ZIP tường minh để tương thích, không phải luồng email. Sender từ chối bundle SUMMARY cũ với hướng dẫn dựng lại FULL; không âm thầm gửi thiếu output hoặc đính kèm ZIP. Không chỉnh hash để gửi lại artifact đã sửa; dựng bundle mới từ nguồn gốc. File/email cũ không tự thay đổi.

Sender là thành phần triển khai riêng, không chứa trong Git công khai. Có thể dùng verified_html(report) cho tích hợp khác. Không đổi SSH/backend hay 10 tools. Không commit inventory, credentials hoặc evidence thật.

## Kiểm chứng

Chạy python -m unittest discover -s tests -p test_report_bundle.py -v. Test kiểm tra render/bảng/CLI, toàn raw/Unicode/CRLF, hash, đích mới và mặc định FULL không ZIP. Kiểm thử sender dùng MIME local, cấm kết nối SMTP và đối chiếu attachment count = 0, đủ nội dung ở plain/HTML.

Đo token nếu cần trên cùng nguồn và tokenizer, tách phần đọc evidence khỏi việc chép raw/render bằng script. Dung lượng email tăng không có nghĩa model phải sinh lại raw. Test truyền đủ byte không chứng nhận chất lượng suy luận; dry-run không chứng minh giao diện Gmail/Outlook sẽ không thu gọn thư dài. Không rút báo cáo để né giới hạn giao diện; người nhận có thể cần mở toàn bộ thư.

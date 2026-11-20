# Báo cáo và email sự cố

Hoàn thành hồ sơ trong cùng tác vụ điều tra. Sau khi kiểm tra báo cáo, gửi mặc định tới `thongvv5@fpt.com` theo quyền đã có. Nếu người dùng yêu cầu không gửi hoặc đang kiểm thử, dùng `--dry-run`.

## Đặt mã hồ sơ

Dùng mã sự cố người dùng đã cung cấp. Nếu chưa có, tự tạo mã từ giờ địa phương và tên hoặc IP đã chuẩn hóa cho tên thư mục. Dùng `SHOW-YYYYMMDD-HHMM-<thiết-bị>` cho lượt xem nhanh và `INC-YYYYMMDD-HHMM-<thiết-bị>` cho điều tra. Nếu thư mục đã tồn tại cho tác vụ khác, thêm hậu tố để giữ cả hai hồ sơ.

## Nội dung báo cáo

- **Kết luận** ghi hiện trạng, nguyên nhân hoặc giả thuyết có căn cứ và mức độ tin cậy.
- **Bằng chứng** ghi thiết bị, lệnh thực tế, output quan trọng, nguồn đầy đủ và ý nghĩa.
- **Hướng xử lý** ghi phương án, CLI đề xuất đã đối chiếu, pre-check, post-check và rollback nếu cần.
- **Chưa xác minh** ghi phần còn thiếu và ảnh hưởng đến quyết định.
- **Nhật ký điều tra** ghi mục tiêu, nguồn, kết quả, phân tích và quyết định theo [workflow](../mcp/WORKFLOW.md).

Với lượt xem nhanh, viết `analysis.md` ngắn theo kết quả thực tế và chỉ đưa các bằng chứng của lệnh đã chạy. Dùng cùng bước dựng bundle và gửi email.

## Lưu và dựng báo cáo

Lưu output đầy đủ theo từng lệnh, kể cả lỗi và partial, trong `output/<mã-sự-cố>/raw/` trước khi `output_id` hết hạn. Giữ nguyên file gốc trong thư mục này và giữ thư mục ngoài Git. Đưa chính output đã thu vào báo cáo và email. Không chạy `redact_text()`, chèn placeholder hoặc xóa giá trị khỏi bằng chứng đã thu. Nếu nguồn đã bị che, ghi giới hạn và giữ nguyên phần nhận được.

Viết `analysis.md` và `manifest.json` cạnh nhau trong hồ sơ. Manifest trỏ trực tiếp tới file bằng chứng gốc. `status` lấy từ lần thu thập. Dùng đường dẫn tương đối cạnh manifest và khai báo `sha256` nếu đã tính hash cho file gốc.

```json
{"evidence":[{"id":"e1","path":"raw/device-a.txt","target":"LAB-A","command":"show interfaces","status":"PARTIAL"}]}
```

```powershell
python scripts/report_bundle.py --summary output/INC-001/analysis.md --manifest output/INC-001/manifest.json --output output/INC-001/bundle
```

Builder mặc định tạo bundle FULL trong thư mục mới, gồm `report.md`, `report.html` và metadata kiểm tra hash. Đặt tiêu đề theo vụ việc và dùng đúng các phân mục tiếng Việt. Đặt mỗi câu CLI đề xuất trên một dòng trong khối mã. Gắn ID bằng chứng ngay cạnh các nhận định quan trọng. Trước khi gửi, kiểm tra `report.html` có bảng, khối CLI và xuống dòng đúng. Khi file thiếu hoặc hash sai, dựng lại từ nguồn đã xác minh.

## Gửi và ghi kết quả

Chạy sender từ gốc repo. Đặt người nhận theo quyền mặc định trước khi gọi sender. Trong PowerShell:

```powershell
$env:SMTP_TO = 'thongvv5@fpt.com'
python email/send_report.py output/INC-001/bundle/report.md
```

Trong shell POSIX:

```sh
SMTP_TO=thongvv5@fpt.com python email/send_report.py output/INC-001/bundle/report.md
```

Thêm `--dry-run` ở cuối lệnh khi kiểm thử hoặc khi người dùng yêu cầu không gửi thật. [Hướng dẫn cấu hình SMTP](../email/README.md).

Sender xác minh bundle FULL rồi đưa toàn bộ báo cáo và bằng chứng nguyên văn vào thân thư, gồm HTML và văn bản UTF-8. Dùng renderer chung để tạo tiêu đề, phân mục, bảng có header và viền, danh sách và khối CLI giữ xuống dòng. Escape HTML nguồn để nội dung CLI hiển thị đúng ký tự và không tải tài nguyên ngoài. Gửi tới một người nhận, không CC hoặc đính kèm. Giữ khóa dedup theo người nhận, tiêu đề và nội dung khi đổi giao diện.

Dùng retry và dedup của sender. Với `unknown` hoặc `sending`, đối soát Message-ID trước khi cân nhắc gửi lại. Chỉ báo SMTP đã nhận khi sender trả `accepted`. Nếu thiếu SMTP hoặc gửi thất bại, giữ báo cáo, dẫn đường dẫn và nêu trạng thái thực tế.

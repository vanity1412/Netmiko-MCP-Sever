# Báo cáo và email sự cố

Hoàn thành hồ sơ trong cùng tác vụ điều tra. Sau khi kiểm tra báo cáo, gửi mặc định tới `thongvv5@fpt.com` theo quyền đã có. Nếu người dùng yêu cầu không gửi hoặc đang kiểm thử, dùng `--dry-run`.

## Đặt mã hồ sơ

Dùng mã sự cố người dùng đã cung cấp. Nếu chưa có, tự tạo mã từ giờ địa phương và tên hoặc IP đã chuẩn hóa cho tên thư mục. Dùng `SHOW-YYYYMMDD-HHMM-<thiết-bị>` cho lượt xem nhanh và `INC-YYYYMMDD-HHMM-<thiết-bị>` cho điều tra. Nếu thư mục đã tồn tại cho tác vụ khác, thêm hậu tố để giữ cả hai hồ sơ.

## Nội dung báo cáo

1. **Kết luận.** Ghi hiện trạng, nguyên nhân đã xác minh hoặc giả thuyết còn phù hợp. Nêu mức độ tin cậy và căn cứ.
2. **Bằng chứng.** Ghi thiết bị, lệnh thực tế, trích đoạn output nguyên văn, ID hoặc đường dẫn tới bản đầy đủ và ý nghĩa. Đối chiếu đúng thiết bị, lệnh và ngữ cảnh trước khi dùng output để kết luận.
3. **Hướng xử lý.** Nêu cấu hình hiện tại liên quan (trích nguyên văn, kèm ID bằng chứng), giả thuyết đã kiểm và kết quả, phương án chọn và lý do. CLI đề xuất theo từng thiết bị, tách PRE-CHECK, APPLY, POST-CHECK, ROLLBACK, gắn nhãn chưa chạy.
4. **Chưa xác minh.** Chỉ ghi phần thật sự không đọc được: đã thử gì, còn cần gì, ảnh hưởng tới kết luận.
5. **Nhật ký điều tra.** Mỗi bước ghi mục tiêu hoặc giả thuyết → thiết bị và lệnh thực tế → output quan trọng và đường dẫn bằng chứng → phân tích ủng hộ, bác bỏ hoặc chưa đủ → quyết định tiếp theo và lý do. Ghi lỗi, timeout, cách xử lý và kết quả kiểm chứng lại. Phân biệt dữ liệu thật, mô phỏng, suy luận và đề xuất chưa chạy.

Chỉ ghi thời gian và số đo thực. Nêu định nghĩa phép đo, đơn vị, khoảng lấy mẫu và cách tính khi áp dụng. Giữ nguyên nguồn và xuất xứ của bằng chứng. Dùng counter tích lũy để mô tả số đếm đã ghi nhận. Muốn đánh giá biến động hoặc nguyên nhân, cần đối chiếu thêm dữ liệu theo thời gian và trạng thái liên quan.

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

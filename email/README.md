# Gửi báo cáo qua email

Chạy từ thư mục gốc sau khi đã hoàn thành bundle FULL theo [quy trình báo cáo](../docs/REPORTING.md). Sender xác minh bundle và đưa toàn bộ báo cáo vào thân thư ở hai định dạng UTF-8 và HTML.

```powershell
python email/send_report.py output/INC-001/bundle/report.md --dry-run
python email/send_report.py output/INC-001/bundle/report.md
```

Lệnh đầu tạo `email-preview.eml` và `email-preview.html` cạnh báo cáo. Lệnh thứ hai gửi thật tới người nhận đã cấu hình.

## Cấu hình SMTP

Sao chép `smtp-settings.example.json` thành `smtp-settings.json` và điền máy chủ, tài khoản, người gửi, người nhận và trường `password`. Nếu dùng Gmail, điền App Password. Sender đọc file trực tiếp khi gửi. Git bỏ qua file cấu hình cục bộ vì mật khẩu trong file ở dạng văn bản rõ.

Biến môi trường `SMTP_PASSWORD` ghi đè trường `password`. Các biến `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_FROM`, `SMTP_USERNAME` và `SMTP_TO` cũng ghi đè cấu hình tương ứng. Trên Windows, sender có thể dùng Windows Credential Manager khi mật khẩu còn trống.

## Kiểm tra trạng thái gửi

Trạng thái `accepted` nghĩa là máy chủ SMTP đã nhận thư. Sender lưu trạng thái trong `runtime/data/email-notification/outbox.sqlite3` và chặn gửi lại cùng người nhận, tiêu đề và nội dung. Nếu trạng thái là `sending` hoặc `unknown`, đối soát Message-ID với máy chủ SMTP trước khi gửi lại.

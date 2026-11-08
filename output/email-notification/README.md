# Email báo cáo

Gửi toàn bộ nội dung Markdown đã lọc bí mật trong body UTF-8 tới `[redacted-email]`, không CC/BCC/attachment.

Preview offline (không cần SMTP, không thay trạng thái outbox):

```text
python output/email-notification/send_report.py output/<ma-su-co>/bao-cao.md --dry-run
```

Email gồm hai phiên bản cùng nội dung: HTML dễ đọc (tiêu đề, bảng, danh sách, khối CLI) và văn bản UTF-8 dự phòng. Toàn bộ báo cáo vẫn nằm trong thân thư, không đính kèm; raw HTML trong Markdown được escape, không tải ảnh/font/script bên ngoài. Renderer không thay khóa dedup, nên đổi giao diện không vượt chặn thư `sending`/`unknown`/đã accepted.

Dry-run tạo `email-preview.eml` và `email-preview.html` cạnh báo cáo. Có thể chọn đường dẫn bằng `--preview <file.eml>` và `--html-preview <file.html>` cùng `--dry-run`. Mở file HTML để xem offline. Thư dài có thể bị ứng dụng email thu gọn; không lược bỏ bằng chứng để né giới hạn hiển thị.

Kiểm thử HTML offline: `python -m unittest discover -s output/email-notification/tests -p test_html_email.py`.

Gửi thật chỉ khi được phép: giữ nguyên lời gọi cũ không có `--dry-run`. Cấu hình Gmail đã được người dùng chỉ định trong `smtp-settings.json`: smtp.gmail.com, 587/STARTTLS, sender/username <tài-khoản-SMTP-cục-bộ>. File này không được chứa password. Biến môi trường `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD` được ưu tiên; đổi host không tự mang theo identity trong JSON. Thiếu credential thì fail trước khi kết nối.

App password từng chia sẻ trong chat phải được thu hồi/tạo lại. Trên máy Windows, dưới đúng tài khoản chạy OpenCode, nhập mật khẩu mới bằng terminal cục bộ (ẩn ký tự, không qua CLI/history):

```text
python output/email-notification/configure_smtp.py
python output/email-notification/configure_smtp.py --check
```

Password được lưu trong Windows Credential Manager, không trong project, opencode.json hoặc báo cáo; chỉ đọc khi gửi thật. Không có credential thì không gửi. Dry-run vẫn hoạt động không cần password và không đọc Credential Manager. Chuyển máy/tài khoản Windows phải nhập lại credential. Không chia sẻ password trong chat hoặc điền literal vào lệnh.

Sau khi đã lưu credential mới, gửi thử đúng một lần:

```text
python output/email-notification/send_report.py output/ACTIVATION-MCP-1.2.0/bao-cao.md --max-attempts 1
```

Outbox mặc định: `runtime/data/email-notification/outbox.sqlite3`, cần giữ bền vững và hạn chế ACL. Khóa theo người nhận + subject + toàn bộ nội dung đã sanitize; Message-ID ổn định. `accepted` là SMTP đã nhận DATA, không bảo đảm thư đã tới inbox. Cùng nội dung đã accepted sẽ không gửi lại. Nội dung thay đổi tạo khóa mới và là một phiên bản báo cáo khác.

Retry tối đa 3 lần mặc định (tối đa 5 qua `--max-attempts`), backoff 5/10 giây..., chỉ với lỗi tạm thời chắc chắn chưa nhận thư. Authentication failure không retry. Mất kết nối trong DATA: `unknown`, không tự gửi lại. Process crash ở trạng thái `sending` cũng chặn gửi lại: cần đối soát Message-ID với quản trị SMTP trước khi quyết định xử lý. Không tự xóa/chỉnh outbox để ép gửi lại; không cam kết exactly-once giữa SQLite và SMTP.

Chương trình không có scheduler gửi nền. Chạy lại cùng report để tiếp tục retryable khi đến hạn, không để lộ bí mật khi xem log. Dry-run và regression dùng SMTP giả lập, không gửi thư thật.

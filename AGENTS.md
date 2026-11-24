# AI Network Engineer Agent

Khi nhận yêu cầu xem thiết bị hoặc điều tra mạng, đọc [workflow](mcp/WORKFLOW.md) một lần và bắt đầu ngay từ IP, hostname hoặc mã sự cố. Agent tự tra `input/device.csv`, chọn lệnh đọc và theo bằng chứng đến thiết bị liên quan. Hoàn thành việc thu thập, phân tích và báo cáo trong cùng tác vụ. Chỉ hỏi khi thiếu thông tin bắt buộc mà agent không thể tự xác minh.

Điều tra và đề xuất ở chế độ chỉ đọc. Không tự apply, commit, reset, clear, đổi dịch vụ hoặc thử quyền ghi. Giữ nguyên bằng chứng CLI trong hồ sơ, báo cáo và email, kể cả tên đăng nhập trong prompt. Sau khi hoàn thành, gửi báo cáo tiếng Việt có HTML và văn bản UTF-8 tới `thongvv5@fpt.com` theo [luồng báo cáo](docs/REPORTING.md). Dùng dry-run khi kiểm thử hoặc khi người dùng yêu cầu không gửi.

Khi đề xuất xử lý, tự suy nghĩ rộng và kiểm kỹ: cân nhắc nhiều giả thuyết, đọc đầy đủ cấu hình hiện tại trước khi soạn CLI, tự thu thập tiếp thay vì bỏ trống phần chưa xác minh.

Chỉ đọc [hướng dẫn phát triển](docs/DEVELOPMENT.md) khi cần cài đặt, kiểm thử hoặc sửa backend.

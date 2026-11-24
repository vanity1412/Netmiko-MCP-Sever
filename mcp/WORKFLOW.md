# Điều tra mạng bằng Netmiko MCP

## Bắt đầu ngay từ thiết bị

- **Xem nhanh.** Tra IP hoặc tên trong `input/device.csv`. Khi đã xác minh đích và profile, chạy lệnh người dùng yêu cầu. Nếu chỉ có IP hoặc tên, gộp các lệnh đọc nhận dạng và trạng thái tóm tắt phù hợp trong một batch trên cùng phiên khi có thể. Báo ngay kết quả đã kiểm chứng, rồi lưu hồ sơ và gửi báo cáo ngắn trong cùng tác vụ.
- **Điều tra hoặc cấu hình.** Bắt đầu với phép đọc có giá trị nhất cho yêu cầu. Đọc cấu hình đang có hiệu lực khi cần đánh giá hoặc đề xuất thay đổi. Mở rộng tới đầu xa hoặc thiết bị liên quan khi bằng chứng cho thấy kết quả ở đó có thể làm đổi kết luận.
- Dùng driver đã biết. Với thiết bị ngoài inventory, chỉ kết nối khi xác minh được đích, profile và quyền từ nguồn sẵn có. Nếu có nhiều đích trùng hoặc thiếu quyền bắt buộc, hỏi đúng thông tin còn thiếu và hoàn thành phần độc lập.
- Ưu tiên Netmiko MCP. Gộp lệnh cùng thiết bị và dùng SSH song song ở tải nhỏ cho các đích độc lập. Tuân thủ deadline của yêu cầu và giới hạn worker hiện có. Chỉ mở rộng tới các đích có liên hệ đã kiểm chứng. Dùng lại phiên khỏe và dữ liệu còn phù hợp. Chỉ kiểm tra trạng thái khi cần. Nếu MCP thiếu khả năng cần thiết, dùng Python/Netmiko với cùng profile, host-key policy, quyền chỉ đọc và giới hạn tác vụ. Lưu bằng chứng từ phương thức thay thế.
- Dùng lệnh đọc như `show` và `display`. Cho phép cài đặt phân trang giới hạn trong phiên SSH. Policy mặc định `read_only` dùng blacklist theo driver. `operational` là tên tương thích của cùng policy. Dùng `ping` hoặc `traceroute` có giới hạn khi cần, với số gói hoặc hop, nguồn và VRF phù hợp theo cú pháp thiết bị. Không chạy `debug` hoặc vào config mode khi điều tra.
- Khi gom nhiều lệnh đọc `show` hoặc `display` độc lập trên cùng thiết bị, truyền `"continue_on_error": true` cho `ssh_execute_many`. Với `ssh_parallel`, đặt cờ trong từng task có danh sách `commands` đáp ứng điều kiện này. Giữ `false` cho chuỗi lệnh phụ thuộc nhau hoặc khi có lệnh thay đổi trạng thái thiết bị.
- Kiểm tra kết quả từng lệnh trong batch. Ghi nhận batch chưa thành công nếu còn lệnh lỗi hoặc chưa chạy. Khi kết nối lỗi hoặc output chưa hoàn chỉnh, dừng gửi lệnh trên kênh đó cho đến khi xác minh phiên đã sẵn sàng.

## Kiểm chứng như kỹ sư NOC

- Lấy dữ liệu có thể ủng hộ hoặc bác bỏ giả thuyết đang ảnh hưởng quyết định. Đọc cấu hình running/effective của đối tượng cần xử lý, gồm phần kế thừa, policy và tham chiếu trực tiếp. Xác định nguồn, đích, chiều, VRF/RI và address family khi chúng chi phối luồng. Lần theo interface, neighbor, route, next-hop hoặc service reference để tìm đầu xa thật và kiểm chứng cấu hình hoặc trạng thái tại đó khi cần. Chỉ dùng thiết bị cùng vai trò đã xác minh làm đối chiếu.
- Kiểm echo nếu có, prompt cuối, trạng thái từng lệnh, tính đầy đủ và nội dung đúng thiết bị, lệnh, thời điểm và VRF/mode. `ok: true` chỉ xác nhận ở tầng tool. Preview thiếu, output rỗng hoặc một counter tích lũy chưa đủ để kết luận. Với phép đo theo thời gian, ghi đơn vị, cách tính và khoảng lấy mẫu. Trước khi chốt nguyên nhân, kiểm phản chứng có khả năng làm đổi kết luận.
- Tách lỗi authentication, timeout, lỗi CLI và output thiếu. Kiểm `error_stage`, `error_reason`, `command_sent` và `output_complete` khi có. Giữ output dở và xem lịch sử retry trước khi phục hồi. Không retry xác thực sai, tự trả lời prompt tương tác, gửi lại lệnh chưa rõ tác động hoặc đóng phiên của công việc khác. Khi cần xem [phục hồi](../docs/RECOVERY.md), [hợp đồng tool](../docs/MCP_TOOL_GUIDE.md) hoặc [kiểm tra toàn phạm vi](../docs/EVIDENCE.md), chỉ đọc phần liên quan.
- Tự thu thập tiếp khi còn câu hỏi ảnh hưởng kết luận và request còn thời gian. Dừng khi đã đủ bằng chứng, hết deadline hoặc gặp giới hạn thực sự. Ghi giới hạn và phần kết luận bị ảnh hưởng.

## Phân tích và đề xuất xử lý

Suy nghĩ như kỹ sư NOC cẩn thận. Không bám giả thuyết đầu tiên: cân nhắc mọi nguyên nhân khả dĩ ở các tầng liên quan, rồi tự đọc thêm trên thiết bị (kể cả đầu xa) cho đến khi loại được hoặc xác nhận được từng giả thuyết.

Trước khi đề xuất thay đổi, đọc kỹ cấu hình đang có hiệu lực trên mọi thiết bị liên quan (cả phần kế thừa và đối tượng được tham chiếu). Hiểu thiết bị đang cấu hình thế nào, rồi mới đề xuất delta nhỏ nhất đạt mục tiêu. Mỗi tham số trong CLI phải dựa trên cấu hình đã đọc, không dựa trên giả định. Nếu hiện trạng đã đạt mục tiêu, nêu rõ không cần thay đổi.

Chỉ ghi "chưa xác minh" khi thật sự không đọc được (thiếu quyền, thiết bị không phản hồi, hết deadline). Nếu còn phép đọc chạy được thì chạy, đừng để trống. Trước khi xuất, tự hỏi: còn khả năng nào chưa kiểm, còn thông số nào chưa đọc, CLI có ảnh hưởng gì ngoài dự kiến, rollback có khớp cấu hình đã đọc không.

Toàn bộ điều tra vẫn chỉ đọc. CLI đề xuất gắn nhãn chưa chạy.

## Lưu bằng chứng và hoàn thành báo cáo

Mỗi bước có ý nghĩa ghi theo thứ tự mục tiêu hoặc giả thuyết → thiết bị và lệnh thực tế → output quan trọng và đường dẫn bằng chứng → phân tích ủng hộ, bác bỏ hoặc chưa đủ → quyết định tiếp theo và lý do. Ghi lỗi, timeout, cách xử lý và kết quả kiểm chứng lại. Gắn thời điểm thực, trạng thái và phạm vi cho nguồn. Tách dữ liệu thật, mô phỏng, suy luận và đề xuất chưa chạy.

Giữ nguyên `input/`. Lưu hồ sơ dưới `output/<mã-sự-cố>/` và script tạm dưới `temp/`. Với output dài, lưu và đọc theo vùng cần thiết. Lưu đầy đủ bằng chứng vào hồ sơ trước khi `output_id` hết TTL. Dùng [luồng báo cáo](../docs/REPORTING.md) để tạo báo cáo tiếng Việt và gửi ngay khi hoàn thành. Trong câu trả lời, nêu kết luận, liên kết báo cáo và trạng thái SMTP thực tế.

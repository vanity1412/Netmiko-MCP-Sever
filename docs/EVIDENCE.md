# Evidence và nhật ký phát hiện

Đọc khi cần kiểm tra toàn phạm vi, kết luận không tồn tại hoặc mẫu nhật ký chi tiết.
Đóng gói báo cáo đã đủ phân tích theo [REPORTING.md](REPORTING.md); không cần nạp
thêm mẫu chỉ để chép raw. Quyền và vòng điều tra vẫn theo [workflow](../mcp/WORKFLOW.md).

## Đọc evidence có mục tiêu, giữ nguyên dữ liệu

Lưu nguyên output và lỗi theo từng đích trong hồ sơ. Đưa cùng dữ liệu đó vào phụ lục báo cáo và thân thư theo [luồng báo cáo](REPORTING.md). Giảm phần đưa vào context bằng cách đọc đúng phạm vi cần phân tích:

- Dùng `save_output=true` khi dự kiến output lớn. Preview/text inline bị cắt không phải toàn bộ output; lưu output_id cùng target/command/thời điểm và vị trí evidence bền vững khi cần báo cáo/resume.
- Cần thông tin cụ thể: search với ngữ cảnh, rồi đọc các đoạn liên quan và vùng cấu hình/phụ thuộc bao quanh. Tìm không thấy trong preview, excerpt bị giới hạn hoặc phạm vi search chưa đủ không chứng minh không tồn tại.
- Cần kiểm tra toàn bộ, số lượng hoặc kết luận không tồn tại: ưu tiên công cụ search/parse duyệt hết phạm vi raw đã lưu, trả kết quả có thể kiểm chứng. Ghi nguồn/hash, phạm vi đã quét (file/byte/dòng/record), biểu thức hoặc quy tắc parse, total_matches, giới hạn/truncation/lỗi và output_complete. Phân biệt số dòng khớp với số đối tượng và phần excerpt; search không có more/offset, còn more của reader chỉ nội dung chưa đọc hết. Không cần đưa mọi dòng vào context nếu phép kiểm tra toàn phạm vi đã đáng tin cậy.
- Độ bao phủ gồm cả thu thập và phân tích: full scan của output PARTIAL, sai lệnh, sai VRF/context hoặc cấu hình chưa xét kế thừa không chứng minh dữ liệu không tồn tại trên thiết bị. total_matches=0 chỉ chứng minh không khớp phép tìm trong phạm vi đã quét. Dựa cấu trúc lệnh/OS và ngữ nghĩa để kiểm tra alias, parent/child, kế thừa và nguồn liên quan. Đọc thêm vùng liên quan hoặc toàn nội dung khi quan hệ/ngữ nghĩa chưa đủ rõ; nếu công cụ chưa chứng minh quét đủ thì phân trang hết phạm vi, dùng byte reader cho dòng dài. Không suy kết luận toàn cục từ preview.
- Lưu nhật ký phát hiện cùng evidence theo mục dưới; giữ trong context các phát hiện đang chi phối quyết định, tái sử dụng dữ kiện đã xác minh thay vì nạp lại transcript. Khi chuyển phiên, đọc các phát hiện liên quan và truy xuất nguồn khi cần, không xem bản tóm tắt là evidence gốc.
- Không lặp nguyên JSON/output trong nhiều tool response, lời giải thích và báo cáo. Trích phần đủ chứng minh, dẫn đường tới phần đầy đủ. Không dựa riêng vào output_id có TTL; export evidence cần giữ lâu. Nếu chưa lưu bền vững được, báo rõ giới hạn.

Các trường search/read được mô tả chính xác tại [MCP_TOOL_GUIDE.md](MCP_TOOL_GUIDE.md).
Search total_matches đếm dòng khớp, không có more/offset để phân trang match;
shown_matches và truncated không bảo đảm excerpt giữ đủ mọi dòng/ký tự. Không
coi các trường hash/output_complete/phạm vi là do search trả nếu chúng không có.
Lấy status/completeness từ kết quả CLI gốc và ghi provenance riêng khi cần.

### Nhật ký phát hiện: ghi kết quả có ý nghĩa

Sau mỗi nhóm lệnh, cập nhật nhật ký trong thư mục evidence của tác vụ. Đơn vị ghi là phát hiện quan trọng, không phải mỗi lần gọi tool. Mỗi phát hiện có ID ổn định để liên kết nguồn và các phát hiện ở thiết bị khác; khi có dữ kiện mới, cập nhật kết luận và giữ rõ điều gì đã thay đổi.

Dùng mẫu ngắn sau, mở rộng phần diễn giải theo độ phức tạp:

```text
F01 — <câu hỏi hoặc giả thuyết cần kiểm tra>
Nguồn: <thiết bị; lệnh; thời điểm; status/output_complete; evidence ID/file và dòng/offset>
Quan sát: <giá trị/trạng thái/quan hệ thực tế; trích CLI ngắn nếu cần>
Phân tích: <dữ kiện chứng minh gì; cơ chế kỹ thuật; giả thuyết được ủng hộ/bác bỏ;
           chưa chứng minh gì; phụ thuộc và tác động liên quan>
Quyết định: <kết luận có căn cứ hoặc bước tiếp cụ thể và lý do chọn bước đó>
```

Gộp nhiều lệnh đơn giản khi chúng trả lời cùng một câu hỏi và vẫn dẫn được từng nguồn. Với bất thường, lỗi/partial hoặc mâu thuẫn có ảnh hưởng kết luận, giải thích riêng thay vì ghi “đã kiểm tra”. Liên kết nguồn giữa thiết bị bằng đối tượng thực trong evidence (interface/neighbor, VRF/RI, route/next-hop, policy hoặc service); đối chiếu thời điểm và phạm vi trước khi suy quan hệ nhân quả.

Trước khi chấp nhận một mục nhật ký, kiểm tra xem người đọc có hiểu kết quả chứng minh điều gì, chưa chứng minh điều gì và vì sao chọn bước tiếp. Các câu “dùng làm cơ sở đối chiếu”, “cần xác minh thêm” chỉ hợp lệ khi kèm nội dung cụ thể đó; không thay cho phân tích đã có thể làm từ output. Phân biệt triệu chứng, nguyên nhân trực tiếp và nguyên nhân gốc; không tự xem khác biệt cấu hình là nguyên nhân sự cố.

Nếu còn khoảng trống, chọn phép kiểm có khả năng phân biệt giả thuyết: đọc thêm vùng cấu hình/phụ thuộc khi chưa rõ ngữ nghĩa; đối chiếu đầu xa khi cần kiểm quan hệ; lấy trạng thái hiệu lực khi cấu hình chưa chứng minh hành vi; bổ sung mẫu theo thời gian khi counter chưa đủ. Ưu tiên nguồn đã lưu trước khi SSH lại và tự điều tra tiếp trong quyền/ngân sách còn có. Chỉ ghi giới hạn thật sau khi xét các nguồn hợp lý; không biến việc chưa đọc thành thiếu dữ liệu.

Tối ưu bằng tìm/parse đúng phạm vi và tái sử dụng phát hiện. Giữ các giả thuyết và phép kiểm còn ảnh hưởng đến quyết định. Nhật ký và phần phân tích trích dữ kiện quan trọng, dẫn tới phụ lục chứa output nguyên vẹn.

### Phụ lục và email bằng script

Agent viết phân tích và manifest tham chiếu bằng chứng gốc. Liệt kê đủ output CLI, nhật ký và cấu hình liên quan để builder chép vào Markdown và HTML. Kiểm tra metadata, hash và phần render cần dùng. Kiểm tra toàn vẹn bundle chỉ xác nhận dữ liệu được đóng gói theo manifest. Dựng và gửi theo [luồng báo cáo](REPORTING.md).


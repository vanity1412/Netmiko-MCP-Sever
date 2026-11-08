# 1.2.2

- Cho phép interface có `/`, IPv4 prefix, IPv6 và nhóm Junos RSVP/BFD/multicast trong policy chỉ đọc.
- Tách pipeline theo dấu nháy để hỗ trợ regex `match "error|CRC|drop"`; vẫn từ chối pipeline ghi file và chuỗi lệnh.
- Sửa vòng tham chiếu trong kết quả `ssh_interact` lỗi; giữ output từng bước khi `save_output=true`.
- Kiểm tra echo theo nguyên lệnh, tránh nhận `show version detail` là echo của `show version`.
- Che tên login Junos dạng hierarchy và public-key material trong output.
- Giữ nguyên 10 tool, strict host key, session pool, inventory và credential cục bộ.
- Bổ sung regression offline; cấu hình thật, inventory, host keys, runtime và báo cáo không được đưa lên Git.

Không có SSH thiết bị thật hoặc thay đổi cấu hình mạng trong đợt sửa này. AAA, nguồn gốc fingerprint và coverage known_hosts cần kiểm chứng theo quy trình vận hành; không tự thêm host key.

# Repository cleanup

- Tập trung source Netmiko MCP, scanner, tests và tài liệu liên quan.
- Bỏ theo dõi launcher/OpenCode config, check client-specific và sender email; file tích hợp cục bộ còn có trên máy được giữ nguyên.
- Giữ inventory, credential, host keys, runtime và báo cáo ngoài Git. Không đổi backend hoặc 10 tool.

# 1.3.0

- Giữ nguyên tên và schema 10 MCP tool.
- Error category/stage giữ được nguyên nhân host key/KEX/auth-method/auth-timeout qua exception chain và detection worker.
- Detection/collection dùng chung SSH slots; Python API có cumulative request budget.
- CLI error với echo/prompt hoàn chỉnh không ngắt transport; BGP notification counters không bị coi CLI failure.
- Scanner CLI preview mặc định, hai lane fast/slow, kết quả/evidence tăng dần, dedup và resume có kiểm chứng.
- Retry lane chậm giới hạn cho transport/read timeout; không thử lại auth/host-key/KEX để làm đẹp tỷ lệ.
- Không thay inventory/credential/trust store. Không tự import credential hoặc legacy algorithms từ SecureCRT.

# 1.2.3

- Sửa prompt cuối, CLI errors/counters, session slot và close deadline.
- Regex search có process riêng, timeout 2 giây và cancellation.
- Suppress auth failure cùng identity 5 phút; signature xét tham số kết nối.
- Bổ sung inheritance, quoted regex anchor, các nhóm lệnh NOC được duyệt.
- Generic termserver qua autodetect; giữ inventory và strict host key.
- Đồng bộ description, workflow, cấu hình mẫu; Python fallback chung policy.
- Pin Netmiko 4.7.0 theo runtime đã kiểm thử. Giữ redaction hiện có.

# 1.2.2

- Cho phép interface có `/`, IPv4 prefix, IPv6 và nhóm Junos RSVP/BFD/multicast trong policy chỉ đọc.
- Tách pipeline theo dấu nháy để hỗ trợ regex `match "error|CRC|drop"`; vẫn từ chối pipeline ghi file và chuỗi lệnh.
- Sửa vòng tham chiếu trong kết quả `ssh_interact` lỗi; giữ output từng bước khi `save_output=true`.
- Kiểm tra echo theo nguyên lệnh, tránh nhận `show version detail` là echo của `show version`.
- Che tên login Junos dạng hierarchy và public-key material trong output.
- Giữ nguyên 10 tool, strict host key, session pool, inventory và credential cục bộ.
- Bổ sung regression offline; cấu hình thật, inventory, host keys, runtime và báo cáo không được đưa lên Git.

Không có SSH thiết bị thật hoặc thay đổi cấu hình mạng trong đợt sửa này. AAA, nguồn gốc fingerprint và coverage known_hosts cần kiểm chứng theo quy trình vận hành; không tự thêm host key.

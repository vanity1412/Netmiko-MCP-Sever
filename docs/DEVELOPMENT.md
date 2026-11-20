# Phát triển Netmiko MCP

## Cài đặt và chạy

- Cài dependency bằng `python -m pip install -r requirements.txt`. Dùng các file mẫu trong `mcp/` để cấu hình thiết bị và [credential](CREDENTIALS.md).
- Inventory cần `name,ip`. Driver lấy từ `netmiko_device_type` khi có. Trường trống dùng autodetect. `profile,port` là tùy chọn.
- Chạy `python -u mcp/bootstrap.py --config mcp/devices.json --inventory-csv input/device.csv` và kiểm tra bằng `python mcp/collector_backend.py --check`.

## Sửa và kiểm thử

- Giữ 10 tool và schema, JSON-RPC UTF-8 và Python 3.10+. Giữ session isolation theo host, port, driver và credential. Tuân thủ deadline, retry hữu hạn, checkpoint và xác minh evidence khi resume.
- Trước khi sửa kết nối, đọc [kiến trúc](ARCHITECTURE.md), [scanner](SCAN.md) và [changelog](../CHANGELOG.md).
- Test phát triển chỉ dùng mock hoặc SSH localhost. Cập nhật test theo hành vi chủ đích. Chạy test phù hợp trước commit và báo kết quả cùng giới hạn. Lệnh chạy toàn bộ là `python -m unittest discover -s tests -v`.
- Giữ inventory, credential, key, known_hosts, cache, runtime và output thiết bị ngoài Git. Fixture chỉ dùng dữ liệu mô phỏng.

# Quét inventory — Netmiko MCP 1.3.0

Giữ nguyên 10 MCP tool và schema. `mcp/scan.py` là CLI/helper Python bổ sung để quản lý một job lớn; không cần thay OpenCode config để có thêm tool. Không import credential từ SecureCRT XML.

## Chạy từ thư mục gốc

Xem kế hoạch toàn inventory, **không SSH**:

```powershell
python mcp/scan.py --all --output output/SCAN-VERSION
```

Khi đã sẵn sàng, chạy thật bằng cùng lệnh thêm `--execute`:

```powershell
python mcp/scan.py --all --output output/SCAN-VERSION --workers 16 --slow-workers 4 --execute
```

Mặc định chỉ lấy version (Linux: uname -s). Để lấy dữ liệu khác, dùng `--commands-file mcp/scan-commands.example.json` hoặc plan có `commands` riêng. Lệnh phải qua policy hiện có. `--all` lấy alias từ CSV; các task cùng identity và cùng lệnh được loại trùng. Cùng IP nhưng khác driver/profile kết nối vẫn là task riêng khi tham số thực tế khác.

Dùng `--plan mcp/scan-plan.example.json` thay `--all` cho danh sách cụ thể. Sửa các target ví dụ thành target thật đã xác minh. Plan chỉ nhận target, commands, device_type, profile, read_timeout, lane. Target ngoài inventory được gọi bằng IP/hostname và driver tường minh/autodetect; không tự thêm CSV.

`lane: slow` đưa thiết bị đã biết chậm vào lượt chậm ngay từ đầu, tránh phải thử đăng nhập hai lần. `profile` chọn một profile đã có trong devices.json, không chứa username/password trong plan. Tool dùng cặp NETWORK_SSH_USER/PASSWORD từ môi trường, nếu thiếu thì cùng fallback input/ssh.txt như bootstrap. Chạy ngoài OpenCode cần cung cấp môi trường hoặc nguồn fallback này; không tự lấy literal credential từ opencode.json.

## Nhanh nhưng không làm đẹp tỷ lệ giả

- Tổng worker mặc định16, tối đa32 và không vượt max_workers của collector; gồm lượt chậm mặc định4. Tối thiểu2 slot để có hai lane. Detection và collection cùng dùng semaphore SSH toàn collector. Một transport vẫn serialize từng lệnh.
- Mỗi thiết bị lấy đủ batch trước khi chuyển sang đích tiếp. Kết quả và bằng chứng được ghi tăng dần, không chờ toàn nhóm hoặc lượt chậm hoàn tất.
- Fast: deadline90s/thiết bị; TCP10s, banner15s, auth30s, read45s. Slow: deadline240s; TCP30s, banner45s, auth60s, read120s. Probe autodetect trong scanner được phép tối đa min(deadline,120s), thay vì trần20s của lời gọi MCP thông thường. Nếu probe hết hard deadline mà chưa xác định được pha auth, không tự retry mù; target đã biết chậm nên đặt lane slow ngay từ đầu. Đây là ngân sách của job, không phải cam kết thời gian thực tế; Netmiko I/O cancellation vẫn cooperative. Điều chỉnh deadline qua --fast-timeout/--slow-timeout, read timeout riêng trong plan. Chúng không sửa config thiết bị hoặc config cục bộ.
- Chỉ retry tối đa một lần ở lane chậm cho connect_timeout/banner_timeout/read_timeout đã phân loại. Không retry authentication/auth_timeout/auth_method, host key, KEX, CLI error hoặc lỗi không rõ nguyên nhân. Deadline chưa rõ pha không bị coi là TCP timeout để retry mù.
- Thiết bị chậm vẫn có kết quả riêng: success, partial, failed hoặc unknown; pending là chưa chạy, không phải thành công. Không biến timeout/auth thành interface down hoặc số đo0.
- Không tắt strict, nhập key chưa xác minh, đổi credential hoặc bật thuật toán cũ toàn mạng. Các entry host key/credential/profile đúng đích vẫn là điều kiện tiên quyết.

## Output và resume

- scan-manifest.json: hash của kế hoạch/identity, không lưu credential.
- results/<task_id>.json: trạng thái, các lần thử, lỗi có category/stage, duration và đường dẫn chứng cứ. elapsed_ms của attempt đo từ bắt đầu thu thập tới trước export evidence (gồm chờ slot/detection/connect/CLI); không phải RTT hoặc thời gian riêng auth. Thời gian toàn job đo riêng khi benchmark, gồm cả ghi checkpoint/evidence.
- bang-chung/: toàn bộ output đã sanitize, có SHA256.
- scan-summary.json: tổng đích/loại trùng/thành công/lỗi/một phần/chưa rõ/chưa chạy.
- raw-output/: scratch riêng của CLI, được dọn theo từng output sau khi kết quả/bằng chứng đã lưu. Không dọn output của MCP hay job khác. Dùng các đường dẫn bang-chung trong kết quả, không phụ thuộc output_id của scratch.

Chạy lại cùng lệnh/output để resume. Job bỏ qua success/failed/partial đã lưu; retry_pending tiếp tục lane chậm. Kế hoạch/identity đổi, JSON lỗi hoặc evidence thiếu/sai checksum thì từ chối resume. Trạng thái running sau gián đoạn chuyển unknown, không tự xác thực lại. Đối soát trước khi tạo job mới cho những đích này.

scan.lock chặn hai process dùng cùng thư mục; crash có thể để lại lock. Chỉ gỡ lock thủ công sau khi xác minh process cũ đã dừng và đối soát checkpoint, không xóa outbox hay hồ sơ để ép chạy lại. Đĩa đầy/không ghi được không được báo success. Với thao tác replace checkpoint bị khóa file tạm thời trên Windows, chỉ retry thao tác file, không lặp SSH.

Scanner chỉ thu thập; agent đọc summary/evidence rồi tạo báo cáo và gửi nội dung trong thân email theo AGENTS. Scanner không tự gửi email cho từng thiết bị.

## Cập nhật bộ công ty

Copy mcp/collector_backend.py, mcp/bootstrap.py, mcp/scan.py; giữ mcp/readonly_client.py bản đã bắt buộc device_type. Có thể copy kèm các file scan ví dụ/tài liệu/tests. Không thay opencode.json, devices.json, input/, known_hosts, SMTP settings hoặc runtime.

Chỉ reconnect MCP khi không còn công việc, kiểm tra ssh_status.version=1.3.0. Thử preview rồi smoke read-only trên nhóm có fingerprint/profile xác minh trước khi quét toàn inventory. Bản này chưa benchmark SSH production. Rollback source từ commit ec8c27a nếu hậu kiểm không đạt, không rollback bằng tắt strict.

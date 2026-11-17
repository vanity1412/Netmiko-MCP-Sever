# Audit hướng dẫn và tình huống suy luận — 2026-11-17

Hướng dẫn mới bổ sung phản chứng, topology theo luồng và delta cấu hình có nguồn.
SSH Engine và schema 10 tool giữ nguyên. Ba test mới kiểm tra evidence cho tám
tình huống mô phỏng. Giới hạn kiểm chứng model và thiết bị thật được ghi ở cuối.

Baseline: HEAD `3ba4aa94a7750c3a888d84769be657aa916dc1df`, working tree ban đầu sạch.
Đọc source, tests và Markdown được Git theo dõi tại HEAD; không đọc inventory,
credential hoặc dữ liệu triển khai private. Không fetch/khẳng định HEAD này là
commit mới nhất trên remote. Đây là audit và kiểm thử phát triển, không điều tra
thiết bị production.

## Phát hiện và thay đổi tối thiểu

File thay đổi: `AGENTS.md`, `mcp/WORKFLOW.md`, `mcp/collector_backend.py`,
`README.md`, `CHANGELOG.md`, `tests/test_workflow_contract.py`.
File mới: `tests/network_reasoning_cases.json`,
`tests/test_network_reasoning_evidence.py`, `docs/NETWORK_REASONING.md`.

| Vị trí tại baseline | Điểm yếu thực tế | Thay đổi |
| --- | --- | --- |
| AGENTS.md và WORKFLOW mục 1/4 | Đã có evidence/recovery tốt nhưng lặp quy tắc; phản chứng và giả thuyết cạnh tranh chưa rõ | AGENTS giữ điểm vào/quyền; workflow giữ vòng điều tra, kiểm phản chứng và tiêu chí dừng |
| WORKFLOW mục 1/4 | Topology chỉ là gợi ý nguồn, chưa nối luồng/VRF/AF/chiều về với phụ thuộc thực | Phân biệt vật lý/control/forwarding, mở rộng theo liên hệ có nguồn, theo RIB/FIB/MPLS/policy/state khi liên quan |
| WORKFLOW mục 4 | Có kiểm inheritance nhưng chưa rõ candidate/running, baseline tương đương, xung đột và rollback về kế thừa | Delta tối thiểu có nguồn tham số, rà ảnh hưởng object dùng chung, không stage candidate để kiểm đề xuất |
| collector_backend.py: TOOLS | Byte reader hứa “exact bytes” dù trả text decode best-effort; search chưa cảnh báo excerpt thiếu/zero match; close chưa nói ảnh hưởng mọi profile/port | Chỉ sửa description của 10 tool; giữ nguyên schema, dispatcher và SSH Engine |
| README: Reader/Status | Hai câu cũ nói lỗi/audit luôn scrub và storage failure có thể chỉ giữ preview, mâu thuẫn source hiện tại và phần Storage | Đồng bộ với redaction_enabled và response giữ đủ output khi lưu thất bại |
| tests hiện có | Kiểm thu thập/transport/evidence; chưa có đầu vào đánh giá suy luận mạng | Thêm tám ca synthetic và replay qua MCP/storage/read/search; đáp án kỹ thuật bên dưới, không thêm reasoning engine |

Backend không tự nạp/thực thi Markdown. Client phải nạp AGENTS + workflow; refresh
catalog/restart MCP để nhận descriptions. Bản copy instructions ngoài repo chưa
được cập nhật trong tác vụ này. Không có allowlist CLI, parser topology, framework,
dependency hoặc thay đổi timeout/pool/retry mới.

Đếm ký tự Unicode trên cùng HEAD/worktree: AGENTS + workflow từ 11.329 xuống
10.729; cộng 10 descriptions từ 12.899 xuống 12.818. Core bớt trùng lặp để dành
chỗ cho suy luận mạng; descriptions dài hơn để nói đúng hợp đồng. Đây không phải
số token, latency hay chi phí model đo thực; không tuyên bố tiết kiệm token từ
mức giảm ký tự nhỏ của tổng context.

## Đầu vào và cách đánh giá

[network_reasoning_cases.json](../tests/network_reasoning_cases.json) chỉ chứa
câu hỏi và evidence mô phỏng: ID, target, command, driver, thời điểm, raw và status
thu thập mong đợi. Tên/địa chỉ/tham số đều synthetic; các file `/fixture`,
`/run/fixture-session`, `/var/log/fixture-flow` là nguồn giả lập, không phải lệnh
chẩn đoán vendor hay đường dẫn phải truy cập thực. Không dùng lệnh mẫu như checklist.

Replay dùng Collector và tools/call thật với connect_factory giả, chặn socket
connect/connect_ex và probe subprocess. Test so từng response với status mong đợi,
target/command, raw file và hash đọc lại qua UTF-8 byte pagination; giữ partial và
lỗi, không gửi thêm lệnh hoặc cấu hình. Thời điểm thuộc manifest fixture, không
phải trường do backend tự trả. Timestamp không được dùng làm bằng chứng trạng
thái mạng hiện tại ngoài tình huống.

Đánh giá kỹ thuật do agent thực hiện trực tiếp từ các đầu vào, có đáp án tham
chiếu công khai bên dưới. Đây là walkthrough có thể review, **không** phải phép đo
blind, A/B hoặc một lượt gọi model độc lập. Test không dùng keyword để chấm kết
luận và không nhúng một bộ luật chẩn đoán giả làm AI Agent.

## Đối chiếu kỹ thuật

ID dạng `<case>-eN` trỏ tới source trong JSON; trích đoạn chỉ ra vùng cần đối chiếu,
không thay raw gốc. Các bước tiếp là lựa chọn có lý do, không ép đúng một CLI.

| Ca | Dữ kiện và kết luận thực hiện trong walkthrough | Phản chứng/giới hạn và bước tiếp |
| --- | --- | --- |
| wrong_vrf | e1: Gi0/1 thuộc BLUE; e2: route global có next-hop; e3: lookup BLUE trả `Network not in table`. Route global không chứng minh luồng BLUE có đường | Phản bác “global có route nên BLUE tốt”. Chưa rõ route đáng lẽ học/cấp từ đâu; theo import/advertisement/đầu xa trong BLUE, chưa thêm static hoặc RT |
| healthy | e1: lookup đích dùng default; e2: exact-route có adjacency Gi0/2; e3: link up. Thiếu /24 không tự yêu cầu thêm static | Phản bác “không có route cụ thể = mất đường”. Chưa chứng minh dịch vụ/chiều về tốt; nếu ticket còn lỗi thì kiểm luồng đúng nguồn, không tuyên bố end-to-end healthy |
| missing | e1: config bị cắt, PARTIAL; e2: permission denied, CLI_ERROR. Zero match `vrf-target` không chứng minh RT không tồn tại | Không bịa RT, không lặp đăng nhập để né thiếu quyền. Tìm effective/inherited config từ nguồn được phép; nếu vẫn bị chặn thì giữ unknown |
| asymmetry | e1: lookup chiều đi trong BLUE ở FW-A; e2/e3: chiều về EDGE tới FW-B; e4: đúng tuple SYN-ACK bị drop `no-session`; e5: state SYN-SENT ở FW-A, NAT none | Có evidence cho drop tại FW-B; bất đối xứng riêng lẻ không đủ. Chưa xác định nguyên nhân gốc là routing intent, state sync hay policy. Tra mapping FW-B `192.0.2.202`, xác minh identity/quyền, HA/state và thiết kế; không thêm route/disable firewall mù |
| inheritance | e1 không có local family MTU; e2/e3: MTU 1500 từ BASE-L3; e4/e5/e6: đúng OS/role/quy ước local override; e6 phê duyệt S100=9000 và group dùng chung 12 dịch vụ; e7: CE IP MTU 9000 | Đủ để lập delta local dưới đây; không sửa group. Chưa có thử tải MTU toàn đường hoặc validate firmware thật, nên không tuyên bố đã khắc phục |
| conflict | e1 chưa duyệt VLAN/VNI/RT; e2: VLAN200 đang dùng bởi tenant RED; e3: peer thuộc S999/GREEN không tương đương | Phản bác sao chép VLAN200/tham số từ máy khác. Dừng phần config chờ allocation/design; tiếp tục xác minh service binding/tài nguyên trong scope, không bịa VNI/RT |
| mpls | e1: VPN route inactive/unusable, next-hop `203.0.113.22`; e2: LLDP P1; e3: inet.3 thiếu /32; e4: LSP tới next-hop down; e5: vrf-target hiện hữu | P1 là vật lý, chưa chứng minh là remote PE. Ưu tiên giả thuyết resolution/transport, chưa kết luận nguyên nhân gốc hay RT sai. Kiểm recursive resolution, transport preference/backup LDP/SR/LSP và mapping next-hop trước mở rộng; RT trùng cũng chưa chứng minh mọi import policy đúng |
| contradiction | e1 lúc 08:00 có route, e2 lúc 09:00 không có. Khác thời điểm nên không coi là cùng snapshot hay bằng chứng policy chắc chắn sai | Có thể là thay đổi mạng, stale evidence hoặc identity/context lệch. Đối chiếu thời gian/identity, nguồn thay đổi và trạng thái mới có mục tiêu; không lặp toàn bộ output |

Các source eN trong bảng đều có prefix tên ca; ví dụ `mpls-e4`, không phải e4
toàn cục. Không ca nào cho phép thực thi thay đổi.

### Delta tham chiếu cho inheritance

Chỉ là đề xuất synthetic cho PE-J, Junos, từ operational/running evidence đã nêu.
Interface/unit lấy e1; giá trị 9000 và cách override lấy e5/e6; e2/e3 chứng minh
trạng thái trước. Không cấp phát IP/VLAN/RT mới.

```text
set interfaces xe-0/0/0 unit 100 family inet mtu 9000
```

Rollback về trạng thái kế thừa trước, vì e1 không có local MTU:

```text
delete interfaces xe-0/0/0 unit 100 family inet mtu
```

Pre-check dự kiến: xác nhận running chưa đổi, candidate không có thay đổi của
người khác, BASE-L3 vẫn kế thừa 1500 và physical MTU 9216, binding/CE và thiết kế
S100 vẫn như e6/e7. Nếu khác thì lập lại delta/rollback. Chưa chạy validate trên
Junos thật; cú pháp/khả năng hỗ trợ phải xác minh đúng image khi triển khai được phép.

Post-check dự kiến sau apply được cấp quyền: effective IP MTU của đúng unit là
9000; physical MTU/group/các unit khác không đổi; đo đúng flow/VRF và hai chiều với
kích thước IP phù hợp, tính header/encapsulation theo đường thực. Nếu không đạt
hoặc phát sinh tác động thì dùng rollback đã đối chiếu, kiểm effective về 1500 và
dịch vụ trở lại baseline. Không chạy configure/commit-check/commit trong tác vụ này.

## Kết quả và giới hạn

Toàn suite đạt **418/418 test trong 492,979 giây**, không failure hoặc skip.
Lượt full trước bị ngắt cùng hội thoại và không có tổng kết. Kết quả 418/418
thuộc lượt chạy lại đầy đủ trên source cuối. Log nằm ngoài Git tại TEMP với tên
`netmiko-reasoning-final-scget40i.log`.

Kiểm tra tập trung đạt 3 test evidence mới, 3 test workflow và 5 test contract/lock.
51 file Python đạt kiểm tra cú pháp Python 3.10. So AST với HEAD cho thấy backend
chỉ đổi descriptions. Nội dung source ngoài TOOLS giữ nguyên. Schema 10 tool và
diff check đều đạt.

Tám ca có 30 source: 28 SUCCESS,
một PARTIAL và một CLI_ERROR theo oracle thu thập; raw đọc lại khớp byte/hash.
SUCCESS ở đây chỉ là thu thập phản hồi fixture, kể cả phản hồi route không tồn tại.
Walkthrough phân biệt đúng scope/giới hạn theo bảng; chưa đo độ chính xác của một
agent độc lập trước/sau, token thực, khả năng tự discovery bằng SSH hoặc hiệu lực
cấu hình trên thiết bị vendor thật. Không dùng tỷ lệ pass backend làm tỷ lệ chẩn đoán.

Chạy lại:

```text
python -m unittest discover -s tests -p test_network_reasoning_evidence.py -v
python -m unittest discover -s tests -v
```

Muốn nghiệm thu model: dùng cùng câu hỏi/evidence nhưng giấu bảng đáp án, ghi model,
instructions, transcript/tool calls, kết luận/delta và citation thực tế. Đối chiếu
cả ca đúng/lỗi/unknown, quyền, discovery có nguồn, phản chứng và rollback; cho phép
phương pháp/lệnh khác có giá trị tương đương. Repo không có client/model runner,
nên đợt này không thêm runner hoặc khẳng định đã chạy benchmark đó.

> Các mục dưới đây là lịch sử theo phiên bản, không phải hướng dẫn vận hành hiện tại. Với 1.9.1, dùng [README](README.md) và [hướng dẫn scanner](docs/SCAN.md); các policy read-only cũ đã được thay thế.

## Unreleased — 2026-11-11

- Add standalone scripts/report_bundle.py to copy complete UTF-8 evidence by checksum into new report bundles and render escaped HTML without model/SSH/SMTP calls. Preserve original raw, manifest metadata and partial/error status. Add targeted fidelity/failure tests and evidence-reading/reporting guidance; backend code and ten tool schemas unchanged.
- Validate 8 report-bundle tests plus local sender dry-run with 10,000 simulated rows. Reference token payload comparison documented in docs/REPORTING.md; not a live-agent cost benchmark.

- Avoid passing redundant force keyword to overridden redact_output during CLI/preparation error handling; retain the public optional keyword for compatibility. Add single-argument override and unredacted routing-identifier regressions.
- Validation: all 350 tests passed in 533.809 seconds (mock and SSH localhost only), plus offline plain/HTML report fidelity checks in the private OpenCode deployment. No production SSH or email sent.

- Add optional boolean continue_on_error to ssh_execute_many (default false), forwarded for parallel batch tasks. Continue only complete synchronized CLI errors, never timeout/disconnect/pending input/storage failures. Still ten MCP tools; update the input contract deliberately.
- Report unsent batch suffix commands as SKIPPED/NOT_SENT with command indexes and blocker index. Preserve aggregate failure/uncertainty, healthy-session retention and the scanner's real fault/prefix/checkpoint/resume behavior. Redaction remains disabled by default.
- Validation: full suite 347 tests passed in 470.005 seconds, plus 21 focused batch/loopback/resume tests after the final blocker-index rebase fix. Includes 500/2,500 simulated devices; Python 3.10 syntax checked. No production SSH.

- Simplify installation examples to one default credential profile; document optional multi-profile setup separately.
- Accept omitted/blank CSV netmiko_device_type as autodetect; retain explicit inventory drivers and mandatory name/IP validation.
- Add no-SSH STDIO install check and Windows/Linux Codex setup using venv Python and absolute paths. Clarify that MCP connectivity does not establish SSH reachability/authentication.
- Correct current preparation-evidence redaction guidance; redaction remains disabled by default.
- Validation: 80 focused onboarding/bootstrap/credential/compatibility/scanner tests passed, including six fresh-install/CSV regressions and localhost SSH; Python 3.10 syntax and local documentation links checked. No production SSH.

- Synchronize shared output quota/cleanup/publication across MCP processes using bounded OS locks. Persist creation pins and protect live readers/search/export with bounded striped leases; process crashes release locks. Scanner retires committed scratch through the same storage protocol.
- Default to unredacted CLI/evidence/structured data and error/audit content, preserving usernames, passwords, hashes, secrets and tokens. Explicit redaction_enabled=true remains supported. Preserve full received output in storage failures instead of returning only a preview.
- Add bounded phase metrics and request/connection timings for connect/authentication/preparation/autodetect/command/output plus session reuse and slot/lease waits. Instrument existing methods without additional SSH, preserve vendor redispatch, and keep all ten tool schemas and Python 3.10+ compatibility.
- Extend offline fleet tests to 500 and 2,500 simulated devices, resource sampling, connection/session bounds, shutdown cleanup and evidence-verified resume. Add real subprocess shared-storage contention/crash regressions. These are not production SSH benchmarks.
- Validation: 321/321 tests passed in 455.512 seconds on Python 3.14.6 / Netmiko 4.7.0, including mock fleets and loopback SSH. Python 3.10 syntax compatibility checked; no production SSH.

## 1.9.1 — 2026-11-10

- Add MIT license. Correct outdated public setup/scanner documentation.
- Treat quiet-time-only completion of recognized log commands as unverified; keep received output without increasing waits or automatically retrying. Add exact 0.7-second delayed-prompt regression and MCP stdio coverage; normal completion and channel-EOF checks remain.

- Retain partial setup evidence for tolerant Junos/Cisco preparation failures; report preparation stage, CLI not ready and business command not sent. Redact setup evidence before returning MCP errors, including worker failures. Keep existing timeouts, retry decisions and architecture.
- Add direct/worker stdio preparation regressions and assertions of final host-key options at the Netmiko boundary; document ssh_mode as the authority for verification flags without changing policy.
- Bootstrap preserves explicit NETWORK_MCP_DATA_DIR, alt_key_file and alt_host_keys; legacy defaults apply only when absent. Optional --inventory-csv retains config devices and dynamic targets; supplied CSV still uses the existing merge/validation path.
- Add deterministic Junos preparation boundaries (slow response within/exceeding 5 seconds, CLI error followed by a valid prompt) and unrecognized timing-question regressions. Keep reader/timeouts/heuristics unchanged; uncertain configuration retains evidence and is not automatically replayed.
- Add bootstrap stdio integration with synthetic localhost SSH, UTF-8 JSON-RPC, all ten frozen tool schemas, dynamic/config/CSV targets and saved uncertain output.
- Add CLI error_reason permission_denied/syntax_error/command_failed; preserve CLI_ERROR, error_category, session/retry behavior and all ten tool schemas.
- Recognize explicit CLI/shell permission diagnostics and access-denied RPC error tags; clear stale CLI reasons when status changes to success/non-CLI failure.
- Add mcp/WORKFLOW.md and AGENTS.md link for evidence-based recovery, authentication/permission separation, pending input, storage/parser recovery and post-command goal verification.
- Keep Reader, pool, semaphore, credential loading and connection architecture unchanged. Validate with mock/vendor fixtures and SSH localhost.

## 1.9.0 — 2026-11-10

- Add shared credentials.json loader with multiple named profiles, password/key/agent authentication and relative key paths.
- Support --credentials-file, NETWORK_MCP_CREDENTIALS_FILE, config reference and optional sibling discovery across launchers/scanner/fleet validator.
- Replace profile auth as a complete bundle while retaining connection settings; reject malformed/incomplete explicit files without silent global fallback.
- Keep legacy config/environment/ssh.txt support, all ten MCP schemas and per-process session pools. Publish credential examples/docs; ignore local credential files.

## 1.8.2 — 2026-11-10

- Wait for session pool capacity with deadline/cancellation; adopt probe sessions outside the SSH semaphore.
- Retain delayed log/config data after prompt candidates and report ambiguous completion instead of false success.
- Share a per-device scanner budget across fast/retry lanes; persist elapsed budget and retain completed prefixes/evidence. Add --device-timeout without changing the ten MCP schemas.
- Preserve cooperative direct-connection timeout limits and prohibit automatic replay of uncertain configuration.

# 1.8.1 - Recomputed status, batch summaries and explicit credential inheritance

- Recompute pending flags and summary fields on normalization; clear obsolete success diagnostics and prevent incomplete responses from becoming success.
- Add status_counts and awaiting task IDs/index/target for all positions, preserving sequential interaction history and uncertainty. Ten input schemas unchanged.
- Select profile/device SSH credentials as a complete source; reject implicit cross-source pairs, support key/agent without passwords, and retain whole-source inheritance for connection-only profiles. inherit_credentials=true explicitly opts into field inheritance.
- No new credential loader, SSH feature, command filter, reader heuristic or benchmark in this release.
- Validation: 257 tests passed including 11 new regressions; final credential/status checks passed after source-label diagnostics. Python 3.10 syntax checked, runtime Python 3.14.6 / Netmiko 4.7.0.

# 1.8.0 - Canonical status, guarded recovery and bounded reader buffering

- Add canonical execution/fault/data/execution-state fields without changing ten MCP schemas or lowercase scanner checkpoint states.
- Supplement Junos/Cisco/Huawei verification and RPC errors while retaining config/log error text as data where applicable; report mixed transport/storage uncertainty accurately.
- Reuse verified sessions before cache lookup; detect exited worker processes locally. Refresh inferred driver cache at most once after preparation verification/read failure, never after explicit driver/auth/network/command errors; bypass stale DB entries even if invalidation is unavailable.
- Recover observational single-command transport loss once, retaining first-attempt data through deadline or failed reconnect. Never automatically replay configuration; scanner batch retry remains separate.
- Spool reader/partial buffers above 1 MiB, bound worker queue and wire chunks, and reconstruct canonical pager-cleaned output without a duplicate full-output frame. Final text processing still materializes output.
- Extend pager footer support and add deterministic/loopback regressions for status, stale caches, recovery, configuration uncertainty and large Unicode hashes. No production SSH or parallel benchmark.
- Validation: full suite of 242 tests passed; final reliability/status (24) and execution/resume (20) regressions passed after follow-up edge-case fixes. Python 3.10 syntax checked; runtime Python 3.14.6 / Netmiko 4.7.0.

# 1.7.0 - Agent-controlled configuration CLI, reader and targeted resume

- Remove vendor command allowlists/denylists and implicit command rewrites; retain framing checks only. Keep all ten MCP schemas; update descriptions and agent guidance. Legacy Python imports remain compatible.
- Support configuration-mode prompt transitions, explicit confirmation/Enter responses and pending-input session retention. Batches support 1000 commands/steps; execution concurrency remains bounded as before.
- Guard XML/JSON completion and Cisco config banners, retain preceding unassociated data, and prevent custom expect from redefining device identity.
- Preserve completed read-command prefixes across retry/resume; add retry-status selection without repeating successful devices, retain attempt/evidence history and recover failed exports without SSH replay.
- Avoid automatic replay after uncertain configuration effects; agent can explicitly authorize whole-batch replay to reconstruct context. No content restrictions are applied to initial execution.
- Validation: full 219-test suite passed; final execution/resume tests (20) and scanner regressions (35) also passed after legacy checkpoint support. Loopback mode tests cover Cisco, Junos and Huawei.
- No parallel benchmark or pool/storage architecture tuning in this release. Development validation uses mocks and loopback SSH, not production configuration.

# 1.6.1 - NOC compatibility and collection correctness

- Guard embedded prompt lines inside Cisco configuration banners; expand pager variants and privilege-error recognition.
- Preserve literal credentials, accept CSV SSH port and encrypted-key/encoding compatibility parameters.
- Apply CLI read/quiet profile options separately from Netmiko kwargs; explicit compatible/strict host-key modes and optional Cisco enable.
- Expand reviewed NOC aliases/filters; preserve healthy sessions on parser, synchronized persistence and interact CLI errors.
- Preserve execution timeout context across parallel tasks; bounded transient retry for initial slow-lane tasks.
- Add compatibility regressions including real localhost SSH banner collision, strict keys, profiles and session retention. Existing ten MCP schemas remain unchanged.

# 1.6.0 - Reuse the probe SSH session for collection

- Keep the isolated SSH worker alive after a verified probe, redispatch the same connection to the detected driver, and adopt its proxy into the session pool; avoid a second login on cold autodetect.
- Preserve hard deadlines and cancellation through parent-supervised RPC; stream partial evidence before final completion. Worker exit or interruption always returns failure, even when partial data contains a prompt.
- Retain paging, prompt/CLI verification, batch stop behavior, TextFSM and timing reads; close transport before driver cleanup on incomplete probes.
- Decode SSH collection data incrementally on each channel to preserve Unicode characters split across packets; retain Netmiko's existing behavior for invalid encoded bytes.
- Reap workers through normal TTL, eviction, close and shutdown. Explicit drivers and persistent-cache hits keep the direct connection path; ten MCP schemas remain unchanged.
- Add real localhost SSH coverage for six drivers, one-login counting, concurrency, large Unicode output, cache restart, deadlines, cancellation, worker crash/hang, confirmation, batch failure and idle reaping. No production SSH benchmark is claimed.
- Validation: 181 unittest tests passed on Python 3.14.6 / Netmiko 4.7.0; all six runtime Python files parse with Python 3.10 syntax rules.

# 1.5.0 - Output storage accounting and persistent driver cache

- Output quota accounting under one thread lock; remove repeated directory scans in a single save.
- Exclusive output index for scanner scratch/continuous collectors with periodic reconciliation, quota-pressure cleanup and explicit retirement notification. Shared mode retains directory reconciliation.
- Persistent verified autodetect results in SQLite, TTL and identity scoped, optional and fail-open to live probing on cache errors; common path for bootstrap/scanner/validator.
- Retain isolated detection process and its hard deadline; probe transport reuse is not implemented in this release.

# 1.4.0 - Collection performance options

- Prefer a concrete inventory driver over autodetect by default; configurable override.
- Reuse sessions with local closed/transport checks and periodic active health probes (30s).
- Faster Junos preparation reads setup responses to the discovered prompt; prompt remains connection-local.
- Prompt quiet defaults: 30ms normal, 100ms timing; configurable 0..2s.
- Optional output redaction; errors and audit commands remain scrubbed. Avoid duplicate output redaction on save; linear backspace cleanup.
- Read-loop budget/cancellation checkpoints at 50ms intervals and nonblocking lock fast path; session locks and SSH limits remain enforced.
- Bounded command validation cache (4096 successful entries).
- Configurable auth cooldown; timeout/lost transport never enters credential cooldown.
- Parallel detection across identities and single-flight detection for one identity retained.
- Optional process-specific known_hosts files; shared mode remains supported with atomic merging.

# 1.3.3 - Fleet and SSH fault validation

- Phát hiện channel EOF/closed ngay, giữ partial output, retry có giới hạn cho connection_lost và handshake_incomplete (Paramiko No existing session).
- Chỉ loại đúng vị trí pager đã xử lý, giữ nguyên chuỗi --More--/[confirm] trong dữ liệu cấu hình/log; phân biệt câu hỏi đang chờ với dòng log.
- ssh_interact giữ phân loại theo từng lệnh, không đánh nhầm bộ đếm BGP ở kết quả gộp.
- Session preparation không bắt echo mặc định; xử lý bước terminal-width Cisco vốn chờ echo trước khi base_prompt tồn tại. Có thể cấu hình global_cmd_verify.
- Lỗi lưu output được phân loại storage_error, không coi là SSH thành công hoặc retry network.
- Thêm validate_fleet.py: census TCP/banner toàn inventory, dedup endpoint, chọn mẫu SSH theo driver, lưu kết quả và bằng chứng; không tự thử nhiều credential.
- Bổ sung replay 2.000 cách chia chunk, stress 500 thiết bị ảo qua scanner thật, kiểm tra SHA256/resume/corrupt evidence, profile isolation và SSH localhost với driver Cisco IOS/XR/NXOS, Huawei, Junos, Linux.

# 1.3.2 - SSH reliability and complete output

- Chỉ báo thành công khi có prompt cuối của phiên và CLI không báo lỗi; không yêu cầu echo. Custom expect, pager và confirmation không thể ghi đè kết quả thành công.
- Đọc trực tiếp Netmiko channel dưới session lease: không chờ echo cố định, tự chuyển trang, giữ partial output khi timeout/cancel/transport error và dừng batch trước lệnh tiếp theo.
- Auth timeout có thể retry một lần ở scanner slow lane, không bị cooldown như sai credential; giữ chống lặp với authentication rejected/auth_method.
- Host-key policy riêng từng SSH client và cả subprocess autodetect; khóa file liên tiến trình, merge lại dưới khóa, atomic replace, warning khi không lưu được key mà vẫn tiếp tục SSH.
- Mở rộng các nhóm lệnh NOC và chẩn đoán; giới hạn số gói ping, tự thêm count 5 cho Junos/Linux khi thiếu.
- Profile CSV được giữ đúng khi xử lý alias trùng; bootstrap chấp nhận credential riêng trong profile mà không bắt có tài khoản toàn cục. Không tự đoán mapping credential.
- STDIO MCP/worker dùng UTF-8 tường minh trên Windows, tránh hỏng JSON-RPC hoặc alias/credential Unicode khi locale của pipe là CP1252.
- Thêm regression và integration SSH localhost cho phân trang, output chậm/thiếu, no-echo, session reuse, autodetect subprocess, host-key changed và ghi nhiều process.

# 1.3.1 - SSH Collection Improvements

- **TOFU host key policy**: Tự động thêm host key mới và cập nhật key đổi vào known_hosts (atomic write với lock)
- **Nới echo/prompt verification**:
  - Tìm echo trong 5 dòng đầu thay vì 3
  - OK khi có prompt cuối HOẶC echo (không phải cả hai bắt buộc)
  - Junos session setup tăng last_read từ 0.3s → 0.5s
  - Linux prompt thêm pattern `[user@host]$` và `[dir]#`
- **Multi-profile credential**: CSV hỗ trợ cột `profile` optional, devices.json có nhiều profile credential

Mục tiêu: giảm lỗi host_key_unknown (~718), output_verification (~244), authentication (~21) trong quét 2376 thiết bị.

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

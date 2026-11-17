## Unreleased — 2026-11-17

- Refine agent guidance for competing hypotheses/refutation, scoped physical and
  logical discovery, bidirectional VRF/AF forwarding and conditional service
  dependencies. Add effective/inherited configuration comparison, sourced minimal
  deltas, shared-object impact checks and rollback to the previous inherited state.
- Correct all ten tool descriptions, especially UTF-8 byte-reader semantics,
  limited search excerpts and host-wide close. Keep input schemas and executable
  SSH/session/reader/retry/storage/dispatcher logic unchanged. Correct two stale
  README statements about redaction and persistence-error evidence retention.
- Add eight synthetic network scenarios with 30 evidence sources and three MCP
  replay/fidelity regressions; record engineering assessments and configuration
  limits in docs/NETWORK_REASONING.md. These verify evidence delivery and a manual
  walkthrough, not blind model accuracy, production discovery or vendor validation.
- Validation: all 418 tests passed in 492.979 seconds with no skips on the final
  source, after an earlier conversation-interrupted run without a final result.
  Eleven focused evidence/workflow/schema/lock tests passed. All 51 Python files
  passed Python 3.10 syntax checks; backend AST differs only in descriptions.
  Mock/localhost only; no production SSH, apply/commit or email.

- Add bounded mock/localhost soak harness with CPU/RSS/thread/handle sampling,
  owned probe-worker measurements and durable hash-verified synthetic evidence.
  Keep warm credential-isolated pools, inject scanner faults, verify prefix-safe
  retry/resume, reject corrupt evidence and prohibit uncertain-write replay.
- Complete isolated 500/2,500-target mock stress, 180-second mock soak (584 cycles,
  59 fault jobs) and 120-second loopback soak (87 cycles, five bounded recoveries).
  Retain raw and scope/resource limits in docs/STRESS_SOAK.md. Diagnose closed
  test-server transport retention separately; do not claim multi-hour leak freedom.
- Add four short harness regressions including network-free mock guards, loopback
  worker shutdown and per-process resource sampling. No backend, schema, dependency
  or deployment-setting changes; mock discovery requires explicit drivers.
- Stage-six validation: all 415 tests passed in 481.408 seconds with no skips;
  four focused harness tests passed. Verify 10,052 mock-soak and 385 loopback
  evidence hashes, plus 118 error/partial payloads byte-for-byte. Both soaks end
  with zero sessions; the loopback worker is reaped. Python 3.10 syntax and diff
  checks passed. This is short mock/localhost testing, not production certification.
- Build and independently verify a FULL local report bundle with 11,158 raw and
  metadata sources (40,692,098 bytes), preserving excluded-startup diagnostics
  separately from accepted measurements. Hashes/Markdown/HTML verified; no ZIP,
  SMTP or device data committed.

- Synchronize agent workflow with current inventory/profile/port metadata,
  parallel queue scope, string interaction steps, host-key modes and host-wide
  close semantics. Document full-file search counts versus limited excerpts,
  zero-based line readers, one-based search lines and UTF-8 byte continuation.
- Keep a smaller core workflow with conditional tool/evidence/recovery/reporting
  references. Preserve detailed findings/recovery guidance in linked documents,
  full raw evidence and FULL inline reports. Clarify completion based on resolved
  decision-relevant gaps instead of expanding investigation merely because more
  commands exist. No runtime, ten-tool schema, storage, reader or retry changes.
- Static context comparison against 83edc75: workflow characters decrease about
  38.9%; AGENTS plus workflow decrease about 31.4%. These are character counts,
  not measured model tokens/cost or a live-agent reasoning benchmark.
- Add executable documentation-contract checks for all ten JSON call examples,
  local links and full-raw search/long-line/UTF-8 paging behavior without SSH.
- Stage-five validation: all 411 tests passed in 468.077 seconds with no skips,
  including three new documentation/evidence contract checks. Runtime source,
  requirements and frozen input schemas are unchanged from 83edc75. Python 3.10
  test syntax and diff checks passed. Mock/localhost only; no production SSH,
  email or live-agent token/cost benchmark.

- Cache reader raw snapshots, cleaned tails and container checks per data revision;
  invalidate before append/callback so partial-write failures retain new evidence.
- Add a bounded, tree-free XML prefix guard that can only veto completion. Keep
  the existing full verifier for closed/unsupported input, including terminal
  rewrites and long pending lines. Preserve quiet/polling/deadline/retry behavior,
  prompt ambiguity, pager handling and all ten input schemas.
- Compare against 04d6449 with synthetic UTF-8 benchmarks: 158 measurements,
  including 15 final-source checks, all matching expected hashes/status. Final
  XML-prompt 10 MiB median processing drops 15.443 → 0.811 seconds; value() drops
  164 → 1. 100 MiB JSON processing drops 33.0%; XML drops 27.3%. Memory results
  remain format-dependent. See docs/READER_OPTIMIZATION.md for scope and limits.
- Final-source differential replay matches the baseline on 1,440 seeded cases;
  add ten cache/prefix/failure regressions, matching first pipeline format
  selection, and benchmark backend selection with
  per-case source hashes. No production SSH or new implicit CLI commands.
- Final validation: all 408 tests passed in 493.289 seconds with no skips,
  including the ten new reader regressions, JSON-RPC/schema contracts, mock
  fleets, localhost SSH, worker lifecycle and crash-safe storage/scanner tests.
  Python 3.10 syntax and diff checks passed. The earlier full run was deliberately
  interrupted to include the pipeline-format compatibility fix; this result is
  a fresh complete run on the final source.

## Unreleased — 2026-11-16

- Add a subprocess-isolated synthetic reader benchmark for 1/10/100 MiB UTF-8,
  three chunk sizes, text/JSON/XML/banner, prompt ambiguity, pager and repeated
  XML prompt-like lines. Record integrity hashes, CPU/RSS, full-buffer calls,
  input character volume and requested sleeps; support real and accelerated
  clocks plus optional cProfile. No backend/schema/timeout/quiet/retry changes.
- Complete 74 offline measurements including repeat samples, real-clock checks
  and profiles. Document measured polling/normalization costs and repeated-prefix
  XML parsing in docs/READER_BENCHMARK.md; distinguish sampled process RSS from
  reader allocations and synthetic timings from production SSH performance.
- Stage-four validation: all 398 tests passed in 469.650 seconds, no skips;
  all 74 benchmark/profile measurements matched expected hashes and failure
  semantics. Four new harness correctness tests passed. Python 3.10 syntax and
  diff checks passed. Runtime reader remains unchanged; optimization is deferred
  to the measured follow-up priorities. Mock/synthetic channel/localhost only.
- Add effective profile/port metadata to inventory without credential resolution.
  Preserve existing fields, paging, summary behavior and ten input schemas.
- Add process-local parallel queue counts, bounded wait metrics, per-task queue
  waits and per-request worker limits; preserve ordering and deadline handling.
  Scanner summaries/progress expose requested/effective workers and lane queues,
  with queue waits persisted per attempt without changing retry/resume budgets.
- The first stage-three suite exposed a Windows lock-file initialization race:
  concurrent creators could flush the sentinel before taking the OS byte lock,
  failing scanner evidence export with PermissionError. Capture a reproducing
  traceback, initialize the sentinel only under the OS lock, and add initialization
  ordering plus concurrent-creator regressions. Preserve export_pending recovery,
  finite lock waits, quota and lease semantics; do not repeat SSH on export errors.
- Stage-three final validation: all 394 tests passed in 468.254 seconds with no
  skips, including 105-target scanner, bounded queue metrics, expired queued
  requests, shared storage contention/crash and all ten frozen input schemas.
  The initial 392-test run had one evidence-export PermissionError, reproduced
  with its traceback and fixed above; the new ordering test fails before the fix.
  Focused scanner (36), shared storage (9) and queue/inventory (4) tests passed.
  Python 3.10 syntax and diff checks passed. Mock/localhost only; no production SSH.
- Investigate the intermittent large-Unicode worker authentication count:
  the localhost fixture reused its 100 ms receive polling timeout for large
  sendall replies. Controlled receiver backpressure reproduced server-side
  TimeoutError, connection_lost and one legitimate recovery (two logins).
  Give static fixture replies a bounded five-second send timeout and restore
  receive polling afterward; retain fixture errors for diagnosis. Backend
  timeout/retry/connection behavior and the one-login assertion stay unchanged.
  A small-window slow-reader regression fails with the old send timeout and
  passes with the fix, preserving exact Unicode bytes with one authentication.
  Validation after the fix: all 387 tests passed in 462.238 seconds, with no
  failures or skips, including the original Unicode test and the new slow-reader
  regression. The focused collection/status module also passed all 24 tests.
  Python 3.10 syntax and diff checks passed. Mock/localhost only; no production SSH.
- Expose the already-supported optional boolean continue_on_error in parallel
  batch task schemas. Preserve ten tools, string interaction steps and defaults.
- Use a stable OS-managed scanner job lock for crash recovery; refuse legacy
  PID-only locks without deleting them. Document safe migration and rollback.
- Add schema example validation and real subprocess lock contention/kill tests.
- Validation: full suite ran 386 tests in 475.442 seconds; 385 passed and the
  large-Unicode worker test failed its one-authentication assertion (2 vs 1).
  Its entire 24-test module and five consecutive isolated repetitions then
  passed unchanged. Cause remains unconfirmed; not a clean full-suite pass.
  All five new contract/lock tests passed, including JSON Schema validation;
  Python 3.10 syntax and diff checks passed. Mock/localhost only.

> Các mục dưới đây là lịch sử theo phiên bản, không phải hướng dẫn vận hành hiện tại. Với 1.9.1, dùng [README](README.md) và [hướng dẫn scanner](docs/SCAN.md); các policy read-only cũ đã được thay thế.

## Unreleased — 2026-11-15

- Default report bundles to FULL inline analysis and CLI with a bundled escaped HTML renderer (headings, tables, emphasis and styled raw blocks). Copy raw by script, retain evidence hashes and targeted AI reading; no model transcription required.
- Private deployment senders send complete plain/HTML bodies without ZIP attachments, use the report title for the subject and reject old SUMMARY bundles with rebuild instructions. Keep recipient, credentials, SMTP/outbox/retry settings unchanged. No production SSH or email sent during development.
- Validation: 15 report-bundle tests passed; offline MIME checks on all three private deployments retained the complete analysis and 10,000 synthetic CLI lines in both plain/HTML, zero attachments, correct subject and exact raw hashes. Python 3.10 syntax checked. No SMTP connections.

## Unreleased — 2026-11-12

- Review the privately field-adjusted reader, diagnostics and batch summaries. Handle a provisional prompt followed by a full command echo, and the known Junos screen-width repaint only when no response body preceded it; keep no-echo devices working. Do not accept a truncated command prefix as echo or discard ambiguity after actual payload.
- Preserve specific preparation diagnostics and non-CLI error reasons; clear stale CLI reasons on a different failure category and all stale diagnostics on success. Reader interruptions retain category-specific reasons and partial output.
- Return consistent batch totals, skipped count and first failed-command diagnostics through direct, parallel and MCP error responses. Keep default batch stop and optional continuation rules unchanged.
- Inventory/credentials remain private and are not imported. Field validation claims from the private changelog are not treated as tests performed in this checkout.
- Validation: 108 focused compatibility tests passed using mocks and SSH localhost; after the final regression additions, all 16 prompt/diagnostic/batch-summary tests passed. Includes 2,000 seeded fragmented-output replays. Python 3.10 syntax checked. No production SSH, email, credential/config update or Git push.

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

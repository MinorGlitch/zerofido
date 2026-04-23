# Current-state protocol conformance
This ledger is the tracked S02 findings surface for the current claimed CTAPHID / CTAP2 / U2F behavior. It is written for later audit authors who need one place to record row-by-row current-state judgments without silently upgrading source review into live proof.
After reading it, a later slice author should be able to pick an S02-owned row ID, replace the scaffold evidence with current code/test/spec anchors, and keep browser or hardware gaps explicit instead of flattening them into a pass.
## Reader contract
- T01 locks the 21 S02-owned manifest row IDs plus the auxiliary checkpoints that keep proof labels, historical buckets, and browser/hardware gaps honest.
- Every finding uses the `docs/17-current-state-proof-taxonomy.md` shape so later slices cannot invent unsupported proof labels or omit impact/revalidation fields.
- The initial T01 verdicts stay `needs-revalidation` on purpose: this file is structurally valid now, but later S02 tasks must replace scaffold evidence with current row-specific code/test/spec anchors before the slice can be closed.
- Every row keeps `docs/18-current-state-revalidation-map.md` in scope so historical remediation notes are treated as context, not as automatic closure.
- Do not claim live-device or browser proof in this ledger unless the matching command was rerun in this slice.

## Transport and U2F rows
### Finding transport.init: CTAPHID_INIT
- Local claim: `docs/13-fido-audit-matrix.md` currently claims `CTAPHID_INIT` allocates unique non-reserved channels on broadcast requests, requires allocated channels for subsequent traffic, accepts same-CID resync during assembly and approval-bound processing, and reclaims the least-recently-used inactive CID when the bounded table fills.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/usb_hid_session.c` reserves `0xffffffff` and `0x00000000`, allocates fresh CIDs through `zf_transport_allocate_cid()`, rejects direct `INIT` on unallocated non-broadcast CIDs, special-cases same-CID resync both in `zf_transport_handle_processing_control()` and in the `transport->processing` path of `zf_handle_packet()`, and reclaims the least-recently-used inactive slot when `ZF_MAX_ALLOCATED_CIDS` (8) is full. Fresh local evidence in this slice is limited to `uv run python -m unittest tests/test_ctaphid_probe.py`, plus `uv run python tools/run_protocol_regressions.py`, which keeps the native transport regressions current; the attached-device `transport_exhaust_cids` / `transport_resync` probes were not rerun.
- External reference: U2F HID Protocol v1.1 `U2FHID_INIT` and reserved-CID rules; CTAP 2.2 USB HID channel allocation and same-channel resynchronization guidance; `docs/18-current-state-revalidation-map.md` findings 4 and 5.
- Impact: `CTAPHID_INIT` is the foundation for every later HID exchange. If channel allocation, reserved-CID handling, or same-channel resync drift, host stacks will mis-handle arbitration and later protocol rows inherit false transport assumptions.
- Revalidation / next check: Rerun `uv run python host_tools/ctaphid_probe.py --cmd exhaustcids`, `uv run python host_tools/ctaphid_probe.py --cmd invalidcid`, and `uv run python host_tools/ctaphid_probe.py --cmd resync` on attached hardware before upgrading this row from source-backed proof to live wire proof.

### Finding transport.ping: CTAPHID_PING
- Local claim: `docs/13-fido-audit-matrix.md` claims `CTAPHID_PING` echoes the caller payload.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/usb_hid_session.c` routes fully assembled `ZF_CTAPHID_PING` messages through `zf_process_complete_message()`, which responds with `zf_send_frames(cid, ZF_CTAPHID_PING, payload, payload_len)` on the same CID. The framing helper rerun in this slice, `uv run python -m unittest tests/test_ctaphid_probe.py`, passed `test_build_frames_fragments_long_payload`, which keeps the host-side fragmentation/continuation expectation in `host_tools/ctaphid_probe.py` current, but no attached-device `transport_ping` replay was rerun.
- External reference: U2F HID Protocol v1.1 message echo framing for `PING`; CTAP 2.2 USB HID packet assembly rules; `docs/18-current-state-revalidation-map.md` as the transport-bucket baseline.
- Impact: If `PING` stops echoing cleanly on the active CID, host-side diagnostics and later transport probes can misattribute framing or channel-state defects to higher protocol layers.
- Revalidation / next check: Rerun `uv run python host_tools/ctaphid_probe.py --cmd ping` on attached hardware if a later slice needs live fragmentation proof; until then this row stays limited to the current source-backed echo path.

### Finding transport.cbor: CTAPHID_CBOR
- Local claim: `docs/13-fido-audit-matrix.md` claims `CTAPHID_CBOR` routes CTAP2 payloads over the serialized HID transport model used by the current tree.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/usb_hid_session.c` requires non-empty CBOR payloads in `zf_transport_validate_command_length()`, assembles them through `zf_transport_begin_message()` / continuation handling, and dispatches completed requests through `zerofido_handle_ctap2()` in `zf_process_complete_message()`. Approval-time control traffic is limited to the active CID via `zerofido_transport_poll_cbor_control()`, which only turns same-CID `CTAPHID_CANCEL` into `ZF_CTAP_ERR_KEEPALIVE_CANCEL` and only allows same-CID `CTAPHID_INIT` to resynchronize the blocked CBOR flow. No live `ctap_get_info` or approval-bound CBOR replay was rerun in this slice.
- External reference: CTAP 2.0 / 2.2 CBOR-over-HID transport rules, especially same-channel request serialization and approval-bound control handling; `docs/18-current-state-revalidation-map.md` findings 4 and 5 for the remaining transport-history context.
- Impact: If the CBOR transport path is described more strongly than the code really supports, later CTAP command rows can inherit false confidence about cancel/resync behavior or about which channel owns an approval-bound request.
- Revalidation / next check: Rerun `uv run python host_tools/ctaphid_probe.py --cmd getinfo`, plus the attached-device `transport_cancel` and `transport_resync` scenarios, before treating this row as live-proven beyond the cited source path.

### Finding transport.msg: CTAPHID_MSG
- Local claim: `docs/13-fido-audit-matrix.md` claims `CTAPHID_MSG` routes U2F APDU payloads correctly for the implemented legacy-compatibility surface.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/dispatch.c` dispatches completed `ZF_CTAPHID_MSG` packets through `zf_u2f_adapter_handle_msg(app, cid, ...)`, and `src/u2f/adapter.c` immediately re-runs `u2f_validate_request()` before approval or dispatch. The request CID is threaded into `zf_u2f_request_approval()` and then into `zerofido_ui_request_approval(..., cid, ...)`, while `zf_transport_wait_for_approval(app, current_cid, ...)` emits keepalives on that same CID. That source path addresses the historical reserved-CID keepalive bug from `docs/18-current-state-revalidation-map.md` finding 7, but this slice did not rerun an attached-device keepalive capture. `src/u2f/session.c` also now writes `U2F->counter + 1` durably before incrementing the in-memory counter, yet `docs/18-current-state-revalidation-map.md` finding 8 remains `not re-proven` because no torn-write or reboot-oriented regression was rerun here.
- External reference: U2F HID Protocol v1.1 message transport; U2F Raw Message Formats v1.1 authentication-counter semantics; `docs/18-current-state-revalidation-map.md` findings 7 and 8.
- Impact: Calling the full `MSG` / U2F surface fully supported would hide two still-open proof boundaries: the wire-observed keepalive CID has not been replayed in this slice, and the authentication counter durability claim still lacks a direct failure-mode regression.
- Revalidation / next check: Rerun the attached-device `u2f_version`, `u2f_register`, and `u2f_authenticate` scenarios together with a live keepalive trace, then add a targeted counter-durability regression before upgrading this row beyond source-backed `needs-revalidation`.

### Finding transport.wink: CTAPHID_WINK
- Local claim: `docs/13-fido-audit-matrix.md` claims `CTAPHID_WINK` is supported on the current transport surface.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/dispatch.c` handles `ZF_CTAPHID_WINK` in `zf_transport_dispatch_wink()` by calling `zf_u2f_adapter_wink(app)`, and `zf_transport_dispatch_send_result()` replies with `ZF_CTAPHID_WINK` on the same CID. `src/u2f/adapter.c` routes that call directly to `u2f_wink(app->u2f)`. No fresh attached-device `transport_wink` replay was rerun in this slice, so this finding is limited to the current source path.
- External reference: U2F HID Protocol v1.1 optional `WINK` support; `docs/18-current-state-revalidation-map.md` as the current transport-history baseline.
- Impact: If `WINK` drifted without being noticed, host-side capability expectations and visible user feedback would diverge from the shipped transport contract.
- Revalidation / next check: Rerun `uv run python host_tools/ctaphid_probe.py --cmd wink` on attached hardware if a later slice needs live notification proof; the current row is otherwise supported by the cited transport/U2F dispatch path.

### Finding transport.cancel: CTAPHID_CANCEL
- Local claim: `docs/13-fido-audit-matrix.md` claims `CTAPHID_CANCEL` acts only on the active approval-bound CBOR request, emits no direct HID reply, ignores non-CBOR or non-matching traffic, and terminates the blocked CBOR flow with `CTAP2_ERR_KEEPALIVE_CANCEL`.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: In `src/transport/usb_hid_session.c`, `zf_transport_handle_init_command()` rejects non-zero-length `CANCEL`, suppresses any direct HID reply, and only treats a cancel as meaningful when `transport->processing && transport->cmd == ZF_CTAPHID_CBOR && cid == transport->cid`. The same rule is mirrored in `zf_transport_handle_processing_control()`, which returns `ZF_CTAP_ERR_KEEPALIVE_CANCEL` to the blocked CBOR worker so the outer response becomes a CBOR status, not a HID transport reply. Same-CID but non-CBOR traffic, wrong-CID traffic, and idle cancels fall through without changing state. The attached-device `transport_cancel` scenario in `host_tools/conformance_suite.py` was not rerun in this slice.
- External reference: CTAP 2.2 approval-time keepalive/cancel semantics for CBOR-over-HID; `docs/18-current-state-revalidation-map.md` for the surrounding transport-history context.
- Impact: If cancellation semantics are documented more broadly than the implemented approval model, browsers or probe tools can treat ignored non-CBOR cancels as regressions or, worse, assume a cancellation guarantee the firmware does not actually provide.
- Revalidation / next check: Rerun the attached-device `transport_cancel` scenario to reconfirm the same-CID CBOR cancellation path on wire; until then this row is limited to the cited source behavior.

### Finding transport.spurious_continuation: Spurious continuation packet
- Local claim: The current transport audit surface treats a spurious continuation packet as ignored when no message is active and as an explicit busy/sequence error only when it collides with an active assembly on the wrong CID or wrong sequence.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/usb_hid_session.c` routes non-init packets to `zf_transport_handle_cont_packet()`. `zf_transport_validate_continuation()` returns `false` without a HID error when `transport->active` is false, which matches the attached-device `transport_spurious_continuation` scenario defined in `host_tools/conformance_suite.py` (`"spurious continuation packet was ignored"`). When a message is active, wrong-CID continuations emit `ZF_HID_ERR_CHANNEL_BUSY`; wrong sequence numbers on the active CID emit `ZF_HID_ERR_INVALID_SEQ` and reset the active assembly. The scenario definition was reviewed in this slice, but not rerun on hardware.
- External reference: CTAP 2.2 / U2F HID continuation sequencing and channel-ownership rules; `docs/18-current-state-revalidation-map.md` for the transport-history baseline.
- Impact: This row controls how continuation floods and post-completion garbage are classified. If the code or docs drift, later audit slices can mislabel an intentional ignore-as-idle behavior as either a regression or a conformance pass for the wrong reason.
- Revalidation / next check: Rerun the attached-device `transport_spurious_continuation` scenario if a later slice needs wire proof of the ignore-on-idle rule; keep any claim scoped to the current source path until then.

### Finding transport.capabilities: Capability bits
- Local claim: `docs/13-fido-audit-matrix.md` claims the transport advertises `WINK | CBOR` and omits `NMSG` because `MSG` is implemented.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/transport/usb_hid_session.c` builds the `CTAPHID_INIT` reply in `zf_handle_init()` and sets `response[16] = ZF_CAPABILITY_WINK | ZF_CAPABILITY_CBOR`; there is no `NMSG` bit in the current response path. The fresh unit rerun for this slice was `uv run python -m unittest tests/test_ctaphid_probe.py`, which keeps the host-side `expect_init_response()` parser current, but no live `transport_init` replay was rerun.
- External reference: U2F HID Protocol v1.1 capability-byte semantics for `INIT`; `docs/18-current-state-revalidation-map.md` as the transport-history baseline.
- Impact: Capability-bit drift feeds directly into host feature negotiation. Overstating `NMSG` or omitting a supported bit would mislead browser and probe expectations before any higher-level command is sent.
- Revalidation / next check: Rerun `uv run python host_tools/ctaphid_probe.py --cmd init` or the attached-device `transport_init` scenario if a later slice needs wire capture of the advertised capability byte; the current row is otherwise settled by the cited init-response construction.

### Finding transport.u2f_apdu_validation: U2F APDU validation
- Local claim: `docs/13-fido-audit-matrix.md` claims the U2F path validates CLA / INS / P1 / P2 and exact APDU length before struct casts.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/u2f/apdu.c` parses APDU headers through `u2f_parse_apdu_header()` and rejects malformed frames before any request struct is trusted. `u2f_validate_apdu()` enforces CLA `0x00`, the expected INS, `P2 == 0x00`, and exact `Lc`; `u2f_validate_request()` then adds command-specific checks for allowed authenticate `P1` modes, minimum authenticate body length, and exact key-handle-length accounting. `src/u2f/adapter.c` re-runs `u2f_validate_request()` at the `CTAPHID_MSG` boundary before approval or dispatch. Fresh local evidence in this slice is limited to `uv run python -m unittest tests/test_ctaphid_probe.py`, which passed the host-helper APDU builder tests for VERSION, REGISTER, and AUTHENTICATE framing; the attached-device `u2f_invalid_apdu` rejection probe was not rerun.
- External reference: FIDO U2F Raw Message Formats v1.1 APDU framing and status-word expectations; U2F HID Protocol v1.1 `MSG` transport framing; `docs/18-current-state-revalidation-map.md`, especially finding 8 to keep post-validation counter durability separate from parser correctness.
- Impact: This row is the guardrail that keeps malformed APDUs from reaching U2F request structs or user-presence handling. If it drifts, later security work can confuse parser acceptance bugs with approval or cryptographic failures.
- Revalidation / next check: Rerun the attached-device `u2f_invalid_apdu` scenario to reconfirm the live rejection path; keep the counter-durability discussion explicit elsewhere rather than silently folding it into APDU-validation correctness.

## CTAP2 rows
### Finding ctap.get_info: GetInfo
- Local claim: `docs/13-fido-audit-matrix.md` claims `GetInfo` advertises `FIDO_2_0`, `U2F_V2`, `rk=true`, `up=true`, `plat=false`, a dynamic `clientPin` bit, and `minPINLength=4` while omitting built-in `uv`.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `zerofido_handle_ctap2()` in `src/zerofido_ctap_dispatch.c` accepts `ZfCtapeCmdGetInfo` only with an empty payload and threads the current PIN-set state into `zf_ctap_build_get_info_response()`. `src/ctap/response.c` then emits versions `[`"FIDO_2_0"`, `"U2F_V2"`]`, the attestation AAGUID, options `{rk:true, up:true, plat:false, clientPin:<dynamic bool>}`, `pinUvAuthProtocols` `[1]`, `transports` `["usb"]`, only the ES256/public-key algorithm descriptor, and `minPINLength=4`. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_get_info_rejects_trailing_payload`, and `uv run python -m unittest tests/test_conformance_suite.py`, which passed the static-contract checks `test_validate_get_info_response_rejects_unexpected_uv_option`, `test_validate_get_info_response_rejects_missing_min_pin_length`, and `test_validate_static_metadata_rejects_built_in_uv_claims`; those reruns strengthen the response-shape contract but do not replace a live `ctap_get_info` replay.
- External reference: CTAP 2.2 §6.4 `authenticatorGetInfo`; CTAP 2.2 §8.2 status codes; `docs/15-milestone-10-protocol-remediation.md` Batch 1; `docs/18-current-state-revalidation-map.md`.
- Impact: `GetInfo` is the product-model handshake for browsers and probe tools. If its option bits or version surface drift, later PIN and credential flows are negotiated against the wrong authenticator model.
- Revalidation / next check: Rerun the attached-device `ctap_get_info` scenario before calling this row live-proven on wire; until then the row is limited to the current source path plus local contract tests.

### Finding ctap.make_credential_rk: MakeCredential with rk=true
- Local claim: `docs/13-fido-audit-matrix.md` claims `MakeCredential` with `rk=true` creates and persists a discoverable credential while replacing any older resident credential for the same RP and user handle.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/ctap/parse_make_credential.c` requires `clientDataHash`, `rp.id`, `user.id`, and `pubKeyCredParams`, rejects duplicate CBOR keys, rejects duplicate `excludeList` descriptors, and rejects `options.up=false` or zero-length `user.id` with parameter errors. `src/zerofido_ctap_dispatch.c` validates `pinAuth` / `pinProtocol`, treats zero-length `pinAuth` as a compatibility probe, rejects built-in-UV requests that are not backed by `pinAuth` with `UNSUPPORTED_OPTION`, and sets `resident_key = request.has_rk && request.rk` before preparing the credential. For resident registrations, `zf_store_delete_resident_credentials_for_user()` in `src/zerofido_store.c` now removes older resident credentials for the same RP and user handle before the new credential is added, while discoverable lookup remains resident-only because `zf_store_find_by_rp()` returns only records with `resident_key=true`. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_make_credential_parse_rejects_empty_user_id`, `test_make_credential_parse_rejects_duplicate_exclude_descriptors`, `test_make_credential_empty_pin_auth_requires_pin_protocol`, `test_make_credential_empty_pin_auth_probe_returns_pin_status_after_touch`, `test_make_credential_uv_without_pin_auth_returns_unsupported_option`, `test_make_credential_pin_auth_takes_precedence_over_uv`, and `test_make_credential_overwrites_resident_credential_for_same_user`; those reruns cover malformed-request, option-handling, and resident-overwrite boundaries, but no attached-device resident registration replay was rerun.
- External reference: CTAP 2.2 §6.1 `authenticatorMakeCredential`; CTAP 2.2 §6.1.3 `Discoverable credentials`; `docs/18-current-state-revalidation-map.md` finding 1.
- Impact: If the resident-key path drifts, passkey/discoverable registration can appear supported in product claims while the stored credential is unusable for RP-wide discovery or malformed requests are handled differently than the current tree implies.
- Revalidation / next check: Rerun `ctap_make_credential_resident` plus the attached-device missing-`clientDataHash` probe before upgrading this row beyond source-backed current-state support.

### Finding ctap.make_credential_nonresident: MakeCredential with rk=false or absent
- Local claim: `docs/13-fido-audit-matrix.md` claims `MakeCredential` with `rk=false` or an omitted `rk` option creates a non-resident credential record that is not used for RP-wide discovery.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/zerofido_ctap_dispatch.c` derives `resident_key = request.has_rk && request.rk`, so an absent or false `rk` bit flows into `zf_store_prepare_credential(..., resident_key=false)` and `zf_store_add_record()`. That record remains usable only through credential-ID matching because `zf_store_find_by_rp()` in `src/zerofido_store.c` returns resident records only, while `zf_store_find_by_rp_and_allow_list()` matches any stored record bound to the RP and exact credential ID. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_get_assertion_parse_treats_empty_allow_list_as_omitted`, `test_store_allow_list_ignores_oversized_descriptor_ids`, and `test_get_assertion_without_matching_credential_skips_approval`; those reruns keep the allow-list lookup boundary current, but no successful non-resident registration/authentication replay was rerun.
- External reference: CTAP 2.2 §6.1 `authenticatorMakeCredential`; CTAP 2.2 §6.2.2 `authenticatorGetAssertion Algorithm` for allow-list lookup; `docs/18-current-state-revalidation-map.md` finding 1 as the surrounding malformed-request bucket.
- Impact: If the non-resident path drifted into discoverable storage or stopped participating in allow-list lookup, direct-credential authentication would break while the public matrix still claims the legacy allow-list surface works.
- Revalidation / next check: Rerun `ctap_make_credential_nonresident` and `ctap_get_assertion_allow_list` before treating this row as anything stronger than source-backed current-state support.

### Finding ctap.exclude_list: excludeList hit
- Local claim: `docs/13-fido-audit-matrix.md` claims an `excludeList` hit waits for approval before returning `CREDENTIAL_EXCLUDED`.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `src/ctap/parse_make_credential.c` reads `excludeList` through `zf_ctap_parse_descriptor_array()`, and `src/zerofido_ctap_dispatch.c` checks the resulting IDs with `zf_store_has_excluded_credential()` before key generation. On a hit, the current tree routes through `zf_ctap_request_approval()` and then returns `ZF_CTAP_ERR_CREDENTIAL_EXCLUDED` unless the blocked request was explicitly canceled. Fresh local evidence in this slice is `uv run python tools/run_protocol_regressions.py`, which passed `test_make_credential_excluded_credential_returns_excluded_after_timeout` and therefore directly re-proved the approval-before-`CREDENTIAL_EXCLUDED` behavior on the current tree. No attached-device `ctap_exclude_list` replay was rerun.
- External reference: CTAP 2.2 §6.1.2 `authenticatorMakeCredential Algorithm`, especially the `excludeList` / user-presence branch that returns `CTAP2_ERR_CREDENTIAL_EXCLUDED` only after the user-presence gate; `docs/18-current-state-revalidation-map.md`.
- Impact: This row is the anti-oracle boundary for already-registered credentials. If it drifts, RPs can learn credential existence without the intended touch/approval step.
- Revalidation / next check: Rerun the attached-device `ctap_exclude_list` scenario if a later slice needs wire proof; the current local test already settles the host-side timeout/approval behavior for the source tree.
### Finding ctap.get_assertion_allow_list: GetAssertion with allow list
- Local claim: `docs/13-fido-audit-matrix.md` claims `GetAssertion` with an allow list matches stored credentials for the RP and credential ID, returns one applicable assertion after approval, and does not seed `GetNextAssertion`.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `src/ctap/parse_get_assertion.c` parses the allow-list through `zf_ctap_parse_descriptor_array()` and treats an empty array as omitted. `src/zerofido_ctap_dispatch.c` uses `zf_request_uses_allow_list()` to select `zf_store_find_by_rp_and_allow_list()`, and `src/zerofido_store.c` matches only exact RP + credential-ID hits while ignoring oversized descriptor IDs. Because `include_count = !zf_request_uses_allow_list(&request) && match_count > 1`, the allow-list path never seeds the multi-assertion queue. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_get_assertion_parse_treats_empty_allow_list_as_omitted`, `test_store_allow_list_ignores_oversized_descriptor_ids`, and `test_get_assertion_without_matching_credential_skips_approval`; those reruns keep the boundary cases current, but no successful allow-list assertion replay was rerun.
- External reference: CTAP 2.2 §6.2 `authenticatorGetAssertion`; CTAP 2.2 §6.2.2 `authenticatorGetAssertion Algorithm` for allow-list-present lookup; `docs/18-current-state-revalidation-map.md`.
- Impact: If this path drifts, direct-credential authentication breaks or starts leaking credential existence before the approval boundary.
- Revalidation / next check: Rerun `ctap_get_assertion_allow_list` and `browser_auth_allow_list` before promoting this row beyond source-backed current-state support.
### Finding ctap.get_assertion_discoverable: GetAssertion without allow list
- Local claim: `docs/13-fido-audit-matrix.md` claims `GetAssertion` without an allow list searches resident credentials only.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: When no allow list is present, `zf_resolve_assertion_matches()` in `src/zerofido_ctap_dispatch.c` calls `zf_store_find_by_rp()`, and `src/zerofido_store.c` returns only `resident_key=true` records for the RP. The discoverable path returns `ZF_CTAP_ERR_NO_CREDENTIALS` before approval if no resident match exists, uses `zf_build_silent_assertion()` when `options.up=false`, and seeds the assertion queue only when the discoverable match count is greater than one. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_get_assertion_without_matching_credential_skips_approval` and `test_get_assertion_polls_control_without_holding_ui_mutex`; these keep the negative path and control polling current, but no successful discoverable assertion replay was rerun.
- External reference: CTAP 2.2 §6.2 `authenticatorGetAssertion`; CTAP 2.2 §6.2.2 `authenticatorGetAssertion Algorithm` for resident-credential lookup when `allowList` is absent; `docs/18-current-state-revalidation-map.md` finding 6 for the still-open silent/multi-assertion replay bucket.
- Impact: If the discoverable path stops being resident-only or mis-handles the no-match boundary, RP-wide authentication either misses valid passkeys or leaks state in ways later rows will misattribute.
- Revalidation / next check: Rerun `ctap_get_assertion_discoverable`, `ctap_silent_assertion`, and `browser_auth_discoverable` before treating the broader discoverable flow as anything stronger than source-backed current-state support.
### Finding ctap.get_assertion_unsupported: GetAssertion unsupported options
- Local claim: `docs/13-fido-audit-matrix.md` claims `GetAssertion` rejects unsupported `options.rk` and built-in `options.uv=true` with unsupported-option semantics.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `src/ctap/parse_get_assertion.c` returns `ZF_CTAP_ERR_INVALID_OPTION` whenever `request.has_rk` is true. Separately, `zf_ctap_effective_uv_requested()` in `src/zerofido_ctap_dispatch.c` now causes `zf_handle_get_assertion()` to return `ZF_CTAP_ERR_UNSUPPORTED_OPTION` when `options.uv=true` is sent without `pinAuth`, matching the ClientPIN-only `GetInfo` model. `src/ctap/parse_shared.c` also now rejects duplicate allow-list descriptors with `ZF_CTAP_ERR_INVALID_PARAMETER`. Fresh local evidence in this slice is `uv run python tools/run_protocol_regressions.py`, which passed `test_get_assertion_parse_rejects_rk_option_with_invalid_option`, `test_get_assertion_parse_rejects_duplicate_allow_list_descriptors`, and `test_get_assertion_uv_without_pin_auth_returns_unsupported_option`. The host helper `host_tools/conformance_suite.py` now validates the same `UNSUPPORTED_OPTION` contract for `options.uv=true`.
- External reference: CTAP 2.2 §6.2.2 `authenticatorGetAssertion Algorithm`; CTAP 2.2 §8.2 status codes; `docs/15-milestone-10-protocol-remediation.md` Batch 2; `docs/18-current-state-revalidation-map.md`.
- Impact: If unsupported-option handling drifts, probe tooling and browser-facing diagnostics will misclassify whether the authenticator is declining a known-but-unsupported feature or rejecting malformed options more broadly.
- Revalidation / next check: Rerun `ctap_unsupported_option_uv` on attached hardware before upgrading this row beyond the current local runtime and helper proofs.
## Protocol-boundary rows
### Finding ctap.multiple_assertions: Multiple assertions
- Local claim: `docs/13-fido-audit-matrix.md` claims discoverable multi-match requests on the display-capable device now use an on-device account chooser, return only the selected assertion, omit `numberOfCredentials`, and do not seed `GetNextAssertion`, while queued follow-up assertions remain caller-bound for the non-display enumeration path.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_handle_get_assertion()` in `src/ctap/dispatch.c` now routes discoverable multi-match requests without an `allowList` through `zf_ctap_request_assertion_selection()`, returns only the selected credential, forces the chooser path count-free, and clears queue state instead of seeding `GetNextAssertion`. Fresh local evidence in this slice is `uv run python tools/run_protocol_regressions.py`, which now passes `test_get_assertion_multi_match_uses_account_selection`, `test_get_assertion_multi_match_selection_denied_returns_operation_denied`, `test_get_assertion_multi_match_selection_cancel_returns_keepalive_cancel`, `test_get_assertion_multi_match_selection_timeout_returns_operation_denied`, `test_get_assertion_allow_list_does_not_open_account_selection`, plus the existing `GetNextAssertion` queue regressions for caller binding and expiry.
- External reference: CTAP 2.2 `authenticatorGetAssertion` / `authenticatorGetNextAssertion` state-carrying rules for multiple assertions; `docs/18-current-state-revalidation-map.md` findings 3 and 6.
- Impact: The current tree now aligns its display-capable multi-match behavior with the CTAP chooser model while preserving the existing caller-bound queue safety rules for any remaining queued follow-up paths.
- Revalidation / next check: Rerun the live HID/browser scenarios for resident multi-match selection and confirm the updated chooser path in certification tooling before retiring the remaining historical references in `docs/18-current-state-revalidation-map.md` finding 6.

### Finding ctap.account_chooser: On-device account chooser
- Local claim: `docs/13-fido-audit-matrix.md` claims an on-device account chooser is implemented for discoverable multi-match `GetAssertion`.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `src/ui/views.c` now allocates a dedicated `ZfViewAssertionSelection` submenu, formats chooser entries from resident credential metadata, and treats submenu selection as the terminal user action. `src/ui/approval_state.c` carries the generic interaction wait/cancel/timeout state used by both binary approval and account selection, and `src/ctap/dispatch.c` consumes the selected credential ID to build a single count-free assertion without seeding queued follow-ups. Fresh local evidence is the chooser regression coverage in `tests/native_protocol_regressions.c`.
- External reference: CTAP 2.2 display-capable multi-match behavior for `authenticatorGetAssertion`.
- Impact: If this chooser regresses, certification and browser tooling will correctly flag resident multi-match assertions as non-conformant for a display-capable authenticator.
- Revalidation / next check: Keep this row open to live-device regression coverage so future UI refactors preserve chooser success, deny, cancel, and timeout semantics.

### Finding clientpin.empty_pin_auth_probe: Empty pinAuth compatibility probe
- Local claim: `docs/13-fido-audit-matrix.md` claims a zero-length `pinAuth` is treated as a touch-required compatibility probe and returns `PIN_INVALID` when a PIN is set or `PIN_NOT_SET` otherwise.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_ctap_validate_pin_auth_protocol()` in `src/zerofido_ctap_dispatch.c` requires `pinProtocol` before either command accepts a `pinAuth` field, and `zf_handle_empty_pin_auth_probe()` then routes zero-length `pinAuth` through the approval flow before returning `ZF_CTAP_ERR_PIN_INVALID` or `ZF_CTAP_ERR_PIN_NOT_SET` based on `zerofido_pin_is_set()`. Fresh local evidence in this slice is `uv run python tools/run_protocol_regressions.py`, which passed `test_make_credential_empty_pin_auth_requires_pin_protocol`, `test_get_assertion_empty_pin_auth_requires_pin_protocol`, `test_make_credential_empty_pin_auth_probe_returns_pin_status_after_touch`, and `test_get_assertion_empty_pin_auth_probe_returns_pin_status_after_touch`. No attached-device empty-`pinAuth` scenario was rerun.
- External reference: CTAP 2.2 §6.5.5.7.1 `Getting pinUvAuthToken using getPinToken (superseded)`, including the backwards-compatibility note for zero-length `pinUvAuthParam` on later `authenticatorMakeCredential` / `authenticatorGetAssertion` requests; `docs/18-current-state-revalidation-map.md`.
- Impact: This compatibility probe affects authenticator selection and PIN prompting when multiple authenticators are attached. If it drifts, platforms can consume the wrong user-presence signal or mis-handle PIN state discovery.
- Revalidation / next check: Rerun `ctap_empty_pin_auth_make_credential` and `ctap_empty_pin_auth_get_assertion` on attached hardware if a later slice needs live touch/transport proof; the current local regressions already settle the tree’s command-level semantics.

### Finding attestation.none: attestation: none outcome
- Local claim: `docs/13-fido-audit-matrix.md` claims `attestation: none` is treated as RP/browser anonymization rather than as a second authenticator attestation format.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `zf_ctap_build_make_credential_response()` in `src/ctap/response.c` always emits a `packed` attestation statement with the attested credential data and the leaf certificate returned by `zf_attestation_get_cert_chain()`, so the authenticator itself does not switch to a second attestation format when a relying party asks for `none`. `docs/11-attestation.md` and `docs/12-metadata.md` both bound the current behavior to shared software-model identity and explicitly note that browsers or relying parties may anonymize provider identity and AAGUID when `attestation: "none"` is requested. The helper boundary in `host_tools/conformance_suite.py` keeps the live browser proof honest by requiring `browser_register_none` to return `fmt == "none"` with no `x5c`, and `tests/test_conformance_suite.py` now locks that helper expectation without claiming the browser scenario was rerun in this slice.
- External reference: CTAP 2.0 / CTAP 2.2 `authenticatorMakeCredential` attestation semantics; `docs/11-attestation.md`; `docs/12-metadata.md`; `docs/18-current-state-revalidation-map.md` finding 10.
- Impact: Treating `attestation: none` as a second authenticator format would blur the boundary between what ZeroFIDO emits locally and what browsers or relying parties redact later, which would overstate the current attestation surface.
- Revalidation / next check: Rerun the live `browser_register_none` scenario before claiming fresh browser proof; until then this row stays source-backed and bounded by `docs/18-current-state-revalidation-map.md` instead of inheriting a browser pass by memory.

### Finding attestation.enterprise: Enterprise attestation
- Local claim: `docs/13-fido-audit-matrix.md` claims enterprise attestation is not claimed or implemented in the current product.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `zf_ctap_build_get_info_response()` in `src/ctap/response.c` advertises only `rk`, `up`, `plat`, and runtime `clientPin` state in the options map and does not expose the `ep` / enterprise-attestation option, while `zf_ctap_build_make_credential_response()` has a single `packed` attestation path with no enterprise-specific branching, certificates, or policy surface. `docs/11-attestation.md`, `docs/12-metadata.md`, and `docs/13-fido-audit-matrix.md` all scope attestation to shared software-model identity rather than enterprise enrollment, and `host_tools/conformance_suite.py` plus `tests/test_conformance_suite.py` fail closed if `GetInfo` ever starts advertising unsupported `ep` semantics.
- External reference: CTAP 2.2 `authenticatorGetInfo` options map and attestation-surface rules; `docs/11-attestation.md`; `docs/12-metadata.md`; `docs/18-current-state-revalidation-map.md` finding 10.
- Impact: Over-claiming enterprise attestation would mislead relying parties and later release work into expecting enterprise policy signals or trust material that ZeroFIDO does not actually expose.
- Revalidation / next check: Keep this row closed unless a later slice intentionally adds enterprise attestation; if that happens, update `GetInfo`, attestation docs, and live browser/device registration checks before changing the verdict, and keep `docs/18-current-state-revalidation-map.md` as the conservative attestation bucket baseline.

## Auxiliary protocol checkpoints
### Checkpoint aux.proof-taxonomy-boundary: Proof-label boundary
- Local claim: S02 findings may only use the proof labels and verdict vocabulary approved for the current-state audit.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `docs/17-current-state-proof-taxonomy.md` defines the allowed proof labels, verdicts, and reusable finding shape, and `tools/verify_protocol_conformance_audit.py` rejects unsupported labels or missing required fields.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, later tasks could silently weaken the proof bar and turn a structural scaffold into an unsupported pass.
- Revalidation / next check: Keep this checkpoint aligned with `docs/17-current-state-proof-taxonomy.md` and extend the verifier if the approved finding shape changes in a later milestone.

### Checkpoint aux.revalidation-map-linkage: Historical-bucket linkage
- Local claim: S02 judgments must reconcile against the current historical revalidation buckets instead of inheriting old “fixed” language by memory.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `docs/18-current-state-revalidation-map.md` names the current owner files, fresh re-check commands, and conservative buckets for the historical protocol findings that can still influence S02 row judgments.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`; `docs/10-release-criteria.md`.
- Impact: Without an explicit bucket linkage, later row findings can drift away from the already-tracked historical uncertainty and overstate current proof.
- Revalidation / next check: Each later S02 task should keep the affected row findings explicitly reconciled with `docs/18-current-state-revalidation-map.md` instead of treating remediation notes as automatic closure.

### Checkpoint aux.live-proof-boundary: Browser and hardware proof boundary
- Local claim: Browser, HID-wire, and attached-hardware claims remain open until this slice reruns the matching live or local replay surface.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: The T01 scaffold intentionally keeps rows at `needs-revalidation`, and the slice verifier/test pair reject empty evidence while preserving room for later `test-proven`, `live-risk hypothesis`, or `not proven without hardware` judgments.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, source-backed scaffolding could be mistaken for live browser/device proof and leak false confidence into release or security work.
- Revalidation / next check: Only upgrade a row beyond this boundary when the named command or live capture was rerun in the current slice and cited directly in the row finding.

## End-of-doc summary
- Supported current-state rows: `ctap.account_chooser`, `attestation.none`, and `attestation.enterprise` are now closed as source-backed boundary findings: ZeroFIDO intentionally uses queued follow-up assertions instead of an on-device chooser, `attestation: none` remains an RP/browser anonymization outcome rather than a second authenticator format, and enterprise attestation is neither advertised nor implemented.
- Rows that still stop at local/source proof: `ctap.multiple_assertions` now has fresh local queue-state regressions for wrong-CID rejection, empty/expired queue handling, final-queue clearing, and expiry refresh, but `docs/18-current-state-revalidation-map.md` finding 6 still keeps the full silent/browser replay in a later slice.
- Open browser/hardware gaps: this slice did not rerun `ctap_get_next_assertion`, `browser_register_none`, or any enterprise/browser ceremony on attached hardware, so live HID/browser proof remains open even though the current source and local tests bound the product surface.
- Current audit failures still open: none.

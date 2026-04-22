# Current-state security and state semantics
This ledger is the tracked S03 findings surface for the current security-critical state, ownership, persistence, and trust-boundary behavior.
It is written for later audit authors who need one place to record row-by-row judgments without silently upgrading source review into browser, hardware, or power-failure proof.
After reading it, a later slice author should be able to pick an S03-owned row or checkpoint, replace the scaffold evidence with current code/test/spec anchors, and keep live/browser/hardware gaps explicit instead of flattening them into a pass.

## Reader contract
- T01 locks the S03-owned manifest and identity rows plus the auxiliary checkpoints that keep queue ownership, persistence semantics, S02 handoff consumption, and trust-boundary wording explicit.
- Every finding uses the `docs/17-current-state-proof-taxonomy.md` shape so later tasks cannot invent weaker proof labels or omit impact/revalidation fields.
- The initial T01 verdicts stay `needs-revalidation` on purpose: this file is structurally valid now, but later S03 tasks must replace scaffold evidence with row-specific code/test/spec anchors before the slice can be closed.
- `docs/18-current-state-revalidation-map.md` remains mandatory context wherever historical security/state lineage exists; historical remediation notes are inputs, not automatic closure.
- Do not claim fresh browser, HID-wire, reboot, or attached-hardware proof in this ledger unless the matching command or capture was rerun in this slice and cited directly in the finding.

## Queue and approval ownership rows
### Finding transport.cancel: CTAPHID_CANCEL
- Local claim: T01 freezes `CTAPHID_CANCEL` as an S03-owned security/state row keyed to `transport.cancel` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep cancellation, caller ownership, and approval-bound control semantics from being judged by memory or prose alone.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `transport.cancel`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding ctap.make_credential_rk: MakeCredential with rk=true
- Local claim: T01 freezes `MakeCredential with rk=true` as an S03-owned security/state row keyed to `ctap.make_credential_rk` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep resident-registration state ownership and approval semantics on the audit surface.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `ctap.make_credential_rk`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding ctap.make_credential_nonresident: MakeCredential with rk=false or absent
- Local claim: T01 freezes `MakeCredential with rk=false or absent` as an S03-owned security/state row keyed to `ctap.make_credential_nonresident` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep non-resident credential state and persistence semantics explicit for later queue and counter work.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `ctap.make_credential_nonresident`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding ctap.exclude_list: excludeList hit
- Local claim: T01 freezes `excludeList hit` as an S03-owned security/state row keyed to `ctap.exclude_list` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep approval-before-exclusion and duplicate-state handling visible as a security boundary.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `ctap.exclude_list`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding ctap.get_assertion_allow_list: GetAssertion with allow list
- Local claim: T01 freezes `GetAssertion with allow list` as an S03-owned security/state row keyed to `ctap.get_assertion_allow_list` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep allow-list ownership, approval, and assertion-state semantics explicit for later counter and queue work.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `ctap.get_assertion_allow_list`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding ctap.get_assertion_discoverable: GetAssertion without allow list
- Local claim: T01 freezes `GetAssertion without allow list` as an S03-owned security/state row keyed to `ctap.get_assertion_discoverable` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep discoverable assertion ownership, approval, and follow-up-state semantics visible to the audit.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `ctap.get_assertion_discoverable`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding ctap.multiple_assertions: Multiple assertions
- Local claim: T01 freezes `Multiple assertions` as an S03-owned security/state row keyed to `ctap.multiple_assertions` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep caller-bound queue ownership, expiry, and follow-up semantics from being inherited uncritically from S02 prose.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `ctap.multiple_assertions`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage exists, and rerun the relevant local/browser/hardware checks before changing the verdict.

## ClientPIN and UV rows
### Finding clientpin.get_retries: getRetries
- Local claim: `docs/16-current-state-claim-inventory.md` treats `clientpin.get_retries` as the current retry-observation surface: `getRetries` should report the retry counter currently loaded into `ZfClientPinState` without minting new auth state, rotating secrets, or hiding persisted lockout state.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: `zerofido_pin_init()` in `src/pin/flow.c` seeds `state->pin_retries` from the sealed PIN file when present and otherwise defaults to `ZF_PIN_RETRIES_MAX`; `zerofido_pin_get_retries()` in `src/pin/flow.c` and `zf_pin_response_retries()` in `src/pin/command.c` then expose that counter without mutating `pin_token`, `pin_auth_blocked`, or `key_agreement`. Historical finding 12 in `docs/18-current-state-revalidation-map.md` is now re-proven by rerun native regressions for persistence and recovery, but this slice did not rerun a direct live `getRetries` fixture probe.
- External reference: `docs/17-current-state-proof-taxonomy.md`; historical finding 12 in `docs/18-current-state-revalidation-map.md`.
- Impact: Later slices can treat `getRetries` as an observational view of already-owned retry state, not as a recovery primitive or a stronger proof surface than the persisted state machinery beneath it.
- Revalidation / next check: If a later slice needs device-level proof, rerun the fixture-gated `clientpin_get_retries` scenario in `host_tools/conformance_suite.py`; until then, keep claims scoped to the current source tree and the persisted-state regressions that feed this counter.

### Finding clientpin.get_key_agreement: getKeyAgreement
- Local claim: `clientpin.get_key_agreement` is the boundary for returning the current COSE P-256 key-agreement public key; on the current tree it must not rotate the runtime `pin_token`, clear retry state, or silently re-key on every read.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zerofido_pin_handle_command()` routes `ZF_CLIENT_PIN_SUBCMD_GET_KEY_AGREEMENT` straight to `zf_pin_response_key_agreement()` in `src/pin/command.c`, which serializes `state->key_agreement` and does not touch `state->pin_token`, retry counters, or auth-block flags. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_get_key_agreement_does_not_rotate_runtime_secrets`, `test_client_pin_key_agreement_requires_alg`, and `test_get_pin_token_success_rotates_pin_token`; together those reruns close historical finding 9 in `docs/18-current-state-revalidation-map.md` without upgrading the row to live attached-device proof.
- External reference: `docs/17-current-state-proof-taxonomy.md`; historical finding 9 in `docs/18-current-state-revalidation-map.md`.
- Impact: Later ClientPIN work must not assume `getKeyAgreement` is itself a retry-reset, token-rotation, or per-call rekey boundary; only the explicitly mutating PIN paths should be treated that way.
- Revalidation / next check: A later slice may still rerun the fixture-gated `clientpin_get_key_agreement` scenario for transport-level proof, but the historical `pin_token`-rotation defect is already retired by the current native regression coverage.

### Finding clientpin.set_pin: setPin
- Local claim: `clientpin.set_pin` should accept only a correctly authenticated 64-byte encrypted PIN block, reject malformed plaintext padding and decrypt/HMAC failures, and persist the new PIN state before installing fresh runtime secrets.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_pin_handle_set_pin()` in `src/pin/command.c` requires `keyAgreement`, `newPinEnc`, and `pinAuth`, enforces `new_pin_enc_len == 64`, authenticates the ciphertext with `zf_pin_hmac_matches()`, decrypts with `zf_crypto_aes256_cbc_zero_iv_decrypt()`, rejects garbage after the first NUL via `zf_pin_validate_plaintext_block()` from `src/pin/flow.c`, and then calls `zf_pin_apply_plaintext(..., require_unset=true)` in `src/pin/flow.c`. `zf_pin_apply_plaintext()` hashes the new PIN, resets retries to `ZF_PIN_RETRIES_MAX`, clears auth-block state, persists first, and only then installs a fresh runtime `pin_token` and key-agreement key. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_set_pin_invalid_new_pin_block_is_rejected` and `test_set_pin_new_pin_decrypt_failure_returns_pin_auth_invalid`; those reruns, together with the shared plaintext-block helper, now retire the `setPin` half of historical finding 13 in `docs/18-current-state-revalidation-map.md`.
- External reference: `docs/17-current-state-proof-taxonomy.md`; historical finding 13 in `docs/18-current-state-revalidation-map.md`.
- Impact: The current tree fail-closes malformed `newPinEnc` content and only commits a new PIN after durable state update, so later audit rows should not treat setup as an in-memory-only or padding-tolerant path.
- Revalidation / next check: If a later slice needs browser or device transport proof, rerun the fixture-gated `clientpin_set_pin` path; for M001, keep claims scoped to the current source and rerun native malformed-input coverage.

### Finding clientpin.change_pin: changePin
- Local claim: `clientpin.change_pin` must authenticate both `newPinEnc` and `pinHashEnc`, consume retries on wrong-current-PIN or decrypt failure, and reject malformed new PIN padding even after the current PIN has been verified.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_pin_handle_change_pin()` in `src/pin/command.c` requires `keyAgreement`, `newPinEnc`, `pinHashEnc`, and `pinAuth`, verifies a joined HMAC across both encrypted fields, routes `pinHashEnc` decrypt failures through `zf_pin_auth_failure()` in `src/pin/flow.c`, calls `zf_pin_verify_hash()` in `src/pin/flow.c` for the current PIN, and only then decrypts and validates `newPinEnc` with `zf_pin_validate_plaintext_block()` in `src/pin/flow.c`. Because `zf_pin_verify_hash()` flows through `zf_pin_auth_success()` in `src/pin/flow.c`, a correct current PIN resets retries before malformed new-PIN padding is rejected. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_change_pin_invalid_new_pin_after_correct_current_pin_resets_retries`, `test_change_pin_pin_hash_decrypt_failure_consumes_retry`, and `test_change_pin_new_pin_decrypt_failure_returns_pin_auth_invalid`; these reruns close the `changePin` half of historical finding 13 in `docs/18-current-state-revalidation-map.md`.
- External reference: `docs/17-current-state-proof-taxonomy.md`; historical finding 13 in `docs/18-current-state-revalidation-map.md`.
- Impact: Later slices can rely on the current tree consuming retries on bad current-PIN material while still fail-closing malformed replacement PIN blocks after a successful verification step.
- Revalidation / next check: A later attached-device replay would strengthen transport confidence, but the malformed-padding and retry-decrement semantics are already locally re-proven on the current tree.

### Finding clientpin.get_pin_token: PIN token issuance
- Local claim: `clientpin.get_pin_token` is the current PIN token-issuance boundary: legacy `getPinToken` should reject unsupported permissions-bearing fields while minimal `0x09` issuance should enforce `mc` / `ga` permission scoping, RP-ID binding, and post-UP permission consumption.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_pin_handle_get_pin_token()` in `src/pin/command.c` now handles both legacy `0x05` and minimal permission-scoped `0x09`: the legacy path rejects `permissions` / `rpId` and grants default `mc|ga`, while the `0x09` path requires `permissions`, requires `rpId` for `mc` / `ga`, and persists the requested permission bits plus permissions RP ID into `ZfClientPinState`. `zerofido_pin_require_auth()` in `src/pin/flow.c` enforces those permission bits, binds the RP ID on first use for default legacy tokens, and rejects mismatched RP IDs; `zf_ctap_consume_pin_token_after_up()` in `src/zerofido_ctap_dispatch.c` clears `mc` / `ga` permissions after successful UP-tested `MakeCredential` / `GetAssertion` operations. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_get_pin_token_success_rotates_pin_token`, `test_client_pin_permissions_subcommand_stores_permissions_and_rp_id`, `test_legacy_pin_token_binds_rp_id_on_first_use_and_rejects_rp_mismatch`, `test_pin_auth_rejects_missing_required_permission`, `test_make_credential_pin_auth_consumes_token_permissions_after_up`, and `test_get_assertion_pin_auth_consumes_token_permissions_after_up`; fixture-gated live browser/device token scenarios were not rerun.
- External reference: CTAP 2.1 errata §6.5.2.1 `pinUvAuthToken` state and §6.5.5.7 token retrieval semantics; `docs/17-current-state-proof-taxonomy.md`; historical findings 9, 11, and 12 in `docs/18-current-state-revalidation-map.md`.
- Impact: Later audit work should treat PIN token issuance as a scoped feature: legacy default-permissions issuance plus minimal permission-scoped `mc` / `ga` issuance. It is no longer accurate to describe the tree as legacy-only, but it is still inaccurate to claim broader 2.1 permission coverage.
- Revalidation / next check: Keep live/browser claims conservative until a later slice reruns the attached-device `clientpin_get_pin_token` scenario; the current local reruns already settle the runtime token and retry semantics.

### Finding clientpin.empty_pin_auth_probe: Empty pinAuth compatibility probe
- Local claim: A zero-length `pinAuth` on `authenticatorMakeCredential` or `authenticatorGetAssertion` remains a compatibility probe: the request still requires `pinProtocol`, routes through touch approval, and returns `PIN_INVALID` when a PIN is set or `PIN_NOT_SET` otherwise.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_ctap_validate_pin_auth_protocol()` in `src/zerofido_ctap_dispatch.c` requires `pinProtocol` before either CTAP command accepts a `pinAuth` field, and `zf_handle_empty_pin_auth_probe()` then runs the approval flow before checking `zerofido_pin_is_set()` and returning `ZF_CTAP_ERR_PIN_INVALID` or `ZF_CTAP_ERR_PIN_NOT_SET`. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_make_credential_empty_pin_auth_requires_pin_protocol`, `test_get_assertion_empty_pin_auth_requires_pin_protocol`, `test_make_credential_empty_pin_auth_probe_returns_pin_status_after_touch`, and `test_get_assertion_empty_pin_auth_probe_returns_pin_status_after_touch`. No attached-device empty-`pinAuth` scenario was rerun.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/19-current-state-protocol-conformance.md` empty-`pinAuth` compatibility finding.
- Impact: This compatibility branch stays explicit and bounded: it is a touch-gated PIN-status probe, not a built-in-UV path and not proof of broader browser interoperability.
- Revalidation / next check: If a later slice needs live transport proof, rerun the fixture-gated empty-`pinAuth` scenarios in `host_tools/conformance_suite.py`; for now the local CTAP regressions settle the current command-level behavior.

### Finding clientpin.pin_uv_auth_param: pinUvAuthParam verification
- Local claim: `clientpin.pin_uv_auth_param` is currently the software-only HMAC gate over `clientDataHash`: it requires a 16-byte `pinAuth`, `pinProtocol=1`, an active non-expired token, and it persists auth-block state on mismatch while setting `uv_verified` only on successful verification.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zerofido_pin_require_auth()` in `src/pin/flow.c` rejects wrong `pin_auth_len`, missing or wrong `pinProtocol`, inactive tokens, and expired tokens before computing `HMAC-SHA-256(pin_token, client_data_hash)` and constant-time comparing the first 16 bytes. Mismatches flow through `zf_pin_note_pin_auth_mismatch()` and persist auth-block state; successful verification clears persisted mismatch/auth-block state and sets `*uv_verified = true`. `zf_handle_make_credential()` and `zf_handle_get_assertion()` in `src/zerofido_ctap_dispatch.c` thread the request’s `clientDataHash`, `pinAuth`, and `pinProtocol` directly into `zerofido_pin_require_auth()`. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_make_credential_pin_auth_takes_precedence_over_uv`, `test_get_assertion_pin_auth_takes_precedence_over_uv`, `test_pin_auth_blocks_after_three_mismatches`, `test_pin_auth_rejects_expired_pin_token`, and `test_correct_pin_auth_keeps_retry_state_when_persist_fails`; fixture-gated live `pinUvAuthParam` scenarios in `host_tools/conformance_suite.py` were not rerun.
- External reference: `docs/17-current-state-proof-taxonomy.md`; historical finding 12 in `docs/18-current-state-revalidation-map.md`.
- Impact: Later slices can rely on the current tree’s HMAC and persistence semantics without overstating them as live browser/device interoperability proof.
- Revalidation / next check: Keep browser-attached claims conservative until a later slice reruns `clientpin_make_credential_with_pin_auth` and `clientpin_get_assertion_with_pin_auth` from `host_tools/conformance_suite.py`.

### Finding clientpin.uv_state: UV state
- Local claim: ZeroFIDO still has no built-in UV; the only current UV state is the transient `uv_verified` bit that CTAP handlers derive from successful `pinUvAuthParam` validation and then thread into response construction.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_ctap_effective_uv_requested()` in `src/zerofido_ctap_dispatch.c` rejects `options.uv=true` without `pinAuth` with `ZF_CTAP_ERR_UNSUPPORTED_OPTION`, matching the no-built-in-UV boundary. When `pinAuth` is present, `zerofido_pin_require_auth()` is the only path that can set `uv_verified`, and the handlers pass that bit into the response builders instead of reading any device-local biometric state. Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_make_credential_uv_without_pin_auth_returns_unsupported_option`, `test_get_assertion_uv_without_pin_auth_returns_unsupported_option`, `test_make_credential_pin_auth_takes_precedence_over_uv`, `test_get_assertion_pin_auth_takes_precedence_over_uv`, and `test_assertion_response_user_fields_follow_uv`. The live `host_tools/conformance_suite.py` checks that inspect returned UV bits were not rerun.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/12-metadata.md` (“ZeroFIDO does not implement built-in UV”).
- Impact: Later slices must keep UV wording bounded to software ClientPIN-derived request state and must not let docs or metadata imply a built-in authenticator UV capability that the runtime does not implement.
- Revalidation / next check: If a later slice needs live proof that the UV bit survives full browser/device exchange, rerun the fixture-gated `pinUvAuthParam` scenarios; until then, keep claims at current-tree CTAP semantics only.

### Finding clientpin.retry_lockout: Retry/lockout persistence
- Local claim: The current tree persists retry and `PIN_AUTH_BLOCKED` state across restarts, fails closed in memory when persistence degrades, and deliberately clears the persisted auth-block only through an explicit local unblock ceremony rather than pretending to model a hidden retained power-cycle primitive.
- Verdict: `supported-current-state`
- Proof label: `test-proven`
- Current code/test evidence: `zf_pin_auth_failure()` and `zf_pin_note_pin_auth_mismatch()` in `src/pin/flow.c` decrement retries or advance `pin_consecutive_mismatches`, set `pin_auth_blocked` after the third mismatch, and preserve the stricter in-memory state even when `zf_pin_state_store_persist()` fails. `zerofido_pin_init()` in `src/pin/flow.c` reloads that sealed state on restart, while `zerofido_pin_resume_auth_attempts()` documents the deliberate tradeoff verbatim: “ZeroFIDO therefore persists PIN_AUTH_BLOCKED and clears it only through this explicit local unblock ceremony instead of depending on fragile hidden firmware state.” Fresh local reruns in this slice were `uv run python tools/run_protocol_regressions.py`, which passed `test_pin_auth_block_state_persists_via_pin_file`, `test_pin_resume_auth_attempts_clears_persisted_block`, `test_pin_auth_blocks_after_three_mismatches`, `test_pin_auth_mismatch_keeps_block_state_when_persist_fails`, `test_wrong_pin_keeps_retry_state_when_persist_fails`, `test_pin_persist_failure_poison_blocks_reinit_after_wrong_pin`, `test_pin_persist_failure_poison_blocks_reinit_after_pin_auth_mismatch`, and `test_correct_pin_auth_keeps_retry_state_when_persist_fails`. Historical finding 12 in `docs/18-current-state-revalidation-map.md` is therefore re-proven, and the intentional local-recovery boundary remains explicit rather than flattened into “fixed”.
- External reference: `docs/17-current-state-proof-taxonomy.md`; historical finding 12 in `docs/18-current-state-revalidation-map.md`.
- Impact: Relying parties and later slices must treat auth-block clearing as an app-local recovery ceremony with a documented trust tradeoff, not as literal CTAP retained-power-session semantics.
- Revalidation / next check: Browser or device proof is still open for any claim that depends on physical power-cycle behavior; for the current tree, the local persistence and fail-closed semantics are directly rerun and settled.

## Counters and persistence checkpoints
### Checkpoint aux.ctap-sign-count-ordering: CTAP sign-count persistence ordering
- Local claim: S03 must judge whether the CTAP assertion sign-count path only claims what current persistence ordering actually proves.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace the scaffold with row-specific code and regression anchors before any stronger claim is made.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, later tasks could overlook response-before-persist ordering and accidentally over-claim counter integrity.
- Revalidation / next check: T04 must replace this scaffold with the exact CTAP sign-count ordering path, the local evidence that was rerun, and the conservative next step if stronger durability proof is still missing.

### Checkpoint aux.credential-store-recovery: Credential-store seal and temp/backup recovery
- Local claim: S03 must judge whether credential-store sealing, `.tmp` / `.bak` recovery, and fail-closed cleanup are still proven only by current-tree evidence or by fresh reruns.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace the scaffold with row-specific code and regression anchors before any stronger claim is made.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, persistence and recovery drift could disappear behind high-level storage prose instead of staying tied to explicit failure-mode evidence.
- Revalidation / next check: T04 must replace this scaffold with the exact recovery paths, seal checks, and rerun evidence used to justify the final persistence judgment.

### Checkpoint aux.u2f-counter-durability: U2F counter durability gap
- Local claim: S03 must keep the historical U2F counter durability gap explicit until fresh local or hardware proof actually retires part of it.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace the scaffold with row-specific code and regression anchors before any stronger claim is made.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, later slices could accidentally convert source review into a false durability pass for the historical U2F counter issue.
- Revalidation / next check: T04 must replace this scaffold with the exact U2F counter path, the rerun evidence that exists, and the still-open torn-write or reboot proof gap if it remains.

## Attestation and metadata trust-boundary rows
### Finding attestation.format: Attestation format
- Local claim: T01 freezes `Attestation format` as an S03-owned security/state row keyed to `attestation.format` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep software-attestation trust boundaries explicit instead of letting documentation or browser behavior imply stronger proof than the tree carries.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `attestation.format`, preserve the attestation-historical linkage in `docs/18-current-state-revalidation-map.md`, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding attestation.aaguid: AAGUID
- Local claim: T01 freezes `AAGUID` as an S03-owned security/state row keyed to `attestation.aaguid` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep runtime/document/metadata identity alignment visible as a trust-boundary question.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `attestation.aaguid`, preserve the attestation-historical linkage in `docs/18-current-state-revalidation-map.md`, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding metadata.clientpin: Metadata clientPin
- Local claim: T01 freezes `Metadata clientPin` as an S03-owned security/state row keyed to `metadata.clientpin` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep the static-metadata versus dynamic-`clientPin` boundary explicit instead of letting metadata wording imply live runtime state.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `metadata.clientpin`, preserve the historical linkage in `docs/18-current-state-revalidation-map.md`, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding identity.aaguid: ZeroFIDO AAGUID
- Local claim: T01 freezes `ZeroFIDO AAGUID` as an S03-owned security/state row keyed to `identity.aaguid` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays required for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep cross-document identity alignment explicit for later truthfulness and trust-boundary work.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `identity.aaguid`, preserve the historical linkage in `docs/18-current-state-revalidation-map.md`, and rerun the relevant local/browser/hardware checks before changing the verdict.

### Finding identity.attestation_subjects: Public attestation subject names
- Local claim: T01 freezes `Public attestation subject names` as an S03-owned security/state row keyed to `identity.attestation_subjects` in `docs/16-current-state-claim-inventory.md`; later tasks must replace this scaffold text with the precise audited claim under review.
- Verdict: `needs-revalidation`
- Proof label: `source-proven`
- Current code/test evidence: T01 scaffolds this row with inventory-derived ownership only: `docs/16-current-state-claim-inventory.md` assigns the row to S03, and later tasks must replace this placeholder with row-specific code paths, rerun commands, or both before any stronger verdict is allowed.
- External reference: `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md` historical linkage stays in scope for this scaffold row until later tasks replace the placeholder with row-specific citations.
- Impact: Until later S03 tasks add row-specific evidence, this row exists only to keep public attestation identity wording explicit instead of allowing stronger hardware or exclusivity implications to slip in.
- Revalidation / next check: Replace this scaffold with current code/test/spec anchors for `identity.attestation_subjects`, keep `docs/18-current-state-revalidation-map.md` linkage where historical lineage matters, and rerun the relevant local/browser/hardware checks before changing the verdict.

## Auxiliary security/state checkpoints
### Checkpoint aux.proof-taxonomy-boundary: Proof-label boundary
- Local claim: S03 findings may only use the proof labels and verdict vocabulary approved for the current-state audit.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace any scaffold wording with row-specific evidence without changing the approved finding shape.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, later tasks could silently weaken the proof bar and turn a security/state audit into prose-only notes.
- Revalidation / next check: Keep this checkpoint aligned with `docs/17-current-state-proof-taxonomy.md` and extend the verifier if the approved finding shape changes in a later milestone.

### Checkpoint aux.revalidation-map-linkage: Historical-bucket linkage
- Local claim: S03 judgments must reconcile against the current historical revalidation buckets instead of inheriting old “fixed” language by memory.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace scaffold text with the exact historical buckets and row-specific evidence they consume.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without an explicit linkage checkpoint, later row findings can drift away from already-tracked historical uncertainty and overstate current proof.
- Revalidation / next check: Each later S03 task should keep affected findings explicitly reconciled with `docs/18-current-state-revalidation-map.md` instead of treating remediation notes as automatic closure.

### Checkpoint aux.s02-handoff-boundary: S02 handoff consumption boundary
- Local claim: S03 consumes S02 queue and attestation boundary findings as inputs, but does not silently reclassify them as stronger proof without fresh S03 evidence.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace scaffold wording with the exact S02 findings and current evidence they consume.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, later S03 findings could inherit stale protocol confidence instead of restating what current security/state evidence actually proves.
- Revalidation / next check: Later tasks should cite the exact S02 findings they consume, keep the proof label conservative, and rerun any new local checks before changing a verdict.

### Checkpoint aux.live-proof-boundary: Browser and hardware proof boundary
- Local claim: Browser, HID-wire, reboot, and attached-hardware claims remain open until this slice reruns the matching live or local replay surface.
- Verdict: `supported-current-state`
- Proof label: `source-proven`
- Current code/test evidence: T01 freezes this as a required audit checkpoint only; later tasks must replace scaffold wording with the exact commands and captures they reran before claiming stronger proof.
- External reference: `docs/10-release-criteria.md`; `docs/17-current-state-proof-taxonomy.md`; `docs/18-current-state-revalidation-map.md`.
- Impact: Without this checkpoint, source-backed scaffolding could be mistaken for live browser/device proof and leak false confidence into release or security work.
- Revalidation / next check: Only upgrade a row beyond this boundary when the named command or live capture was rerun in the current slice and cited directly in the finding.

## End-of-doc summary
- Rows currently settled by current evidence: The nine ClientPIN / UV rows now carry row-specific findings instead of scaffolds. `clientpin.get_key_agreement`, `clientpin.set_pin`, `clientpin.change_pin`, `clientpin.get_pin_token`, `clientpin.empty_pin_auth_probe`, `clientpin.pin_uv_auth_param`, `clientpin.uv_state`, and `clientpin.retry_lockout` are settled by the current source plus fresh local reruns in this slice, while `clientpin.get_retries` is settled conservatively at the source-backed reporting boundary.
- Rows that still stop at source/local proof: Queue ownership, counter durability, attestation, metadata, and identity rows remain outside this task’s rerun scope, and even the settled ClientPIN rows do not claim more than current-tree or local-regression proof. `clientpin.get_retries` still stops at a source-backed boundary because no direct live `getRetries` probe was rerun here.
- Historical revalidation anchors still open: `docs/18-current-state-revalidation-map.md` findings 9, 12, and 13 are now reconciled directly in the ClientPIN section; queue-state, attestation, metadata, and U2F durability buckets remain mandatory context for later S03 tasks.
- Open browser/hardware gaps: This task did not rerun attached-device or browser scenarios for `clientpin_get_retries`, `clientpin_get_key_agreement`, `clientpin_get_pin_token`, or the fixture-gated `pinUvAuthParam` conformance flows, so those transport/browser proofs remain explicitly open even where local regressions now settle the current runtime semantics.

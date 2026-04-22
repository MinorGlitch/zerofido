# Milestone 10: Protocol Remediation Sweep

## Progress

- [x] Batch 1: CTAP MakeCredential and GetInfo correctness
- [x] Verify Batch 1: `tidy` and `cppcheck`
- [x] Batch 2: GetAssertion and GetNextAssertion correctness
- [-] Verify Batch 2: `run_protocol_regressions.py`, `tests/test_ctaphid_probe.py`, `tidy`, `cppcheck`, and `ufbt` passed; live CTAP host probes remain deferred until hardware is attached
- [x] Batch 3: ClientPIN semantics
- [-] Verify Batch 3: native regression coverage for trailing CBOR rejection, COSE key-agreement validation, temporary `PIN_AUTH_BLOCKED`, and wrong-PIN key-agreement regeneration passed locally; live ClientPIN host probes remain deferred until hardware is attached
- [x] Batch 4: CTAPHID transport correctness
- [-] Verify Batch 4: `run_protocol_regressions.py`, `tests/test_ctaphid_probe.py`, `tidy`, `cppcheck`, and `ufbt` passed; live transport host probes remain deferred until hardware is attached
- [x] Batch 5: U2F durability and APDU correctness
- [-] Verify Batch 5: static checks plus `ufbt` passed, including runtime certificate/private-key coherence validation; live U2F fault-oriented probes remain deferred until hardware is attached
- [x] Documentation sync
- [-] Final acceptance

## Objective

Clear the still-valid CTAP, ClientPIN, transport, and U2F correctness findings from the current
source tree, then bring the docs back into sync with what the code actually implements.

## Exact Implementation Scope

### Batch 1: CTAP MakeCredential and GetInfo correctness

- Require `pinAuth` for `MakeCredential` when `clientPin` is set under the currently supported
  product model.
- Reject unsupported built-in UV semantics instead of silently treating `options.uv = true` as
  ClientPIN.
- Fix `GetInfo` so `uv`, `clientPin`, and related options describe a ClientPIN-only authenticator
  honestly.
- Allow empty `user.id` while still requiring the field to be present.
- Distinguish missing `pubKeyCredParams` from present-but-unsupported algorithms.

### Batch 2: GetAssertion and GetNextAssertion correctness

- Move normal-flow credential existence disclosure behind the approval boundary.
- Split allow-list selection from discoverable multi-assertion queueing.
- Preserve queued request state needed by `GetNextAssertion`, including silent `up = false`.
- Refresh the queue expiry timer after each successful `GetNextAssertion`.
- Reject unsupported `GetAssertion` options explicitly.

### Batch 3: ClientPIN semantics

- Stop consuming retries on malformed ECDH, decrypt, or structurally invalid token requests.
- Keep retry persistence, temporary auth-block behavior, and successful-reset behavior internally
  consistent for the implemented ClientPIN model.
- Stop rotating the key-agreement key on every `getKeyAgreement`.
- Tighten zero-length `pinAuth` compatibility, malformed UTF-8 PIN, trailing-CBOR rejection, and
  unsupported legacy-subcommand extra-field handling.

### Batch 4: CTAPHID transport correctness

- Finish the approval-time transport behavior for the supported subset.
- Make active-CID `CANCEL` and same-CID resync behavior consistent with the implemented approval
  model.
- Return invalid-channel vs busy HID errors correctly for reserved and unallocated CIDs.

### Batch 5: U2F durability and APDU correctness

- Stop regenerating the U2F device key on load/decrypt/parse failure.
- Make the U2F counter durable against torn or corrupt writes.
- Enforce the semantic U2F key-handle length byte.
- Keep persist-before-commit counter behavior intact after the durability work.

## Exit Criteria

- Code, milestone status, and docs agree.
- Local static checks pass after each batch.
- Remaining open items are only explicit live-device/browser verification gaps.

## Failure Conditions

- Docs claim fixes that are not present in code.
- A batch lands without updating this milestone file.
- Verification is reported complete without the corresponding checks being run.

## Verification Checklist

- Run `uv run python tools/check_c.py tidy` after each code batch.
- Run `uv run python tools/check_c.py cppcheck` after each code batch.
- Run `uv run python tools/run_protocol_regressions.py` and `uv run python -m unittest tests/test_ctaphid_probe.py` after transport, CTAP, or ClientPIN behavior changes.
- Run `uv run python -m ufbt` before marking firmware-side remediation complete.
- Extend host probes for CTAP, ClientPIN, transport, and U2F durability as the code changes land.
- Keep this file updated immediately after each completed fix batch and verification batch.

## Notes

- This milestone tracks only findings that are still valid in the current source tree.
- Historical findings that are already fixed stay out of scope unless the current tree regresses.
- Live hardware/browser verification remains required before release claims are updated to broad
  protocol correctness.
- The current pass added host-side probe coverage for malformed CTAP requests, silent assertions,
  same-CID approval-path resync, `GetNextAssertion`, and invalid-CID transport checks, and added
  native regression coverage for ClientPIN parsing, temporary auth blocking, and wrong-PIN
  key-agreement regeneration.

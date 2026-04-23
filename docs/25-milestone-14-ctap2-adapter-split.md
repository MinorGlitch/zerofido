# Milestone 14: CTAP2 Adapter Split

## Progress

Status: `complete`

- [x] Extract `ctap_request_decode`.
- [x] Extract `ctap_request_policy`.
- [x] Extract `ctap_dispatch`.
- [x] Extract `ctap_assertion_queue`.
- [x] Extract `ctap_approval_flow`.
- [x] Extract `ctap_response_encode`.
- [x] Preserve current wire behavior and queue semantics.

## Objective

Split CTAP2 into narrow owners so decoding, request policy, approval flow, queue management, and
response encoding stop living inside the same control paths.

## Exact Implementation Scope

- Create narrow CTAP2 owners:
  - `ctap_request_decode`
  - `ctap_request_policy`
  - `ctap_dispatch`
  - `ctap_assertion_queue`
  - `ctap_approval_flow`
  - `ctap_response_encode`
- Keep current behavior stable for:
  - request validation
  - empty `pinAuth` compatibility probe
  - `GetAssertion` / `GetNextAssertion` queue semantics
  - approval flow integration
  - attestation/response encoding
- Move approval/poll/cancel integration behind transport-neutral hooks.

## Required Interfaces / Types

- Narrow request structs reused by decode and policy layers
- One transport-neutral approval/progress contract consumed by CTAP2
- One assertion-queue owner with explicit state/input/output boundaries

## Exit Criteria

- CTAP2 decode, policy, queue, approval, and response encoding each have a single clear owner.
- CTAP2 handlers no longer embed transport-specific behavior.
- Current command semantics stay stable.

## Failure Conditions

- Queue behavior changes silently during the split.
- Approval or cancel semantics drift while being extracted.
- New helpers keep taking broad `ZerofidoApp*` access and preserve the same ownership tangle.

## Verification Checklist

- Re-run protocol and unit checks after code changes:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/check_c.py all`
- Confirm preserved behavior for:
  - empty `pinAuth`
  - `GetNextAssertion`
  - queue expiry/CID handling
  - approval-required paths

## Handoff State

- Completed items:
  - Created the foldered `src/ctap/` subsystem and hard-moved the request-parse and response
    seams into it:
    - `src/ctap/parse.h`
    - `src/ctap/parse_internal.h`
    - `src/ctap/parse_shared.c`
    - `src/ctap/parse_get_assertion.c`
    - `src/ctap/parse_make_credential.c`
    - `src/ctap/response.h`
    - `src/ctap/response.c`
  - Added foldered CTAP owners for approval and queue state:
    - `src/ctap/approval.h`
    - `src/ctap/approval.c`
    - `src/ctap/assertion_queue.h`
    - `src/ctap/assertion_queue.c`
  - Added the foldered CTAP policy owner:
    - `src/ctap/policy.h`
    - `src/ctap/policy.c`
  - Added the foldered CTAP dispatch owner:
    - `src/ctap/dispatch.h`
    - `src/ctap/dispatch.c`
  - Moved the approval request / empty-`pinAuth` probe logic into `src/ctap/approval.c`.
  - Moved assertion-queue clear/seed/invalidate/next-assertion handling into
    `src/ctap/assertion_queue.c`.
  - Moved request-policy helpers into `src/ctap/policy.c`:
    - allow-list semantics
    - `pinAuth` / `pinProtocol` validation
    - effective `uv` option handling
    - empty-payload validation
    - assertion-match filtering through credProtect
    - local-maintenance busy gating
  - Rewired `src/zerofido_ctap_dispatch.c` to call the new approval and queue owners instead of
    embedding those behaviors directly.
  - Rewired `src/zerofido_ctap_dispatch.c` to consume the new CTAP policy owner and updated
    `tools/run_protocol_regressions.py` so its structural guard follows `src/ctap/policy.c`
    instead of the old flat dispatch helper location.
  - Moved the remaining CTAP command handler bodies and command switch into `src/ctap/dispatch.c`
    so `src/zerofido_ctap_dispatch.c` is reduced to the exported entrypoint plus result/status
    bookkeeping.
  - Switched runtime and native-harness includes to the new foldered CTAP paths without adding
    compatibility wrappers.
  - Updated doc/test path references so audit fixtures and claim inventories no longer point at the
    deleted flat CTAP parse/response files.
  - Re-ran local verification after the folder move:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - Confirmed the touched CTAP/runtime files are clang-format clean with a narrow
    `clang-format --dry-run -Werror` pass.
- Current blocker:
  - No milestone-local blocker.
- Exact next resume step:
  Milestone 14 is complete. Resume at milestone 15 by moving U2F runtime ownership into a foldered
  `src/u2f/` subsystem and splitting APDU/session/persistence/response responsibilities.
  `uv run python tools/check_c.py all` was rerun after this batch and still fails only on broader
  pre-existing formatting debt in `src/u2f/persistence.c`, `src/zerofido_attestation.c`,
  `src/zerofido_runtime_config.c`, `src/zerofido_runtime_config.h`,
  `src/zerofido_store_file.c`, and `src/u2f/adapter.c`.

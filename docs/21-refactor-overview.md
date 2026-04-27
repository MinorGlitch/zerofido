# ZeroFIDO Runtime Refactor Overview

## Summary

This bundle is the source of truth for the runtime decoupling campaign. It exists so the refactor
can survive long gaps, interruptions, and context compactions without hidden state in chat.

The target runtime shape is:

1. `transport adapters`
2. `protocol adapters`
3. `authenticator core`

USB becomes one transport adapter. FIDO2 and U2F become transport-agnostic protocol adapters.
Version targeting stays deferred, but the runtime gets a central config/profile model now so later
version work is additive instead of another structural rewrite.

## Progress

Status: `complete`

| Milestone | File | Status | Notes |
| --- | --- | --- | --- |
| 11 | `22-milestone-11-runtime-boundaries-and-contracts.md` | `complete` | Architecture rules and contract surfaces frozen in docs before code movement. |
| 12 | `23-milestone-12-runtime-config-and-profile-resolution.md` | `complete` | Runtime config/profile scaffolding landed with startup capability resolution and default-preserving gates. |
| 13 | `24-milestone-13-usb-transport-adapter-extraction.md` | `complete` | USB worker, HID session, transport dispatch, and transport-neutral adapter services now live under `src/transport/` with the flat transport file removed. |
| 14 | `25-milestone-14-ctap2-adapter-split.md` | `complete` | CTAP decode, policy, response, approval, assertion-queue, and dispatch seams now live under `src/ctap/`, with `src/zerofido_ctap_dispatch.c` reduced to the exported entrypoint plus result/status bookkeeping. |
| 15 | `26-milestone-15-u2f-adapter-split.md` | `complete` | U2F now lives under `src/u2f/` with APDU, session, response-encode, persistence, and adapter owners, and the full `tools/check_c.py all` gate passed on that split. |
| 16 | `27-milestone-16-pin-ui-store-seam-extraction.md` | `complete` | PIN command/flow/state-store now live under `src/pin/`, UI approval/status/views now live under `src/ui/`, and store bootstrap/record-format/recovery now live under `src/store/`, with the milestone verification gate passing on the foldered tree. |
| 17 | `28-milestone-17-app-composition-root-reduction.md` | `complete` | App allocation, record wiring, backend startup policy, worker lifecycle, and shutdown sequencing now live under `src/app/lifecycle.c`, leaving `src/zerofido_app.c` as a thin entrypoint. |
| 18 | `29-milestone-18-multi-transport-readiness-and-final-gate.md` | `complete` | Final readiness sweep confirmed the foldered runtime boundaries, synced top-level docs to the final architecture, and recorded the remaining live-proof gaps explicitly. |

## Milestone Map

1. `22-milestone-11-runtime-boundaries-and-contracts.md`
2. `23-milestone-12-runtime-config-and-profile-resolution.md`
3. `24-milestone-13-usb-transport-adapter-extraction.md`
4. `25-milestone-14-ctap2-adapter-split.md`
5. `26-milestone-15-u2f-adapter-split.md`
6. `27-milestone-16-pin-ui-store-seam-extraction.md`
7. `28-milestone-17-app-composition-root-reduction.md`
8. `29-milestone-18-multi-transport-readiness-and-final-gate.md`

## Execution Order

1. Freeze architectural boundaries and contracts.
2. Add the central runtime config/profile resolution layer.
3. Extract the USB HID path into a transport adapter.
4. Split CTAP2 into narrow owners.
5. Split U2F into narrow owners.
6. Split PIN, UI, and store/bootstrap/recovery into narrow owners.
7. Reduce the app root to composition/lifecycle only.
8. Verify multi-transport readiness and run the final gate.

Do not reorder these milestones. The campaign is broad, but the internal extraction order is fixed.

## Architectural Rules

- USB is an adapter only.
- FIDO2 and U2F are protocol adapters only.
- The authenticator core owns authenticator behavior only.
- No protocol code may call USB/HID APIs directly.
- No transport code may contain `MakeCredential`, `GetAssertion`, `ClientPIN`, or U2F business
  logic.
- HID-only concepts such as `cid`, fragmentation, `KEEPALIVE`, `CANCEL`, and `WINK` terminate at
  the USB adapter boundary.
- New runtime modules must take narrow state/config structs, not `ZerofidoApp*`, unless the module
  is the actual composition root.
- No new mixed-responsibility files.
- No new ownership blobs in the 1000+ line style currently present in transport, PIN, UI, store,
  and protocol files.

## Tracking Rules

- Keep exactly one milestone marked `in progress` at a time.
- After every completed or partially completed implementation batch, immediately update this file
  and the active milestone file.
- If work stops mid-milestone, update the milestone `Handoff State` before ending the turn.
- Do not mark a milestone complete until its verification checklist passes or the remaining gap is
  explicitly recorded as deferred live hardware proof.
- Never rely on chat state alone for tracking completion.

## Current Active Milestone

- Active: `none - refactor campaign complete`
- Last completed: `Milestone 18 - Multi-Transport Readiness And Final Gate`
- Next concrete resume step:
  No further structural refactor milestone remains. Future work should be additive transport
  implementation, profile targeting, or live hardware/browser proof against the existing runtime
  boundaries.
- Last verification evidence:
  `uv run python tools/run_protocol_regressions.py` passed after the foldered milestone 13 transport
  move and again after the transport-neutral adapter wiring. After the milestone 14 folder move,
  `uv run python tools/run_protocol_regressions.py` passed again with `src/ctap/` wired in, and
  `uv run python -m unittest discover -s tests -p 'test_*.py'` passed on the same tree. After the
  follow-up approval/assertion-queue extraction into `src/ctap/`, both commands passed again.
  After the request-policy extraction into `src/ctap/policy.c`, both commands passed again. A
  final milestone 14 dispatch extraction moved the command switch and handlers into
  `src/ctap/dispatch.c`; both commands passed again after that cut. Milestone 15 then moved U2F
  into `src/u2f/` with separate APDU, session, response-encode, persistence, and adapter owners;
  after that cut, both `uv run python tools/run_protocol_regressions.py` and
  `uv run python -m unittest discover -s tests -p 'test_*.py'` passed again, and direct native
  compiles for `tests/native_protocol_regressions.c` and `tests/native_transport_u2f_regressions.c`
  also passed. The `src/u2f/` folder was then formatted with the system `clang-format` binary, and
  the same regression gates passed again after narrowing user-presence ownership behind
  `u2f_consume_user_present()` / `u2f_clear_user_present()`. The remaining repo-wide formatter and
  static-analysis debt was then cleared, and `uv run python tools/check_c.py all` passed. After
  milestone 16 started, PIN durable-state ownership moved into `src/pin/store/state_store.c` and
  `src/pin/store/state_store.h`, with file-format internals isolated in
  `src/pin/store/internal.h` for the native regression harness. The native harness was
  rewired to include the new owner, and `uv run python tools/check_c.py all` passed again. The UI
  approval-state owner then moved from `src/zerofido_ui_approval.c` into `src/ui/approval_state.c`
  and the full `uv run python tools/check_c.py all` gate passed again on that tree. Milestone 16
  then completed with store/bootstrap/recovery ownership extracted under `src/store/`, PIN command
  and local flow ownership extracted under `src/pin/`, and UI status/views ownership extracted
  under `src/ui/`. The completion gate passed with:
  `uv run python tools/run_protocol_regressions.py`,
  `uv run python -m unittest discover -s tests -p 'test_*.py'`,
  `uv run python tools/check_c.py all`, and the embedded `uv run python -m ufbt` path exercised
  as part of `tools/check_c.py all`. Milestone 17 then reduced app-root ownership by moving
  allocation, record wiring, backend startup policy, worker lifecycle, and shutdown sequencing
  into `src/app/lifecycle.c`, leaving `src/zerofido_app.c` as a thin entrypoint. The verification
  gate passed again with:
  `uv run python tools/run_protocol_regressions.py`,
  `uv run python -m unittest discover -s tests -p 'test_*.py'`,
  `uv run python tools/check_c.py all`. Milestone 18 then completed after a final source-level
  readiness sweep confirmed transport framing and USB worker ownership stayed under
  `src/transport/`, while top-level architecture docs were synced to the final foldered runtime
  shape. The final close-out gate then passed again with:
  `uv run python tools/run_protocol_regressions.py`,
  `uv run python -m unittest discover -s tests -p 'test_*.py'`,
  `uv run python tools/check_c.py all`,
  `uv run python -m ufbt`.

## Cross-Milestone Blockers

- The current worktree is already dirty across runtime, host tools, and docs; the refactor must
  work with the existing tree instead of assuming a clean baseline.
- The current runtime now has foldered transport, CTAP, U2F, PIN, UI, and store owners under
  `src/transport/`, `src/ctap/`, `src/u2f/`, `src/pin/`, `src/ui/`, and `src/store/`; milestone
  18 must preserve those boundaries while validating final multi-transport readiness.
- Live-device/browser proof remains outside this overview milestone and should only be claimed in
  later milestones when the matching commands are rerun.

## Final Acceptance Spine

The campaign is only done when all of the following are true:

- USB is fully adapterized and no longer owns FIDO2/U2F behavior.
- FIDO2 and U2F are transport-agnostic protocol adapters.
- The runtime has a central config/profile model that later version targeting can extend.
- The app root is reduced to composition, settings/config resolution, lifecycle, and shutdown.
- Future NFC/BLE support requires new transport adapters and adapter tests, not core rewrites.
- No new mixed-responsibility files or new ownership blobs were introduced.
- Final verification passed:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/check_c.py all`
  - `uv run python -m ufbt`

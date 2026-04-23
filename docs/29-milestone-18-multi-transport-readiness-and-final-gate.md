# Milestone 18: Multi-Transport Readiness And Final Gate

## Progress

Status: `complete`

- [x] Verify the runtime is transport-agnostic.
- [x] Verify future NFC/BLE support only requires new transport adapters plus adapter tests.
- [x] Sync architecture docs to the final runtime shape.
- [x] Run the final verification gate.
- [x] Record any remaining deferred live hardware/browser proof explicitly.

## Objective

Confirm the runtime is genuinely ready for additive transport work and close the refactor campaign
with synced docs and a full verification gate.

## Exact Implementation Scope

- Confirm the runtime is transport-agnostic.
- Confirm future NFC/BLE support only requires:
  - new transport adapters
  - adapter tests
  - optional config/profile wiring
- Sync the architecture docs to the final runtime shape.
- Run the full verification gate.
- Record any deferred live hardware/browser proof without overstating closure.

## Required Interfaces / Types

- Final transport adapter contract
- Final protocol dispatch envelope
- Final runtime config/profile and resolved capability shapes

## Exit Criteria

- Transport-agnostic core and protocol layers are confirmed.
- Future NFC/BLE work is additive at the adapter layer.
- Docs match the runtime architecture.
- The final local verification gate passes.

## Failure Conditions

- USB assumptions still leak into protocol or core modules.
- NFC/BLE would still require another core refactor.
- Docs overclaim readiness without the final verification evidence.

## Verification Checklist

- Run:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/check_c.py all`
  - `uv run python -m ufbt`
- Confirm the remaining open items, if any, are only explicitly recorded live hardware/browser
  verification gaps.

## Handoff State

- Completed items:
  - Final source-level readiness sweep confirmed USB HID framing, channel/session ownership, and
    worker lifecycle remain isolated under `src/transport/`.
  - CTAP2 and U2F remain foldered protocol adapters under `src/ctap/` and `src/u2f/`.
  - PIN, UI, store, and app lifecycle ownership remain split under `src/pin/`, `src/ui/`,
    `src/store/`, and `src/app/`.
  - Top-level docs were synced to the final foldered runtime architecture.
  - Final verification gate passed with:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
    - `uv run python tools/check_c.py all`
    - `uv run python -m ufbt`
  - Remaining live-proof gaps are explicitly tracked in
    `docs/18-current-state-revalidation-map.md` instead of being silently collapsed into a blanket
    completion claim.
- Current blocker:
  - No structural blocker. The refactor campaign is complete.
- Exact next resume step:
  No further milestone work remains. Future follow-up should be either additive transport work or
  targeted live hardware/browser proof against the remaining checkpoints in
  `docs/18-current-state-revalidation-map.md`.

## Deferred live-proof gaps

Milestone completion does not erase the explicitly tracked live-runtime gaps that still need
attached hardware or browser evidence. The current conservative checkpoints remain in:

- `docs/18-current-state-revalidation-map.md`

The remaining deferred proof includes:

- finding 4: CTAPHID channel allocation and invalid/unallocated CID behavior
- finding 5: same-CID `INIT` re-synchronization during active assembly
- finding 7: U2F approval keepalive CID on live transport
- finding 8: U2F counter durability under persistence failure / reboot-oriented proof
- finding 10: live attestation-registration artifact capture

Additional partially re-proven current-state rows also remain documented there for malformed
request replay and silent multi-assertion confirmation. The milestone is complete because the
runtime architecture and local verification gate are complete, not because every live hardware
checkpoint has been replayed in this slice.

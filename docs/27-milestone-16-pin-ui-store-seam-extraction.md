# Milestone 16: PIN, UI, And Store Seam Extraction

## Progress

Status: `complete`

- [x] Split PIN into `pin_state_store`.
- [x] Split PIN into `pin_command`.
- [x] Split PIN into `pin_flow`.
- [x] Split UI into `ui_status`.
- [x] Split UI into `ui_approval_state`.
- [x] Split UI into `ui_views`.
- [x] Split store into `store_bootstrap`.
- [x] Split store into `store_record_format`.
- [x] Split store into `store_recovery`.
- [x] Preserve current fail-closed and persistence semantics.

## Objective

Separate persistent PIN state, local PIN flow, UI approval/status state, and store
bootstrap/format/recovery responsibilities so these subsystems stop sharing the same broad
ownership blobs.

## Exact Implementation Scope

- Split PIN into:
  - `pin_state_store`
  - `pin_command`
  - `pin_flow`
- Split UI into:
  - `ui_status`
  - `ui_approval_state`
  - `ui_views`
- Split store into:
  - `store_bootstrap`
  - `store_record_format`
  - `store_recovery`
- Preserve current semantics for:
  - retry persistence
  - auth-block persistence
  - fail-closed behavior
  - status/approval lifecycle
  - store write/replace rollback and wipe behavior

## Required Interfaces / Types

- Dedicated PIN durable/runtime state owners
- Dedicated UI approval/status state owners
- Dedicated store bootstrap/format/recovery state or API boundaries

## Exit Criteria

- PIN, UI, and store each have narrow single-purpose owners.
- Current fail-closed and persistence rules remain stable.
- UI lifecycle logic is separated from protocol/storage semantics.

## Failure Conditions

- UI callbacks continue to own storage mutation and state-machine logic directly.
- PIN persistence and protocol handling remain mixed together.
- Store bootstrap/format/recovery logic remains in one ownership blob.

## Verification Checklist

- Re-run checks after code changes:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/check_c.py all`
- Confirm preserved behavior for:
  - PIN retry/block persistence
  - local PIN flow mutation timing
  - approval generation/hide ordering
  - store write/replace rollback and wipe behavior

## Handoff State

- Completed items:
  - PIN durable-state ownership now lives under:
    - `src/pin/store/state_store.c`
    - `src/pin/store/state_store.h`
    - `src/pin/store/internal.h`
  - PIN command routing and ClientPIN request/response ownership now live under:
    - `src/pin/command.c`
    - `src/pin/internal.h`
  - PIN local/runtime flow ownership now lives under:
    - `src/pin/flow.c`
  - The previous flat `src/zerofido_pin.c` file is gone.
  - The native regression harness now includes the foldered PIN owners directly and uses
    `src/pin/store/internal.h` plus `src/store/record_format_internal.h` for the
    intentionally tested file-format internals.
  - UI approval ownership now lives under:
    - `src/ui/approval_state.c`
  - UI status ownership now lives under:
    - `src/ui/status.c`
    - `src/ui/status.h`
  - UI views/orchestration ownership now lives under:
    - `src/ui/views.c`
  - The previous flat `src/zerofido_ui.c` and `src/zerofido_ui_approval.c` files are gone.
  - Store ownership now lives under:
    - `src/store/bootstrap.c`
    - `src/store/bootstrap.h`
    - `src/store/record_format.c`
    - `src/store/record_format.h`
    - `src/store/record_format_internal.h`
    - `src/store/recovery.c`
    - `src/store/recovery.h`
    - `src/store/internal.h`
  - The previous flat `src/zerofido_store_file.c` and `src/zerofido_store_file.h` files are gone.
  - Verification run after the completed milestone:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
    - `uv run python tools/check_c.py all`
- Current blocker:
  - None. Milestone exit criteria are met.
- Exact next resume step:
  Move to milestone 17 and reduce `src/zerofido_app.c` to composition/lifecycle wiring only,
  keeping the foldered subsystem boundaries intact.

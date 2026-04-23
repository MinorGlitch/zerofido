# Milestone 15: U2F Adapter Split

## Progress

Status: `complete`

- [x] Extract `u2f_apdu`.
- [x] Extract `u2f_session`.
- [x] Extract `u2f_persistence`.
- [x] Extract `u2f_response_encode`.
- [x] Keep user-presence ownership inside `u2f_session`.
- [x] Preserve U2F transport independence.

## Objective

Split U2F into APDU, session, persistence, and response owners so user-presence state,
bootstrapping, and APDU behavior stop living in the same file and so U2F can remain independent of
USB as a transport.

## Exact Implementation Scope

- Create narrow U2F owners:
  - `u2f_apdu`
  - `u2f_session`
  - `u2f_persistence`
  - `u2f_response_encode`
- Keep user-presence state, connect/disconnect reset, and success-path consumption inside
  `u2f_session`.
- Keep cert/key/counter bootstrap and persistence rules inside `u2f_persistence`.
- Preserve U2F callable behavior from any transport adapter that declares U2F support.

## Required Interfaces / Types

- A U2F session state type that owns user-presence and runtime-only state
- A persistence-facing U2F state or storage contract for cert/key/counter operations
- One APDU classification surface used by protocol dispatch

## Exit Criteria

- U2F APDU parsing, runtime session behavior, persistence/bootstrap, and response encoding each
  have clear owners.
- U2F no longer depends on USB-specific transport behavior.
- Current U2F semantics remain stable.

## Failure Conditions

- User-presence state remains split between wrapper and core paths.
- USB-specific assumptions survive inside U2F request handling.
- Persistence/bootstrap logic remains braided into the runtime session code.

## Verification Checklist

- Re-run transport/U2F-sensitive checks after code changes:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/check_c.py all`
  - `uv run python -m ufbt`
- Confirm preserved behavior for:
  - invalid-handle handling
  - user-presence consumption
  - connect/disconnect reset
  - durability-sensitive counter rules

## Handoff State

- Completed items:
  - U2F now lives under `src/u2f/` instead of the previous flat runtime files:
    - `src/u2f/apdu.c` and `src/u2f/apdu.h`
    - `src/u2f/session.c` and `src/u2f/session.h`
    - `src/u2f/response_encode.c` and `src/u2f/response_encode.h`
    - `src/u2f/persistence.c` and `src/u2f/persistence.h`
    - `src/u2f/adapter.c` and `src/u2f/adapter.h`
  - The flat `src/u2f.c`, `src/u2f.h`, `src/zerofido_u2f.c`, `src/zerofido_u2f.h`,
    `src/u2f_data.c`, and `src/u2f_data.h` files are gone.
  - Transport dispatch now calls the foldered U2F adapter directly, and the native U2F regressions
    include the split U2F modules rather than the deleted flat files.
  - Audit-frame docs/tests were updated to reference the new `src/u2f/` owners so the current-tree
    verification harness no longer points at deleted files.
  - Verification run after the split:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
    - direct native compiles for `tests/native_protocol_regressions.c` and
      `tests/native_transport_u2f_regressions.c`
- Current blocker:
  - None for this milestone. The full repo gate now passes on the foldered `src/u2f/` split.
- Exact next resume step:
  Start milestone 16 by extracting PIN durable state, then UI approval/status ownership, then the
  store bootstrap/format/recovery seams into folders.

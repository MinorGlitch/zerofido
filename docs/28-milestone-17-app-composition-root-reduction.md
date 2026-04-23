# Milestone 17: App Composition Root Reduction

## Progress

Status: `complete`

- [x] Reduce the app root to subsystem allocation.
- [x] Reduce the app root to settings/config load and capability resolution.
- [x] Reduce the app root to transport/protocol/core registration.
- [x] Reduce the app root to shutdown ordering.
- [x] Remove deep branching runtime business logic from the app root.

## Objective

Reduce the application root to composition, lifecycle, settings/config resolution, transport
registration, and shutdown only.

## Exact Implementation Scope

- Keep the app root responsible only for:
  - subsystem allocation
  - settings/config load
  - runtime capability resolution
  - transport/protocol/core registration
  - startup/shutdown ordering
- Remove deep branching transport/protocol/storage logic from the app root.
- Keep the current startup status behavior stable.

## Required Interfaces / Types

- App-composition helpers for startup and shutdown ordering
- A clean boundary between app root and subsystem initialization
- Startup status/capability reporting that does not reintroduce ownership tangles

## Exit Criteria

- The app root is a composition root only.
- Runtime business logic no longer lives in app startup/shutdown paths.
- Current startup/shutdown behavior remains stable.

## Failure Conditions

- The app root keeps broad knowledge of transport, protocol, and storage internals.
- New helpers merely move the same branching into another broad owner file.
- Startup status behavior regresses during the cleanup.

## Verification Checklist

- Re-run checks after code changes:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/check_c.py all`
  - `uv run python -m ufbt`
- Confirm startup status mapping and shutdown ordering remain stable.

## Handoff State

- Completed items:
  - App lifecycle ownership now lives under:
    - `src/app/lifecycle.c`
    - `src/app/lifecycle.h`
  - `src/zerofido_app.c` is now a thin entrypoint that sequences:
    - lifecycle allocation
    - lifecycle open/startup
    - status-view dispatch
    - lifecycle shutdown/free
  - Allocation, record wiring, backend startup policy, worker lifecycle, and shutdown sequencing
    no longer live directly in `src/zerofido_app.c`.
  - Verification run after the completed milestone:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
    - `uv run python tools/check_c.py all`
- Current blocker:
  - None. Milestone exit criteria are met.
- Exact next resume step:
  Move to milestone 18 and perform the final transport-readiness and documentation sync pass
  against the fully foldered runtime.

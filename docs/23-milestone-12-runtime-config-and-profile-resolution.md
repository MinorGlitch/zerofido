# Milestone 12: Runtime Config And Profile Resolution

## Progress

Status: `complete`

- [x] Freeze the intended runtime config/profile model in docs.
- [x] Add `ZfRuntimeConfig` to the runtime code.
- [x] Add `ZfResolvedCapabilities` to the runtime code.
- [x] Add one startup resolution step: settings -> runtime config -> resolved capabilities.
- [x] Ensure transport and protocol wiring consume the resolved capabilities instead of scattered
      booleans.
- [x] Verify no ad hoc handler-level feature/version checks were introduced.

## Objective

Introduce one central runtime config/profile layer so protocol enablement, future version profiles,
and transport capability selection are resolved once at startup instead of scattered through the
handlers.

## Exact Implementation Scope

- Introduce one central runtime config with slots for:
  - `fido2_enabled`
  - `fido2_profile`
  - `u2f_enabled`
  - `u2f_profile`
  - transport enablement/capability selection
- Add one startup resolution step:
  - settings -> runtime config -> resolved capabilities -> adapter/core wiring
- Defer actual CTAP version targeting.
- Forbid handler-level scattered feature/version checks.
- Keep the current shipped behavior as the resolved default until later milestones add settings UI
  or profile selection logic.

## Required Interfaces / Types

- `ZfRuntimeConfig`
  - persisted or startup-loaded desired configuration
- `ZfResolvedCapabilities`
  - effective enabled protocols, transport exposure, and behavior flags after resolution
- One runtime resolution function or module that converts config to capabilities before transport
  initialization

## Exit Criteria

- Runtime code has one central config type.
- Runtime code has one resolved capability type.
- Startup performs one explicit config-resolution step before transport/protocol/core wiring.
- Current behavior is preserved with the resolved default profile.

## Failure Conditions

- Feature or profile checks are added directly inside CTAP/U2F handlers.
- Transport or protocol code reads settings directly instead of the resolved capability set.
- Multiple competing config shapes appear during the refactor.

## Verification Checklist

- [x] Inspect startup after the change and confirm one config-resolution path exists.
- [x] Confirm transport/protocol modules depend on resolved capability data, not raw settings reads.
- [x] Run targeted runtime checks if code changes land:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`

## Handoff State

- Completed items:
  - `src/zerofido_runtime_config.h` and `src/zerofido_runtime_config.c` landed with
    `ZfRuntimeConfig`, `ZfResolvedCapabilities`, default loading, capability resolution, and
    effective-capability helpers.
  - Startup now resolves runtime config once in `src/zerofido_app.c` before worker start.
  - CTAP `GetInfo`, CTAP command gating, U2F init/dispatch, and HID command exposure now consume
    resolved capabilities instead of ad hoc booleans.
  - Native and Python regression suites passed:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
- Current blocker:
  - None for milestone 12. Remaining transport decoupling work moved to milestone 13.
- Exact next resume step:
  Start milestone 13 by extracting HID session/framing and normalized transport dispatch out of
  `src/transport/usb_hid_session.c`, keeping CTAPHID cancel, keepalive, and same-CID resync behavior
  stable while USB lifecycle remains in the worker owner.

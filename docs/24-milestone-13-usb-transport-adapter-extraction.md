# Milestone 13: USB Transport Adapter Extraction

## Progress

Status: `complete`

- [x] Split the USB HID path into `transport_usb_hid_worker`.
- [x] Split the USB HID path into `transport_usb_hid_session`.
- [x] Introduce `transport_dispatch` for normalized protocol routing.
- [x] Terminate HID-only concepts at the USB adapter boundary.
- [x] Keep current wire behavior stable.
- [x] Add or tighten adapter-boundary tests for USB HID framing and dispatch.

## Objective

Turn the current USB HID path into a pure transport adapter with separate worker/session ownership,
and stop the transport layer from owning FIDO2/U2F business logic.

## Exact Implementation Scope

- Split the current USB path into:
  - `transport_usb_hid_worker`
  - `transport_usb_hid_session`
  - `transport_dispatch`
- Keep HID-only concerns in the adapter:
  - USB config save/restore
  - HID callback loop
  - CTAPHID packet assembly
  - CID allocation/reclamation
  - keepalive, cancel, wink, same-CID resync
- Move normalized protocol routing behind `transport_dispatch`.
- Do not let `cid`, fragmentation, `KEEPALIVE`, `CANCEL`, or `WINK` leak into protocol handlers.
- Use hard ownership moves only. Do not add wrapper layers or compatibility shims between the old
  transport file and the new adapter owners.

## Required Interfaces / Types

- `ZfTransportAdapterOps`
- `ZfProtocolDispatchRequest`
- `ZfProtocolDispatchResult`
- USB HID worker/session state types that are owned by the USB adapter only

## Exit Criteria

- USB lifecycle and CTAPHID framing live entirely inside the USB adapter.
- Protocol code no longer depends on HID packet or CID details.
- Current USB wire behavior is preserved.

## Failure Conditions

- CTAP2/U2F handlers still call USB/HID functions directly.
- USB adapter continues to own MakeCredential/GetAssertion/ClientPIN/U2F business logic.
- HID-specific state remains shared across unrelated runtime modules.

## Verification Checklist

- Re-run transport-sensitive checks after code changes:
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python -m unittest discover -s tests -p 'test_*.py'`
  - `uv run python tools/run_protocol_regressions.py`
  - `uv run python tools/check_c.py all`
- Confirm same-CID resync, cancel, keepalive, CID allocation/reclamation, and disconnect/reset
  behavior remain stable.

## Handoff State

- Completed items:
  - `src/transport/usb_hid_session.h` and `src/transport/usb_hid_session.c` landed. CTAPHID
    framing, CID bookkeeping, message assembly, same-CID resync, cancel handling, and assembly
    timeout logic now live in the HID session owner.
  - `src/transport/dispatch.h` and `src/transport/dispatch.c` landed. Completed HID messages now
    route through a dedicated transport-dispatch seam instead of being handled inline by the worker.
  - `src/transport/usb_hid_worker.h` and `src/transport/usb_hid_worker.c` landed. USB lifecycle,
    HID callback/event-loop handling, approval wait, and keepalive ownership now live in the worker
    owner instead of the deleted flat `src/zerofido_transport.c`.
  - `src/transport/adapter.h` and `src/transport/adapter.c` landed. App/UI/CTAP code now consume a
    transport-neutral adapter interface and no longer include USB-worker headers directly.
  - `application.fam` and `tools/check_c.py` now include `src/**/*.c` and `src/**/*.h`, so future
    milestone extractions can keep grouping code in subsystem folders.
  - Regression evidence for this milestone:
    - `uv run python tools/run_protocol_regressions.py`
    - `uv run python -m unittest discover -s tests -p 'test_*.py'`
- Current blocker:
  - None inside milestone 13. Remaining gaps are later cross-transport and live-hardware proof, not
    USB ownership shape.
- Exact next resume step:
  Start milestone 14 by creating the CTAP folder split under `src/ctap/`, beginning with
  decode/policy and response-building seams before queue and approval extraction.

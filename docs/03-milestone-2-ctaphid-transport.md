# Milestone 2: CTAPHID Transport Core

## Objective

Implement a complete CTAPHID transport state machine before any real CTAP2 command work.

## Exact Implementation Scope

- Implement 64-byte HID packet RX/TX on top of `usb_hid_u2f`.
- Reassemble init and continuation frames into a single logical request buffer.
- Enforce one active transaction at a time.
- Support these CTAPHID commands:
  - `INIT`
  - `PING`
  - `CBOR`
  - `CANCEL`
  - `WINK`
- Return transport errors for:
  - `ERR_CHANNEL_BUSY`
  - `ERR_INVALID_SEQ`
  - `ERR_INVALID_LEN`
  - `ERR_MSG_TIMEOUT`
  - `ERR_INVALID_CMD`
- On same-CID `INIT`, abort the active transaction, flush transport state, and resynchronize that CID.
- On different-CID traffic during an active transaction, return `ERR_CHANNEL_BUSY`.
- Enforce a `1024`-byte assembled payload ceiling.
- Enforce a `3 second` host message assembly timeout.
- Support KEEPALIVE emission every `100 ms` while a CBOR request is active.
- Make `CANCEL` a state-change input only. It must not produce a direct transport reply.
- Advertise CTAPHID capabilities as `WINK | CBOR | NMSG`.

## Dependencies

- Milestone 1 passed
- worker-owned transport thread in place
- USB lifecycle stable enough to exercise host traffic repeatedly

## Non-Goals

- no CBOR command parsing beyond passing raw CBOR payloads to the next layer
- no CTAP2 `GetInfo`
- no `MSG`
- no `LOCK`
- no credential logic

## Exit Criteria

- host script can complete `INIT`
- host script can complete `PING`
- `INIT` response advertises `WINK | CBOR | NMSG`
- timeout, oversize, invalid-sequence, and channel-busy paths behave exactly as specified

## Failure Conditions

- malformed continuation flow is accepted
- same-CID resync does not fully reset transport state
- different-CID request is processed instead of rejected as busy
- `CANCEL` gets a direct HID reply
- payloads above `1024` are accepted

## Verification Checklist

- validate normal `INIT` handshake
- validate normal `PING` echo behavior
- send bad continuation sequence and confirm `ERR_INVALID_SEQ`
- send oversize `BCNT` and confirm `ERR_INVALID_LEN`
- start a request, then exceed the `3 second` assembly timeout and confirm `ERR_MSG_TIMEOUT`
- send same-CID `INIT` during an active transaction and confirm resync
- send different-CID traffic during an active transaction and confirm `ERR_CHANNEL_BUSY`
- send `CANCEL` during active CBOR work and confirm no direct transport reply

## Review Notes

This milestone is correctly separated from `GetInfo`. The transport state machine needs to be stable before any command-layer debugging starts.

The biggest implementation risk here is partial reset behavior. The document explicitly fixes resync, busy arbitration, timeout, and cancel semantics so the implementer does not improvise them.

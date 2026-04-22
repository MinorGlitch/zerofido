# Milestone 5: GetAssertion and GetNextAssertion

## Objective

Authenticate with allowList and discoverable flows, including silent preflight and multi-assertion enumeration.

## Exact Implementation Scope

- Implement `authenticatorGetAssertion`.
- Implement `authenticatorGetNextAssertion`.
- Support allowList-based matching for a supplied `rpId`.
- Support discoverable lookup when `allowList` is omitted.
- Implement silent preflight when `options.up = false`:
  - no approval UI
  - no `STATUS_UPNEEDED`
  - return assertion with `UP=0`, `UV=0`
- Implement normal approval flow when `up` is absent or `true`:
  - approval UI required
  - `STATUS_UPNEEDED` emitted while waiting
  - return assertion with `UP=1`, `UV=0`
- If multiple credentials match:
  - return the first assertion
  - include `numberOfCredentials`
  - queue the remaining matches for `GetNextAssertion`
- Enforce `30 second` queued-assertion session expiry.
- Include `user.id` in assertion responses.
- Omit `user.name`, `user.displayName`, and `user.icon` when UV was not performed.

## Dependencies

- Milestone 4 passed
- Milestone 6 passed before this milestone is marked complete:
  - per-credential counters
  - persist-before-signing rule
  - durable credential reads

## Non-Goals

- no on-device account chooser in Phase 1
- no built-in UV
- no PIN enforcement in Phase 1
- no extensions

## Exit Criteria

- browser or platform preflight succeeds without showing UI
- normal assertion path requires explicit approval
- multi-credential RP works through `GetNextAssertion`

## Failure Conditions

- silent preflight shows UI or sets `UP=1`
- `GetNextAssertion` works without a valid queued state
- user-identifying fields are exposed without UV
- queued assertion state survives beyond the `30 second` expiry

## Verification Checklist

- validate allowList assertion flow
- validate discoverable assertion flow with no allowList
- validate silent preflight with `up=false`
- validate normal approved assertion with `up` omitted
- validate multi-match first response includes `numberOfCredentials`
- validate successive `GetNextAssertion` calls drain the queue
- validate expiry causes `CTAP2_ERR_NOT_ALLOWED`

## Review Notes

This milestone must test the silent-preflight path explicitly. That is not an edge case; it is part of real browser interoperability.

Leaving the on-device chooser out of Phase 1 is the right simplification. The current ZeroFIDO UI is
approval-only and does not expose account identity, so host-driven enumeration via
`GetNextAssertion` remains the Phase 1 contract.

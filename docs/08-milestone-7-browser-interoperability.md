# Milestone 7: Browser Interoperability Gate

## Objective

Prove that the Phase 1 app works against real WebAuthn clients, not just transport scripts and unit-level protocol checks.

## Exact Implementation Scope

- Validate browser-based registration flow.
- Validate browser-based authentication flow.
- Validate discoverable credential flow with `allowList` omitted.
- Validate silent-preflight behavior within a real browser or platform flow.
- Validate repeated assertions against persisted credentials after app restart.
- Record the exact tested environment:
  - browser name and version
  - operating system version
  - firmware version
  - test page or client used

## Dependencies

- Milestones 0 through 6 passed
- device usable end to end over USB HID from the browser host

## Non-Goals

- no PIN compatibility claims yet
- no broad-compatibility marketing claim yet
- no certification claim

## Exit Criteria

- at least one real browser or WebAuthn test page can register a credential
- the same environment can authenticate with that credential
- discoverable credential flow works end to end
- persisted credential remains usable after app restart

## Failure Conditions

- scripted protocol checks pass but browser flow fails
- silent preflight breaks the real client flow
- persisted credentials only work until the app restarts

## Verification Checklist

- record the full test environment matrix
- run registration from a browser test page
- run authentication from the same test page
- run discoverable sign-in with no allowList
- restart the app and repeat authentication
- confirm UI only appears on the normal assertion path

## Review Notes

This milestone is correctly its own gate. Phase 1 should not be called done just because local transport tests pass.

The environment-recording requirement matters. Browser behavior changes over time, and future regressions need a concrete baseline rather than “worked once.”

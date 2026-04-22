# Milestone 8: ClientPIN for Broad Compatibility

## Objective

Add PIN capability so the app can credibly target broader WebAuthn compatibility.

## Exact Implementation Scope

- Implement `authenticatorClientPIN`.
- Support:
  - `getRetries`
  - `getKeyAgreement`
  - `setPIN`
  - `changePIN`
  - legacy `getPinToken` for CTAP2.0 compatibility
  - minimal `getPinUvAuthTokenUsingPinWithPermissions` for `mc` / `ga` with RP-ID binding
- Persist PIN state safely and consistently.
- Enforce retry tracking and failure handling durably across restarts.
- Update `authenticatorGetInfo` only after PIN support is actually working.
- Continue to omit built-in UV unless it is separately implemented later.

## Dependencies

- Milestones 0 through 7 passed
- durable storage and cryptographic wrapping already stable
- browser or client interoperability baseline already established for Phase 1

## Non-Goals

- no built-in biometric or hardware UV
- no claim that PIN makes the device equivalent to a certified hardware key
- no CTAP1/U2F fallback unless separately planned

## Exit Criteria

- CTAP2 client tooling can complete PIN setup and PIN-based token flows
- retry handling behaves correctly across restart boundaries
- `GetInfo` truthfully advertises PIN capability after the implementation is real
- clients that require PIN-capable authenticators can use the app

## Failure Conditions

- `GetInfo` advertises `clientPin` before flows work
- PIN state is stored inconsistently or in insecure cleartext against the chosen storage policy
- retry handling is incorrect or resets unexpectedly on restart
- PIN token issuance does not work end to end

## Verification Checklist

- set an initial PIN
- change the PIN
- validate retry decrement behavior
- restart after a failed PIN attempt and confirm the decremented retry count is preserved
- reach the blocked state, restart, and confirm the block is preserved
- validate successful legacy token retrieval after correct PIN entry
- validate successful permission-scoped token retrieval for `mc` / `ga` with `rpId`
- validate client behavior that depends on PIN token issuance
- confirm `GetInfo` changes only after the full PIN path is operational

## Review Notes

This belongs after the Phase 1 browser gate. That ordering is correct because it keeps the first compatibility target realistic and measurable.

For a real app, this milestone is required before making broad-compatibility claims. The document keeps UV out of scope so the boundary stays honest. If newer permissions-capable ClientPIN subcommands are claimed, the implementation has to actually enforce their permission and RP-ID semantics instead of aliasing them to the legacy token path.

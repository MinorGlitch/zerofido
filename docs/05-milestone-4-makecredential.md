# Milestone 4: MakeCredential

## Objective

Create discoverable ES256 credentials with `packed` attestation and explicit user approval.

## Exact Implementation Scope

- Parse `authenticatorMakeCredential`.
- Require at least one supported `pubKeyCredParams` entry with `alg = -7`.
- Reject `options.uv = true`.
- Reject `options.up = false`.
- Ignore unsupported optional cosmetic fields such as `icon`.
- Enforce `excludeList` matching against existing credentials for the same RP.
- Show a deterministic approval UI containing:
  - operation type
  - RP ID
  - username when present
- Apply a `30 second` approval timeout.
- Map approval timeout to `CTAP2_ERR_USER_ACTION_TIMEOUT`.
- Map explicit denial to `CTAP2_ERR_OPERATION_DENIED`.
- Generate:
  - credential ID of `32` random bytes
  - P-256 keypair for ES256
  - attested credential data with the committed AAGUID
  - COSE ES256 public key
- Return `attestationObject` with:
  - `fmt = "packed"`
  - `attStmt` containing `alg`, `sig`, and `x5c`

## Dependencies

- Milestone 3 passed
- Milestone 6 storage primitives available before this milestone is marked complete:
  - private-key wrapping
  - atomic file write path
  - credential record format
- P-256 generation and signing support available through `mbedtls`

## Non-Goals

- no extensions
- no enterprise attestation
- no PIN or UV enforcement
- no CTAP1/U2F requirement for this registration path

## Exit Criteria

- host tooling can register a credential
- returned attestation object is accepted by a WebAuthn registration flow
- exclusion path returns the correct error for an existing credential

## Failure Conditions

- unsupported options are silently accepted when they should fail
- attested credential data is malformed
- AAGUID in attested credential data differs from `GetInfo`
- storage write occurs after the response is already committed

## Verification Checklist

- register a new credential for a fresh RP
- repeat the same request with matching `excludeList` and confirm exclusion failure
- verify returned `fmt` is `packed`
- inspect authData flags and confirm `UP=1`, `UV=0`, `AT=1`, `ED=0`
- confirm credential record persists only on successful approval
- confirm timeout and deny paths do not leave partially created credentials behind

## Review Notes

This milestone stays intentionally tight: registration only, no extensions, no enterprise claims.

The explicit dependency on Milestone 6 foundation is necessary. Credential creation is not complete until the private key is wrapped and the record is durably stored.

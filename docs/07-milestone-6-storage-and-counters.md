# Milestone 6: Storage, Wrapping, and Counters

## Objective

Make credential persistence durable, atomic, and WebAuthn-correct.

## Exact Implementation Scope

- Store app data only under `APP_DATA_PATH(...)`.
- Persist one file per credential record.
- Define each record to include:
  - schema version
  - credential ID
  - RP ID
  - user ID
  - optional stored user name
  - optional stored display name
  - public key coordinates
  - encrypted private key blob
  - IV for wrapped private key
  - per-credential signature counter
  - creation timestamp
- Protect private keys with slot `11` wrapping:
  - ensure key exists
  - load key with random IV
  - encrypt private key material
  - unload key immediately after use
- Write all state atomically with temp-file then rename in the same directory.
- Clean orphan temp files on startup before loading state.
- Use per-credential counters, not a global counter.
- For every successful `GetAssertion`, including silent preflight:
  - load credential record
  - increment counter by one
  - persist the new counter atomically
  - build authData with the persisted value
  - sign only after persistence succeeds

## Dependencies

- Milestone 0 passed for crypto-enclave symbol availability
- app data path available from external app runtime
- ES256 credential record format agreed before registration work is merged

## Non-Goals

- no plaintext fallback unless a later written decision explicitly approves it
- no sync to external storage paths outside app data
- no global signature counter

## Exit Criteria

- credentials survive app restart and device reboot
- per-credential counters survive app restart and device reboot
- signed counter matches durable stored value
- interrupted write leaves either the old valid record or the new valid record, never a partial record

## Failure Conditions

- private keys are stored unwrapped without an explicit design change
- counter increments after signing
- non-atomic writes can leave torn records
- orphan temp files are treated as valid records on startup

## Verification Checklist

- create credentials, restart app, and confirm they still load
- reboot device and confirm credentials still load
- perform repeated assertions and confirm counter increments per credential
- confirm silent preflight also increments and persists the counter
- simulate interrupted writes and confirm startup recovers to a valid state
- inspect stored files and confirm no plaintext private key material is present

## Review Notes

This milestone is foundational, not polish. Registration and assertion are not real until storage and counter behavior are correct.

The persist-before-signing rule is fixed here because it is the only way to keep signed `signCount` aligned with durable state after crashes or power loss.

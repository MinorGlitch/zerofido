# Milestone 3: CTAP2 GetInfo

## Objective

Expose a minimal, truthful CTAP2 identity surface that matches the actual Phase 1 feature set.

## Exact Implementation Scope

- Implement `authenticatorGetInfo`.
- Commit and use one fixed app-model AAGUID:
  - `b51a976a-0b02-40aa-9d8a-36c8b91bbd1a`
- Return:
  - `versions = ["FIDO_2_0", "U2F_V2"]`
  - `aaguid = b51a976a-0b02-40aa-9d8a-36c8b91bbd1a`
  - `options = {"up": true, "rk": true, "uv": false, "plat": false, "clientPin": dynamic}`
  - `maxMsgSize = 1024`
  - `pinUvAuthProtocols = [1]`
  - `transports = ["usb"]`
  - `algorithms = [{"type": "public-key", "alg": -7}]`
- Omit unsupported extensions, enterprise attestation, and other unsupported later CTAP2 surfaces.

## Dependencies

- Milestone 2 passed
- CBOR request dispatch available
- transport response path stable

## Non-Goals

- no credential creation
- no assertion logic
- no attestation object
- no credential-management surface beyond identity reporting

## Exit Criteria

- host CTAP2 tooling can parse `GetInfo`
- returned AAGUID is stable and nonzero
- reported limits and options match the actual app behavior

## Failure Conditions

- AAGUID changes between runs
- returned `GetInfo` data claims unsupported behavior
- `maxMsgSize` differs from the real transport ceiling

## Verification Checklist

- query `GetInfo` multiple times across app restarts
- confirm the same AAGUID every time
- verify `versions`, `options`, `transports`, and `algorithms` match the implemented Phase 1 surface
- verify omitted fields are actually unsupported rather than accidentally forgotten

## Review Notes

This milestone freezes the public identity contract early, which is correct. AAGUID cannot stay fuzzy past this point.

Keeping `FIDO_2_0` as the CTAP2 version is deliberate. Advertising `U2F_V2` in addition reflects the real compatibility surface and should stay aligned with the runtime.

# ZeroFIDO FIDO Audit Matrix

This matrix tracks the implemented protocol surface against two bars:

- **Protocol**: normative CTAP/U2F/WebAuthn expectations
- **Interop**: browser-facing behavior that matters in practice

Each row is classified as one of:

- `aligned`
- `spec violation`
- `interop risk`
- `intentional product choice`
- `intentional deviation`

## CTAPHID and U2F transport

| Surface | Implemented behavior | Protocol bar | Interop bar | Classification |
| --- | --- | --- | --- | --- |
| `CTAPHID_INIT` | allocates unique non-reserved channels on broadcast requests, requires allocated channels for subsequent traffic, serializes requests while a message is assembling or approval-bound processing, accepts same-CID resync during assembly and during the blocked approval path, reclaims the least-recently-used inactive allocated CID when the bounded table fills, and resets channel allocation state on USB reconnect | matches the serialized transport model for the implemented surface | acceptable | aligned |
| `CTAPHID_PING` | echoes payload | correct | correct | aligned |
| `CTAPHID_CBOR` | routes CTAP2 requests | correct for implemented command set | correct | aligned |
| `CTAPHID_MSG` | routes U2F APDU payloads | correct because U2F compatibility is implemented | required for legacy browser fallback | aligned |
| `CTAPHID_WINK` | supported | correct | helpful but optional | aligned |
| `CTAPHID_CANCEL` | acts as a state-change input for the active approval-bound CBOR request only, emits no direct HID reply, ignores non-CBOR or non-matching traffic, and terminates the blocked CBOR flow with `CTAP2_ERR_KEEPALIVE_CANCEL` | correct | matches browser cancellation expectations for the implemented approval model | aligned |
| Spurious continuation packet | ignored when no transaction is active | correct | correct | aligned |
| Capability bits | advertises `WINK \| CBOR` and omits `NMSG` because `MSG` exists | correct | correct | aligned |
| U2F APDU validation | validates CLA / INS / P1 / P2 / exact APDU length before struct casts | correct | correct | aligned |

## CTAP2 commands

| Surface | Implemented behavior | Protocol bar | Interop bar | Classification |
| --- | --- | --- | --- | --- |
| `GetInfo` | advertises `FIDO_2_0`, `U2F_V2`, `rk=true`, `up=true`, `plat=false`, dynamic `clientPin`, and `minPINLength=4`; omits `uv` because built-in UV is not implemented | correct for current product model | matches browser expectations for a ClientPIN-only authenticator | aligned |
| `MakeCredential` with `rk=true` | creates and persists a discoverable credential, replacing any older resident credential for the same RP and user handle | correct | required for passkey/discoverable flows | aligned |
| `MakeCredential` with `rk=false` or absent | creates a non-resident credential record that is not used for RP-wide discovery | correct | keeps allow-list auth working without polluting discoverable lookup | aligned |
| `excludeList` hit | waits for approval before returning `CREDENTIAL_EXCLUDED` | correct | avoids a credential-existence oracle | aligned |
| `GetAssertion` with allow list | matches against stored credentials for the RP and credential ID, returns one applicable assertion after approval, and does not seed `GetNextAssertion` | correct | correct | aligned |
| `GetAssertion` without allow list | searches resident credentials only | correct | correct | aligned |
| `GetAssertion` unsupported options | rejects unsupported `options.rk` and built-in `options.uv=true` with unsupported-option semantics | correct | honest for the implemented feature set | aligned |
| Multiple assertions | discoverable multi-match requests on the display-capable device now show an on-device account chooser, return only the selected assertion, omit `numberOfCredentials`, and do not seed `GetNextAssertion`; queued follow-up assertions remain caller-bound for the non-display enumeration path | correct for the implemented display-capable product model | matches certification and browser expectations for resident multi-match account selection | aligned |
| On-device account chooser | implemented for discoverable `GetAssertion` multi-match flows using the on-device submenu UI, with selection as the only confirmation step and cancel / timeout mapped to the corresponding CTAP error | correct for a display-capable authenticator | required for spec-conformant resident multi-match behavior on this product | aligned |

## ClientPIN and UV

| Surface | Implemented behavior | Protocol bar | Interop bar | Classification |
| --- | --- | --- | --- | --- |
| `getRetries` | returns the persisted retry count and preserves blocked/decremented state across restart | correct for the implemented ClientPIN surface | matches browser expectations | aligned |
| `getKeyAgreement` | supported with a stable power-session key-agreement key and without rotating previously issued PIN tokens | correct for the implemented ClientPIN surface | required | aligned |
| `setPin` | supported; malformed key-agreement input is rejected as invalid parameters and `newPinEnc` auth/decrypt failures are rejected as `PIN_AUTH_INVALID` | correct | required | aligned |
| `changePin` | supported; malformed key-agreement input is rejected as invalid parameters, `pinHashEnc` failures consume retries like a wrong PIN, and `newPinEnc` auth/decrypt failures are rejected as `PIN_AUTH_INVALID` | correct | required | aligned |
| `PIN token issuance` | legacy `getPinToken` is supported with default `mc|ga` permissions and rejects `permissions` / `rpId` on the legacy path; `getPinUvAuthTokenUsingPinWithPermissions` is supported for `mc` / `ga` only, requires `permissions`, requires `rpId` for those permissions, stores permission-scoped token state, and clears those permissions after a successful UP-tested use | correct for the implemented ClientPIN surface | required for current browser PIN flows | aligned |
| Empty `pinAuth` compatibility probe | zero-length `pinAuth` is treated as a touch-required compatibility probe and returns `PIN_INVALID` when a PIN is set or `PIN_NOT_SET` otherwise | compatible with CTAP 2.0 compatibility behavior | matches browser authenticator-selection expectations | aligned |
| `pinUvAuthParam` verification | enforced from request semantics and verified independently of `options.uv` | correct | required for browser PIN flows | aligned |
| UV state | valid `pinUvAuthParam` sets UV for the request; no built-in UV is claimed | correct | correct | aligned |
| Retry/lockout persistence | persists retry counters in durable PIN state, restores them on restart, and persists `PIN_AUTH_BLOCKED` after three consecutive bad PIN or `pinAuth` attempts until the user explicitly clears it through the local ZeroFIDO UI | CTAP expects a real power-cycle-scoped temporary auth block; stock external apps do not have an app-owned retained power-session primitive, so this is an intentional product deviation | chosen as the least-fragile app-only behavior while keeping host software unable to clear the block silently | intentional deviation |

## Attestation and metadata

| Surface | Implemented behavior | Protocol bar | Interop bar | Classification |
| --- | --- | --- | --- | --- |
| Attestation format | emits `packed` only, returns an `x5c` array containing the ZeroFIDO leaf certificate, and runtime-validates that the leaf certificate is signed by the bundled root and that the attestation private key matches the leaf public key | correct for the current private-trust distribution model | useful for direct attestation flows, but public provenance should be interpreted conservatively | intentional deviation |
| `attestation: none` outcome | treated as RP/browser anonymization, not a second authenticator format | correct | correct | aligned |
| AAGUID | consistent across `GetInfo`, attested credential data, certificate extension, and metadata | correct | correct | aligned |
| Metadata `clientPin` | omitted from static metadata because runtime state is dynamic | avoids static/runtime contradiction | correct | aligned |
| Enterprise attestation | not claimed or implemented | correct for current product boundary | correct | aligned |

## Open non-goals
- ClientPIN permissions beyond minimal `mc` / `ga` token issuance (`cm`, `be`, `lbw`, `acfg`, later permissions flow expansion)

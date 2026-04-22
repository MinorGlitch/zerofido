# ZeroFIDO Metadata

This repo now includes a model metadata statement in
[12-metadata-statement.json](<repo>/docs/12-metadata-statement.json).

What it does:

- identifies the ZeroFIDO authenticator model by AAGUID
- describes the current transport, algorithms, user-verification model, and attestation trust root
- keeps the static model metadata aligned with the runtime contract instead of claiming dynamic state
- gives private relying parties a stable metadata document they can pin locally
- documents a shared project/model identity rather than an exclusive official-build identity

What it does not do by itself:

- it does not publish ZeroFIDO into the FIDO Alliance Metadata Service
- it does not make arbitrary public websites trust or display ZeroFIDO automatically
- it does not create a friendly provider name on sites that ignore non-MDS metadata

For a private relying party, the practical path is:

1. trust the attestation root from
   [11-attestation-root.pem](<repo>/docs/11-attestation-root.pem)
2. optionally inspect the shipped leaf certificate in
   [11-attestation-leaf.pem](<repo>/docs/11-attestation-leaf.pem)
3. ingest or pin
   [12-metadata-statement.json](<repo>/docs/12-metadata-statement.json)
4. verify that `MakeCredential` returns:
   - `fmt = "packed"`
   - an `x5c` array that begins with the ZeroFIDO leaf certificate
   - `authData` with AAGUID `b51a976a-0b02-40aa-9d8a-36c8b91bbd1a`

The current ZeroFIDO runtime returns only the attestation leaf certificate in `x5c`. Relying
parties that want to trust ZeroFIDO attestation should pin or import the root certificate
separately instead of expecting the authenticator to send the trust anchor on the wire.

If you want broader ecosystem recognition, the remaining step is publication and distribution, not a
different CTAP response:

- publish a stable vendor endpoint for the metadata statement
- provide relying-party integration guidance
- optionally pursue MDS publication if you want interoperable public metadata distribution

Current honest model statement:

- ZeroFIDO is a software authenticator model
- attestation is real and stable
- attestation identity is shared across builds of the ZeroFIDO project
- attestation key protection is software, not hardware-backed
- attestation should be treated as model/project identity, not official-distribution proof
- attestation subject literals are part of the shipped project-scoped trust identity and should not
  be treated alone as independent public-vendor proof
- metadata claims should stay aligned with that boundary
- `clientPin` is runtime state and is intentionally not hard-coded in the static metadata statement
- `uv` is omitted from the static metadata statement because ZeroFIDO does not implement built-in UV
- static `userVerificationDetails` only describe the supported external PIN plus on-device presence path

Version mapping:

- `application.fam` uses semantic version `1.0`
- `pyproject.toml` uses semantic version `1.0.0`
- metadata `authenticatorVersion` and `authenticatorGetInfo.firmwareVersion` encode semantic version
  as `major * 10000 + minor * 100 + patch`
- the current shipped build `1.0.0` is therefore represented as `10000` in
  [12-metadata-statement.json](<repo>/docs/12-metadata-statement.json)

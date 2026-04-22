# ZeroFIDO Attestation

`zerofido` returns a `packed` attestation statement from `MakeCredential`.

Model identity:

- AAGUID: `b51a976a-0b02-40aa-9d8a-36c8b91bbd1a`
- attestation leaf subject: `C=BG, O=ZeroFIDO, OU=Authenticator Attestation, CN=ZeroFIDO Software Authenticator`
- attestation root subject: `C=BG, O=ZeroFIDO, CN=ZeroFIDO Root CA`
- root SHA-256 fingerprint: `57:03:8B:6B:23:08:E7:2B:A2:B9:3E:97:EA:DD:25:FA:EF:A3:5C:0E:CB:D1:AC:B1:44:88:E6:AF:B1:5F:08:1A`

Important boundary:

- this is a software attestation model
- the attestation identity is shared across builds of the ZeroFIDO project
- it identifies the ZeroFIDO software authenticator model, not a hardware-protected secure element
- it does not prove that a credential came from an exclusive official ZeroFIDO binary
- the subject literals are part of the shipped ZeroFIDO project identity used for explicit private
  trust pinning; do not treat them on their own as independent proof of public legal-vendor status

Operationally:

- browsers or RPs that request `attestation: "none"` may still anonymize provider identity and AAGUID
- RPs that want to trust ZeroFIDO attestation need to pin or import the root certificate from
  [11-attestation-root.pem](<repo>/docs/11-attestation-root.pem)
- the public leaf certificate is available in
  [11-attestation-leaf.pem](<repo>/docs/11-attestation-leaf.pem)
- public websites may still show `Name: (Unavailable)` unless they request direct attestation and
  have metadata or local trust policy for this model
- runtime self-checks verify the leaf certificate's `TBSCertificate` signature against the bundled
  root public key and verify that the attestation private key matches the leaf public key

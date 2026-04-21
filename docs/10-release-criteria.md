# Milestone 9: Release Criteria

## Objective

Freeze the rules for calling the app released, and define the boundary between a usable Phase 1 app and a broader-compatibility release.

## Exact Implementation Scope

- Define supported firmware version policy.
- Define supported browser and client matrix policy.
- Define allowed and forbidden security claims.
- Define Phase 1 release label and what it permits.
- Define Phase 2 broad-compatibility label and what it permits.
- Define regression checklist requirements before each release cut.
- Define known limitations that must stay visible in release materials.

## Dependencies

- Milestone 7 passed for a Phase 1 release decision
- Milestone 8 passed for a broad-compatibility release decision
- current test matrix documented and reproducible

## Non-Goals

- no certification claim
- no secure-element claim
- no statement that keys are non-extractable under physical compromise

## Exit Criteria

- release statement matches tested behavior exactly
- unsupported claims are explicitly forbidden
- compatibility wording differs clearly between Phase 1 and Phase 2

## Failure Conditions

- release materials over-claim compatibility
- release materials over-claim security properties
- test matrix is missing or too vague to back the stated claims

## Verification Checklist

- review release wording against implemented features
- review release wording against the tested environment matrix
- confirm Phase 1 language does not imply broad compatibility
- confirm Phase 2 language is blocked until `ClientPIN` is proven
- confirm known limitations remain visible in public materials

## Review Notes

This document is necessary because the app is intended to be real and user-facing. Without it, product claims will drift faster than the implementation.

The separation between Phase 1 and Phase 2 is the critical part of the document. It keeps “usable now” from quietly turning into “broadly compatible” without the required work.

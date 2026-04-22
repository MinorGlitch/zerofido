# Current-state proof taxonomy

This document defines the proof and verdict vocabulary for M001 current-state audit work.
It is written for later audit slices that need to record what the current tree claims, what the current tree actually proves, and what still requires live-device or browser revalidation.
After reading it, a later slice author should be able to write a finding without accidentally treating source review, local regression output, historical remediation notes, and hardware-only proof as the same kind of evidence.

## Grounding rules

- [Release criteria](10-release-criteria.md) require shipped wording to match tested behavior exactly and treat over-claims as release failures.
- [Metadata notes](12-metadata.md) distinguish static model identity from dynamic runtime state; a metadata statement cannot be stretched into proof of live behavior it does not encode.
- [Milestone 10 protocol remediation](15-milestone-10-protocol-remediation.md) records useful historical fixes, but its own notes keep live CTAP, ClientPIN, transport, and U2F probes explicitly deferred when hardware was not attached.
- Decision `D003` means README, metadata, attestation, and release-language over-claims are audit failures, not harmless wording drift.
- Decision `D004` fixes the allowed proof taxonomy for M001 and forbids collapsing source review, local tests, live-risk hypotheses, and hardware-only gaps into one certainty bucket.
- Decision `D005` allows targeted local checks when they materially strengthen a finding, but forbids treating generic ritual verification as proof for claims it did not actually test.

## Allowed proof labels

| Proof label | Legal when | Required evidence | Illegal when |
| --- | --- | --- | --- |
| `source-proven` | The claim is limited to what the tracked source tree, shipped docs, metadata, or static assets currently say or encode. | Cite the current files, functions, tables, or assets that were read in the current tree. | Do not use it to claim live browser interoperability, hardware semantics, or physical security properties that were not exercised. |
| `test-proven` | The claim is backed by a named local command, regression, or unit test that was run against the current tree and directly covers the behavior being discussed. | Name the command or test case and the observed result, then keep the claim scoped to what that test actually exercised. | Do not use it to imply unrun platforms, browsers, transports, or attached-hardware behavior. |
| `live-risk hypothesis` | Current code, docs, or local checks suggest a plausible live failure mode, but the behavior has not yet been reproduced in the required live environment. | Pair the local evidence with an external reference that explains why the risk matters or why the unverified behavior could fail in practice. | Do not use it as a substitute for a confirmed failure or a confirmed pass. |
| `not proven without hardware` | Closing the question honestly requires attached hardware, live browser behavior, or another physical/runtime proof surface that M001 does not currently have. | State the exact live probe or hardware-only property that is still missing and why source/local tests cannot settle it. | Do not use it when the current source tree or local tests already settle the claim. |

## Allowed verdict vocabulary

| Verdict | Meaning | Closure rule |
| --- | --- | --- |
| `supported-current-state` | The current claim is supported by the cited current evidence and does not overstate what was actually proven. | Legal only when the local claim, proof label, and evidence scope all align without hidden live-runtime assumptions. |
| `audit-failure` | The current public claim, behavior, or metadata is stronger than the current proof or contradicts the current tree. | Required when D003 is triggered by an over-claim, contradiction, or unsupported current-state statement. |
| `needs-revalidation` | The repo contains useful evidence or historical remediation, but the current slice cannot honestly close the claim yet. | Use when later targeted replay, cross-checking, or slice work is still needed before the claim can be called supported. |
| `hardware-gap` | The remaining uncertainty is specifically a live-device, browser, transport, or physical-proof gap. | Use only when the matching proof label is `not proven without hardware`; this is not a soft pass. |

## Required finding fields

| Field | Why it is required |
| --- | --- |
| `Local claim` | Forces the finding to quote or restate the exact current claim being audited instead of drifting into vague topic labels. |
| `Proof label` | Prevents source review, local tests, live-risk hypotheses, and hardware-only gaps from being blended together. |
| `Current code/test evidence` | Records the current-tree evidence actually inspected or run, so later slices can replay or challenge it. |
| `External reference` | Anchors the finding against a spec rule, release-policy statement, metadata boundary, or historical remediation note instead of private interpretation. |
| `Impact` | Makes the consequence explicit for users, relying parties, or downstream audit slices so trivial wording differences do not hide material risk. |

## Reusable finding template

Every later audit finding should use this shape.
If a field cannot be filled honestly, the finding is not ready to be closed.

```md
### Finding <ID>: <short title>
- Local claim: <precise current-state statement under audit>
- Verdict: `audit-failure`
- Proof label: `source-proven`
- Current code/test evidence: <current files read, commands run, and observed result>
- External reference: <spec clause, release-policy rule, metadata boundary, or historical remediation note>
- Impact: <why this matters for users, relying parties, or later slices>
- Revalidation / next check: <later slice, live probe, or hardware check that would retire the remaining uncertainty>
```

Template rules:

- `source-proven` findings may cite current source and documentation only; they must not silently inherit live confidence from historical notes.
- `test-proven` findings must name the exact local command or test case, not just say that regressions exist.
- `live-risk hypothesis` findings must keep the verdict open until the live behavior is actually exercised.
- `not proven without hardware` findings must say what attached-hardware or browser proof is still missing, and they must keep release wording conservative until that proof exists.

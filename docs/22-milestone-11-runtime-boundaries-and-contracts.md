# Milestone 11: Runtime Boundaries And Contracts

## Progress

Status: `complete`

- [x] Freeze the target runtime layering in repo docs.
- [x] Freeze the ownership rules that stop USB, protocol, and core logic from bleeding together.
- [x] Freeze the initial contract surfaces for runtime config, transport adapters, and normalized
      dispatch.
- [x] Record the next resume step for the code milestone that follows.

## Objective

Define the hard architectural rules and the central runtime contract surfaces before any code
movement starts.

## Exact Implementation Scope

- Define the target layering:
  - `transport adapters`
  - `protocol adapters`
  - `authenticator core`
- Freeze the hard rules:
  - USB is an adapter only.
  - FIDO2/U2F are protocol adapters only.
  - The core owns authenticator behavior only.
  - No protocol code may call USB/HID APIs.
  - No transport code may contain `MakeCredential`, `GetAssertion`, `ClientPIN`, or U2F business
    logic.
- Freeze the central contract names for later code milestones:
  - `ZfRuntimeConfig`
  - `ZfResolvedCapabilities`
  - `ZfTransportAdapterOps`
  - `ZfProtocolDispatchRequest`
  - `ZfProtocolDispatchResult`

## Required Interfaces / Types

- `ZfRuntimeConfig`
  - runtime settings and selected protocol/profile enablement
- `ZfResolvedCapabilities`
  - fully resolved effective behavior after startup resolution
- `ZfTransportAdapterOps`
  - adapter-facing operations for transport lifecycle and dispatch plumbing
- `ZfProtocolDispatchRequest`
  - normalized input from transport adapter to protocol layer
- `ZfProtocolDispatchResult`
  - normalized output from protocol/core back to the transport layer

These names are frozen here so later milestones do not reinvent them mid-refactor.

## Exit Criteria

- The rules above are written in-repo and treated as the authoritative refactor boundary.
- The contract surfaces are named and fixed before code movement starts.
- The next milestone has an explicit handoff state.

## Failure Conditions

- Code movement starts before the architectural rules are frozen.
- Later milestones rename or reshape the contract surfaces ad hoc without updating this milestone.
- USB/HID details continue to leak upward because the boundary was never written down clearly.

## Verification Checklist

- Verify the overview and this milestone agree on the layering and contract names.
- Verify milestone 12 is the only active next step.
- Verify no code claims were made here; this milestone is documentation and boundary freezing only.

## Handoff State

- Completed items:
  - Architecture rules frozen in `docs/21-refactor-overview.md`.
  - Contract surface names frozen here for later code milestones.
- Current blocker:
  - None in this milestone.
- Exact next resume step:
  Start milestone 12 by inspecting the current startup/config/settings surfaces and adding the
  central runtime config and capability-resolution scaffolding in code.


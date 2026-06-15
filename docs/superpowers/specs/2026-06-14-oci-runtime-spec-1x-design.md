# OCI Runtime-Spec 1.x Bundle Compatibility For systemd-nspawn

## Goal

Allow `systemd-nspawn --oci-bundle=` to accept any OCI runtime-spec `1.x` bundle that systemd can safely interpret, instead of rejecting everything except `ociVersion == "1.0.0"`.

This change is specifically about OCI runtime bundles (`config.json` with `ociVersion`), not OCI image-spec manifests, image layouts, or conversion workflows.

## Current State

Today `systemd-nspawn` hard-rejects any OCI bundle whose top-level `ociVersion` is not exactly the string `1.0.0`.

The version gate is implemented in `src/nspawn/nspawn-oci.c` after parsing `config.json` and before dispatching the remaining bundle fields into `Settings`.

The current test suite also encodes this behavior by asserting that an arbitrary non-`1.0.0` version fails in `test/units/TEST-13-NSPAWN.nspawn-oci.sh`.

## Scope

In scope:

- Accept OCI runtime-spec bundles declaring `ociVersion` in the `1.x.y` line.
- Preserve parser strictness for malformed or unsupported bundle content.
- Keep failure behavior for requested semantics that systemd cannot safely realize.
- Update tests to reflect `1.x` compatibility.

Out of scope:

- Supporting OCI runtime-spec major versions other than `1`.
- Rewriting or mutating OCI bundles on disk.
- Adding support for currently unsupported OCI runtime features solely because a newer `1.x` bundle may mention them.
- Changing OCI image-spec import or conversion code in `src/import/pull-oci.c`, unless a separate issue is later identified there.

## Compatibility Contract

`ociVersion` should be treated as a runtime-spec compatibility declaration, not an exact version fingerprint.

The loader will:

- Accept OCI runtime-spec bundles with major version `1`.
- Reject malformed `ociVersion` strings.
- Reject major versions other than `1`, such as `0.x` or `2.x`.

Acceptance of a `1.x` bundle does not imply support for every feature introduced anywhere in the runtime spec's `1.x` history. The compatibility rule is narrower:

- Parse and enforce fields systemd already implements.
- Ignore unknown or newer fields only when ignoring them does not change the semantics of the behavior systemd does implement.
- Reject bundles that request behavior systemd recognizes but cannot safely preserve.

This follows the user's selected policy: fail only when semantics would be lost or changed, and otherwise ignore unsupported additions with warnings where appropriate.

## Runtime Spec Versus Image Spec

This work is for OCI runtime bundles consumed by `systemd-nspawn --oci-bundle=`.

It is not the same as OCI image-spec support:

- OCI runtime spec defines the `config.json` bundle format used by runtimes.
- OCI image spec defines image layouts, indexes, manifests, layers, and image configuration objects.

In the current systemd tree, `src/nspawn/nspawn-oci.c` handles runtime bundles, while `src/import/pull-oci.c` handles OCI image-spec downloads and translates image configuration into `.nspawn` settings. Those are separate subsystems and should remain separate in this design.

## Proposed Implementation

### Version Parsing

Replace the current exact string comparison with a small helper dedicated to OCI runtime-spec version validation.

The helper should:

- Accept a string from the top-level `ociVersion` field.
- Parse it as a SemVer-like `major.minor.patch` version.
- Return success only when `major == 1`.
- Return a precise error for malformed version strings or unsupported major versions.

The helper should be invoked immediately after the JSON object is loaded and before dispatching the rest of the bundle.

### Parser Behavior

The rest of the parser should remain structurally strict.

The change should not weaken existing validation for:

- required fields
- invalid types
- malformed field contents
- explicitly unsupported semantics that systemd cannot safely emulate

The existing distinction between "unexpected" and "unsupported" OCI content remains useful and should be preserved:

- "unexpected" means structurally invalid or not acceptable at that location
- "unsupported" means recognized, but intentionally not implemented

No general "downgrade everything to 1.0 semantics" layer is proposed in the first patch.

Instead:

- accept `1.x`
- continue validating each field on its own merits
- add version-specific normalization later only if concrete `1.1+` semantic differences are found to affect fields systemd already interprets

## In-Memory Only Compatibility

The implementation should not rewrite `config.json` and should not create migrated bundle copies on disk.

Reasons:

- parsing compatibility can be decided entirely in memory
- rewriting bundles would introduce side effects into a runtime path
- persisted migration artifacts would complicate trust, debugging, and ownership
- systemd should remain a consumer of OCI runtime bundles, not a mutating bundle converter

## Safety Rules

The following rules define when a `1.x` bundle is accepted or rejected:

- A newer `1.x` version number by itself is never a reason to reject the bundle.
- A malformed `ociVersion` string is rejected.
- A non-`1` major version is rejected.
- A malformed supported field is rejected.
- A recognized field requesting behavior systemd cannot safely preserve is rejected.
- A new or unknown field may be ignored only when doing so does not alter the semantics of the behavior systemd otherwise applies.

This keeps acceptance aligned with runtime-spec compatibility while avoiding silent semantic drift.

## Testing Plan

### Integration Test Updates

Update `test/units/TEST-13-NSPAWN.nspawn-oci.sh` so that:

- `1.0.0` still succeeds
- representative newer `1.x` values such as `1.1.0` succeed
- a non-`1` major version such as `2.0.0` fails
- malformed version strings fail

The current test named around "invalid OCI bundle version" should be adjusted to reflect unsupported major versions rather than any non-`1.0.0` string.

### Fuzz And Sample Coverage

Update or extend `test/fuzz/fuzz-nspawn-oci/` inputs so version handling is not permanently coupled to the exact `1.0.0` string.

At minimum:

- retain an existing `1.0.0` sample
- add at least one `1.1.x` sample
- add a malformed or unsupported-major sample if there is a convenient place for a negative corpus case

### Verification Focus

Verification should specifically confirm:

- newer `1.x` bundles pass the version gate
- current valid `1.0.0` bundles are unaffected
- invalid or unsupported-major versions still fail early and clearly
- existing unsupported runtime features continue to fail as before

## Risks

The primary risk is silent semantic mismatch: accepting a newer `1.x` bundle while unintentionally dropping behavior that matters.

This design controls that risk by:

- limiting automatic acceptance to major version `1`
- keeping per-field validation strict
- refusing semantics systemd knows it cannot preserve
- avoiding on-disk migration or rewriting

Another risk is overcomplicating the first patch with speculative compatibility machinery. This design avoids that by keeping the first change narrowly focused on semver-aware acceptance and leaving any future normalization layer to a later patch if real evidence requires it.

## Open Questions

None for the initial design.

The remaining implementation work is mostly mechanical:

- add version parsing helper
- replace exact string check
- adjust tests
- verify that no other runtime-bundle version gates exist

## Recommended Plan Hand-Off

The implementation plan should focus on:

1. introducing the OCI runtime-spec version parser/helper
2. updating the `oci_load()` gate to accept `1.x`
3. adjusting unit or integration coverage for `1.x`, malformed input, and unsupported major versions
4. verifying no behavior regressions in existing OCI bundle handling

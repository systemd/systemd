# UEFI Components Security Posture
The systemd project provides a UEFI boot menu, `systemd-boot`, and a stub that can wrap a Linux kernel in a
PE binary, adding various features, `systemd-stub`. These components fully support UEFI SecureBoot, and
this document will describe their security posture and how they comply with industry-standard expectations
for UEFI SecureBoot workflows.

Note that `systemd-stub` is not the same, or an alternative, to the Linux kernel's own EFI stub. The kernel
stub's role is that of the fundamental entrypoint to kernel execution from UEFI mode, implementing the
modern Linux boot protocol. `systemd-stub` on the other hand loads various resources, including the kernel
image, via the EFI LoadImage/StartImage protocol (although it does support the legacy Linux boot protocol,
as a fallback for older kernels on x86). The purpose of `systemd-stub` is to provide additional features and
functionality for `systemd-boot` and `systemd` (in userspace).

## Fundamental Security Design Goals
The fundamental security design goal for these components is the separation of security policy logic from the
rest of the functionality. This is achieved by offloading security-critical tasks to the firmware or earlier stages
of the boot process (in particular `Shim`).

When SecureBoot is enabled, these components are designed to avoid loading, executing, or using
unauthenticated payloads that could compromise the boot process, with special care taken for anything that
could affect the system before `ExitBootServices()` has been called. For example, when additional resources
are loaded, if running with SecureBoot enabled, they will be validated before use. The only exceptions are
the bootloader's own textual configuration files, and metadata parsed out of kernel images for display purposes
only. There are no build time or runtime configuration options that can be set to weaken the security model
of these components when SecureBoot is enabled.

The role of `systemd-boot` is to discover next stage components in the ESP (and XBOOTLDR if present), via
filesystem enumeration or explicit configuration files, and present a menu to the user to choose the next
step. This auto discovery mechanism is described in detail in the [BLS (Boot Loader
Specification)](https://uapi-group.org/specifications/specs/boot_loader_specification/).

The role of `systemd-stub` is to load and measure in the TPM the post-bootloader stages, such as the kernel,
initrd, and kernel command line, and implement optional features such as augmenting the initrd with
additional content such as configuration or optional services. [Unified Kernel
Images](https://uapi-group.org/specifications/specs/unified_kernel_image/) embed `systemd-stub`, a kernel
and other optional components as sections in a PE signed binary, that can thus be executed in UEFI
environments.

Since it is embedded in a PE signed binary, `systemd-stub` will temporarily disable the UEFI authentication
protocol while loading the payload kernel it wraps, in order to avoid redundant duplicate authentication of
the image, given that the payload kernel was already authenticated and verified as part of the whole image.
SecureBoot authentication is re-enabled immediately after the kernel image has been loaded.

Various EFI variables, under the vendor UUID `4a67b082-0a4c-41cf-b6c7-440b29bb8c4f`, are set and read by
these components. This is used to pass metadata and configuration between different stages of the boot process, as
defined in the [Boot Loader Interface](https://systemd.io/BOOT_LOADER_INTERFACE/).

## Dependencies
Neither of these components implements cryptographic primitives, cryptographic checks, or drivers. File
access to the ESP is implemented solely via the appropriate UEFI file protocols. Verification of next stage
payloads is implementend solely via the appropriate UEFI image load protocols, which means `authenticode`
signature checks are again done by the firmware or `Shim`. As a consequence, no external security-critical
libraries (such as OpenSSL or gnu-efi) are linked, embedded, or used.

## Additional Resources
BLS Type #1 entries allow the user to load two types of additional resources that can affect the system
before `ExitBootServices()` has been called — kernel command line arguments and DeviceTree blobs — that are
not validated before use, as they do not carry signatures. For this reason, when SecureBoot is enabled,
loading these resources is automatically disabled. There is no override for this security mechanism, neither
at build time nor at runtime. Note that initrds are also not verified in BLS Type #1 configurations, for
compatibility with how SecureBoot has been traditionally handled on Linux-based OSes, as the kernel will
only load them after `ExitBootServices()` has been called.

Another mechanism is supported by `systemd-boot` and `systemd-stub` to add additional payloads to the boot
process: "addons". Addons are PE signed binaries that can carry kernel command line arguments or DeviceTree
blobs (more payload types might be added in the future).
In contrast to the user-specified additions in the Type #1 case
described above, these addons are loaded through the UEFI image loading protocol, and thus are subject to
signature validation, and will be rejected if not signed or if the signature is invalid, following the
standard SecureBoot model. They are also measured in the TPM.

`systemd-boot` will also load file system drivers that are stored in the ESP, to allow enhancing the
firmware's capabilities. These are again PE signed binaries and will be verified using the appropriate
UEFI protocol.

A random seed will be loaded and passed to the kernel for early-boot entropy if found in the ESP.
It is mixed with various other sources of entropy available in the UEFI environment, such as the RNG
protocol, the boot counter and the clock. Moreover, the seed is updated before the kernel is invoked, as
well as after the kernel is invoked (from userspace), with a new seed derived from the Linux kernel entropy
pool.

When operating as a virtual machine payload, the loaded payloads can be customized via `SMBIOS Type 11
Strings`. Those settings are specified by the hypervisor and trusted.
They are automatically disabled if running inside a confidential computing VM.

## Certificates Enrollment
When SecureBoot is supported, but in `setup` mode, `systemd-boot` can enroll user certificates if a set of
`PK`, `KEK` and `db` certificates is found in the ESP. Afterwards, SecureBoot is enabled and a firmware
reset is performed. When running on bare metal, the certificates will be shown to the user on the console,
and manual confirmation is required before proceeding. When running as a virtual machine payload,
enrollment is fully automated without user interaction, unless disabled via a configuration file in the
ESP. The configuration file can also be used to disable enrollment completely.

## Compiler Hardening
The PE binaries are built with `-fstack-protector-strong`, and the stack canary is seeded with random data if
the UEFI RNG protocol is available.

The binaries also are linked with `-z relro` and ship with native PE relocations, with the conversion from
ELF performed at build time, instead of containing ELF dynamic relocations, so the image loaded by
firmware/Shim requires fewer writable pages.

The binaries are linked by default with full LTO support, so no code will be shipped unless it's reachable.

Finally, the binaries ship with the `NX_COMPAT` bit set.

The CI infrastructure also employs fuzz testing on various components, including string functions and the
BCD parser.

## SBAT
`systemd-boot` and `systemd-stub` are built with an `SBAT` section by default. There are build options to
allow customizations of the metadata included in the section, that can be used by downstream distributors.
The `systemd` project will participate in the coordinated `SBAT` disclosure and metadata revision process as
deemed necessary, in coordination with the Shim Review group.

The upstream project name used to be unified (`systemd`) for both components, but since version 255 has
been split into separate `systemd-boot` and `systemd-stub` project names, so that each component can be
revisioned independently. Most of the code tends to be shared between these two components, but the
overlap is not complete, so a future vulnerability may affect only one of the components.

## Known Vulnerabilities
There is currently one known (and fixed) security vulnerability affecting `systemd-boot` on arm64 and
riscv64 systems. For details of the affected and fixed versions, please see the [published security
advisory.](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c)

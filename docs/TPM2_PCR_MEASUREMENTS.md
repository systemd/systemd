---
title: TPM2 PCR Measurements Made by systemd
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# TPM2 PCR Measurements Made by systemd

Various systemd components issue TPM2 PCR measurements during the boot process,
both in UEFI mode and from userspace. The following lists all measurements
done, and describes (in case done before `ExitBootServices()`) how they appear
in the TPM2 Event Log, maintained by the PC firmware. Note that the userspace
measurements listed below are (by default) only done if a system is booted with
`systemd-stub` — or in other words: systemd's userspace measurements are linked
to systemd's UEFI-mode measurements, and if the latter are not done the former
aren't made either.

See
[UAPI.7 Linux TPM PCR Registry](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)
for an overview of PCRs.

systemd will measure to PCRs 5 (`boot-loader-config`), 11 (`kernel-boot`),
12 (`kernel-config`), 13 (`sysexts`), 15 (`system-identity`).

Currently, four components will issue TPM2 PCR measurements:

* The [`systemd-boot`](https://www.freedesktop.org/software/systemd/man/latest/systemd-boot.html) boot menu (UEFI)
* The [`systemd-stub`](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html) boot stub (UEFI)
* The [`systemd-pcrextend`](https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrphase.service.html) measurement tool (userspace)
* The [`systemd-cryptsetup`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptsetup@.service.html) disk encryption tool (userspace)

A userspace measurement event log in a format close to TCG CEL-JSON is
maintained in `/run/log/systemd/tpm2-measure.log`. Userspace measurements into
CC measurement registers (see below) are recorded in
`/run/log/systemd/cc-measure.log` in the same format.

## Measurements Added in Future

We expect that we'll add further PCR extensions in future (both in firmware and
user mode), which also will be documented here. When executed from firmware
mode future additions are expected to be recorded as `EV_EVENT_TAG`
measurements in the event log, in order to make them robustly
recognizable. Measurements currently recorded as `EV_IPL` will continue to be
recorded as `EV_IPL`, for compatibility reasons. However, `EV_IPL` will not be
used for new, additional measurements.

## NvPCR Measurements

Since the PCR number space is very small, systemd userspace supports additional
PCRs implemented via TPM2 NV Indexes (here called *NvPCRs*, even though they
are no less volatile than classic PCRs), using the `TPM2_NT_EXTEND` type. These
mostly behave like real PCRs, but we can allocate them relatively freely from
the NV index handle space.

The NV index range to use for this is configurable at build time, so that
downstreams have some flexibility to change this if they want. This uses the
0x01d10200 NV index as base by default. To abstract the actual nvindex number
away there's a naming concept, so that nvindexes are referenced by name string
rather than number.

NvPCRs are defined in little JSON snippets in `/usr/lib/nvpcr/*.nvpcr`, that
match up index number and name, as well as pick a hash algorithm. The recognized
fields are:

* `name` — the NvPCR name (string), which must match the file name (without the
  `.nvpcr` suffix). Mandatory.
* `nvIndex` — the fixed TPM2 NV index handle (number) to allocate for this NvPCR.
  Mandatory.
* `algorithm` — the hash algorithm to use (string), e.g. `sha256` (the default).
* `priority` — an unsigned integer allocation priority, defaulting to `1000`.
  Lower values are considered more important and are allocated first. This only
  affects the order in which `systemd-tpm2-setup.service` attempts allocation at
  boot: if the TPM's NV index space is too small to fit all NvPCRs, the most
  important ones (lowest `priority` value) win the available space, and the
  least important ones are skipped gracefully rather than the allocation failing
  arbitrarily. Ties are broken by name. Priority does not affect the NV index,
  the algorithm, or anything measured into the NvPCR.
* `orderly` — a boolean, defaulting to `true`. It controls whether the NV index
  is allocated with the `TPMA_NV_ORDERLY` attribute set, which selects whether
  the TPM keeps the NV index in RAM or in persistent memory (NVRAM). On
  physical TPMs RAM is typically much more constrained than persistent memory,
  but persistent memory is subject to wear. We hence prefer `TPMA_NV_ORDERLY`
  disabled (i.e. NVRAM) for NvPCRs that are written only once each boot — which
  translates into a conservative number of write cycles over the lifetime of a
  TPM — but enabled (i.e. RAM) for NvPCRs we expect to be written many times
  during runtime, so that we minimize wear. This reflects real-life experience
  where the RAM in TPMs is so constrained that allocating many NvPCRs in TPM
  RAM simply doesn't work. For now, only the `hardware` NvPCR (which is written
  just once, early at boot) sets this flag to false.

There's one complication: these NV indexes (like any NV indexes) can be deleted
by anyone with access to the TPM, and then be recreated. This could be used to
reset the NvPCRs to zero during runtime, which defeats the whole point of
them. Our way out: we measure a secret as first thing after creation into the
NvPCRs. (Or actually, we measure a per-NvPCR secret we derive from a system
secret via an HMAC of the NvPCR name and the NV index handle). This "anchoring"
secret is stored in `/run/` + `/var/lib/` + ESP/XBOOTLDR (the latter encrypted
as credential, locked to the TPM), to make it available at the whole runtime of
the OS. It's only accessible to privileged processes with access to the
TPM. Due to this, any process with access to the TPM and read access to any of
the storage locations of the anchor secret is considered part of the TCB, as
they are able to replay the NvPCR with their own content at will, so due care
must be employed when designing a system that uses this feature.

## Runtime measurements on Confidential VMs

On confidential VMs that provide runtime measurement registers, systemd userspace
measures into those too, in addition to (or in absence of) a TPM2. This is
currently implemented for Intel TDX RTMRs, via the Linux kernel's sysfs
interface for TSM measurement registers (Linux 6.16+,
`/sys/devices/virtual/misc/tdx_guest/measurements/`).

PCR-indexed measurements are mapped to the existing runtime measurement registers,
if possible based on the existing UEFI specification. For TDX, measurements are
following the fixed mapping of the UEFI specification (v2.10, section 38.4.1),
which is the same mapping the virtual firmware uses:

| PCR   | TDX register          |
|-------|-----------------------|
| 0     | MRTD (boot-time only) |
| 1, 7  | RTMR0                 |
| 2–6   | RTMR1                 |
| 8–15  | RTMR2                 |
| 16–23 | not mapped            |

NvPCR measurements have no UEFI-defined mapping and are measured into RTMR2 by
systemd convention, next to the other OS-level measurements. Note the
semantic difference to the TPM2 counterpart: RTMRs are strictly per-boot,
i.e. the cross-boot accumulation that persistent NvPCRs provide does not
transfer, and NvPCR anchoring is a TPM2-only concept that is never mirrored to RTMRs.

Userspace RTMR measurements are recorded in
`/run/log/systemd/cc-measure.log`, in the same CEL-JSON-like format
as `tpm2-measure.log`. Records carry an `rtmr` field (the register number, as
used in the sysfs attribute names) in place of the `pcr`/`nv_index` field,
plus an informational `mapped_pcr` field naming the PCR the measurement was
mapped from. NvPCR-mapped events carry no `mapped_pcr`; they are identified by
the `nvIndexName` field of their `content` object. Across both log files,
exactly one register key (`pcr`, `nv_index` or `rtmr`) is present per record,
and the `content` object has the same structure.

To verify (replay) an RTMR, process the firmware CC event log (the CCEL ACPI
table, exposed at `/sys/firmware/acpi/tables/data/CCEL`), followed by the
records for that register from `/run/log/systemd/cc-measure.log`, in file
order.

Userspace measurements (and hence the OS measurement services) are only
enabled if the kernel was measured by `systemd-stub` via the UEFI CC measurement
protocol. Kernels booted without `systemd-stub` are still measured by the virtual
firmware, but do not enable the systemd userspace measurement machinery, matching
the behavior on TPM2 systems.

The RTMR sysfs interface is provided by the kernel's `tdx-guest` driver. Where
it is built as a module, `systemd-tpm2-generator` makes `tpm2.target` wait for
the device to show up, so that the early measurement services (which order
themselves after that target) do not start before the interface is available.
For measurements from within the initrd (such as the `enter-initrd` boot
phase), the module must be included in the initrd; kernels that build the
driver in need no special handling.

## PCR Measurements Made by `systemd-boot` (UEFI)

### PCR 1, `EV_EVENT_TAG`, SMBIOS information

Select SMBIOS structures provided by the firmware are measured into PCR 1 (the
TCG-defined register for platform configuration data), one tagged event per
structure:

* SMBIOS type 1 (system information). The volatile "Wake-up Type" field is
  zeroed before measuring, since it varies depending on how the machine was
  powered on (cold boot, resume from sleep, AC restore, …) and would otherwise
  make the measurement non-reproducible.
* SMBIOS type 2 (baseboard information).
* SMBIOS type 11 (OEM strings). There may be more than one such structure; all
  are measured.

Note that these measurements are – strictly speaking – redundant, since
firmwares are supposed to measure SMBIOS data anyway on their own. However, it
has been found this is not the case on many real-life implementations. Since in
particular SMBIOS type 11 may carry highly relevant input for the OS
(e.g. system credentials), an explicit measurement is made here to ensure all
parameters for the OS are comprehensively measured even on flaky firmwares.

→ **Event Tag** `0xd5cb7cbc` for type 1, `0xe0d47bc8` for type 2, `0xc0b3bd23`
for type 11.

→ **Description** in the event log record is `smbios:type1`, `smbios:type2` or
`smbios:type11` respectively, in UTF-16.

→ **Measured hash** covers the raw bytes of the SMBIOS structure (formatted area
plus trailing string set), with the type 1 "Wake-up Type" field zeroed out as
described above.

This measurement is also performed by `systemd-stub` (see below), so that systems
that boot a UKI directly, bypassing `systemd-boot`, still get it. Whichever
component runs first performs the measurement and sets the volatile
`LoaderPcrSMBIOS` EFI variable to the PCR index used; its presence suppresses a
second measurement of the same data into the same PCR during the same boot. Note
that the firmware itself typically also extends PCR 1, so its final value is not
solely determined by this measurement.

### PCR 5, `EV_EVENT_TAG`, `loader.conf`

The content of `systemd-boot`'s configuration file, `loader/loader.conf`, is
measured as a tagged event.

→ **Event Tag** `0xf5bc582a`

→ **Description** in the event log record is the file name, `loader.conf`.

→ **Measured hash** covers the content of `loader.conf` as it is read from the ESP.

### PCR 12, `EV_IPL`, kernel command line

If the kernel command line was specified explicitly (by the user or in a Boot
Loader Specification Type #1 file), the kernel command line passed to the
invoked kernel is measured before it is executed. (In case an UKI/Boot Loader
Specification Type #2 entry is booted, the built-in kernel command line is
implicitly measured as part of the PE sections, because it is embedded in the
`.cmdline` PE section, hence doesn't need to be measured by `systemd-boot`; see
below for details on PE section measurements done by `systemd-stub`.)

→ **Description** in the event log record is the literal kernel command line in
UTF-16.

→ **Measured hash** covers the literal kernel command line in UTF-16 (without any
trailing NUL bytes).

## PCR Measurements Made by `systemd-stub` (UEFI)

### PCR 1, `EV_EVENT_TAG`, SMBIOS information

Identical to the SMBIOS measurement described above for `systemd-boot`. When
`systemd-stub` is invoked by `systemd-boot`, the measurement has typically already
been made (tracked via the `LoaderPcrSMBIOS` EFI variable) and is not repeated;
when the UKI is booted directly by the firmware, `systemd-stub` performs it
itself.

### PCR 11, `EV_IPL`, PE section name

A measurement is made for each PE section of the UKI that is defined by the
[UAPI.5 UKI
Specification](https://uapi-group.org/specifications/specs/unified_kernel_image/),
in the canonical order described in the specification.

Happens once for each UKI-defined PE section of the UKI, in the canonical UKI
PE section order, as per the UKI specification. For each record a pair of
records is written, first one that covers the PE section name (described here),
and the second one that covers the PE section data (described below), so that
both types of records appear interleaved in the event log.

→ **Description** in the event log record is the PE section name in UTF-16.

→ **Measured hash** covers the PE section name in ASCII (*including* a trailing NUL byte!).

### PCR 11, `EV_IPL`, PE section data

Happens once for each UKI-defined PE section of the UKI, in the canonical UKI
PE section order, as per the UKI specification, see above.

→ **Description** in the event log record is the PE section name in UTF-16.

→ **Measured hash** covers the (binary) PE section contents.

### PCR 12, `EV_IPL`, kernel command line

Might happen up to three times, for kernel command lines from:

 1. Passed cmdline
 2. System and per-UKI cmdline add-ons (one measurement covering all add-ons combined)
 3. SMBIOS cmdline

→ **Description** in the event log record is the literal kernel command line in
UTF-16.

→ **Measured hash** covers the literal kernel command line in UTF-16 (without any
trailing NUL bytes).

### PCR 12, `EV_EVENT_TAG`, DeviceTrees

DeviceTree addons are measured individually as a tagged event.

→ **Event Tag** `0x6c46f751`

→ **Description** is the addon filename.

→ **Measured hash** covers the content of the DeviceTree.

### PCR 12, `EV_EVENT_TAG`, initrd addons

Initrd addons are measured individually as a tagged event.

→ **Event Tag** `0x49dffe0f`

→ **Description** is the addon filename.

→ **Measured hash** covers the contents of the initrd.

### PCR 12, `EV_EVENT_TAG`, ucode addons

Ucode addons are measured individually as a tagged event.

→ **Event Tag** `0xdac08e1a`

→ **Description** is the addon filename.

→ **Measured hash** covers the contents of the ucode initrd.

### PCR 12, `EV_IPL`, per-uki credentials initrd

→ **Description** in the event log record is the constant string "Credentials
initrd" in UTF-16.

→ **Measured hash** covers the per-UKI credentials cpio archive (which is generated
 on-the-fly by `systemd-stub`).

### PCR 12, `EV_IPL`, global credentials initrd

→ **Description** in the event log record is the constant string "Global
credentials initrd" in UTF-16.

→ **Measured hash** covers the global credentials cpio archive (which is generated
on-the-fly by `systemd-stub`).

### PCR 13, `EV_IPL`, sysext initrd

→ **Description** in the event log record is the constant string "System extension
initrd" in UTF-16.

→ **Measured hash** covers the per-UKI sysext cpio archive (which is generated
on-the-fly by `systemd-stub`).

## PCR Measurements Made by `systemd-tpm2-setup` (Userspace)

### PCR 9, NvPCR Initializations

The `systemd-tpm2-setup-early.service` service initializes any NvPCRs defined via
`*.nvpcr` files. For each initialized NvPCR it will measure an event into PCR
9.

→ **Measured hash** covers the string `nvpcr-init:`, suffixed by the NvPCR
name, suffixed by `:0x`, suffixed by the NV Index handle (formatted in
hexadecimal), suffixed by a colon, suffixed by the hash function used, in
lowercase (i.e. `sha256` or so), suffixed by a colon, and finally suffixed by
the state of the NvPCR after its initialization with the anchor measurement, in
hexadecimal. Example:
`nvpcr-init:hardware:0x1d10200:sha256:de3857f637c61e82f02e3722e1b207585fe9711045d863238904be8db10683f2`

## PCR/NvPCR Measurements Made by `systemd-pcrextend` (Userspace)

### PCR 11, boot phases

The `systemd-pcrphase.service`, `systemd-pcrphase-initrd.service`,
`systemd-pcrphase-sysinit.service` services will measure the boot phase reached
during various times of the boot process. Specifically, the strings
"enter-initrd", "leave-initrd", "sysinit", "ready", "shutdown", "final" are
measured, in this order. (These are regular units, and administrators may
choose to define additional/different phases.)

→ **Measured hash** covers the phase string (in UTF-8, without trailing NUL
bytes).

### PCR 15, machine ID

The `systemd-pcrmachine.service` service will measure the machine ID (as read
from `/etc/machine-id`) during boot.

→ **Measured hash** covers the string "machine-id:" suffixed by the machine ID
formatted in hexadecimal lowercase characters (in UTF-8, without trailing NUL
bytes).

### NvPCR `hardware` (base+0), product UUID

The `systemd-pcrproduct.service` service will measure the product UUID (as
available from SMBIOS or Devicetree) of the host system, once at boot.

→ **Measured hash** covers the string "product-id:" suffixed by the product
UUID formatted in hexadecimal lowercase characters, without separators. If no
product UUID of the local system could be determined the string
"product-id:missing" is measured instead. Example string:
`product-id:4691595be6a345f1833cc75fab63e475`.

### PCR 15, file system

The `systemd-pcrfs-root.service` and `systemd-pcrfs@.service` services will
measure a string identifying a specific file system, typically covering the
root file system and `/var/` (if it is its own file system).

→ **Measured hash** covers the string "file-system:" suffixed by a series of six
colon-separated strings, identifying the file system type, UUID, label as well
as the GPT partition entry UUID, entry type UUID and entry label (in UTF-8,
without trailing NUL bytes).

### NvPCR `login` (base+3), user logins

The `systemd-pcrlogin@.service` service (a per-UID template unit started by
`systemd-logind.service` on a user's first login of the current boot) will
measure that user's record into the `login` NvPCR. Each user is measured exactly
once per boot (the unit is `Type=oneshot`/`RemainAfterExit=yes` and is never
stopped again), so the NvPCR forms an append-only record of which user
identities were activated during the current boot. Note that its value is
inherently dynamic: it depends on *which* users log in and *in which order*.

→ **Measured hash** covers the string "login:", suffixed by the (escaped)
user name, a colon, and the user's record reduced to its `regular`, `perMachine`
and `binding` sections (i.e. with the `privileged`, `secret`, `status` and
`signature` sections stripped), normalized and serialized to canonical,
single-line JSON. Example string:
`login:lennart:{"userName":"lennart","uid":1000,…}`.

### PCR 9, NvPCR initialization separator

After completion of `systemd-tpm2-setup-early.service` (which initializes all NvPCRs
and measures their initial state) at early boot the `systemd-pcrnvdone.service`
service will measure a separator event into PCR 9, isolating the early-boot
NvPCR initializations from any later additions.

→ **Measured hash** covers the string `nvpcr-separator`.

## PCR/NvPCR Measurements Made by `systemd-cryptsetup` (Userspace)

### PCR 15, volume key

The `systemd-cryptsetup@.service` service will measure a key derived from the
LUKS volume key of a specific encrypted volume, typically covering the backing
encryption device of the root file system and `/var/` (if it is its own file
system).

→ **Measured hash** covers the (binary) result of the HMAC(V,S) calculation where V
is the LUKS volume key, and S is the string "cryptsetup:" followed by the LUKS
volume name and the UUID of the LUKS superblock.

### NvPCR `cryptsetup` (base+1), LUKS unlock mechanism/key slot

The `systemd-cryptsetup@.service` service will measure information about the
used LUKS keyslot, and in particular include the used unlock mechanism (pkcs11,
tpm2, fido2, …) in it.

→ **Measured hash** covers the string "cryptsetup-keyslot:", suffixed by the DM
volume name, a ":" separator, the UUID of the LUKS superblock, a ":" separator,
a brief string identifying the unlock mechanism, a ":" separator, and finally
the LUKS slot number used. Example string:
`cryptsetup-keyslot:root:1e023a55-60f9-4b6b-9b80-67438dc5f065:tpm2:1`

## PCR/NvPCR Measurements Made by `systemd-veritysetup` + image dissection logic (Userspace)

### NvPCR `verity` (base+2), Verity root hash + signature info of activated Verity images

The `systemd-veritysetup@.service` service as well as any component using the
image dissection logic (i.e. `RootImage=` in unit files, or `systemd-nspawn
--image=`, `systemd-tmpfiles --image=` and similar) will measure information
about activated Verity images before they are activated.

→ **Measured hash** covers the string `verity:`, followed by the Verity device
name, followed by `:`, followed by a hexadecimal formatted string indicating
the root hash of the Verity image, followed by `:`, followed by a comma
separatec list of PKCS#7 signature key's serial (formatted in hexadecimal), `/`, and
key issuer (formatted in Base64).

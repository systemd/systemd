---
title: Recognizing TPM2 PCR Measurements Made by systemd
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Recognizing TPM2 PCR Measurements Made by systemd

Various systemd components issue TPM2 PCR measurements during the boot process,
both in UEFI mode and from userspace. The following lists all measurements
done, and describes (in case done before `ExitBootServices()`) how they appear
in the TPM2 Event Log, maintained by the PC firmware.

systemd will measure to PCRs 11, 12, 13, 15.

Note that the userspace measurements listed below are only done on systems
booted with `systemd-stub`.

## PCR Measurements Made by `systemd-boot` (UEFI)

### PCR 12, EV_IPL, "Kernel Command Line"

If the kernel command line was specified explicitly (by the user or in a Boot
Loader Specification Type #1 file), the kernel command line passed to the
invoked kernel is measured before it is executed.

*Description* in the event log record is the literal kernel command line in
UTF-16.

*Measured hash* covers the literal kernel command line in UTF-16 (without any
trailing NUL byte).

## PCR Measurements Made by `systemd-stub` (UEFI)

### PCR 11, EV_IPL "PE Section Name"

Happens once for each UKI-defined PE section of the UKI, in the canonical UKI
PE section order, as per the UKI specification. For each record a pair of
records are written, first one that covers the PE Section Name, and then one
that covers the "PE Section Data", so that both types of records appear
interleaved in the event log.

*Description* in the event log record is the PE section name in UTF-16.

*Measured hash* covers the PE section name in UTF-8 (including a trailing NUL byte!).

### PCR 11, EV_IPL, "PE Section Data"

Happens once for each UKI-defined PE section of the UKI, in the canonical UKI
PE section order, as per the UKI specification, see above.

Description in the event log record is the PE section name in UTF-16.

Measured hash covers the PE section contents.

### PCR 12, EV_IPL, "Kernel Command Line"

Might happen up to four times, for kernel command lines from:

 1. Passed cmdline
 2. System cmdline add-ons (one measurement covering all add-ons combined)
 3. Per-UKI cmdline add-ons (one measurement covering all add-ons combined)
 2. SMBIOS cmdline

*Description* in the event log record is the literal kernel command line in
UTF-16.

*Measured hash* covers the literal kernel command line in UTF-16 (without any
trailing NUL byte).

### PCR 12, EV_IPL, "Per-UKI Credentials initrd"

*Description* in the event log record is the constant string "Credentials
initrd" in UTF-16.

*Measured hash* covers the per-UKI credentials cpio archive (which is generated
 on-the-fly by `systemd-stub`).

### PCR 12, EV_IPL, "Global Credentials initrd"

*Description* in the event log record is the constant string "Global
credentials initrd" in UTF-16.

*Measured hash* covers the global credentials cpio archive (which is generated
on-the-fly by `systemd-stub`).

### PCR 13, EV_IPL, "sysext initrd"

*Description* in the event log record is the constant string "System extension
initrd" in UTF-16.

*Measured hash* covers the per-UKI sysext cpio archive (which is generated
on-the-fly by `systemd-stub`).

## PCR Measurements Made by `systemd-pcrextend` (Userspace)

### PCR 11, "Boot Phases"

The `systemd-pcrphase.service`, `systemd-pcrphase-initrd.service`,
`systemd-pcrphase-sysinit.service` services will measure the boot phase reached
during various times of the boot process. Specifically, the strings
"enter-initrd", "leave-initrd", "sysinit", "ready", "shutdown", "final" are
measured, in this order.

*Measured hash* covers the listed phase strings (in UTF-8).

### PCR 15, "Machine ID"

The `systemd-pcrmachine.service` service will measure the machine ID (as read
from `/etc/machine-id`) during boot.

*Measured hash* covers the string "machine-id:" suffixed by the machine ID
formatted in hexadecimal lowercase characters.

### PCR 15, "File System"

The `systemd-pcrfs-root.service` and `systemd-pcrfs@.service` services will
measure a string identifying a specific file system, typically covering the
root file system and `/var/` (if it is its own file system).

*Measured hash* covers the string "file-system:" suffixed by a series of six
colon-separated strings, identifying the file system type, UUID, label as well
as the GPT partition entry UUID, entry type UUID and entry label.

## PCR Measurements Made by `systemd-cryptsetup` (Userspace)

### PCR 15, "Volume Key"

The `systemd-cryptsetup@.service` service will measure a key derived from the
LUKS volume key of a specific encrypted volume, typically covering the backing
encryption device of the root file system and `/var/` (if it is its own file
system).

*Measured hash* covers the result of the HMAC(V,S) calculation where V := LUKS
volume key, and S := the string "cryptsetup:" followed by a the volume name and
the UUID of the LUKS superblock.

---
title: Factory Reset
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Factory Reset

In various scenarios it is important to be able to reset operating systems back
into a "factory state", i.e. where all state, user data and configuration is
reset so that it resembles the system state when it was originally shipped.

systemd natively supports a concept of factory reset, through a series of
generic hook points that can be integrated with a factory reset mechanism.
Factory reset always takes place during early boot, i.e. from a well-defined
"clean" state. Factory reset operations are requested from one boot to be
executed on the next.

The mechanism works as follows:

* The `factory-reset.target` unit is used to request a factory reset operation
  and trigger a reboot in order to execute it. Services invoked via this target
  prepare the system such that a factory reset will be requested on the next
  boot. Once these services are done,
  [`systemd-factory-reset-reboot.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-reboot.service.html)
  is started, which triggers the reboot.

* On the next boot, `systemd-factory-reset-generator` checks whether a factory
  reset was requested. A factory reset may be requested via a kernel
  command line option (`systemd.factory_reset=1`) or via the UEFI variable
  `FactoryResetRequest` (see below). If either condition is met,
  `factory-reset-now.target` is added to the boot transaction.

* `factory-reset-now.target` will be started at boot whenever a factory reset is
  requested. Services ordered before this target do the work of factory resetting
  the system. Once these services are done,
  [`systemd-factory-reset-complete.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-complete.service.html)
  marks the factory reset operation as completed. The boot process may then
  continue.

* The
  [`systemd-factory-reset`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset.html)
  tool can be used to query the current state of the factory request mechanism,
  i.e. whether a factory reset is currently being executed, or if one has been
  requested for the next boot.

* The `/run/systemd/io.systemd.FactoryReset` Varlink service provides two IPC
  APIs for working with factory reset: it permits querying whether the local
  system supports requesting a factory reset by starting
  `factory-reset.target`. This may be used by UIs to hide or show in the UI an
  interface to request a factory reset. The Varlink IPC service also reports
  the current factory reset state, much like the `systemd-factory-reset` tool
  mentioned above. This may be used by various early boot services that
  potentially intent to reset system state during a factory reset operation.

* The
  [`systemd-logind.service(8)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-logind.service.html)
  unit supports automatically binding factory reset to special keypresses
  (typically long presses). See the
  [`logind.conf(5)`](https://www.freedesktop.org/software/systemd/man/latest/logind.conf.html)
  man page.

## Implementation for UEFI systems

systemd also provides an implementation of this mechanism for UEFI-based systems.
This implementation can act completely standalone for distributions that rely on
tools like `systemd-repart`, but it can also be extended to meet other needs.

The UEFI support works as follows:

* The
  [`systemd-factory-reset-request.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-request.service.html)
  unit is invoked via `factory-reset.target`. It requests a factory reset
  operation for the next boot by setting the `FactoryResetRequest` EFI
  variable. The EFI variable contains information about the requesting OS, so
  that multi-boot scenarios are somewhat covered.

* The
  [`systemd-tpm2-clear.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-tpm2-clear.service.html)
  unit can request a TPM2 clear operation from the firmware on the next
  boot. It is also invoked via `factory-reset.target`. UEFI firmwares that
  support TPMs will ask the user for confirmation and then reset the TPM,
  invalidating all prior keys associated with the security chip and generating
  a new seed key.

* The
  [`systemd-factory-reset-esp.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-esp.service.html)
  unit is also invoked via `factory-reset.target`, and deletes non-vendor UKI
  companion files (i.e. system extension images and addons) from the EFI System
  and Extended Bootloader partitions. See the
  [`systemd-stub(7)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html)
  man page.

* The
  [`systemd-repart`](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html)
  tool is one of the early-boot services that do the work of factory resetting
  the system. In normal operation, it starts on every boot. When invoked during
  a factory reset, it will erase all partitions marked for that via the
  `FactoryReset=` setting in its partition definition files. Once that is
  complete, it will resume its usual setup operation, i.e. reformatting the
  empty partition with a file system.

## Support for non-UEFI Systems

On non-EFI systems, the `FactoryResetRequest` EFI variable cannot be used to
communicate the factory reset request to the next boot. Instead, a service that
somehow stores the request should be plugged into `factory-reset.target`. At
boot, the request should then be fed back into the booted kernel via the
`systemd.factory_reset=1` kernel command line option.

If your distribution provides a custom factory reset implementation, the Varlink
service doesn't know about this and will report that factory reset is unsupported.
You can correct this by setting the `SYSTEMD_FACTORY_RESET_SUPPORTED` environment
variable on `systemd-factory-reset@.service`.

Please consider the end-user's expectations for factory reset. For instance,
people will use this feature before selling their device. To that end, the factory
reset must do as much as it can to irrevocably destroy the user's data. Deleting
files or partitions isn't actually enough because the data is still there and
easily recoverable by various data recovery tools. Overwriting isn't enough for
modern SSDs, which will keep around chunks of the deleted data as part of their
wear-leveling. After you've carefully considered the capabilities of your factory
reset implementation, set the `SYSTEMD_FACTORY_RESET_SECURE` environment variable
on `systemd-factory-reset@.service`.

## Exposure in the UI

If a graphical UI shall expose a factory reset operation, it should first check
if requesting a factory reset is supported at all via the Varlink service
mentioned above. Once the end-user triggers a factory reset, the UI can start
the process by asking systemd to activate the `factory-reset.target` unit.

Alternatively, `systemd-logind.service`'s hotkey support may be used. For
example, it can be configured to request factory reset if the reboot button is
pressed for a long time.

The GUI should communicate the security properties of the factory reset that it
is offering to the user. Alternatively, it's perfectly appropriate to hide the
factory reset function entirely if only an insecure reset is available.

## Support for Resetting other Resources than Partitions + TPM

By default a factory reset implemented with systemd's tools can reset/erase
partitions (via `systemd-repart`, see above), reset the TPM (via
`systemd-tpm2-clear.service`, see above), and delete non-vendor resources from
the ESP (via `systemd-factory-reset-esp.service`, see above).

In some cases other resources shall be reset/erased too. To support that,
define your own service and plug it into `factory-reset-now.target` or the
Varlink service. Ensure that your service is ordered before the target.

## Factory Reset via Boot Menu

Factory reset can also be requested via the boot menu, by booting with certain
kernel command line arguments. The specifics vary by distribution, but here
are some pointers:

The most portable solution would be to boot with
`rd.systemd.unit=factory-reset.target` set. This will execute the entire factory
reset process from within the initrd, including a reboot. To preserve the state
of the TPM, you can pass `systemd.tpm2_allow_clear=false`.

Depending on the way your distribution uses the factory reset integration points,
a simpler case may be possible. Booting with `systemd.factory_reset=1` will
bypass `factory-reset.target` entirely, and skip a reboot. However, bear in mind
that this may have unintended consequences: some firmware or hardware may not be
completely reset this way, including the TPM.

Note that the portable solution requires that distributions include their entire
factory reset integration in the initrd. If that is undesirable, alternatives
do exist. For instance, image-based distributions that separate `/usr` from the
rootfs can use something like `root=tmpfs systemd.unit=factory-reset.target` to
trigger the factory reset from the real `/usr`.

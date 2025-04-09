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

* On the next boot, `systemd-factory-reset-generator` checks whether or not a
  factory reset was requested. A factory reset may be requested via a kernel
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
  requested for the next boot. It also provides the
  `/run/systemd/io.systemd.FactoryReset` Varlink service for the same purpose.
  Early boot services that wish to participate in factory reset should use this
  service to determine whether the system is currently being reset.

* Not all systems will support factory reset. It's possible that there's nothing
  listening for the factory reset request, and nothing happens before
  `factory-reset-now.target` is reached. To avoid this situation, factory reset
  should only be requested if the `/run/systemd/factory-reset-supported` stamp
  file exists. Early boot services that participate in factory reset can create
  this file if they determine that they have a meaningful amount of work to do.

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
  [`systemd-repart`](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html)
  tool is one of the early-boot services that do the work of factory resetting
  the system. In normal operation, it starts on every boot. When invoked during
  a factory reset, it will erase all partitions marked for that via the
  `FactoryReset=` setting in its partition definition files. Once that is
  complete, it will resume its usual setup operation, i.e. reformatting the
  empty partition with a file system. If any partition definitions have
  `FactoryReset=` enabled, `systemd-repart` will create the
  `/run/systemd/factory-reset-supported` stamp file.

## Support for non-UEFI Systems

On non-EFI systems, the `FactoryResetRequest` EFI variable cannot be used to
communicate the factory reset request to the next boot. Instead, a service that
somehow stores the request should be plugged into `factory-reset.target`. At
boot, the request should then be fed back into the booted kernel via the
`systemd.factory_reset=1` kernel command line option.

## Exposure in the UI

If a graphical UI shall expose a factory reset operation, it should first check
if requesting a factory reset is supported at all. This can be achieved by
checking whether `/run/systemd/factory-reset-supported` exists. Once the end-user
triggers a factory reset, the UI can start the process by asking systemd to
activate the `factory-reset.target` unit.

Alternatively, `systemd-logind.service`'s hotkey support may be used. For
example, it can be configured to request factory reset if the reboot button is
pressed for a long time.

## Support for Resetting other Resources than Partitions + TPM

By default a factory reset implemented with systemd's tools can reset/erase
partitions (via `systemd-repart`, see above) and reset the TPM (via
`systemd-tpm2-clear.service`, see above).

In some cases other resources shall be reset/erased too. To support that,
define your own service and plug it into `factory-reset-now.target`. Ensure that
your service is ordered before the target!

If your service should be enough to enable factory reset support, it should be
create `/run/systemd/factory-reset-supported` on every boot. Order the service
before `factory-reset.target`. You can use the Varlink API to determine at
runtime whether or not your service needs to perform the factory reset.

## Factory Reset via Boot Menu

Factory reset can also be requested via the boot menu, by booting with certain
kernel command line arguments. The specifics vary by distribution, but here
are some pointers:

The most potable solution would be to boot with
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


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

systemd natively supports a concept of factory reset, that can both act as a
specific implementation for UEFI based systems, as well as a series of hook
points and a template for implementations on other systems.

Factory reset always takes place during early boot, i.e. from a well-defined
"clean" state. Factory reset operations may be requested from one boot to be
executed on the next.

Specifically, the following concepts are available:

* The `factory-reset.target` unit may be used to request a factory reset
  operation and trigger a reboot in order to execute it. It by default executes
  three services: `systemd-factory-reset-request.service`,
  `systemd-tpm2-clear.service` and `systemd-factory-reset-reboot.service`.

* The
  [`systemd-factory-reset-request.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-request.service.html)
  unit is typically invoked via `factory-reset.target`. It requests a factory
  reset operation for the next boot by setting the `FactoryResetRequest` EFI
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
  [`systemd-factory-reset-reboot.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-reboot.service.html)
  unit automatically reboots the system as part of `factory-reset.target`. It
  is ordered after `systemd-tpm2-clear.service` and
  `systemd-factory-reset-request.service` in order to initiate the reboot that
  is supposed to execute the factory reset operations.

* The `factory-reset-now.target` unit is started at boot whenever a factory
  reset is requested for the boot. A factory reset may be requested via a
  kernel command line option (`systemd.factory_reset=1`) or via the UEFI
  variable `FactoryResetRequest` (see above). The
  `systemd-factory-reset-generator` unit generator checks both these conditions
  and adds `factory-reset-now.target` to the boot transaction, already in the
  initial RAM disk (initrd).

* The
  [`systemd-factory-reset-complete.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-factory-reset-complete.service.html)
  unit is invoked after `factory-reset-now.target` and marks the factory reset
  operation as complete. The boot process then may continue.

* The
  [`systemd-repart`](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html)
  tool can take the factory reset logic into account. Either on explicit
  request via the `--factory-reset=` logic, or automatically derived from the
  aforementioned kernel command line switch and EFI variable. When invoked for
  factory reset it will securely erase all partitions marked for that via the
  `FactoryReset=` setting in its partition definition files. Once that is
  complete it will execute the usual setup operation, i.e. format new
  partitions again.

* The
  [`systemd-logind.service(8)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-logind.service.html)
  unit supports automatically binding factory reset to special keypresses
  (typically long presses), see the
  [`logind.conf(5)`](https://www.freedesktop.org/software/systemd/man/latest/logind.conf.html)
  man page.

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

## Exposure in the UI

If a graphical UI shall expose a factory reset operation it should first check
if requesting a factory reset is supported at all via the Varlink service
mentioned above. Once a factory reset shall be executed it shall ask for
activation of the `factory-reset.target` unit.

Alternatively, `systemd-logind.service`'s hotkey support may be used, for
example to request factory reset if the reboot button is pressed for a long
time.

## Support for non-UEFI Systems

The above is a relatively bespoke solution for EFI systems. It uses EFI
variables as stateful memory to request the factory reset on the next boot.

On non-EFI systems, a different mechanism should be devised. A service
requesting the factory request can then be plugged into
`factory-reset.target`. At boot the request should then be fed back to the
booted kernel via the `systemd.factory_reset=1` kernel command line option, in
order to execute the reset operation.

## Support for Resetting other Resources than Partitions + TPM

By default a factory reset implemented with systemd's tools can reset/erase
partitions (via `systemd-repart`, see above) and reset the TPM (via
`systemd-tpm2-clear.service`, see above).

In some cases other resources shall be reset/erased too. To support that,
define your own service and plug it into `factory-reset-now.target`, ensuring
it is ordered before that.

## Factory Reset via Boot Menu

Factory reset can also be requested via the boot menu. A simple factory reset
(that does not touch the TPM) at boot can be requested via a boot menu item
containing the `systemd.factory_reset=1` kernel command line option. A more
comprehensive factory reset operation (that also erases the TPM) can be
requested by booting with `rd.systemd.unit=factory-reset.target`. Note that the
latter will require one reboot (required since that's how TPM resets work),
while the former will reset state and continue running without an additional
reboot.

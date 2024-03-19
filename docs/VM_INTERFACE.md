---
title: VM Interface
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The VM Interface

Also consult [Writing Virtual Machine or Container
Managers](https://systemd.io/WRITING_VM_AND_CONTAINER_MANAGERS).

systemd has a number of interfaces for interacting with virtual machine
managers, when systemd is used inside of a VM. If you work on a VM manager,
please consider supporting the following interfaces.

1. systemd supports passing immutable binary data blobs with limited size and
   restricted access to services via the `ImportCredential=`, `LoadCredential=`
   and `SetCredential=` settings. These credentials may be passed into a system
   via SMBIOS Type 11 vendor strings, see
   [systemd(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd.html)
   for details. This concept may be used to flexibly configure various facets
   ot the guest system. See
   [systemd.system-credentials(7)](https://www.freedesktop.org/software/systemd/man/latest/systemd.system-credentials.html)
   for a list of system credentials implemented by various systemd components.

2. Readiness, information about various system properties and functionality, as
   well as progress of boot may be reported by systemd to a machine manager via
   the `sd_notify()` protocol via `AF_VSOCK` sockets. The address of this
   socket may be configured via the `vmm.notify_socket` system credential. See
   [systemd(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd.html).

3. The
   [systemd-ssh-generator(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-ssh-generator.html)
   functionality will automatically bind SSH login functionality to `AF_VSOCK`
   port 22, if the system runs in a VM.

4. If not initialized yet the system's
   [machine-id(5)](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html)
   is automatically set to the SMBIOS product UUID if available and invocation
   in an VM environment is detected.

5. The
   [`systemd-boot(7)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-boot.html)
   and
   [`systemd-stub(7)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html)
   components support two SMBIOS Type 11 vendor strings that may be used to
   extend the kernel command line of booted Linux environments:
   `io.systemd.stub.kernel-cmdline-extra=` and
   `io.systemd.boot.kernel-cmdline-extra=`.

Also see
[smbios-type-11(7)](https://www.freedesktop.org/software/systemd/man/latest/smbios-type-11.html)
for a list of supported SMBIOS Type 11 vendor strings.

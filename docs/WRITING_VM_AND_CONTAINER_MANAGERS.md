---
title: Writing VM and Container Managers
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Writing VM and Container Managers

_Or: How to hook up your favorite VM or container manager with systemd_

Nomenclature: a _Virtual Machine_ shall refer to a system running on virtualized hardware consisting of a full OS with its own kernel.
A _Container_ shall refer to a system running on the same shared kernel of the host, but running a mostly complete OS with its own init system.
Both kinds of virtualized systems shall collectively be called "machines".

systemd provides a number of integration points with virtual machine and container managers, such as libvirt, LXC or systemd-nspawn.
On one hand there are integration points of the VM/container manager towards the host OS it is running on, and on the other there integration points for container managers towards the guest OS it is managing.

Note that this document does not cover lightweight containers for the purpose
of application sandboxes, i.e. containers that do _not_ run a init system of
their own.

## Host OS Integration

All virtual machines and containers should be registered with the [machined](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.machine1) mini service that is part of systemd. This provides integration into the core OS at various points. For example, tools like ps, cgls, gnome-system-manager use this registration information to show machine information for running processes, as each of the VM's/container's processes can reliably attributed to a registered machine.
The various systemd tools (like systemctl, journalctl, loginctl, systemd-run, ...) all support a -M switch that operates on machines registered with machined.
"machinectl" may be used to execute operations on any such machine.
When a machine is registered via machined its processes will automatically be placed in a systemd scope unit (that is located in the machines.slice slice) and thus appear in "systemctl" and similar commands.
The scope unit name is based on the machine meta information passed to machined at registration.

For more details on the APIs provided by machine consult [the bus API interface documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.machine1).

## Guest OS Integration

As container virtualization is much less comprehensive, and the guest is less isolated from the host, there are a number of interfaces defined how the container manager can set up the environment for systemd running inside a container. These Interfaces are documented in [Container Interface of systemd](/CONTAINER_INTERFACE).

VM virtualization is more comprehensive and fewer integration APIs are available.
In fact there's only one: a VM manager may initialize the SMBIOS DMI field "Product UUUID" to a UUID uniquely identifying this virtual machine instance.
This is read in the guest via `/sys/class/dmi/id/product_uuid`, and used as configuration source for `/etc/machine-id` if in the guest, if that file is not initialized yet.
Note that this is currently only supported for kvm hosts, but may be extended to other managers as well.

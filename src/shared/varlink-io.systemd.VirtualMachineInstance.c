/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.VirtualMachineInstance.h"

/* VM-specific control interface. Currently empty — reserved for methods that apply to virtual
 * machines generically but not to containers (e.g. snapshot, migration, device hotplug). */
SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_VirtualMachineInstance,
                "io.systemd.VirtualMachineInstance");

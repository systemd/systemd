/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.SysUpdate.h"

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_SysUpdate,
                "io.systemd.SysUpdate",
                SD_VARLINK_INTERFACE_COMMENT("APIs to manage system updates"));

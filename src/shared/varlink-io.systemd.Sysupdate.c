/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Sysupdate.h"

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Sysupdate,
                "io.systemd.Sysupdate",
                SD_VARLINK_INTERFACE_COMMENT("APIs to manage system updates"));

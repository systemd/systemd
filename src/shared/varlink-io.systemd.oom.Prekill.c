/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.oom.Prekill.h"

/* This is a new Varlink interface for pre-kill notifications from oomd.
 * It will be available through /run/systemd/oomd.prekill.hook/ */

static SD_VARLINK_DEFINE_METHOD(
                Notify,
                SD_VARLINK_FIELD_COMMENT("The cgroup which is going to be killed"),
                SD_VARLINK_DEFINE_INPUT(cgroup, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_oom_Prekill,
                "io.systemd.oom.Prekill",
                SD_VARLINK_INTERFACE_COMMENT("Prekill notifications from oomd"),
                SD_VARLINK_SYMBOL_COMMENT("Notify about an imminent OOM kill"),
                &vl_method_Notify);

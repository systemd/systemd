/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.QemuMachineInstance.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                AcquireQMP,
                SD_VARLINK_REQUIRES_UPGRADE);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_QemuMachineInstance,
                "io.systemd.QemuMachineInstance",
                SD_VARLINK_SYMBOL_COMMENT("Acquire a direct QMP connection to the QEMU instance via protocol upgrade"),
                &vl_method_AcquireQMP);

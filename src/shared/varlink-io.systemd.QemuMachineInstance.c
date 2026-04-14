/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.QemuMachineInstance.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                AcquireQMP,
                SD_VARLINK_REQUIRES_UPGRADE);

static SD_VARLINK_DEFINE_ERROR(AlreadyAcquired);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_QemuMachineInstance,
                "io.systemd.QemuMachineInstance",
                SD_VARLINK_SYMBOL_COMMENT("Acquire a direct QMP connection to the QEMU instance via protocol upgrade"),
                &vl_method_AcquireQMP,
                SD_VARLINK_SYMBOL_COMMENT("A QMP connection has already been acquired by another client"),
                &vl_error_AlreadyAcquired);

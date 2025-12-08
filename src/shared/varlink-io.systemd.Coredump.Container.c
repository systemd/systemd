/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Coredump.Container.h"

static SD_VARLINK_DEFINE_METHOD(
                Transfer,
                SD_VARLINK_FIELD_COMMENT("The index of the coredump socket file descriptor, which is a socket connection to the AF_UNIX socket path registered to the linux/core_pattern sysctl opened by the kernel on a process being crashed."),
                SD_VARLINK_DEFINE_INPUT(coredumpFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The timestamp of the crash."),
                SD_VARLINK_DEFINE_INPUT(timestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_CoredumpContainer,
                "io.systemd.Coredump.Container",
                SD_VARLINK_INTERFACE_COMMENT("APIs for processing coredumps inside container."),
                SD_VARLINK_SYMBOL_COMMENT("Transfer coredump from the host to the container."),
                &vl_method_Transfer);

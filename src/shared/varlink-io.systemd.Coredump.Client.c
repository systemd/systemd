/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Coredump.Client.h"

static SD_VARLINK_DEFINE_METHOD(
                Submit,
                SD_VARLINK_FIELD_COMMENT("The index of the coredump socket file descriptor."),
                SD_VARLINK_DEFINE_INPUT(coredumpFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The timestamp of the crash."),
                SD_VARLINK_DEFINE_INPUT(timestamp, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Specifies the kernel coredump socket mode."),
                SD_VARLINK_DEFINE_INPUT(requestMode, SD_VARLINK_BOOL, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_CoredumpClient,
                "io.systemd.Coredump.Client",
                SD_VARLINK_INTERFACE_COMMENT("APIs for processing coredumps."),
                SD_VARLINK_SYMBOL_COMMENT("Process and save passed coredump."),
                &vl_method_Submit);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "varlink-io.systemd.MuteConsole.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                Mute,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Whether to mute the kernel's output to the console (defaults to true)."),
                SD_VARLINK_DEFINE_INPUT(kernel, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to mute PID1's output to the console (defaults to true)."),
                SD_VARLINK_DEFINE_INPUT(pid1, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_MuteConsole,
                "io.systemd.MuteConsole",
                SD_VARLINK_INTERFACE_COMMENT("API for temporarily muting noisy output to the main kernel console"),
                SD_VARLINK_SYMBOL_COMMENT("Mute kernel and PID 1 output to the main kernel console"),
                &vl_method_Mute);

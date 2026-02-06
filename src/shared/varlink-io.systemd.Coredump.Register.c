/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Coredump.Register.h"

static SD_VARLINK_DEFINE_METHOD(
                SetCorePattern,
                SD_VARLINK_FIELD_COMMENT("The core pattern to be written to /proc/sys/kernel/core_pattern."),
                SD_VARLINK_DEFINE_INPUT(pattern, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(CoredumpPatternNotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_CoredumpRegister,
                "io.systemd.Coredump.Register",
                SD_VARLINK_INTERFACE_COMMENT("Core pattern register APIs."),
                SD_VARLINK_SYMBOL_COMMENT("Set the specified core pattern."),
                &vl_method_SetCorePattern,
                SD_VARLINK_SYMBOL_COMMENT("The requested core pattern is not supported."),
                &vl_error_CoredumpPatternNotSupported);

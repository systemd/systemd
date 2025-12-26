/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Coredump.Register.h"

static SD_VARLINK_DEFINE_METHOD(
                RegisterSocket,
                SD_VARLINK_FIELD_COMMENT("The path to unix socket."),
                SD_VARLINK_DEFINE_INPUT(path, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(CoredumpPatternNotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_CoredumpRegister,
                "io.systemd.Coredump.Register",
                SD_VARLINK_INTERFACE_COMMENT("Core pattern register APIs."),
                SD_VARLINK_SYMBOL_COMMENT("Register the specified path to socket as core pattern."),
                &vl_method_RegisterSocket,
                SD_VARLINK_SYMBOL_COMMENT("The requested core pattern is not supported."),
                &vl_error_CoredumpPatternNotSupported);

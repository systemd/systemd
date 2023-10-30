/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "varlink-io.systemd.service.h"

static VARLINK_DEFINE_METHOD(Ping);

static VARLINK_DEFINE_METHOD(Reload);

static VARLINK_DEFINE_METHOD(
                SetLogLevel,
                VARLINK_DEFINE_INPUT(level, VARLINK_INT, VARLINK_NULLABLE));

VARLINK_DEFINE_INTERFACE(
                io_systemd_service,
                "io.systemd.service",
                &vl_method_Ping,
                &vl_method_Reload,
                &vl_method_SetLogLevel);

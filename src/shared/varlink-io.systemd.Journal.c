/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Journal.h"

static SD_VARLINK_DEFINE_METHOD(Synchronize);
static SD_VARLINK_DEFINE_METHOD(Rotate);
static SD_VARLINK_DEFINE_METHOD(FlushToVar);
static SD_VARLINK_DEFINE_METHOD(RelinquishVar);

static SD_VARLINK_DEFINE_ERROR(NotSupportedByNamespaces);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Journal,
                "io.systemd.Journal",
                &vl_method_Synchronize,
                &vl_method_Rotate,
                &vl_method_FlushToVar,
                &vl_method_RelinquishVar,
                &vl_error_NotSupportedByNamespaces);

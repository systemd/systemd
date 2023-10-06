/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Journal.h"

static VARLINK_DEFINE_METHOD(Synchronize);
static VARLINK_DEFINE_METHOD(Rotate);
static VARLINK_DEFINE_METHOD(FlushToVar);
static VARLINK_DEFINE_METHOD(RelinquishVar);

static VARLINK_DEFINE_ERROR(NotSupportedByNamespaces);

VARLINK_DEFINE_INTERFACE(
                io_systemd_Journal,
                "io.systemd.Journal",
                &vl_method_Synchronize,
                &vl_method_Rotate,
                &vl_method_FlushToVar,
                &vl_method_RelinquishVar,
                &vl_error_NotSupportedByNamespaces);

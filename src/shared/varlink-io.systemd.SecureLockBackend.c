/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.SecureLockBackend.h"

static VARLINK_DEFINE_METHOD(
                Activate,
                VARLINK_DEFINE_INPUT(userName, VARLINK_STRING, 0));

static VARLINK_DEFINE_ERROR(NoSuchUser);

VARLINK_DEFINE_INTERFACE(
                io_systemd_SecureLockBackend,
                "io.systemd.SecureLockBackend",
                &vl_method_Activate,
                &vl_error_NoSuchUser);

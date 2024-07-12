/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.h"

/* These are local errors that never cross the wire, and are our own invention */
static SD_VARLINK_DEFINE_ERROR(Disconnected);
static SD_VARLINK_DEFINE_ERROR(TimedOut);
static SD_VARLINK_DEFINE_ERROR(Protocol);

/* This one we invented, and use for generically propagating system errors (errno) to clients */
static SD_VARLINK_DEFINE_ERROR(
                System,
                SD_VARLINK_DEFINE_FIELD(errno, SD_VARLINK_INT, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd,
                "io.systemd",
                &vl_error_Disconnected,
                &vl_error_TimedOut,
                &vl_error_Protocol,
                &vl_error_System);

/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "varlink-io.systemd.udev.h"

static VARLINK_DEFINE_METHOD(StartExecQueue);

static VARLINK_DEFINE_METHOD(StopExecQueue);

VARLINK_DEFINE_INTERFACE(
                io_systemd_udev,
                "io.systemd.udev",
                &vl_method_StartExecQueue,
                &vl_method_StopExecQueue);

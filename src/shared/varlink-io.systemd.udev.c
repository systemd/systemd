/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "varlink-io.systemd.udev.h"

static VARLINK_DEFINE_METHOD(StartExecQueue);

static VARLINK_DEFINE_METHOD(StopExecQueue);

static VARLINK_DEFINE_METHOD(
                SetEnvironment,
                VARLINK_DEFINE_INPUT(assignment, VARLINK_STRING, 0));

VARLINK_DEFINE_INTERFACE(
                io_systemd_udev,
                "io.systemd.udev",
                &vl_method_SetEnvironment,
                &vl_method_StartExecQueue,
                &vl_method_StopExecQueue);

/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "varlink-io.systemd.udev.h"

static SD_VARLINK_DEFINE_METHOD(StartExecQueue);

static SD_VARLINK_DEFINE_METHOD(StopExecQueue);

static SD_VARLINK_DEFINE_METHOD(
                SetEnvironment,
                SD_VARLINK_DEFINE_INPUT(assignments, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                UnsetEnvironment,
                SD_VARLINK_DEFINE_INPUT(names, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                SetChildrenMax,
                SD_VARLINK_DEFINE_INPUT(n, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(Exit);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_udev,
                "io.systemd.udev",
                &vl_method_Exit,
                &vl_method_SetChildrenMax,
                &vl_method_SetEnvironment,
                &vl_method_UnsetEnvironment,
                &vl_method_StartExecQueue,
                &vl_method_StopExecQueue);

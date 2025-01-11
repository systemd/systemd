/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "varlink-io.systemd.Udev.h"

static SD_VARLINK_DEFINE_METHOD(
                SetTrace,
                SD_VARLINK_FIELD_COMMENT("Enable/disable."),
                SD_VARLINK_DEFINE_INPUT(enable, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetChildrenMax,
                SD_VARLINK_FIELD_COMMENT("The maximum number of child processes. When 0 is specified, the maximum is determined based on the system resources."),
                SD_VARLINK_DEFINE_INPUT(number, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetEnvironment,
                SD_VARLINK_FIELD_COMMENT("An array of global udev property assignments. Each string must be in KEY=VALUE style."),
                SD_VARLINK_DEFINE_INPUT(assignments, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(StartExecQueue);

static SD_VARLINK_DEFINE_METHOD(StopExecQueue);

static SD_VARLINK_DEFINE_METHOD(Exit);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Udev,
                "io.systemd.Udev",
                SD_VARLINK_INTERFACE_COMMENT("An interface for controlling systemd-udevd."),
                SD_VARLINK_SYMBOL_COMMENT("Enable/disable trace logging."),
                &vl_method_SetTrace,
                SD_VARLINK_SYMBOL_COMMENT("Sets the maximum number of child processes."),
                &vl_method_SetChildrenMax,
                SD_VARLINK_SYMBOL_COMMENT("Sets the global udev properties."),
                &vl_method_SetEnvironment,
                SD_VARLINK_SYMBOL_COMMENT("Starts processing of queued events."),
                &vl_method_StartExecQueue,
                SD_VARLINK_SYMBOL_COMMENT("Stops processing of queued events."),
                &vl_method_StopExecQueue,
                SD_VARLINK_SYMBOL_COMMENT("Terminates systemd-udevd. This exists for backward compatibility. Please consider to use 'systemctl stop systemd-udevd.service'."),
                &vl_method_Exit);

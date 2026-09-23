/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.AppInstanceMonitor.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                Event,
                SD_VARLINK_FIELD_COMMENT("App instance changed and should be re-queried via io.systemd.AppInstance.Query"),
                SD_VARLINK_DEFINE_ENUM_VALUE(changed),
                SD_VARLINK_FIELD_COMMENT("App instance no longer exists"),
                SD_VARLINK_DEFINE_ENUM_VALUE(disappeared));

static SD_VARLINK_DEFINE_METHOD(
                Notify,
                SD_VARLINK_FIELD_COMMENT("The app's ID"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The app's cgroup path"),
                SD_VARLINK_DEFINE_INPUT(cgroup, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Type of event that occurred"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(event, Event, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_AppInstanceMonitor,
                "io.systemd.AppInstanceMonitor",
                SD_VARLINK_INTERFACE_COMMENT("API for monitoring changes to io.systemd.AppInstance"),
                SD_VARLINK_SYMBOL_COMMENT("Type of event that occurred"),
                &vl_type_Event,
                SD_VARLINK_SYMBOL_COMMENT("Some event occurred to an app instance"),
                &vl_method_Notify);

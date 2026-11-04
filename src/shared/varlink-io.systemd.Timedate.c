/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Timedate.h"

static SD_VARLINK_DEFINE_METHOD(
                SetTimezone,
                SD_VARLINK_FIELD_COMMENT("The time zone to set, e.g. 'Europe/Berlin'. Must be a valid, installed time zone."),
                SD_VARLINK_DEFINE_INPUT(timezone, SD_VARLINK_STRING, 0),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetLocalRTC,
                SD_VARLINK_FIELD_COMMENT("If true the RTC is maintained in local time, otherwise in UTC."),
                SD_VARLINK_DEFINE_INPUT(localRTC, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("If true the system clock is updated from the RTC, otherwise the RTC is updated from the system clock. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(fixSystem, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Timedate,
                "io.systemd.Timedate",
                SD_VARLINK_INTERFACE_COMMENT("APIs for querying and changing the system clock and timezone settings."),
                SD_VARLINK_SYMBOL_COMMENT("Sets the system time zone."),
                &vl_method_SetTimezone,
                SD_VARLINK_SYMBOL_COMMENT("Configures whether the RTC is maintained in local time or UTC."),
                &vl_method_SetLocalRTC);

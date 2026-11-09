/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Timedate.h"

static SD_VARLINK_DEFINE_METHOD(
                Describe,
                SD_VARLINK_FIELD_COMMENT("The configured system time zone. Null if none could be determined."),
                SD_VARLINK_DEFINE_OUTPUT(Timezone, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the RTC is maintained in local time rather than UTC."),
                SD_VARLINK_DEFINE_OUTPUT(LocalRTC, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether a network time synchronization service is installed."),
                SD_VARLINK_DEFINE_OUTPUT(CanNTP, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether automatic time synchronization via a network time service is enabled."),
                SD_VARLINK_DEFINE_OUTPUT(NTP, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the system clock is synchronized."),
                SD_VARLINK_DEFINE_OUTPUT(NTPSynchronized, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The current system time, in µs since the UNIX epoch."),
                SD_VARLINK_DEFINE_OUTPUT(TimeUSec, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The current time of the RTC, in µs since the UNIX epoch. Null if it could not be read."),
                SD_VARLINK_DEFINE_OUTPUT(RTCTimeUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                ListTimezones,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("One known time zone."),
                SD_VARLINK_DEFINE_OUTPUT(timezone, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetTimezone,
                SD_VARLINK_FIELD_COMMENT("The time zone to set, e.g. 'Europe/Berlin' or 'Asia/Tokyo'. Must be a valid, installed time zone."),
                SD_VARLINK_DEFINE_INPUT(timezone, SD_VARLINK_STRING, 0),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetLocalRTC,
                SD_VARLINK_FIELD_COMMENT("If true the RTC is maintained in local time, otherwise in UTC."),
                SD_VARLINK_DEFINE_INPUT(localRTC, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("If true the system clock is updated from the RTC, otherwise the RTC is updated from the system clock. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(adjustSystemClock, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetTime,
                SD_VARLINK_FIELD_COMMENT("The time to set, in µs. If 'relative' is true this is an offset to the current system time (and may be negative), otherwise an absolute timestamp in µs since the UNIX epoch."),
                SD_VARLINK_DEFINE_INPUT(timeUSec, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("If true 'timeUSec' is interpreted relative to the current system time, otherwise as an absolute timestamp. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(relative, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                SetNTP,
                SD_VARLINK_FIELD_COMMENT("If true, enables automatic time synchronization via a network time service, otherwise disables it."),
                SD_VARLINK_DEFINE_INPUT(useNTP, SD_VARLINK_BOOL, 0),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_ERROR(AutomaticTimeSyncEnabled);
static SD_VARLINK_DEFINE_ERROR(NoNTPSupport);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Timedate,
                "io.systemd.Timedate",
                SD_VARLINK_INTERFACE_COMMENT("APIs for querying and changing the system clock and timezone settings."),
                SD_VARLINK_SYMBOL_COMMENT("Returns the time zone, RTC mode, NTP status and current system and RTC time in one call."),
                &vl_method_Describe,
                SD_VARLINK_SYMBOL_COMMENT("Returns the list of known time zones."),
                &vl_method_ListTimezones,
                SD_VARLINK_SYMBOL_COMMENT("Sets the system time zone."),
                &vl_method_SetTimezone,
                SD_VARLINK_SYMBOL_COMMENT("Configures whether the RTC is maintained in local time or UTC."),
                &vl_method_SetLocalRTC,
                SD_VARLINK_SYMBOL_COMMENT("Sets the system clock."),
                &vl_method_SetTime,
                SD_VARLINK_SYMBOL_COMMENT("Enables or disables automatic time synchronization via a network time service. The reply is delayed until the relevant units have been started or stopped."),
                &vl_method_SetNTP,
                SD_VARLINK_SYMBOL_COMMENT("Returned when the clock cannot be set because automatic time synchronization (NTP) is enabled, or a previous enablement request is still in progress."),
                &vl_error_AutomaticTimeSyncEnabled,
                SD_VARLINK_SYMBOL_COMMENT("Returned when automatic time synchronization cannot be configured because no network time service is installed."),
                &vl_error_NoNTPSupport);

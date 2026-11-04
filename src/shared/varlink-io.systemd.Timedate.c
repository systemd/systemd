/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.Timedate.h"

static SD_VARLINK_DEFINE_METHOD(
                SetTimezone,
                SD_VARLINK_FIELD_COMMENT("The time zone to set, e.g. 'Europe/Berlin' or 'Asia/Tokyo'. Must be a valid, installed time zone."),
                SD_VARLINK_DEFINE_INPUT(timezone, SD_VARLINK_STRING, 0),
                VARLINK_DEFINE_POLKIT_INPUT);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Timedate,
                "io.systemd.Timedate",
                SD_VARLINK_INTERFACE_COMMENT("APIs for querying and changing the system clock and timezone settings."),
                SD_VARLINK_SYMBOL_COMMENT("Sets the system time zone."),
                &vl_method_SetTimezone);

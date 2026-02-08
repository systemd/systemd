/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-org.freedesktop.LogControl.h"

static SD_VARLINK_DEFINE_METHOD(
                GetLogLevel,
                SD_VARLINK_FIELD_COMMENT("The current maximum log level, as a string."),
                SD_VARLINK_DEFINE_OUTPUT(level, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetLogLevel,
                SD_VARLINK_FIELD_COMMENT("The new maximum log level, as a string."),
                SD_VARLINK_DEFINE_INPUT(level, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                GetLogTarget,
                SD_VARLINK_FIELD_COMMENT("The current log target."),
                SD_VARLINK_DEFINE_OUTPUT(target, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetLogTarget,
                SD_VARLINK_FIELD_COMMENT("The new log target."),
                SD_VARLINK_DEFINE_INPUT(target, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                GetSyslogIdentifier,
                SD_VARLINK_FIELD_COMMENT("The syslog identifier of this service."),
                SD_VARLINK_DEFINE_OUTPUT(identifier, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_INTERFACE(
                org_freedesktop_LogControl,
                "org.freedesktop.LogControl",
                SD_VARLINK_INTERFACE_COMMENT("An interface for querying and setting logging configuration."),
                SD_VARLINK_SYMBOL_COMMENT("Returns the current maximum log level."),
                &vl_method_GetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Sets the maximum log level."),
                &vl_method_SetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Returns the current log target."),
                &vl_method_GetLogTarget,
                SD_VARLINK_SYMBOL_COMMENT("Sets the log target."),
                &vl_method_SetLogTarget,
                SD_VARLINK_SYMBOL_COMMENT("Returns the syslog identifier."),
                &vl_method_GetSyslogIdentifier);

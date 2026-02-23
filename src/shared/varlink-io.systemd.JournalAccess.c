/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.JournalAccess.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                GetEntries,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("Show messages for the specified systemd units (e.g. ['foo.service'])."),
                SD_VARLINK_DEFINE_INPUT(units, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Show messages for the specified user units (e.g. ['foo.service'])."),
                SD_VARLINK_DEFINE_INPUT(userUnits, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("If specified, shows the log data of the specified namespace, otherwise the default namespace."),
                SD_VARLINK_DEFINE_INPUT(namespace, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Filter output by message priorities or priority ranges (i.e. between 0/'emerg' and 7/'debug')"),
                SD_VARLINK_DEFINE_INPUT(priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Maximum number of entries to return. Defaults to 100, capped at 10000."),
                SD_VARLINK_DEFINE_INPUT(limit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The journal entry in flat JSON format, matching journalctl --output=json."),
                SD_VARLINK_DEFINE_OUTPUT(entry, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoMatches);
static SD_VARLINK_DEFINE_ERROR(NoEntries);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_JournalAccess,
                "io.systemd.JournalAccess",
                SD_VARLINK_INTERFACE_COMMENT("Journal log read APIs"),
                SD_VARLINK_SYMBOL_COMMENT("Retrieve journal log entries, optionally filtered by unit, priority, etc."),
                &vl_method_GetEntries,
                SD_VARLINK_SYMBOL_COMMENT("No matches found for specified unit patterns"),
                &vl_error_NoMatches,
                SD_VARLINK_SYMBOL_COMMENT("No journal entries matched the specified filters."),
                &vl_error_NoEntries);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Journal.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                GetEntries,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("System unit names to filter by (e.g. ['foo.service']). Entries matching any listed unit are returned."),
                SD_VARLINK_DEFINE_INPUT(units, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("User unit names to filter by. Entries matching any listed unit are returned."),
                SD_VARLINK_DEFINE_INPUT(userUnits, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Maximum priority (0=emerg ... 7=debug). Entries up to and including this priority are returned."),
                SD_VARLINK_DEFINE_INPUT(priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Maximum number of entries to return. Defaults to 100, capped at 10000."),
                SD_VARLINK_DEFINE_INPUT(limit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The journal entry in flat JSON format, matching journalctl --output=json."),
                SD_VARLINK_DEFINE_OUTPUT(entry, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Synchronize,
                SD_VARLINK_FIELD_COMMENT("Controls whether to offline the journal files as part of the synchronization operation."),
                SD_VARLINK_DEFINE_INPUT(offline, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(Rotate);
static SD_VARLINK_DEFINE_METHOD(FlushToVar);
static SD_VARLINK_DEFINE_METHOD(RelinquishVar);

static SD_VARLINK_DEFINE_ERROR(NotSupportedByNamespaces);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Journal,
                "io.systemd.Journal",
                SD_VARLINK_INTERFACE_COMMENT("Journal control APIs"),
                SD_VARLINK_SYMBOL_COMMENT("Retrieve journal log entries, optionally filtered by unit, priority, boot, etc."),
                &vl_method_GetEntries,
                SD_VARLINK_SYMBOL_COMMENT("Write out all pending log messages out to disk, and reply only after that's complete."),
                &vl_method_Synchronize,
                SD_VARLINK_SYMBOL_COMMENT("Rotate journal files, i.e. close existing files, start new ones."),
                &vl_method_Rotate,
                SD_VARLINK_SYMBOL_COMMENT("Flush runtime logs to persistent logs, i.e. flush log data from /run/ into /var/, and continue writing future log data to the latter location."),
                &vl_method_FlushToVar,
                SD_VARLINK_SYMBOL_COMMENT("Relinquish use of /var/ again, return to do runtime logging into /run/ only."),
                &vl_method_RelinquishVar,
                SD_VARLINK_SYMBOL_COMMENT("Journal service running as per-namespace instance, and requested operation is not supported for namespaced journal."),
                &vl_error_NotSupportedByNamespaces);

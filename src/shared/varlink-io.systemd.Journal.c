/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.Journal.h"

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

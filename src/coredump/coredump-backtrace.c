/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-journal.h"
#include "sd-messages.h"

#include "coredump-backtrace.h"
#include "coredump-context.h"
#include "iovec-util.h"
#include "journal-importer.h"
#include "log.h"
#include "string-util.h"

int coredump_backtrace(int argc, char *argv[]) {
        _cleanup_(journal_importer_cleanup) JournalImporter importer = JOURNAL_IMPORTER_INIT(STDIN_FILENO);
        _cleanup_(iovw_free_freep) struct iovec_wrapper *iovw = NULL;
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        assert(argc >= 2);

        log_debug("Processing backtrace on stdin...");

        iovw = iovw_new();
        if (!iovw)
                return log_oom();

        (void) iovw_put_string_field(iovw, "MESSAGE_ID=", SD_MESSAGE_BACKTRACE_STR);
        (void) iovw_put_string_field(iovw, "PRIORITY=", STRINGIFY(LOG_CRIT));

        /* Collect all process metadata from argv[] by making sure to skip the '--backtrace' option. */
        r = gather_pid_metadata_from_argv(iovw, &context, argc - 2, argv + 2);
        if (r < 0)
                return r;

        /* Collect the rest of the process metadata retrieved from the runtime */
        r = gather_pid_metadata_from_procfs(iovw, &context);
        if (r < 0)
                return r;

        for (;;) {
                r = journal_importer_process_data(&importer);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse journal entry on stdin: %m");
                if (r == 1 ||                        /* complete entry */
                    journal_importer_eof(&importer)) /* end of data */
                        break;
        }

        if (journal_importer_eof(&importer)) {
                log_warning("Did not receive a full journal entry on stdin, ignoring message sent by reporter.");

                const char *message = strjoina("Process ", context.meta[META_ARGV_PID],
                                               " (", context.meta[META_COMM], ")"
                                               " of user ", context.meta[META_ARGV_UID],
                                               " failed with ", context.meta[META_ARGV_SIGNAL]);

                r = iovw_put_string_field(iovw, "MESSAGE=", message);
                if (r < 0)
                        return r;
        } else {
                /* The imported iovecs are not supposed to be freed by us so let's copy and merge them at the
                 * end of the array. */
                r = iovw_append(iovw, &importer.iovw);
                if (r < 0)
                        return r;
        }

        r = sd_journal_sendv(iovw->iovec, iovw->count);
        if (r < 0)
                return log_error_errno(r, "Failed to log backtrace: %m");

        return 0;
}

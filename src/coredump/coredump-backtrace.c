/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-journal.h"
#include "sd-messages.h"

#include "coredump-backtrace.h"
#include "coredump-context.h"
#include "format-util.h"
#include "journal-importer.h"
#include "log.h"

int coredump_backtrace(int argc, char *argv[]) {
        _cleanup_(journal_importer_cleanup) JournalImporter importer = JOURNAL_IMPORTER_INIT(STDIN_FILENO);
        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        int r;

        assert(argc >= 2);

        log_setup();
        log_debug("Processing backtrace on stdin...");

        /* Collect all process metadata from argv[] by making sure to skip the '--backtrace' option. */
        r = coredump_context_parse_from_argv(&context, argc - 2, argv + 2);
        if (r < 0)
                return r;

        r = coredump_context_build_iovw(&context);
        if (r < 0)
                return r;

        (void) iovw_replace_string_field(&context.iovw, "MESSAGE_ID=", SD_MESSAGE_BACKTRACE_STR);

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
                r = iovw_put_string_fieldf(&context.iovw, "MESSAGE=", "Process "PID_FMT" (%s) of user "UID_FMT" failed with %i.",
                                           context.pidref.pid, context.comm, context.uid, context.signo);
                if (r < 0)
                        return r;
        } else {
                /* The imported iovecs are not supposed to be freed by us so let's copy and merge them at the
                 * end of the array. */
                r = iovw_append(&context.iovw, &importer.iovw);
                if (r < 0)
                        return r;
        }

        r = sd_journal_sendv(context.iovw.iovec, context.iovw.count);
        if (r < 0)
                return log_error_errno(r, "Failed to log backtrace: %m");

        return 0;
}

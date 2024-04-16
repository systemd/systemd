/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "journal-util.h"
#include "journalctl.h"
#include "journalctl-util.h"
#include "rlimit-util.h"
#include "sigbus.h"
#include "terminal-util.h"

char* format_timestamp_maybe_utc(char *buf, size_t l, usec_t t) {
        assert(buf);

        if (arg_utc)
                return format_timestamp_style(buf, l, t, TIMESTAMP_UTC);

        return format_timestamp(buf, l, t);
}

int acquire_journal(sd_journal **ret) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(ret);

        /* Increase max number of open files if we can, we might needs this when browsing journal files, which might be
         * split up into many files. */
        (void) rlimit_nofile_bump(HIGH_RLIMIT_NOFILE);

        sigbus_install();

        if (arg_directory)
                r = sd_journal_open_directory(&j, arg_directory, arg_journal_type | arg_journal_additional_open_flags);
        else if (arg_root)
                r = sd_journal_open_directory(&j, arg_root, arg_journal_type | arg_journal_additional_open_flags | SD_JOURNAL_OS_ROOT);
        else if (arg_file_stdin)
                r = sd_journal_open_files_fd(&j, (int[]) { STDIN_FILENO }, 1, arg_journal_additional_open_flags);
        else if (arg_file)
                r = sd_journal_open_files(&j, (const char**) arg_file, arg_journal_additional_open_flags);
        else if (arg_machine)
                r = journal_open_machine(&j, arg_machine, arg_journal_additional_open_flags);
        else
                r = sd_journal_open_namespace(
                                &j,
                                arg_namespace,
                                (arg_merge ? 0 : SD_JOURNAL_LOCAL_ONLY) |
                                arg_namespace_flags | arg_journal_type | arg_journal_additional_open_flags);
        if (r < 0)
                return log_error_errno(r, "Failed to open %s: %m", arg_directory ?: arg_file ? "files" : "journal");

        r = journal_access_check_and_warn(j, arg_quiet,
                                          !(arg_journal_type == SD_JOURNAL_CURRENT_USER || arg_user_units));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(j);
        return 0;
}

bool journal_boot_has_effect(sd_journal *j) {
        assert(j);

        if (arg_boot_offset != 0 &&
            sd_journal_has_runtime_files(j) > 0 &&
            sd_journal_has_persistent_files(j) == 0) {
                log_info("Specifying boot ID or boot offset has no effect, no persistent journal was found.");
                return false;
        }

        return true;
}

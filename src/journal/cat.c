/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "build.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-util.h"
#include "syslog-util.h"

static const char *arg_identifier = NULL;
static const char *arg_namespace = NULL;
static int arg_priority = LOG_INFO;
static int arg_stderr_priority = -1;
static bool arg_level_prefix = true;

#include "cat.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cat", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n"
               "\n%sExecute process with stdout/stderr connected to the journal.%s\n\n"
               OPTION_HELP_GENERATED
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int outfd = -EBADF, errfd = -EBADF, saved_stderr = -EBADF;
        int r;

        log_setup();

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        outfd = sd_journal_stream_fd_with_namespace(arg_namespace, arg_identifier, arg_priority, arg_level_prefix);
        if (outfd < 0)
                return log_error_errno(outfd, "Failed to create stream fd: %m");

        if (arg_stderr_priority >= 0 && arg_stderr_priority != arg_priority) {
                errfd = sd_journal_stream_fd_with_namespace(arg_namespace, arg_identifier, arg_stderr_priority, arg_level_prefix);
                if (errfd < 0)
                        return log_error_errno(errfd, "Failed to create stream fd: %m");
        }

        saved_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);

        r = rearrange_stdio(STDIN_FILENO, outfd, errfd < 0 ? outfd : errfd); /* Invalidates fd on success + error! */
        TAKE_FD(outfd);
        TAKE_FD(errfd);
        if (r < 0)
                return log_error_errno(r, "Failed to rearrange stdout/stderr: %m");

        if (argc <= optind)
                (void) execl("/bin/cat", "/bin/cat", NULL);
        else {
                struct stat st;

                if (fstat(STDERR_FILENO, &st) < 0)
                        return log_error_errno(errno,
                                               "Failed to fstat(%s): %m",
                                               FORMAT_PROC_FD_PATH(STDERR_FILENO));

                r = setenvf("JOURNAL_STREAM", /* overwrite= */ true, DEV_FMT ":" INO_FMT, (dev_t) st.st_dev, st.st_ino);
                if (r < 0)
                        return log_error_errno(r, "Failed to set environment variable JOURNAL_STREAM: %m");

                (void) execvp(argv[optind], argv + optind);
        }
        r = -errno;

        /* Let's try to restore a working stderr, so we can print the error message */
        if (saved_stderr >= 0)
                (void) dup3(saved_stderr, STDERR_FILENO, 0);

        return log_error_errno(r, "Failed to execute process: %m");
}

DEFINE_MAIN_FUNCTION(run);

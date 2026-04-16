/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "build.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"

static const char *arg_identifier = NULL;
static const char *arg_namespace = NULL;
static int arg_priority = LOG_INFO;
static int arg_stderr_priority = -1;
static bool arg_level_prefix = true;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-cat", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sExecute process with stdout/stderr connected to the journal.%s\n\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('t', "identifier", "STRING", "Set syslog identifier"):
                        arg_identifier = empty_to_null(arg);
                        break;

                OPTION('p', "priority", "PRIORITY", "Set priority value (0..7)"):
                        arg_priority = log_level_from_string(arg);
                        if (arg_priority < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse priority value.");
                        break;

                OPTION_LONG("stderr-priority", "PRIORITY",
                            "Set priority value (0..7) used for stderr"):
                        arg_stderr_priority = log_level_from_string(arg);
                        if (arg_stderr_priority < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse stderr priority value.");
                        break;

                OPTION_LONG("level-prefix", "BOOL",
                            "Control whether level prefix shall be parsed"):
                        r = parse_boolean_argument("--level-prefix=", arg, &arg_level_prefix);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("namespace", "NAMESPACE",
                            "Connect to specified journal namespace"):
                        arg_namespace = empty_to_null(arg);
                        break;
                }

        *ret_args = option_parser_get_args(&state);
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int outfd = -EBADF, errfd = -EBADF, saved_stderr = -EBADF;
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
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

        if (strv_isempty(args))
                (void) execlp("cat", "cat", NULL);
        else {
                struct stat st;

                if (fstat(STDERR_FILENO, &st) < 0)
                        return log_error_errno(errno,
                                               "Failed to fstat(%s): %m",
                                               FORMAT_PROC_FD_PATH(STDERR_FILENO));

                r = setenvf("JOURNAL_STREAM", /* overwrite= */ true, DEV_FMT ":" INO_FMT, (dev_t) st.st_dev, st.st_ino);
                if (r < 0)
                        return log_error_errno(r, "Failed to set environment variable JOURNAL_STREAM: %m");

                (void) execvp(args[0], args);
        }
        r = -errno;

        /* Let's try to restore a working stderr, so we can print the error message */
        if (saved_stderr >= 0)
                (void) dup3(saved_stderr, STDERR_FILENO, 0);

        return log_error_errno(r, "Failed to execute process: %m");
}

DEFINE_MAIN_FUNCTION(run);

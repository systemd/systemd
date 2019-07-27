/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "syslog-util.h"
#include "util.h"

static const char *arg_identifier = NULL;
static int arg_priority = LOG_INFO;
static int arg_stderr_priority = -1;
static bool arg_level_prefix = true;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cat", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Execute process with stdout/stderr connected to the journal.\n\n"
               "  -h --help                      Show this help\n"
               "     --version                   Show package version\n"
               "  -t --identifier=STRING         Set syslog identifier\n"
               "  -p --priority=PRIORITY         Set priority value (0..7)\n"
               "     --stderr-priority=PRIORITY  Set priority value (0..7) used for stderr\n"
               "     --level-prefix=BOOL         Control whether level prefix shall be parsed\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_STDERR_PRIORITY,
                ARG_LEVEL_PREFIX
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "identifier",      required_argument, NULL, 't'                 },
                { "priority",        required_argument, NULL, 'p'                 },
                { "stderr-priority", required_argument, NULL, ARG_STDERR_PRIORITY },
                { "level-prefix",    required_argument, NULL, ARG_LEVEL_PREFIX    },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+ht:p:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case 't':
                        if (isempty(optarg))
                                arg_identifier = NULL;
                        else
                                arg_identifier = optarg;
                        break;

                case 'p':
                        arg_priority = log_level_from_string(optarg);
                        if (arg_priority < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse priority value.");
                        break;

                case ARG_STDERR_PRIORITY:
                        arg_stderr_priority = log_level_from_string(optarg);
                        if (arg_stderr_priority < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse stderr priority value.");
                        break;

                case ARG_LEVEL_PREFIX: {
                        int k;

                        k = parse_boolean(optarg);
                        if (k < 0)
                                return log_error_errno(k, "Failed to parse level prefix value.");

                        arg_level_prefix = k;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int outfd = -1, errfd = -1, saved_stderr = -1;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        outfd = sd_journal_stream_fd(arg_identifier, arg_priority, arg_level_prefix);
        if (outfd < 0)
                return log_error_errno(outfd, "Failed to create stream fd: %m");

        if (arg_stderr_priority >= 0 && arg_stderr_priority != arg_priority) {
                errfd = sd_journal_stream_fd(arg_identifier, arg_stderr_priority, arg_level_prefix);
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
        else
                (void) execvp(argv[optind], argv + optind);
        r = -errno;

        /* Let's try to restore a working stderr, so we can print the error message */
        if (saved_stderr >= 0)
                (void) dup3(saved_stderr, STDERR_FILENO, 0);

        return log_error_errno(r, "Failed to execute process: %m");
}

DEFINE_MAIN_FUNCTION(run);

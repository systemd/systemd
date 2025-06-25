/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "label-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-util.h"
#include "time-util.h"

static char *arg_root = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int save_timestamp(const char *dir, struct timespec *ts) {
        _cleanup_free_ char *message = NULL, *dirpath = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        /*
         * We store the timestamp both as mtime of the file and in the file itself,
         * to support filesystems which cannot store nanosecond-precision timestamps.
         */

        fd = chase_and_open(dir, arg_root,
                            CHASE_PREFIX_ROOT | CHASE_WARN | CHASE_MUST_BE_DIRECTORY,
                            O_DIRECTORY | O_CLOEXEC | O_CREAT,
                            &dirpath);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s%s: %m", strempty(arg_root), dir);

        if (asprintf(&message,
                     "# This file was created by systemd-update-done. The timestamp below is the\n"
                     "# modification time of /usr/ for which the most recent updates of %s have\n"
                     "# been applied. See man:systemd-update-done.service(8) for details.\n"
                     "TIMESTAMP_NSEC=" NSEC_FMT "\n",
                     dir,
                     timespec_load_nsec(ts)) < 0)
                return log_oom();

        r = write_string_file_full(fd, ".updated", message,
                                   WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL,
                                   ts, NULL);
        if (r == -EROFS && !arg_root)
                log_debug_errno(r, "Cannot create \"%s/.updated\", file system is read-only.", dirpath);
        else if (r < 0)
                return log_error_errno(r, "Failed to write \"%s/.updated\": %m", dirpath);
        else
                log_debug("%s/.updated updated to TIMESTAMP_NSEC="NSEC_FMT, dirpath, timespec_load_nsec(ts));

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-update-done", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n\n"
               "%5$sMark /etc/ and /var/ as fully updated.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --root=PATH         Operate on root directory PATH\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ROOT = 0x100,
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'          },
                { "root",     required_argument, NULL, ARG_ROOT     },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        return 1;
}


static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        r = chase_and_stat("/usr", arg_root,
                           CHASE_PREFIX_ROOT | CHASE_WARN | CHASE_MUST_BE_DIRECTORY,
                           /* ret_path = */ NULL,
                           &st);
        if (r < 0)
                return log_error_errno(r, "Failed to stat %s/usr/: %m", strempty(arg_root));

        r = mac_init();
        if (r < 0)
                return r;

        r = 0;
        RET_GATHER(r, save_timestamp("/etc/", &st.st_mtim));
        RET_GATHER(r, save_timestamp("/var/", &st.st_mtim));
        return r;
}

DEFINE_MAIN_FUNCTION(run);

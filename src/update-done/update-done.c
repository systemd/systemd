/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "build.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "label-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
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
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-update-done", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n"
               "\n%sMark /etc/ and /var/ as fully updated.%s\n"
               "\n%sOptions:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());
        table_print(options, stdout);

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = {};
        const char *arg;

        FOREACH_OPTION(&state, c, argc, argv, &arg, /* on_error= */ return c)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("root", "PATH", "Operate on root directory PATH"):
                        r = parse_path_argument(arg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;
                }

        if (option_parser_get_n_args(&state, argc, argv) > 0)
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
                           /* ret_path= */ NULL,
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

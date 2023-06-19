/* SPDX-License-Identifier: LPGL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "sd-id128.h"
#include "sd-journal.h"
#include "terminal-util.h"

static void help(void) {
        printf("%s\n\n"
               "filters the journal to fetch the first message from the current boot with an emergency log level.\n\n"
               "   -h --help            Show this help\n"
               "      --version         Show package version\n",
               program_invocation_short_name);
}

static char* first_emerg_boot_message(void) {
        sd_journal *j;
        const void *d;
        size_t l;
        char boot_id_string[33];
        sd_id128_t boot_id;
        char boot_id_filter[42];
        int r;
        _cleanup_free_ char *message = NULL;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_warning_errno(r, "Failed to open journal: %m");
                return NULL;
        }

        r = sd_id128_get_boot(&boot_id);
        if (r < 0) {
                log_warning_errno(r, "Failed to get boot ID, ignoring : %m");
                goto clean_journal;
        }
        sd_id128_to_string(boot_id, boot_id_string);

        snprintf(boot_id_filter, sizeof(boot_id_filter), "_BOOT_ID=%s", boot_id_string);
        r = sd_journal_add_match(j, boot_id_filter, 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to add boot ID filter: %m");
                goto clean_journal;
        }

        r = sd_journal_add_match(j, "_UID=0", 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to add User ID filter: %m");
                goto clean_journal;
        }

        r = sd_journal_add_match(j, "PRIORITY=0", 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to add Emergency filter: %m");
                goto clean_journal;
        }

        SD_JOURNAL_FOREACH(j) {
                r = sd_journal_get_data(j, "MESSAGE", &d, &l);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read journal message: %m");
                        continue;
                }
                message = strndup((char *) d, l);
                break;
        }

clean_journal:
        sd_journal_close(j);
        return message;
}

static int parse_argv(int argc, char * argv[]) {

        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no argument.",
                                       program_invocation_short_name);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_open();
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        _cleanup_close_ int fd = -EBADF;
        char * message = first_emerg_boot_message();

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                log_warning_errno(fd, "Failed to open console, ignoring: %m");
        else
                dprintf(fd, ANSI_HIGHLIGHT_RED "%s" ANSI_NORMAL "\n", message);
        return 0;
}

DEFINE_MAIN_FUNCTION(run);

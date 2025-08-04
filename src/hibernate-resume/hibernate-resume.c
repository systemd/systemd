/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "build.h"
#include "devnum-util.h"
#include "hibernate-resume-config.h"
#include "hibernate-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "static-destruct.h"

static HibernateInfo arg_info = {};
static bool arg_clear = false;

STATIC_DESTRUCTOR_REGISTER(arg_info, hibernate_info_done);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-hibernate-resume", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [DEVICE [OFFSET]]\n"
               "\n%sInitiate resume from hibernation.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --clear           Clear hibernation storage information from EFI and exit\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CLEAR,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "clear",     no_argument,       NULL, ARG_CLEAR     },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_CLEAR:
                        arg_clear = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc > optind && arg_clear)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous arguments specified with --clear, refusing.");

        return 1;
}

static int setup_hibernate_info_and_warn(void) {
        int r;

        r = acquire_hibernate_info(&arg_info);
        if (r == -ENODEV) {
                log_info_errno(r, "No resume device found, exiting.");
                return 0;
        }
        if (r < 0)
                return r;

        compare_hibernate_location_and_warn(&arg_info);

        return 1;
}

static int action_clear(void) {
        int r;

        assert(arg_clear);

        /* Let's insist that the system identifier is verified still. After all if things don't match,
         * the resume wouldn't get triggered in the first place. We should not erase the var if booted
         * from LiveCD/portable systems/... */
        r = get_efi_hibernate_location(/* ret = */ NULL);
        if (r <= 0)
                return r;

        r = clear_efi_hibernate_location_and_warn();
        if (r > 0)
                log_notice("Successfully cleared HibernateLocation EFI variable.");
        return r;
}

static int run(int argc, char *argv[]) {
        struct stat st;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (argc - optind > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects zero, one, or two arguments.");

        umask(0022);

        if (arg_clear)
                return action_clear();

        if (!in_initrd())
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Not running in initrd, refusing to initiate resume from hibernation.");

        if (argc <= optind) {
                r = setup_hibernate_info_and_warn();
                if (r <= 0)
                        return r;

                if (arg_info.efi)
                        (void) clear_efi_hibernate_location_and_warn();
        } else {
                arg_info.device = ASSERT_PTR(argv[optind]);

                if (argc - optind == 2) {
                        r = safe_atou64(argv[optind + 1], &arg_info.offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resume offset %s: %m", argv[optind + 1]);
                }
        }

        if (stat(arg_info.device, &st) < 0)
                return log_error_errno(errno, "Failed to stat resume device '%s': %m", arg_info.device);

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK),
                                       "Resume device '%s' is not a block device.", arg_info.device);

        /* The write shall not return if a resume takes place. */
        r = write_resume_config(st.st_rdev, arg_info.offset, arg_info.device);
        log_full_errno(r < 0 || arg_info.efi ? LOG_WARNING : LOG_INFO,
                       r < 0 ? r : SYNTHETIC_ERRNO(ENOENT),
                       "Unable to resume from device '%s' (" DEVNUM_FORMAT_STR ") offset %" PRIu64 ", continuing boot process.",
                       arg_info.device, DEVNUM_FORMAT_VAL(st.st_rdev), arg_info.offset);
        return r;
}

DEFINE_MAIN_FUNCTION(run);

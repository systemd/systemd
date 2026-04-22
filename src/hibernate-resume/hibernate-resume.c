/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "alloc-util.h"
#include "build.h"
#include "devnum-util.h"
#include "format-table.h"
#include "hibernate-resume-config.h"
#include "hibernate-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "static-destruct.h"
#include "strv.h"

static HibernateInfo arg_info = {};
static bool arg_clear = false;

STATIC_DESTRUCTOR_REGISTER(arg_info, hibernate_info_done);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-hibernate-resume", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...] [DEVICE [OFFSET]]\n\n"
               "%sInitiate resume from hibernation.%s\n\n",
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
        assert(ret_args);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("clear", NULL,
                            "Clear hibernation storage information from EFI and exit"):
                        arg_clear = true;
                        break;
                }

        if (option_parser_get_n_args(&state) > 0 && arg_clear)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous arguments specified with --clear, refusing.");

        *ret_args = option_parser_get_args(&state);
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
        r = get_efi_hibernate_location(/* ret= */ NULL);
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

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        size_t n_args = strv_length(args);

        if (n_args > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects zero, one, or two arguments.");

        umask(0022);

        if (arg_clear)
                return action_clear();

        if (!in_initrd())
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Not running in initrd, refusing to initiate resume from hibernation.");

        if (n_args == 0) {
                r = setup_hibernate_info_and_warn();
                if (r <= 0)
                        return r;

                if (arg_info.efi)
                        (void) clear_efi_hibernate_location_and_warn();
        } else {
                arg_info.device = ASSERT_PTR(args[0]);

                if (n_args == 2) {
                        r = safe_atou64(args[1], &arg_info.offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resume offset %s: %m", args[1]);
                }
        }

        if (stat(arg_info.device, &st) < 0)
                return log_error_errno(errno, "Failed to stat resume device '%s': %m", arg_info.device);

        r = stat_verify_block(&st);
        if (r < 0)
                return log_error_errno(r, "Resume device '%s' is not a block device.", arg_info.device);

        /* The write shall not return if a resume takes place. */
        r = write_resume_config(st.st_rdev, arg_info.offset, arg_info.device);
        log_full_errno(r < 0 || arg_info.efi ? LOG_WARNING : LOG_INFO,
                       r < 0 ? r : SYNTHETIC_ERRNO(ENOENT),
                       "Unable to resume from device '%s' (" DEVNUM_FORMAT_STR ") offset %" PRIu64 ", continuing boot process.",
                       arg_info.device, DEVNUM_FORMAT_VAL(st.st_rdev), arg_info.offset);
        return r;
}

DEFINE_MAIN_FUNCTION(run);

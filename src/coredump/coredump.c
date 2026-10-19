/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-json.h"

#include "build.h"
#include "coredump-backtrace.h"
#include "coredump-kernel-helper.h"
#include "coredump-manager.h"
#include "coredump-receive.h"
#include "coredump-util.h"
#include "dlopen-note.h"
#include "log.h"
#include "main-func.h"
#include "strv.h"
#include "verbs.h"

COMMAND(
        "systemd-coredump\0",
        "Acquire, save, and process core dumps.",
        .argspec = "[METADATA…]\0",
        .man_pages = "systemd-coredump(8)\0",
);

typedef enum CoredumpMode {
        COREDUMP_MODE_KERNEL_HELPER,      /* Run as a privileged helper binary invoked by the kernel */
        COREDUMP_MODE_BACKTRACE,          /* Log a backtrace received on standard input */
        COREDUMP_MODE_CHECK_REQUIREMENTS, /* Check whether core dumps can be processed */
        COREDUMP_MODE_MANAGER,            /* Run as the core dump manager handling */
} CoredumpMode;

static CoredumpMode arg_mode = COREDUMP_MODE_KERNEL_HELPER;

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        /* The kernel passes the core_pattern fields after our own options, starting with the PID. Some of
         * them, like the hostname, are under the control of the crashing process, so they must never be
         * looked at as options: stop parsing at the first positional argument. */
        OptionParser opts = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG_DATA("backtrace", NULL, /* data= */ COREDUMP_MODE_BACKTRACE,
                                 "Log a backtrace received on standard input"): {}
                OPTION_LONG_DATA("check-requirements", NULL, /* data= */ COREDUMP_MODE_CHECK_REQUIREMENTS,
                                 "Check whether core dumps can be processed"): {}
                OPTION_LONG_DATA("manager", NULL, /* data= */ COREDUMP_MODE_MANAGER,
                                 "Run as the core dump manager"):
                        if (arg_mode != COREDUMP_MODE_KERNEL_HELPER)
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(EINVAL),
                                                "Only one of --backtrace, --check-requirements, and --manager may be specified.");
                        arg_mode = opts.opt->data;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        COMPRESS_DEFAULT_NOTE;
        LIBACL_NOTE(recommended);
        LIBDW_NOTE(suggested);
        LIBELF_NOTE(suggested);
        LIBSELINUX_NOTE(recommended);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        if (IN_SET(arg_mode, COREDUMP_MODE_CHECK_REQUIREMENTS, COREDUMP_MODE_MANAGER) && !strv_isempty(args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");

        /* When running as backtrace mode, it is not necessary to use kmsg, not necessary to disable coredump
         * from the command, and unexpectedly passed file descriptors can be silently ignored. */
        if (arg_mode == COREDUMP_MODE_BACKTRACE)
                return coredump_backtrace(args);

        if (arg_mode == COREDUMP_MODE_CHECK_REQUIREMENTS) {
                log_setup();
                return coredump_manager_check_requirements(LOG_DEBUG);
        }

        /* Make sure we never enter a loop. */
        (void) set_dumpable(SUID_DUMP_DISABLE);

        if (arg_mode == COREDUMP_MODE_MANAGER)
                return coredump_manager();

        /* First, log to a safe place, since we don't know what crashed and it might be journald which we'd
         * rather not log to then. */
        log_parse_environment();
        log_set_target_and_open(LOG_TARGET_KMSG);

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");

        /* If we got an fd passed, we are running in coredumpd mode. Otherwise we are invoked from the
         * kernel as coredump handler. */
        if (r == 0)
                return coredump_kernel_helper(args);
        if (r == 1)
                return coredump_receive(SD_LISTEN_FDS_START);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "Received unexpected number of file descriptors.");
}

DEFINE_MAIN_FUNCTION(run);

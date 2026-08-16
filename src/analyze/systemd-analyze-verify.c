/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "analyze-verify-varlink.h"
#include "ansi-color.h"
#include "build.h"
#include "dlopen-note.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "runtime-scope.h"

static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n"
               "\n%sVerify systemd unit files over Varlink%s\n"
               "\n%sOptions:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        return table_print_or_warn(options);
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_SYSTEM:
                        if (arg_runtime_scope >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Please specify exactly one of --system or --user.");
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_COMMON_USER:
                        if (arg_runtime_scope >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Please specify exactly one of --system or --user.");
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no positional arguments.");

        if (arg_runtime_scope < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify exactly one of --system or --user.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program can only run as a Varlink service.");

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBACL_NOTE(suggested);
        LIBAPPARMOR_NOTE(suggested);
        LIBAUDIT_NOTE(suggested);
        LIBBLKID_NOTE(suggested);
        LIBBPF_NOTE(suggested);
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(suggested);
        LIBMOUNT_NOTE(suggested);
        LIBPCRE2_NOTE(suggested);
        LIBSECCOMP_NOTE(suggested);
        LIBSELINUX_NOTE(suggested);
        TPM2_NOTE(suggested);

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return verify_varlink_server(arg_runtime_scope);
}

DEFINE_MAIN_FUNCTION(run);

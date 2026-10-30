/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-messages.h"

#include "build.h"
#include "efi-loader.h"
#include "efivars.h"
#include "env-util.h"
#include "log.h"
#include "main-func.h"
#include "proc-cmdline.h"
#include "verbs.h"

static bool arg_graceful = false;

COMMAND(
        "systemd-efivars-clear\0",
        "Request erasing of the boot loader's EFI variables from systemd-boot.",
        .man_pages = "systemd-efivars-clear.service(8)\0",
);

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("graceful", NULL, "Exit gracefully if the boot loader does not support erasing EFI variables"):
                        arg_graceful = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects no arguments.");

        return 1;
}

static int request_efivars_clear(void) {
        int r, clear = -1;

        r = secure_getenv_bool("SYSTEMD_EFIVARS_ALLOW_CLEAR");
        if (r < 0 && r != -ENXIO)
                return log_error_errno(r, "Failed to parse $SYSTEMD_EFIVARS_ALLOW_CLEAR: %m");
        if (r >= 0)
                clear = r;

        if (clear < 0) {
                bool b;
                r = proc_cmdline_get_bool("systemd.efivars_allow_clear", PROC_CMDLINE_TRUE_WHEN_MISSING, &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse systemd.efivars_allow_clear kernel command line argument: %m");
                clear = b;
        }

        assert(clear >= 0);

        if (!clear) {
                log_info("Erasing EFI variables disabled, exiting early.");
                return 0;
        }

        r = efi_set_variable_string(EFI_LOADER_VARIABLE_STR("LoaderFactoryResetVariables"), "1");
        if (r < 0)
                return log_error_errno(r, "Failed to set LoaderFactoryResetVariables EFI variable: %m");

        log_struct(LOG_NOTICE,
                   LOG_MESSAGE_ID(SD_MESSAGE_EFIVARS_CLEAR_REQUESTED_STR),
                   LOG_MESSAGE("Requested erasing of boot loader EFI variables. Boot loader will verify with user and erase variables on reboot."));
        return 0;
}

static int run(int argc, char *argv[]) {
        uint64_t features;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!is_efi_boot()) {
                if (arg_graceful) {
                        log_notice("Not an EFI boot, exiting gracefully.");
                        return 0;
                }

                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Not an EFI boot, cannot request erasing of EFI variables.");
        }

        r = efi_loader_get_features(&features);
        if (r < 0)
                return log_error_errno(r, "Failed to query boot loader features: %m");

        if (!FLAGS_SET(features, EFI_LOADER_FEATURE_FACTORY_RESET_VARIABLES)) {
                if (arg_graceful) {
                        log_notice("Boot loader does not support erasing EFI variables, exiting gracefully.");
                        return 0;
                }

                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Boot loader does not support erasing EFI variables.");
        }

        return request_efivars_clear();
}

DEFINE_MAIN_FUNCTION(run);

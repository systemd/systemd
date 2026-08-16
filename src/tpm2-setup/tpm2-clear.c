/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-messages.h"

#include "build.h"
#include "dlopen-note.h"
#include "env-util.h"
#include "fileio.h"
#include "log.h"
#include "main-func.h"
#include "proc-cmdline.h"
#include "tpm2-util.h"
#include "verbs.h"

static bool arg_graceful = false;

COMMAND(
        "systemd-tpm2-clear\0",
        "Request clearing of the TPM2 from PC firmware.",
        .man_pages = "systemd-tpm2-clear.service.8\0",
);

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help("systemd-tpm2-clear");

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("graceful", NULL, "Exit gracefully if no TPM2 device is found"):
                        arg_graceful = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects no arguments.");

        return 1;
}

static int request_tpm2_clear(void) {
        int r, clear = -1;

        r = secure_getenv_bool("SYSTEMD_TPM2_ALLOW_CLEAR");
        if (r < 0 && r != -ENXIO)
                return log_error_errno(r, "Failed to parse $SYSTEMD_TPM2_ALLOW_CLEAR: %m");
        if (r >= 0)
                clear = r;

        if (clear < 0) {
                bool b;
                r = proc_cmdline_get_bool("systemd.tpm2_allow_clear", PROC_CMDLINE_TRUE_WHEN_MISSING, &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse systemd.tpm2_allow_clear kernel command line argument: %m");
                clear = b;
        }

        assert(clear >= 0);

        if (!clear) {
                log_info("Clearing TPM2 disabled, exiting early.");
                return 0;
        }

        /* Now issue PPI request */
        r = write_string_file("/sys/class/tpm/tpm0/ppi/request", "5", /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to request TPM2 clearing via PPI, unable to write to /sys/class/tpm/tpm0/ppi/request: %m");

        log_struct(LOG_NOTICE,
                   LOG_MESSAGE_ID(SD_MESSAGE_TPM2_CLEAR_REQUESTED_STR),
                   LOG_MESSAGE("Requested TPM2 clearing via PPI. Firmware will verify with user and clear TPM on reboot."));
        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBTSS2_ESYS_NOTE(suggested);
        LIBTSS2_MU_NOTE(suggested);
        LIBTSS2_RC_NOTE(suggested);

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* If we don't fully support the TPM we are unlikely able to reinitialize it after boot, hence don't
         * be tempted to reset it in graceful mode. Otherwise we might destroy something without being able
         * to rebuild it. */
        if (arg_graceful && !tpm2_is_fully_supported()) {
                log_notice("No complete TPM2 support detected, exiting gracefully.");
                return 0;
        }

        return request_tpm2_clear();
}

DEFINE_MAIN_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "integrity-util.h"
#include "log.h"
#include "main-func.h"
#include "path-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"

static uint32_t arg_activate_flags;
static int arg_percent;
static usec_t arg_commit_time;
static char *arg_existing_data_device;
static char *arg_integrity_algorithm;
static struct crypt_params_integrity arg_params;

STATIC_DESTRUCTOR_REGISTER(arg_existing_data_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_integrity_algorithm, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-integritysetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME DEVICE [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attach or detach an integrity (non-verity) protected block device.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               link);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;
        char *action, *volume;

        if (argc <= 1 ||
            strv_contains(strv_skip(argv, 1), "--help") ||
            strv_contains(strv_skip(argv, 1), "-h") ||
            streq(argv[1], "help"))
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires at least two arguments.");

        action = argv[1];
        volume = argv[2];

        log_setup();

        cryptsetup_enable_logging(NULL);

        umask(0022);

        if (streq(action, "attach")) {
                /* attach name device optional_options */

                crypt_status_info status;
                char *device, *options;

                if (argc < 4)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least three arguments.");

                device = argv[3];
                options = (argc > 4) ? argv[4] : NULL;

                arg_integrity_algorithm = strdup("crc32c");  /* default for integritysetup */
                if (!arg_integrity_algorithm)
                        return log_oom();

                if (options) {
                        r = parse_integrity_options(options, &arg_activate_flags, &arg_percent,
                                                    &arg_commit_time, &arg_existing_data_device, &arg_integrity_algorithm);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse options: %m");
                }

                r = crypt_init(&cd, device);
                if (r < 0)
                        return log_error_errno(r, "Failed to open integrity device %s: %m", device);

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, volume);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", volume);
                        return 0;
                }

                if (arg_existing_data_device && *arg_existing_data_device) {
                        r = crypt_init_data_device(&cd, device, arg_existing_data_device);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add separate data device: %m");
                }

                arg_params.journal_watermark = arg_percent;
                arg_params.journal_commit_time = arg_commit_time;
                arg_params.integrity = arg_integrity_algorithm;
                r = crypt_load(cd, CRYPT_INTEGRITY, &arg_params);
                if (r < 0)
                        return log_error_errno(r, "Failed to load integrity superblock: %m");

                r = crypt_activate_by_volume_key(cd, volume, NULL, 0, arg_activate_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up integrity device: %m");

        } else if (streq(action, "detach")) {

                r = crypt_init_by_name(&cd, volume);
                if (r == -ENODEV) {
                        log_info("Volume %s already inactive.", volume);
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "crypt_init_by_name() failed: %m");

                cryptsetup_enable_logging(cd);

                r = crypt_deactivate(cd, volume);
                if (r < 0)
                        return log_error_errno(r, "Failed to deactivate: %m");

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", action);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

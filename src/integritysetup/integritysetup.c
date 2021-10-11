/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "integrity_common.h"
#include "log.h"
#include "main-func.h"
#include "path-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"

static uint32_t arg_activate_flags;
static char *arg_datadevice;
static char *arg_integrity_algr;
static struct crypt_params_integrity params = {
        .integrity = "crc32c",                  /* Default for integritysetup */
};

STATIC_DESTRUCTOR_REGISTER(arg_datadevice, freep);
STATIC_DESTRUCTOR_REGISTER(arg_integrity_algr, freep);

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

        if (argc <= 1 ||
            strv_contains(strv_skip(argv, 1), "--help") ||
            strv_contains(strv_skip(argv, 1), "-h") ||
            streq(argv[1], "help"))
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires at least two arguments.");

        log_setup();

        cryptsetup_enable_logging(NULL);

        umask(0022);

        if (streq(argv[1], "attach")) {
                /* attach name device optional_options */
                _cleanup_free_ void *m = NULL;
                crypt_status_info status;

                if (argc < 4)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least three arguments.");

                r = crypt_init(&cd, argv[3]);
                if (r < 0)
                        return log_error_errno(r, "Failed to open integrity device %s: %m", argv[3]);

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, argv[2]);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", argv[2]);
                        return 0;
                }

                if (argc > 4) {
                        r = parse_integrity_options(argv[4], &arg_activate_flags, &params, &arg_datadevice, &arg_integrity_algr);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse options: %m");
                }

                if (arg_datadevice && *arg_datadevice) {
                        r = crypt_init_data_device(&cd, argv[3], arg_datadevice);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add separate data device: %m");
                }

                r = crypt_load(cd, CRYPT_INTEGRITY, &params);
                if (r < 0)
                        return log_error_errno(r, "Failed to load integrity superblock: %m");

                r = crypt_activate_by_volume_key(cd, argv[2], NULL, 0, arg_activate_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up integrity device: %m");

        } else if (streq(argv[1], "detach")) {

                r = crypt_init_by_name(&cd, argv[2]);
                if (r == -ENODEV) {
                        log_info("Volume %s already inactive.", argv[2]);
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "crypt_init_by_name() failed: %m");

                cryptsetup_enable_logging(cd);

                r = crypt_deactivate(cd, argv[2]);
                if (r < 0)
                        return log_error_errno(r, "Failed to deactivate: %m");

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", argv[1]);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "crypt-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"

static char *arg_root_hash = NULL;
static char *arg_data_what = NULL;
static char *arg_hash_what = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_data_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hash_what, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-veritysetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME DATADEVICE HASHDEVICE ROOTHASH\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an integrity protected block device.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               link);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        if (argc <= 1)
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires at least two arguments.");

        log_setup_service();

        umask(0022);

        if (streq(argv[1], "attach")) {
                _cleanup_free_ void *m = NULL;
                crypt_status_info status;
                size_t l;

                if (argc < 6)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least two arguments.");

                r = unhexmem(argv[5], strlen(argv[5]), &m, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse root hash: %m");

                r = crypt_init(&cd, argv[4]);
                if (r < 0)
                        return log_error_errno(r, "Failed to open verity device %s: %m", argv[4]);

                crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);

                status = crypt_status(cd, argv[2]);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", argv[2]);
                        return 0;
                }

                r = crypt_load(cd, CRYPT_VERITY, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to load verity superblock: %m");

                r = crypt_set_data_device(cd, argv[3]);
                if (r < 0)
                        return log_error_errno(r, "Failed to configure data device: %m");

                r = crypt_activate_by_volume_key(cd, argv[2], m, l, CRYPT_ACTIVATE_READONLY);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up verity device: %m");

        } else if (streq(argv[1], "detach")) {

                r = crypt_init_by_name(&cd, argv[2]);
                if (r == -ENODEV) {
                        log_info("Volume %s already inactive.", argv[2]);
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "crypt_init_by_name() failed: %m");

                crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);

                r = crypt_deactivate(cd, argv[2]);
                if (r < 0)
                        return log_error_errno(r, "Failed to deactivate: %m");

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", argv[1]);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <libcryptsetup.h>
#include <stdio.h>
#include <sys/stat.h>

#include "log.h"
#include "hexdecoct.h"
#include "string-util.h"
#include "alloc-util.h"

static char *arg_root_hash = NULL;
static char *arg_data_what = NULL;
static char *arg_hash_what = NULL;

static int help(void) {
        printf("%s attach VOLUME DATADEVICE HASHDEVICE ROOTHASH\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an integrity protected block device.\n",
               program_invocation_short_name,
               program_invocation_short_name);

        return 0;
}

static void log_glue(int level, const char *msg, void *usrptr) {
        log_debug("%s", msg);
}

int main(int argc, char *argv[]) {
        struct crypt_device *cd = NULL;
        int r;

        if (argc <= 1) {
                r = help();
                goto finish;
        }

        if (argc < 3) {
                log_error("This program requires at least two arguments.");
                r = -EINVAL;
                goto finish;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (streq(argv[1], "attach")) {
                _cleanup_free_ void *m = NULL;
                crypt_status_info status;
                size_t l;

                if (argc < 6) {
                        log_error("attach requires at least two arguments.");
                        r = -EINVAL;
                        goto finish;
                }

                r = unhexmem(argv[5], strlen(argv[5]), &m, &l);
                if (r < 0) {
                        log_error("Failed to parse root hash.");
                        goto finish;
                }

                r = crypt_init(&cd, argv[4]);
                if (r < 0) {
                        log_error_errno(r, "Failed to open verity device %s: %m", argv[4]);
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);

                status = crypt_status(cd, argv[2]);
                if (status == CRYPT_ACTIVE || status == CRYPT_BUSY) {
                        log_info("Volume %s already active.", argv[2]);
                        r = 0;
                        goto finish;
                }

                r = crypt_load(cd, CRYPT_VERITY, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to load verity superblock: %m");
                        goto finish;
                }

                r = crypt_set_data_device(cd, argv[3]);
                if (r < 0) {
                        log_error_errno(r, "Failed to configure data device: %m");
                        goto finish;
                }

                r = crypt_activate_by_volume_key(cd, argv[2], m, l, CRYPT_ACTIVATE_READONLY);
                if (r < 0) {
                        log_error_errno(r, "Failed to set up verity device: %m");
                        goto finish;
                }

        } else if (streq(argv[1], "detach")) {

                r = crypt_init_by_name(&cd, argv[2]);
                if (r == -ENODEV) {
                        log_info("Volume %s already inactive.", argv[2]);
                        goto finish;
                } else if (r < 0) {
                        log_error_errno(r, "crypt_init_by_name() failed: %m");
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);

                r = crypt_deactivate(cd, argv[2]);
                if (r < 0) {
                        log_error_errno(r, "Failed to deactivate: %m");
                        goto finish;
                }

        } else {
                log_error("Unknown verb %s.", argv[1]);
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        if (cd)
                crypt_free(cd);

        free(arg_root_hash);
        free(arg_data_what);
        free(arg_hash_what);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>
#include <errno.h>

#include <libcryptsetup.h>

#include "log.h"
#include "util.h"
#include "ask-password-api.h"

static unsigned opt_tries = 0;
static char *opt_cipher = NULL;
static unsigned opt_size = 0;
static char *opt_hash = NULL;
static bool opt_readonly = false;
static bool opt_verify = false;
static usec_t arg_timeout = 0;

static int parse_one_option(const char *option) {
        assert(option);

        /* Handled outside of this tool */
        if (streq(option, "swap") ||
            streq(option, "tmp") ||
            streq(option, "noauto"))
                return 0;

        if (startswith(option, "cipher=")) {
                char *t;

                if (!(t = strdup(option+7)))
                        return -ENOMEM;

                free(opt_cipher);
                opt_cipher = t;

        } else if (startswith(option, "size=")) {

                if (safe_atou(option+5, &opt_size) < 0) {
                        log_error("size= parse failure, ignoring.");
                        return 0;
                }

        } else if (startswith(option, "hash=")) {
                char *t;

                if (!(t = strdup(option+5)))
                        return -ENOMEM;

                free(opt_hash);
                opt_hash = t;

        } else if (startswith(option, "tries=")) {

                if (safe_atou(option+6, &opt_tries) < 0) {
                        log_error("tries= parse failure, ignoring.");
                        return 0;
                }

        } else if (streq(option, "readonly"))
                opt_readonly = true;
        else if (streq(option, "verify"))
                opt_verify = true;
        else if (startswith(option, "timeout=")) {

                if (parse_usec(option+8, &arg_timeout) < 0) {
                        log_error("timeout= parse failure, ignoring.");
                        return 0;
                }

        } else
                log_error("Encountered unknown /etc/crypttab option '%s', ignoring.", option);

        return 0;
}

static int parse_options(const char *options) {
        char *state;
        char *w;
        size_t l;

        assert(options);

        FOREACH_WORD_SEPARATOR(w, l, options, ",", state) {
                char *o;
                int r;

                if (!(o = strndup(w, l)))
                        return -ENOMEM;

                r = parse_one_option(o);
                free(o);

                if (r < 0)
                        return r;
        }

        return 0;
}

static void log_glue(int level, const char *msg, void *usrptr) {

        log_full(level == CRYPT_LOG_ERROR   ? LOG_ERR :
                 level == CRYPT_LOG_VERBOSE ? LOG_INFO :
                 level == CRYPT_LOG_DEBUG   ? LOG_DEBUG :
                                              LOG_NOTICE,
                 "%s", msg);
}

static int password_glue(const char *msg, char *buf, size_t length, void *usrptr) {
        usec_t until;
        char *password = NULL;
        int k;

        until = now(CLOCK_MONOTONIC) + (arg_timeout > 0 ? arg_timeout : 60 * USEC_PER_SEC);

        if ((k = ask_password_agent(msg, "drive-harddisk", until, &password)) < 0)
                return k;

        strncpy(buf, password, length-1);
        buf[length-1] = 0;

        free(password);

        return strlen(buf);
}

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE;
        struct crypt_device *cd = NULL;

        if (argc < 3) {
                log_error("This program requires at least two arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (streq(argv[1], "attach") ||
            streq(argv[1], "format-and-attach")) {
                uint32_t flags = 0;
                int k;
                const char *key_file = NULL;

                if (argc < 4) {
                        log_error("attach requires at least two arguments.");
                        goto finish;
                }

                if (argc >= 5 && argv[4][0] && !streq(argv[4], "-")) {

                        if (!path_is_absolute(argv[4]))
                                log_error("Password file path %s is not absolute. Ignoring.", argv[4]);
                        else
                                key_file = argv[4];
                }

                if (argc >= 6 && argv[5][0] && !streq(argv[5], "-"))
                        parse_options(argv[5]);

                if ((k = crypt_init(&cd, argv[3]))) {
                        log_error("crypt_init() failed: %s", strerror(-k));
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);
                crypt_set_password_callback(cd, password_glue, NULL);

                if (streq(argv[1], "format-and-attach")) {

                        /* Format with random key and attach */

                        log_error("Formatting not yet supported.");
                        goto finish;

                } else if ((k = crypt_load(cd, CRYPT_LUKS1, NULL))) {
                        log_error("crypt_load() failed: %s", strerror(-k));
                        goto finish;
                }

                if (opt_readonly)
                        flags |= CRYPT_ACTIVATE_READONLY;

                if (key_file) {
                        crypt_set_password_retry(cd, 1);
                        k = crypt_activate_by_keyfile(cd, argv[2], CRYPT_ANY_SLOT, key_file, 0, flags);
                } else  {
                        crypt_set_password_retry(cd, opt_tries > 0 ? opt_tries : 3);
                        k = crypt_activate_by_passphrase(cd, argv[2], CRYPT_ANY_SLOT, NULL, 0, flags);
                }

                if (k < 0) {
                        log_error("Failed to activate: %s", strerror(-k));
                        goto finish;
                }

        } else if (streq(argv[1], "detach")) {
                int k;

                if ((k = crypt_init_by_name(&cd, argv[2]))) {
                        log_error("crypt_init() failed: %s", strerror(-k));
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);

                if ((k = crypt_deactivate(cd, argv[2])) < 0) {
                        log_error("Failed to deactivate: %s", strerror(-k));
                        goto finish;
                }

        } else {
                log_error("Unknown verb %s.", argv[1]);
                goto finish;
        }

        r = EXIT_SUCCESS;

finish:

        if (cd)
                crypt_free(cd);

        return r;
}

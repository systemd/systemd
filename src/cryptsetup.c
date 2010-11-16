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
#include <sys/mman.h>

#include <libcryptsetup.h>

#include "log.h"
#include "util.h"
#include "ask-password-api.h"

static const char *opt_type = NULL; /* LUKS1 or PLAIN */
static char *opt_cipher = NULL;
static unsigned opt_key_size = 0;
static char *opt_hash = NULL;
static unsigned opt_tries = 0;
static bool opt_readonly = false;
static bool opt_verify = false;
static usec_t opt_timeout = 0;

/* Options Debian's crypttab knows we don't:

    offset=
    skip=
    precheck=
    check=
    checkargs=
    noearly=
    loud=
    keyscript=
*/

static int parse_one_option(const char *option) {
        assert(option);

        /* Handled outside of this tool */
        if (streq(option, "noauto"))
                return 0;

        if (startswith(option, "cipher=")) {
                char *t;

                if (!(t = strdup(option+7)))
                        return -ENOMEM;

                free(opt_cipher);
                opt_cipher = t;

        } else if (startswith(option, "size=")) {

                if (safe_atou(option+5, &opt_key_size) < 0) {
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
        else if (streq(option, "luks"))
                opt_type = CRYPT_LUKS1;
        else if (streq(option, "plain") ||
                 streq(option, "swap") ||
                 streq(option, "tmp"))
                opt_type = CRYPT_PLAIN;
        else if (startswith(option, "timeout=")) {

                if (parse_usec(option+8, &opt_timeout) < 0) {
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
        log_debug("%s", msg);
}

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE;
        struct crypt_device *cd = NULL;
        char *password = NULL, *truncated_cipher = NULL;
        const char *cipher = NULL, *cipher_mode = NULL, *hash = NULL;

        if (argc < 3) {
                log_error("This program requires at least two arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (streq(argv[1], "attach")) {
                uint32_t flags = 0;
                int k;
                unsigned try;
                const char *key_file = NULL;
                usec_t until;
                crypt_status_info status;

                if (argc < 4) {
                        log_error("attach requires at least two arguments.");
                        goto finish;
                }

                if (argc >= 5 &&
                    argv[4][0] &&
                    !streq(argv[4], "-") &&
                    !streq(argv[4], "none")) {

                        if (!path_is_absolute(argv[4]))
                                log_error("Password file path %s is not absolute. Ignoring.", argv[4]);
                        else
                                key_file = argv[4];
                }

                if (argc >= 6 && argv[5][0] && !streq(argv[5], "-"))
                        parse_options(argv[5]);

                /* A delicious drop of snake oil */
                mlockall(MCL_FUTURE);

                if ((k = crypt_init(&cd, argv[3]))) {
                        log_error("crypt_init() failed: %s", strerror(-k));
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);

                status = crypt_status(cd, argv[2]);
                if (status == CRYPT_ACTIVE || status == CRYPT_BUSY) {
                        log_info("Volume %s already active.", argv[2]);
                        r = EXIT_SUCCESS;
                        goto finish;
                }

                if (opt_readonly)
                        flags |= CRYPT_ACTIVATE_READONLY;

                until = now(CLOCK_MONOTONIC) + (opt_timeout > 0 ? opt_timeout : 60 * USEC_PER_SEC);

                opt_tries = opt_tries > 0 ? opt_tries : 3;
                opt_key_size = (opt_key_size > 0 ? opt_key_size : 256);
                hash = opt_hash ? opt_hash : "ripemd160";

                if (opt_cipher) {
                        size_t l;

                        l = strcspn(opt_cipher, "-");

                        if (!(truncated_cipher = strndup(opt_cipher, l))) {
                                log_error("Out of memory");
                                goto finish;
                        }

                        cipher = truncated_cipher;
                        cipher_mode = opt_cipher[l] ? opt_cipher+l+1 : "plain";
                } else {
                        cipher = "aes";
                        cipher_mode = "cbc-essiv:sha256";
                }

                for (try = 0; try < opt_tries; try++) {
                        bool pass_volume_key = false;

                        free(password);
                        password = NULL;

                        if (!key_file) {
                                char *text;

                                if (asprintf(&text, "Please enter passphrase for disk %s!", argv[2]) < 0) {
                                        log_error("Out of memory");
                                        goto finish;
                                }

                                k = ask_password_auto(text, "drive-harddisk", until, &password);
                                free(text);

                                if (k < 0) {
                                        log_error("Failed to query password: %s", strerror(-k));
                                        goto finish;
                                }

                                if (opt_verify) {
                                        char *password2 = NULL;

                                        if (asprintf(&text, "Please enter passphrase for disk %s! (verification)", argv[2]) < 0) {
                                                log_error("Out of memory");
                                                goto finish;
                                        }

                                        k = ask_password_auto(text, "drive-harddisk", until, &password2);
                                        free(text);

                                        if (k < 0) {
                                                log_error("Failed to query verification password: %s", strerror(-k));
                                                goto finish;
                                        }

                                        if (!streq(password, password2)) {
                                                log_warning("Passwords did not match, retrying.");
                                                free(password2);
                                                continue;
                                        }

                                        free(password2);
                                }

                                if (strlen(password)+1 < opt_key_size) {
                                        char *c;

                                        /* Pad password if necessary */

                                        if (!(c = new(char, opt_key_size))) {
                                                log_error("Out of memory.");
                                                goto finish;
                                        }

                                        strncpy(c, password, opt_key_size);
                                        free(password);
                                        password = c;
                                }
                        }

                        if (!opt_type || streq(opt_type, CRYPT_LUKS1))
                                k = crypt_load(cd, CRYPT_LUKS1, NULL);

                        if ((!opt_type && k < 0) || streq_ptr(opt_type, CRYPT_PLAIN)) {
                                struct crypt_params_plain params;

                                zero(params);
                                params.hash = hash;

                                /* In contrast to what the name
                                 * crypt_setup() might suggest this
                                 * doesn't actually format anything,
                                 * it just configures encryption
                                 * parameters when used for plain
                                 * mode. */
                                k = crypt_format(cd, CRYPT_PLAIN,
                                                 cipher,
                                                 cipher_mode,
                                                 NULL,
                                                 NULL,
                                                 opt_key_size / 8,
                                                 &params);

                                pass_volume_key = streq(hash, "plain");
                        }

                        if (k < 0) {
                                log_error("Loading of cryptographic parameters failed: %s", strerror(-k));
                                goto finish;
                        }

                        log_info("Set cipher %s, mode %s, key size %i bits for device %s.",
                                 crypt_get_cipher(cd),
                                 crypt_get_cipher_mode(cd),
                                 crypt_get_volume_key_size(cd)*8,
                                 argv[3]);

                        if (key_file)
                                k = crypt_activate_by_keyfile(cd, argv[2], CRYPT_ANY_SLOT, key_file, opt_key_size, flags);
                        else if (pass_volume_key)
                                k = crypt_activate_by_volume_key(cd, argv[2], password, opt_key_size, flags);
                        else
                                k = crypt_activate_by_passphrase(cd, argv[2], CRYPT_ANY_SLOT, password, strlen(password), flags);

                        if (k >= 0)
                                break;

                        if (k != -EPERM) {
                                log_error("Failed to activate: %s", strerror(-k));
                                goto finish;
                        }

                        log_warning("Invalid passphrase.");
                }

                if (try >= opt_tries) {
                        log_error("Too many attempts.");
                        r = EXIT_FAILURE;
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

        free(opt_cipher);
        free(opt_hash);

        free(truncated_cipher);

        free(password);

        return r;
}

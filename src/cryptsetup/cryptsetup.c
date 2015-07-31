/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <mntent.h>

#include <libcryptsetup.h>

#include "fileio.h"
#include "log.h"
#include "util.h"
#include "path-util.h"
#include "strv.h"
#include "ask-password-api.h"
#include "sd-device.h"
#include "device-util.h"

static const char *arg_type = NULL; /* CRYPT_LUKS1, CRYPT_TCRYPT or CRYPT_PLAIN */
static char *arg_cipher = NULL;
static unsigned arg_key_size = 0;
static int arg_key_slot = CRYPT_ANY_SLOT;
static unsigned arg_keyfile_size = 0;
static unsigned arg_keyfile_offset = 0;
static char *arg_hash = NULL;
static char *arg_header = NULL;
static unsigned arg_tries = 3;
static bool arg_readonly = false;
static bool arg_verify = false;
static bool arg_discards = false;
static bool arg_tcrypt_hidden = false;
static bool arg_tcrypt_system = false;
static char **arg_tcrypt_keyfiles = NULL;
static uint64_t arg_offset = 0;
static uint64_t arg_skip = 0;
static usec_t arg_timeout = 0;

/* Options Debian's crypttab knows we don't:

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
        if (STR_IN_SET(option, "noauto", "auto", "nofail", "fail"))
                return 0;

        if (startswith(option, "cipher=")) {
                char *t;

                t = strdup(option+7);
                if (!t)
                        return log_oom();

                free(arg_cipher);
                arg_cipher = t;

        } else if (startswith(option, "size=")) {

                if (safe_atou(option+5, &arg_key_size) < 0) {
                        log_error("size= parse failure, ignoring.");
                        return 0;
                }

                if (arg_key_size % 8) {
                        log_error("size= not a multiple of 8, ignoring.");
                        return 0;
                }

                arg_key_size /= 8;

        } else if (startswith(option, "key-slot=")) {

                arg_type = CRYPT_LUKS1;
                if (safe_atoi(option+9, &arg_key_slot) < 0) {
                        log_error("key-slot= parse failure, ignoring.");
                        return 0;
                }

        } else if (startswith(option, "tcrypt-keyfile=")) {

                arg_type = CRYPT_TCRYPT;
                if (path_is_absolute(option+15)) {
                        if (strv_extend(&arg_tcrypt_keyfiles, option + 15) < 0)
                                return log_oom();
                } else
                        log_error("Key file path '%s' is not absolute. Ignoring.", option+15);

        } else if (startswith(option, "keyfile-size=")) {

                if (safe_atou(option+13, &arg_keyfile_size) < 0) {
                        log_error("keyfile-size= parse failure, ignoring.");
                        return 0;
                }

        } else if (startswith(option, "keyfile-offset=")) {

                if (safe_atou(option+15, &arg_keyfile_offset) < 0) {
                        log_error("keyfile-offset= parse failure, ignoring.");
                        return 0;
                }

        } else if (startswith(option, "hash=")) {
                char *t;

                t = strdup(option+5);
                if (!t)
                        return log_oom();

                free(arg_hash);
                arg_hash = t;

        } else if (startswith(option, "header=")) {
                arg_type = CRYPT_LUKS1;

                if (!path_is_absolute(option+7)) {
                        log_error("Header path '%s' is not absolute, refusing.", option+7);
                        return -EINVAL;
                }

                if (arg_header) {
                        log_error("Duplicate header= options, refusing.");
                        return -EINVAL;
                }

                arg_header = strdup(option+7);
                if (!arg_header)
                        return log_oom();

        } else if (startswith(option, "tries=")) {

                if (safe_atou(option+6, &arg_tries) < 0) {
                        log_error("tries= parse failure, ignoring.");
                        return 0;
                }

        } else if (STR_IN_SET(option, "readonly", "read-only"))
                arg_readonly = true;
        else if (streq(option, "verify"))
                arg_verify = true;
        else if (STR_IN_SET(option, "allow-discards", "discard"))
                arg_discards = true;
        else if (streq(option, "luks"))
                arg_type = CRYPT_LUKS1;
        else if (streq(option, "tcrypt"))
                arg_type = CRYPT_TCRYPT;
        else if (streq(option, "tcrypt-hidden")) {
                arg_type = CRYPT_TCRYPT;
                arg_tcrypt_hidden = true;
        } else if (streq(option, "tcrypt-system")) {
                arg_type = CRYPT_TCRYPT;
                arg_tcrypt_system = true;
        } else if (STR_IN_SET(option, "plain", "swap", "tmp"))
                arg_type = CRYPT_PLAIN;
        else if (startswith(option, "timeout=")) {

                if (parse_sec(option+8, &arg_timeout) < 0) {
                        log_error("timeout= parse failure, ignoring.");
                        return 0;
                }

        } else if (startswith(option, "offset=")) {

                if (safe_atou64(option+7, &arg_offset) < 0) {
                        log_error("offset= parse failure, refusing.");
                        return -EINVAL;
                }

        } else if (startswith(option, "skip=")) {

                if (safe_atou64(option+5, &arg_skip) < 0) {
                        log_error("skip= parse failure, refusing.");
                        return -EINVAL;
                }

        } else if (!streq(option, "none"))
                log_error("Encountered unknown /etc/crypttab option '%s', ignoring.", option);

        return 0;
}

static int parse_options(const char *options) {
        const char *word, *state;
        size_t l;
        int r;

        assert(options);

        FOREACH_WORD_SEPARATOR(word, l, options, ",", state) {
                _cleanup_free_ char *o;

                o = strndup(word, l);
                if (!o)
                        return -ENOMEM;
                r = parse_one_option(o);
                if (r < 0)
                        return r;
        }

        /* sanity-check options */
        if (arg_type != NULL && !streq(arg_type, CRYPT_PLAIN)) {
                if (arg_offset)
                      log_warning("offset= ignored with type %s", arg_type);
                if (arg_skip)
                      log_warning("skip= ignored with type %s", arg_type);
        }

        return 0;
}

static void log_glue(int level, const char *msg, void *usrptr) {
        log_debug("%s", msg);
}

static int disk_major_minor(const char *path, char **ret) {
        struct stat st;

        assert(path);

        if (stat(path, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -EINVAL;

        if (asprintf(ret, "/dev/block/%d:%d", major(st.st_rdev), minor(st.st_rdev)) < 0)
                return -errno;

        return 0;
}

static char* disk_description(const char *path) {

        static const char name_fields[] =
                "ID_PART_ENTRY_NAME\0"
                "DM_NAME\0"
                "ID_MODEL_FROM_DATABASE\0"
                "ID_MODEL\0";

        _cleanup_device_unref_ sd_device *device = NULL;
        struct stat st;
        const char *i;
        int r;

        assert(path);

        if (stat(path, &st) < 0)
                return NULL;

        if (!S_ISBLK(st.st_mode))
                return NULL;

        r = sd_device_new_from_devnum(&device, 'b', st.st_rdev);
        if (r < 0)
                return NULL;

        NULSTR_FOREACH(i, name_fields) {
                const char *name;

                r = sd_device_get_property_value(device, i, &name);
                if (r >= 0 && !isempty(name))
                        return strdup(name);
        }

        return NULL;
}

static char *disk_mount_point(const char *label) {
        _cleanup_free_ char *device = NULL;
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

        /* Yeah, we don't support native systemd unit files here for now */

        if (asprintf(&device, "/dev/mapper/%s", label) < 0)
                return NULL;

        f = setmntent("/etc/fstab", "r");
        if (!f)
                return NULL;

        while ((m = getmntent(f)))
                if (path_equal(m->mnt_fsname, device))
                        return strdup(m->mnt_dir);

        return NULL;
}

static int get_password(const char *vol, const char *src, usec_t until, bool accept_cached, char ***passwords) {
        int r = 0;
        char **p;
        _cleanup_free_ char *text = NULL;
        _cleanup_free_ char *escaped_name = NULL;
        char *id;
        const char *name = NULL;
        _cleanup_free_ char *description = NULL, *name_buffer = NULL,
                *mount_point = NULL, *maj_min = NULL;

        assert(vol);
        assert(src);
        assert(passwords);

        description = disk_description(src);
        mount_point = disk_mount_point(vol);

        if (description && streq(vol, description)) {
                /* If the description string is simply the
                 * volume name, then let's not show this
                 * twice */
                description = mfree(description);
        }

        if (mount_point && description)
                r = asprintf(&name_buffer, "%s (%s) on %s", description, vol, mount_point);
        else if (mount_point)
                r = asprintf(&name_buffer, "%s on %s", vol, mount_point);
        else if (description)
                r = asprintf(&name_buffer, "%s (%s)", description, vol);

        if (r < 0)
                return log_oom();

        name = name_buffer ? name_buffer : vol;

        if (asprintf(&text, "Please enter passphrase for disk %s!", name) < 0)
                return log_oom();

        if (src)
                (void) disk_major_minor(src, &maj_min);

        if (maj_min) {
                escaped_name = maj_min;
                maj_min = NULL;
        } else
                escaped_name = cescape(name);

        if (!escaped_name)
                return log_oom();

        id = strjoina("cryptsetup:", escaped_name);

        r = ask_password_auto(text, "drive-harddisk", id, until, accept_cached, passwords);
        if (r < 0)
                return log_error_errno(r, "Failed to query password: %m");

        if (arg_verify) {
                _cleanup_strv_free_ char **passwords2 = NULL;

                assert(strv_length(*passwords) == 1);

                if (asprintf(&text, "Please enter passphrase for disk %s! (verification)", name) < 0)
                        return log_oom();

                id = strjoina("cryptsetup-verification:", escaped_name);

                r = ask_password_auto(text, "drive-harddisk", id, until, false, &passwords2);
                if (r < 0)
                        return log_error_errno(r, "Failed to query verification password: %m");

                assert(strv_length(passwords2) == 1);

                if (!streq(*passwords[0], passwords2[0])) {
                        log_warning("Passwords did not match, retrying.");
                        return -EAGAIN;
                }
        }

        strv_uniq(*passwords);

        STRV_FOREACH(p, *passwords) {
                char *c;

                if (strlen(*p)+1 >= arg_key_size)
                        continue;

                /* Pad password if necessary */
                if (!(c = new(char, arg_key_size)))
                        return log_oom();

                strncpy(c, *p, arg_key_size);
                free(*p);
                *p = c;
        }

        return 0;
}

static int attach_tcrypt(struct crypt_device *cd,
                                const char *name,
                                const char *key_file,
                                char **passwords,
                                uint32_t flags) {
        int r = 0;
        _cleanup_free_ char *passphrase = NULL;
        struct crypt_params_tcrypt params = {
                .flags = CRYPT_TCRYPT_LEGACY_MODES,
                .keyfiles = (const char **)arg_tcrypt_keyfiles,
                .keyfiles_count = strv_length(arg_tcrypt_keyfiles)
        };

        assert(cd);
        assert(name);
        assert(key_file || (passwords && passwords[0]));

        if (arg_tcrypt_hidden)
                params.flags |= CRYPT_TCRYPT_HIDDEN_HEADER;

        if (arg_tcrypt_system)
                params.flags |= CRYPT_TCRYPT_SYSTEM_HEADER;

        if (key_file) {
                r = read_one_line_file(key_file, &passphrase);
                if (r < 0) {
                        log_error_errno(r, "Failed to read password file '%s': %m", key_file);
                        return -EAGAIN;
                }

                params.passphrase = passphrase;
        } else
                params.passphrase = passwords[0];
        params.passphrase_size = strlen(params.passphrase);

        r = crypt_load(cd, CRYPT_TCRYPT, &params);
        if (r < 0) {
                if (key_file && r == -EPERM) {
                        log_error("Failed to activate using password file '%s'.", key_file);
                        return -EAGAIN;
                }
                return r;
        }

        return crypt_activate_by_volume_key(cd, name, NULL, 0, flags);
}

static int attach_luks_or_plain(struct crypt_device *cd,
                                const char *name,
                                const char *key_file,
                                const char *data_device,
                                char **passwords,
                                uint32_t flags) {
        int r = 0;
        bool pass_volume_key = false;

        assert(cd);
        assert(name);
        assert(key_file || passwords);

        if (!arg_type || streq(arg_type, CRYPT_LUKS1)) {
                r = crypt_load(cd, CRYPT_LUKS1, NULL);
                if (r < 0) {
                        log_error("crypt_load() failed on device %s.\n", crypt_get_device_name(cd));
                        return r;
                }

                if (data_device)
                        r = crypt_set_data_device(cd, data_device);
        }

        if ((!arg_type && r < 0) || streq_ptr(arg_type, CRYPT_PLAIN)) {
                struct crypt_params_plain params = {
                        .offset = arg_offset,
                        .skip = arg_skip,
                };
                const char *cipher, *cipher_mode;
                _cleanup_free_ char *truncated_cipher = NULL;

                if (arg_hash) {
                        /* plain isn't a real hash type. it just means "use no hash" */
                        if (!streq(arg_hash, "plain"))
                                params.hash = arg_hash;
                } else if (!key_file)
                        /* for CRYPT_PLAIN, the behaviour of cryptsetup
                         * package is to not hash when a key file is provided */
                        params.hash = "ripemd160";

                if (arg_cipher) {
                        size_t l;

                        l = strcspn(arg_cipher, "-");
                        truncated_cipher = strndup(arg_cipher, l);
                        if (!truncated_cipher)
                                return log_oom();

                        cipher = truncated_cipher;
                        cipher_mode = arg_cipher[l] ? arg_cipher+l+1 : "plain";
                } else {
                        cipher = "aes";
                        cipher_mode = "cbc-essiv:sha256";
                }

                /* for CRYPT_PLAIN limit reads
                 * from keyfile to key length, and
                 * ignore keyfile-size */
                arg_keyfile_size = arg_key_size;

                /* In contrast to what the name
                 * crypt_setup() might suggest this
                 * doesn't actually format anything,
                 * it just configures encryption
                 * parameters when used for plain
                 * mode. */
                r = crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode,
                                 NULL, NULL, arg_keyfile_size, &params);

                /* hash == NULL implies the user passed "plain" */
                pass_volume_key = (params.hash == NULL);
        }

        if (r < 0)
                return log_error_errno(r, "Loading of cryptographic parameters failed: %m");

        log_info("Set cipher %s, mode %s, key size %i bits for device %s.",
                 crypt_get_cipher(cd),
                 crypt_get_cipher_mode(cd),
                 crypt_get_volume_key_size(cd)*8,
                 crypt_get_device_name(cd));

        if (key_file) {
                r = crypt_activate_by_keyfile_offset(cd, name, arg_key_slot,
                                                     key_file, arg_keyfile_size,
                                                     arg_keyfile_offset, flags);
                if (r < 0) {
                        log_error_errno(r, "Failed to activate with key file '%s': %m", key_file);
                        return -EAGAIN;
                }
        } else {
                char **p;

                STRV_FOREACH(p, passwords) {
                        if (pass_volume_key)
                                r = crypt_activate_by_volume_key(cd, name, *p, arg_key_size, flags);
                        else
                                r = crypt_activate_by_passphrase(cd, name, arg_key_slot, *p, strlen(*p), flags);

                        if (r >= 0)
                                break;
                }
        }

        return r;
}

static int help(void) {

        printf("%s attach VOLUME SOURCEDEVICE [PASSWORD] [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an encrypted block device.\n",
               program_invocation_short_name,
               program_invocation_short_name);

        return 0;
}

int main(int argc, char *argv[]) {
        int r = EXIT_FAILURE;
        struct crypt_device *cd = NULL;

        if (argc <= 1) {
                help();
                return EXIT_SUCCESS;
        }

        if (argc < 3) {
                log_error("This program requires at least two arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (streq(argv[1], "attach")) {
                uint32_t flags = 0;
                int k;
                unsigned tries;
                usec_t until;
                crypt_status_info status;
                const char *key_file = NULL;

                /* Arguments: systemd-cryptsetup attach VOLUME SOURCE-DEVICE [PASSWORD] [OPTIONS] */

                if (argc < 4) {
                        log_error("attach requires at least two arguments.");
                        goto finish;
                }

                if (argc >= 5 &&
                    argv[4][0] &&
                    !streq(argv[4], "-") &&
                    !streq(argv[4], "none")) {

                        if (!path_is_absolute(argv[4]))
                                log_error("Password file path '%s' is not absolute. Ignoring.", argv[4]);
                        else
                                key_file = argv[4];
                }

                if (argc >= 6 && argv[5][0] && !streq(argv[5], "-")) {
                        if (parse_options(argv[5]) < 0)
                                goto finish;
                }

                /* A delicious drop of snake oil */
                mlockall(MCL_FUTURE);

                if (arg_header) {
                        log_debug("LUKS header: %s", arg_header);
                        k = crypt_init(&cd, arg_header);
                } else
                        k = crypt_init(&cd, argv[3]);

                if (k) {
                        log_error_errno(k, "crypt_init() failed: %m");
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);

                status = crypt_status(cd, argv[2]);
                if (status == CRYPT_ACTIVE || status == CRYPT_BUSY) {
                        log_info("Volume %s already active.", argv[2]);
                        r = EXIT_SUCCESS;
                        goto finish;
                }

                if (arg_readonly)
                        flags |= CRYPT_ACTIVATE_READONLY;

                if (arg_discards)
                        flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

                if (arg_timeout > 0)
                        until = now(CLOCK_MONOTONIC) + arg_timeout;
                else
                        until = 0;

                arg_key_size = (arg_key_size > 0 ? arg_key_size : (256 / 8));

                if (key_file) {
                        struct stat st;

                        /* Ideally we'd do this on the open fd, but since this is just a
                         * warning it's OK to do this in two steps. */
                        if (stat(key_file, &st) >= 0 && S_ISREG(st.st_mode) && (st.st_mode & 0005))
                                log_warning("Key file %s is world-readable. This is not a good idea!", key_file);
                }

                for (tries = 0; arg_tries == 0 || tries < arg_tries; tries++) {
                        _cleanup_strv_free_ char **passwords = NULL;

                        if (!key_file) {
                                k = get_password(argv[2], argv[3], until, tries == 0 && !arg_verify, &passwords);
                                if (k == -EAGAIN)
                                        continue;
                                else if (k < 0)
                                        goto finish;
                        }

                        if (streq_ptr(arg_type, CRYPT_TCRYPT))
                                k = attach_tcrypt(cd, argv[2], key_file, passwords, flags);
                        else
                                k = attach_luks_or_plain(cd,
                                                         argv[2],
                                                         key_file,
                                                         arg_header ? argv[3] : NULL,
                                                         passwords,
                                                         flags);
                        if (k >= 0)
                                break;
                        else if (k == -EAGAIN) {
                                key_file = NULL;
                                continue;
                        } else if (k != -EPERM) {
                                log_error_errno(k, "Failed to activate: %m");
                                goto finish;
                        }

                        log_warning("Invalid passphrase.");
                }

                if (arg_tries != 0 && tries >= arg_tries) {
                        log_error("Too many attempts; giving up.");
                        r = EXIT_FAILURE;
                        goto finish;
                }

        } else if (streq(argv[1], "detach")) {
                int k;

                k = crypt_init_by_name(&cd, argv[2]);
                if (k) {
                        log_error_errno(k, "crypt_init() failed: %m");
                        goto finish;
                }

                crypt_set_log_callback(cd, log_glue, NULL);

                k = crypt_deactivate(cd, argv[2]);
                if (k < 0) {
                        log_error_errno(k, "Failed to deactivate: %m");
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

        free(arg_cipher);
        free(arg_hash);
        free(arg_header);
        strv_free(arg_tcrypt_keyfiles);

        return r;
}

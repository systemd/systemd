/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <mntent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptsetup-keyfile.h"
#include "cryptsetup-pkcs11.h"
#include "cryptsetup-util.h"
#include "device-util.h"
#include "escape.h"
#include "fileio.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pkcs11-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"

/* internal helper */
#define ANY_LUKS "LUKS"
/* as in src/cryptsetup.h */
#define CRYPT_SECTOR_SIZE 512
#define CRYPT_MAX_SECTOR_SIZE 4096

static const char *arg_type = NULL; /* ANY_LUKS, CRYPT_LUKS1, CRYPT_LUKS2, CRYPT_TCRYPT, CRYPT_BITLK or CRYPT_PLAIN */
static char *arg_cipher = NULL;
static unsigned arg_key_size = 0;
static unsigned arg_sector_size = CRYPT_SECTOR_SIZE;
static int arg_key_slot = CRYPT_ANY_SLOT;
static unsigned arg_keyfile_size = 0;
static uint64_t arg_keyfile_offset = 0;
static bool arg_keyfile_erase = false;
static bool arg_try_empty_password = false;
static char *arg_hash = NULL;
static char *arg_header = NULL;
static unsigned arg_tries = 3;
static bool arg_readonly = false;
static bool arg_verify = false;
static bool arg_discards = false;
static bool arg_same_cpu_crypt = false;
static bool arg_submit_from_crypt_cpus = false;
static bool arg_tcrypt_hidden = false;
static bool arg_tcrypt_system = false;
static bool arg_tcrypt_veracrypt = false;
static char **arg_tcrypt_keyfiles = NULL;
static uint64_t arg_offset = 0;
static uint64_t arg_skip = 0;
static usec_t arg_timeout = USEC_INFINITY;
static char *arg_pkcs11_uri = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_cipher, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_header, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tcrypt_keyfiles, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_uri, freep);

/* Options Debian's crypttab knows we don't:

    check=
    checkargs=
    noearly
    loud
    quiet
    keyscript=
    initramfs
*/

static int parse_one_option(const char *option) {
        const char *val;
        int r;

        assert(option);

        /* Handled outside of this tool */
        if (STR_IN_SET(option, "noauto", "auto", "nofail", "fail", "_netdev", "keyfile-timeout"))
                return 0;

        if (startswith(option, "keyfile-timeout="))
                return 0;

        if ((val = startswith(option, "cipher="))) {
                r = free_and_strdup(&arg_cipher, val);
                if (r < 0)
                        return log_oom();

        } else if ((val = startswith(option, "size="))) {

                r = safe_atou(val, &arg_key_size);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

                if (arg_key_size % 8) {
                        log_error("size= not a multiple of 8, ignoring.");
                        return 0;
                }

                arg_key_size /= 8;

        } else if ((val = startswith(option, "sector-size="))) {

                r = safe_atou(val, &arg_sector_size);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

                if (arg_sector_size % 2) {
                        log_error("sector-size= not a multiple of 2, ignoring.");
                        return 0;
                }

                if (arg_sector_size < CRYPT_SECTOR_SIZE || arg_sector_size > CRYPT_MAX_SECTOR_SIZE) {
                        log_error("sector-size= is outside of %u and %u, ignoring.", CRYPT_SECTOR_SIZE, CRYPT_MAX_SECTOR_SIZE);
                        return 0;
                }

        } else if ((val = startswith(option, "key-slot=")) ||
                   (val = startswith(option, "keyslot="))) {

                arg_type = ANY_LUKS;
                r = safe_atoi(val, &arg_key_slot);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

        } else if ((val = startswith(option, "tcrypt-keyfile="))) {

                arg_type = CRYPT_TCRYPT;
                if (path_is_absolute(val)) {
                        if (strv_extend(&arg_tcrypt_keyfiles, val) < 0)
                                return log_oom();
                } else
                        log_error("Key file path \"%s\" is not absolute. Ignoring.", val);

        } else if ((val = startswith(option, "keyfile-size="))) {

                r = safe_atou(val, &arg_keyfile_size);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

        } else if ((val = startswith(option, "keyfile-offset="))) {

                r = safe_atou64(val, &arg_keyfile_offset);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

        } else if ((val = startswith(option, "keyfile-erase="))) {

                r = parse_boolean(val);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

                arg_keyfile_erase = r;

        } else if (streq(option, "keyfile-erase"))
                arg_keyfile_erase = true;

        else if ((val = startswith(option, "hash="))) {
                r = free_and_strdup(&arg_hash, val);
                if (r < 0)
                        return log_oom();

        } else if ((val = startswith(option, "header="))) {
                arg_type = ANY_LUKS;

                if (!path_is_absolute(val))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Header path \"%s\" is not absolute, refusing.", val);

                if (arg_header)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Duplicate header= option, refusing.");

                arg_header = strdup(val);
                if (!arg_header)
                        return log_oom();

        } else if ((val = startswith(option, "tries="))) {

                r = safe_atou(val, &arg_tries);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

        } else if (STR_IN_SET(option, "readonly", "read-only"))
                arg_readonly = true;
        else if (streq(option, "verify"))
                arg_verify = true;
        else if (STR_IN_SET(option, "allow-discards", "discard"))
                arg_discards = true;
        else if (streq(option, "same-cpu-crypt"))
                arg_same_cpu_crypt = true;
        else if (streq(option, "submit-from-crypt-cpus"))
                arg_submit_from_crypt_cpus = true;
        else if (streq(option, "luks"))
                arg_type = ANY_LUKS;
/* since cryptsetup 2.3.0 (Feb 2020) */
#ifdef CRYPT_BITLK
        else if (streq(option, "bitlk"))
                arg_type = CRYPT_BITLK;
#endif
        else if (streq(option, "tcrypt"))
                arg_type = CRYPT_TCRYPT;
        else if (STR_IN_SET(option, "tcrypt-hidden", "tcrypthidden")) {
                arg_type = CRYPT_TCRYPT;
                arg_tcrypt_hidden = true;
        } else if (streq(option, "tcrypt-system")) {
                arg_type = CRYPT_TCRYPT;
                arg_tcrypt_system = true;
        } else if (STR_IN_SET(option, "tcrypt-veracrypt", "veracrypt")) {
                arg_type = CRYPT_TCRYPT;
                arg_tcrypt_veracrypt = true;
        } else if (STR_IN_SET(option, "plain", "swap", "tmp") ||
                   startswith(option, "tmp="))
                arg_type = CRYPT_PLAIN;
        else if ((val = startswith(option, "timeout="))) {

                r = parse_sec_fix_0(val, &arg_timeout);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

        } else if ((val = startswith(option, "offset="))) {

                r = safe_atou64(val, &arg_offset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s: %m", option);

        } else if ((val = startswith(option, "skip="))) {

                r = safe_atou64(val, &arg_skip);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s: %m", option);

        } else if ((val = startswith(option, "pkcs11-uri="))) {

                if (!pkcs11_uri_valid(val))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "pkcs11-uri= parameter expects a PKCS#11 URI, refusing");

                r = free_and_strdup(&arg_pkcs11_uri, val);
                if (r < 0)
                        return log_oom();

        } else if ((val = startswith(option, "try-empty-password="))) {

                r = parse_boolean(val);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

                arg_try_empty_password = r;

        } else if (streq(option, "try-empty-password"))
                arg_try_empty_password = true;

        else if (!streq(option, "x-initrd.attach"))
                log_warning("Encountered unknown /etc/crypttab option '%s', ignoring.", option);

        return 0;
}

static int parse_options(const char *options) {
        assert(options);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                int r;

                r = extract_first_word(&options, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse options: %m");
                if (r == 0)
                        break;

                r = parse_one_option(word);
                if (r < 0)
                        return r;
        }

        /* sanity-check options */
        if (arg_type && !streq(arg_type, CRYPT_PLAIN)) {
                if (arg_offset != 0)
                      log_warning("offset= ignored with type %s", arg_type);
                if (arg_skip != 0)
                      log_warning("skip= ignored with type %s", arg_type);
        }

        return 0;
}

static char* disk_description(const char *path) {
        static const char name_fields[] =
                "ID_PART_ENTRY_NAME\0"
                "DM_NAME\0"
                "ID_MODEL_FROM_DATABASE\0"
                "ID_MODEL\0";

        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *i, *name;
        struct stat st;

        assert(path);

        if (stat(path, &st) < 0)
                return NULL;

        if (!S_ISBLK(st.st_mode))
                return NULL;

        if (sd_device_new_from_devnum(&device, 'b', st.st_rdev) < 0)
                return NULL;

        NULSTR_FOREACH(i, name_fields)
                if (sd_device_get_property_value(device, i, &name) >= 0 &&
                    !isempty(name))
                        return strdup(name);

        return NULL;
}

static char *disk_mount_point(const char *label) {
        _cleanup_free_ char *device = NULL;
        _cleanup_endmntent_ FILE *f = NULL;
        struct mntent *m;

        /* Yeah, we don't support native systemd unit files here for now */

        device = strjoin("/dev/mapper/", label);
        if (!device)
                return NULL;

        f = setmntent(fstab_path(), "re");
        if (!f)
                return NULL;

        while ((m = getmntent(f)))
                if (path_equal(m->mnt_fsname, device))
                        return strdup(m->mnt_dir);

        return NULL;
}

static char *friendly_disk_name(const char *src, const char *vol) {
        _cleanup_free_ char *description = NULL, *mount_point = NULL;
        char *name_buffer = NULL;
        int r;

        assert(src);
        assert(vol);

        description = disk_description(src);
        mount_point = disk_mount_point(vol);

        /* If the description string is simply the volume name, then let's not show this twice */
        if (description && streq(vol, description))
                description = mfree(description);

        if (mount_point && description)
                r = asprintf(&name_buffer, "%s (%s) on %s", description, vol, mount_point);
        else if (mount_point)
                r = asprintf(&name_buffer, "%s on %s", vol, mount_point);
        else if (description)
                r = asprintf(&name_buffer, "%s (%s)", description, vol);
        else
                return strdup(vol);
        if (r < 0)
                return NULL;

        return name_buffer;
}

static int get_password(
                const char *vol,
                const char *src,
                usec_t until,
                bool accept_cached,
                char ***ret) {

        _cleanup_free_ char *friendly = NULL, *text = NULL, *disk_path = NULL;
        _cleanup_strv_free_erase_ char **passwords = NULL;
        char **p, *id;
        int r = 0;

        assert(vol);
        assert(src);
        assert(ret);

        friendly = friendly_disk_name(src, vol);
        if (!friendly)
                return log_oom();

        if (asprintf(&text, "Please enter passphrase for disk %s:", friendly) < 0)
                return log_oom();

        disk_path = cescape(src);
        if (!disk_path)
                return log_oom();

        id = strjoina("cryptsetup:", disk_path);

        r = ask_password_auto(text, "drive-harddisk", id, "cryptsetup", until,
                              ASK_PASSWORD_PUSH_CACHE | (accept_cached*ASK_PASSWORD_ACCEPT_CACHED),
                              &passwords);
        if (r < 0)
                return log_error_errno(r, "Failed to query password: %m");

        if (arg_verify) {
                _cleanup_strv_free_erase_ char **passwords2 = NULL;

                assert(strv_length(passwords) == 1);

                if (asprintf(&text, "Please enter passphrase for disk %s (verification):", friendly) < 0)
                        return log_oom();

                id = strjoina("cryptsetup-verification:", disk_path);

                r = ask_password_auto(text, "drive-harddisk", id, "cryptsetup", until, ASK_PASSWORD_PUSH_CACHE, &passwords2);
                if (r < 0)
                        return log_error_errno(r, "Failed to query verification password: %m");

                assert(strv_length(passwords2) == 1);

                if (!streq(passwords[0], passwords2[0]))
                        return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                 "Passwords did not match, retrying.");
        }

        strv_uniq(passwords);

        STRV_FOREACH(p, passwords) {
                char *c;

                if (strlen(*p)+1 >= arg_key_size)
                        continue;

                /* Pad password if necessary */
                c = new(char, arg_key_size);
                if (!c)
                        return log_oom();

                strncpy(c, *p, arg_key_size);
                free_and_replace(*p, c);
        }

        *ret = TAKE_PTR(passwords);

        return 0;
}

static int attach_tcrypt(
                struct crypt_device *cd,
                const char *name,
                const char *key_file,
                const void *key_data,
                size_t key_data_size,
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
        assert(key_file || key_data || !strv_isempty(passwords));

        if (arg_pkcs11_uri)
                /* Ask for a regular password */
                return log_error_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "Sorry, but tcrypt devices are currently not supported in conjunction with pkcs11 support.");

        if (arg_tcrypt_hidden)
                params.flags |= CRYPT_TCRYPT_HIDDEN_HEADER;

        if (arg_tcrypt_system)
                params.flags |= CRYPT_TCRYPT_SYSTEM_HEADER;

        if (arg_tcrypt_veracrypt)
                params.flags |= CRYPT_TCRYPT_VERA_MODES;

        if (key_data) {
                params.passphrase = key_data;
                params.passphrase_size = key_data_size;
        } else {
                if (key_file) {
                        r = read_one_line_file(key_file, &passphrase);
                        if (r < 0) {
                                log_error_errno(r, "Failed to read password file '%s': %m", key_file);
                                return -EAGAIN; /* log with the actual error, but return EAGAIN */
                        }

                        params.passphrase = passphrase;
                } else
                        params.passphrase = passwords[0];

                params.passphrase_size = strlen(params.passphrase);
        }

        r = crypt_load(cd, CRYPT_TCRYPT, &params);
        if (r < 0) {
                if (r == -EPERM) {
                        if (key_data)
                                log_error_errno(r, "Failed to activate using discovered key. (Key not correct?)");

                        if (key_file)
                                log_error_errno(r, "Failed to activate using password file '%s'. (Key data not correct?)", key_file);

                        return -EAGAIN; /* log the actual error, but return EAGAIN */
                }

                return log_error_errno(r, "Failed to load tcrypt superblock on device %s: %m", crypt_get_device_name(cd));
        }

        r = crypt_activate_by_volume_key(cd, name, NULL, 0, flags);
        if (r < 0)
                return log_error_errno(r, "Failed to activate tcrypt device %s: %m", crypt_get_device_name(cd));

        return 0;
}

static int attach_luks_or_plain_or_bitlk(
                struct crypt_device *cd,
                const char *name,
                const char *key_file,
                const void *key_data,
                size_t key_data_size,
                char **passwords,
                uint32_t flags,
                usec_t until) {

        int r = 0;
        bool pass_volume_key = false;

        assert(cd);
        assert(name);

        if ((!arg_type && !crypt_get_type(cd)) || streq_ptr(arg_type, CRYPT_PLAIN)) {
                struct crypt_params_plain params = {
                        .offset = arg_offset,
                        .skip = arg_skip,
                        .sector_size = arg_sector_size,
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

                /* for CRYPT_PLAIN limit reads from keyfile to key length, and ignore keyfile-size */
                arg_keyfile_size = arg_key_size;

                /* In contrast to what the name crypt_format() might suggest this doesn't actually format
                 * anything, it just configures encryption parameters when used for plain mode. */
                r = crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, arg_keyfile_size, &params);
                if (r < 0)
                        return log_error_errno(r, "Loading of cryptographic parameters failed: %m");

                /* hash == NULL implies the user passed "plain" */
                pass_volume_key = (params.hash == NULL);
        }

        log_info("Set cipher %s, mode %s, key size %i bits for device %s.",
                 crypt_get_cipher(cd),
                 crypt_get_cipher_mode(cd),
                 crypt_get_volume_key_size(cd)*8,
                 crypt_get_device_name(cd));

        if (arg_pkcs11_uri) {
                _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                _cleanup_free_ void *decrypted_key = NULL;
                _cleanup_free_ char *friendly = NULL;
                size_t decrypted_key_size = 0;

                if (!key_file && !key_data)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "PKCS#11 mode selected but no key file specified, refusing.");

                friendly = friendly_disk_name(crypt_get_device_name(cd), name);
                if (!friendly)
                        return log_oom();

                for (;;) {
                        bool processed = false;

                        r = decrypt_pkcs11_key(
                                        friendly,
                                        arg_pkcs11_uri,
                                        key_file, arg_keyfile_size, arg_keyfile_offset,
                                        key_data, key_data_size,
                                        until,
                                        &decrypted_key, &decrypted_key_size);
                        if (r >= 0)
                                break;
                        if (r != -EAGAIN) /* EAGAIN means: token not found */
                                return r;

                        if (!monitor) {
                                /* We didn't find the token. In this case, watch for it via udev. Let's
                                 * create an event loop and monitor first. */

                                assert(!event);

                                r = sd_event_default(&event);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to allocate event loop: %m");

                                r = sd_device_monitor_new(&monitor);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to allocate device monitor: %m");

                                r = sd_device_monitor_filter_add_match_tag(monitor, "security-device");
                                if (r < 0)
                                        return log_error_errno(r, "Failed to configure device monitor: %m");

                                r = sd_device_monitor_attach_event(monitor, event);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to attach device monitor: %m");

                                r = sd_device_monitor_start(monitor, NULL, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to start device monitor: %m");

                                log_notice("Security token %s not present for unlocking volume %s, please plug it in.",
                                           arg_pkcs11_uri, friendly);

                                /* Let's immediately rescan in case the token appeared in the time we needed
                                 * to create and configure the monitor */
                                continue;
                        }

                        for (;;) {
                                /* Wait for one event, and then eat all subsequent events until there are no
                                 * further ones */
                                r = sd_event_run(event, processed ? 0 : UINT64_MAX);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to run event loop: %m");
                                if (r == 0)
                                        break;

                                processed = true;
                        }

                        log_debug("Got one or more potentially relevant udev events, rescanning PKCS#11...");
                }

                if (pass_volume_key)
                        r = crypt_activate_by_volume_key(cd, name, decrypted_key, decrypted_key_size, flags);
                else {
                        _cleanup_free_ char *base64_encoded = NULL;

                        /* Before using this key as passphrase we base64 encode it. Why? For compatibility
                         * with homed's PKCS#11 hookup: there we want to use the key we acquired through
                         * PKCS#11 for other authentication/decryption mechanisms too, and some of them do
                         * not not take arbitrary binary blobs, but require NUL-terminated strings — most
                         * importantly UNIX password hashes. Hence, for compatibility we want to use a string
                         * without embedded NUL here too, and that's easiest to generate from a binary blob
                         * via base64 encoding. */

                        r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
                        if (r < 0)
                                return log_oom();

                        r = crypt_activate_by_passphrase(cd, name, arg_key_slot, base64_encoded, strlen(base64_encoded), flags);
                }
                if (r == -EPERM) {
                        log_error_errno(r, "Failed to activate with PKCS#11 decrypted key. (Key incorrect?)");
                        return -EAGAIN; /* log actual error, but return EAGAIN */
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to activate with PKCS#11 acquired key: %m");

        } else if (key_data) {
                if (pass_volume_key)
                        r = crypt_activate_by_volume_key(cd, name, key_data, key_data_size, flags);
                else
                        r = crypt_activate_by_passphrase(cd, name, arg_key_slot, key_data, key_data_size, flags);
                if (r == -EPERM) {
                        log_error_errno(r, "Failed to activate. (Key incorrect?)");
                        return -EAGAIN; /* Log actual error, but return EAGAIN */
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to activate: %m");

        } else if (key_file) {
                r = crypt_activate_by_keyfile_device_offset(cd, name, arg_key_slot, key_file, arg_keyfile_size, arg_keyfile_offset, flags);
                if (r == -EPERM) {
                        log_error_errno(r, "Failed to activate with key file '%s'. (Key data incorrect?)", key_file);
                        return -EAGAIN; /* Log actual error, but return EAGAIN */
                }
                if (r == -EINVAL) {
                        log_error_errno(r, "Failed to activate with key file '%s'. (Key file missing?)", key_file);
                        return -EAGAIN; /* Log actual error, but return EAGAIN */
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to activate with key file '%s': %m", key_file);

        } else {
                char **p;

                r = -EINVAL;
                STRV_FOREACH(p, passwords) {
                        if (pass_volume_key)
                                r = crypt_activate_by_volume_key(cd, name, *p, arg_key_size, flags);
                        else
                                r = crypt_activate_by_passphrase(cd, name, arg_key_slot, *p, strlen(*p), flags);
                        if (r >= 0)
                                break;
                }
                if (r == -EPERM) {
                        log_error_errno(r, "Failed to activate with specified passphrase. (Passphrase incorrect?)");
                        return -EAGAIN; /* log actual error, but return EAGAIN */
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to activate with specified passphrase: %m");
        }

        return r;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cryptsetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME SOURCEDEVICE [PASSWORD] [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an encrypted block device.\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , program_invocation_short_name
               , link
        );

        return 0;
}

static uint32_t determine_flags(void) {
        uint32_t flags = 0;

        if (arg_readonly)
                flags |= CRYPT_ACTIVATE_READONLY;

        if (arg_discards)
                flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

        if (arg_same_cpu_crypt)
                flags |= CRYPT_ACTIVATE_SAME_CPU_CRYPT;

        if (arg_submit_from_crypt_cpus)
                flags |= CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;

#ifdef CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF
        /* Try to decrease the risk of OOM event if memory hard key derivation function is in use */
        /* https://gitlab.com/cryptsetup/cryptsetup/issues/446/ */
        flags |= CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF;
#endif

        return flags;
}

static void remove_and_erasep(const char **p) {
        int r;

        if (!*p)
                return;

        r = unlinkat_deallocate(AT_FDCWD, *p, UNLINK_ERASE);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Unable to erase key file '%s', ignoring: %m", *p);
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        if (argc <= 1)
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires at least two arguments.");

        log_setup_service();

        cryptsetup_enable_logging(cd);

        umask(0022);

        if (streq(argv[1], "attach")) {
                uint32_t flags = 0;
                unsigned tries;
                usec_t until;
                crypt_status_info status;
                _cleanup_(remove_and_erasep) const char *destroy_key_file = NULL;
                const char *key_file = NULL;
                _cleanup_(erase_and_freep) void *key_data = NULL;
                size_t key_data_size = 0;

                /* Arguments: systemd-cryptsetup attach VOLUME SOURCE-DEVICE [PASSWORD] [OPTIONS] */

                if (argc < 4)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least two arguments.");

                if (!filename_is_valid(argv[2]))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", argv[2]);

                if (argc >= 5 && !STR_IN_SET(argv[4], "", "-", "none")) {
                        if (path_is_absolute(argv[4]))
                                key_file = argv[4];
                        else
                                log_warning("Password file path '%s' is not absolute. Ignoring.", argv[4]);
                }

                if (argc >= 6 && !STR_IN_SET(argv[5], "", "-", "none")) {
                        r = parse_options(argv[5]);
                        if (r < 0)
                                return r;
                }

                log_debug("%s %s ← %s type=%s cipher=%s", __func__,
                          argv[2], argv[3], strempty(arg_type), strempty(arg_cipher));

                /* A delicious drop of snake oil */
                (void) mlockall(MCL_FUTURE);

                if (!key_file) {
                        const char *fn;

                        /* If a key file is not explicitly specified, search for a key in a well defined
                         * search path, and load it. */

                        fn = strjoina(argv[2], ".key");
                        r = load_key_file(fn,
                                          STRV_MAKE("/etc/cryptsetup-keys.d", "/run/cryptsetup-keys.d"),
                                          0, 0,  /* Note we leave arg_keyfile_offset/arg_keyfile_size as something that only applies to arg_keyfile! */
                                          &key_data, &key_data_size);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                log_debug("Automatically discovered key for volume '%s'.", argv[2]);
                } else if (arg_keyfile_erase)
                        destroy_key_file = key_file; /* let's get this baby erased when we leave */

                if (arg_header) {
                        log_debug("LUKS header: %s", arg_header);
                        r = crypt_init(&cd, arg_header);
                } else
                        r = crypt_init(&cd, argv[3]);
                if (r < 0)
                        return log_error_errno(r, "crypt_init() failed: %m");

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, argv[2]);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", argv[2]);
                        return 0;
                }

                flags = determine_flags();

                if (arg_timeout == USEC_INFINITY)
                        until = 0;
                else
                        until = now(CLOCK_MONOTONIC) + arg_timeout;

                arg_key_size = (arg_key_size > 0 ? arg_key_size : (256 / 8));

                if (key_file) {
                        struct stat st;

                        /* Ideally we'd do this on the open fd, but since this is just a
                         * warning it's OK to do this in two steps. */
                        if (stat(key_file, &st) >= 0 && S_ISREG(st.st_mode) && (st.st_mode & 0005))
                                log_warning("Key file %s is world-readable. This is not a good idea!", key_file);
                }

                if (!arg_type || STR_IN_SET(arg_type, ANY_LUKS, CRYPT_LUKS1, CRYPT_LUKS2)) {
                        r = crypt_load(cd, !arg_type || streq(arg_type, ANY_LUKS) ? CRYPT_LUKS : arg_type, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to load LUKS superblock on device %s: %m", crypt_get_device_name(cd));

                        if (arg_header) {
                                r = crypt_set_data_device(cd, argv[3]);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set LUKS data device %s: %m", argv[3]);
                        }

                        /* Tokens are available in LUKS2 only, but it is ok to call (and fail) with LUKS1. */
                        if (!key_file && !key_data) {
                                r = crypt_activate_by_token(cd, argv[2], CRYPT_ANY_TOKEN, NULL, flags);
                                if (r >= 0) {
                                        log_debug("Volume %s activated with LUKS token id %i.", argv[2], r);
                                        return 0;
                                }

                                log_debug_errno(r, "Token activation unsuccessful for device %s: %m", crypt_get_device_name(cd));
                        }
                }

/* since cryptsetup 2.3.0 (Feb 2020) */
#ifdef CRYPT_BITLK
                if (streq_ptr(arg_type, CRYPT_BITLK)) {
                        r = crypt_load(cd, CRYPT_BITLK, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to load Bitlocker superblock on device %s: %m", crypt_get_device_name(cd));
                }
#endif

                for (tries = 0; arg_tries == 0 || tries < arg_tries; tries++) {
                        _cleanup_strv_free_erase_ char **passwords = NULL;

                        /* When we were able to acquire multiple keys, let's always process them in this order:
                         *
                         *    1. A key acquired via PKCS#11 token
                         *    2. The discovered key: i.e. key_data + key_data_size
                         *    3. The configured key: i.e. key_file + arg_keyfile_offset + arg_keyfile_size
                         *    4. The empty password, in case arg_try_empty_password is set
                         *    5. We enquire the user for a password
                         */

                        if (!key_file && !key_data && !arg_pkcs11_uri) {

                                if (arg_try_empty_password) {
                                        /* Hmm, let's try an empty password now, but only once */
                                        arg_try_empty_password = false;

                                        key_data = strdup("");
                                        if (!key_data)
                                                return log_oom();

                                        key_data_size = 0;
                                } else {
                                        /* Ask the user for a passphrase only as last resort, if we have
                                         * nothing else to check for */

                                        r = get_password(argv[2], argv[3], until, tries == 0 && !arg_verify, &passwords);
                                        if (r == -EAGAIN)
                                                continue;
                                        if (r < 0)
                                                return r;
                                }
                        }

                        if (streq_ptr(arg_type, CRYPT_TCRYPT))
                                r = attach_tcrypt(cd, argv[2], key_file, key_data, key_data_size, passwords, flags);
                        else
                                r = attach_luks_or_plain_or_bitlk(cd, argv[2], key_file, key_data, key_data_size, passwords, flags, until);
                        if (r >= 0)
                                break;
                        if (r != -EAGAIN)
                                return r;

                        /* Key not correct? Let's try again! */

                        key_file = NULL;
                        key_data = erase_and_free(key_data);
                        key_data_size = 0;
                        arg_pkcs11_uri = mfree(arg_pkcs11_uri);
                }

                if (arg_tries != 0 && tries >= arg_tries)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Too many attempts to activate; giving up.");

        } else if (streq(argv[1], "detach")) {

                if (!filename_is_valid(argv[2]))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", argv[2]);

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

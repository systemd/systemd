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
#include "cryptsetup-fido2.h"
#include "cryptsetup-keyfile.h"
#include "cryptsetup-pkcs11.h"
#include "cryptsetup-tpm2.h"
#include "cryptsetup-util.h"
#include "device-util.h"
#include "efi-loader.h"
#include "env-util.h"
#include "escape.h"
#include "fileio.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "hexdecoct.h"
#include "libfido2-util.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pkcs11-util.h"
#include "pretty-print.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"
#include "tpm2-util.h"

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
static AskPasswordFlags arg_ask_password_flags = 0;
static bool arg_discards = false;
static bool arg_same_cpu_crypt = false;
static bool arg_submit_from_crypt_cpus = false;
static bool arg_no_read_workqueue = false;
static bool arg_no_write_workqueue = false;
static bool arg_tcrypt_hidden = false;
static bool arg_tcrypt_system = false;
static bool arg_tcrypt_veracrypt = false;
static char **arg_tcrypt_keyfiles = NULL;
static uint64_t arg_offset = 0;
static uint64_t arg_skip = 0;
static usec_t arg_timeout = USEC_INFINITY;
static char *arg_pkcs11_uri = NULL;
static bool arg_pkcs11_uri_auto = false;
static char *arg_fido2_device = NULL;
static bool arg_fido2_device_auto = false;
static void *arg_fido2_cid = NULL;
static size_t arg_fido2_cid_size = 0;
static char *arg_fido2_rp_id = NULL;
static char *arg_tpm2_device = NULL;
static bool arg_tpm2_device_auto = false;
static uint32_t arg_tpm2_pcr_mask = UINT32_MAX;
static bool arg_headless = false;
static usec_t arg_token_timeout_usec = 30*USEC_PER_SEC;

STATIC_DESTRUCTOR_REGISTER(arg_cipher, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_header, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tcrypt_keyfiles, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_uri, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_cid, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_rp_id, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);

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
        else if ((val = startswith(option, "password-echo="))) {
                if (streq(val, "masked"))
                        arg_ask_password_flags &= ~(ASK_PASSWORD_ECHO|ASK_PASSWORD_SILENT);
                else {
                        r = parse_boolean(val);
                        if (r < 0) {
                                log_warning_errno(r, "Invalid password-echo= option \"%s\", ignoring.", val);
                                return 0;
                        }

                        SET_FLAG(arg_ask_password_flags, ASK_PASSWORD_ECHO, r);
                        SET_FLAG(arg_ask_password_flags, ASK_PASSWORD_SILENT, !r);
                }
        } else if (STR_IN_SET(option, "allow-discards", "discard"))
                arg_discards = true;
        else if (streq(option, "same-cpu-crypt"))
                arg_same_cpu_crypt = true;
        else if (streq(option, "submit-from-crypt-cpus"))
                arg_submit_from_crypt_cpus = true;
        else if (streq(option, "no-read-workqueue"))
                arg_no_read_workqueue = true;
        else if (streq(option, "no-write-workqueue"))
                arg_no_write_workqueue = true;
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

                if (streq(val, "auto")) {
                        arg_pkcs11_uri = mfree(arg_pkcs11_uri);
                        arg_pkcs11_uri_auto = true;
                } else {
                        if (!pkcs11_uri_valid(val))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "pkcs11-uri= parameter expects a PKCS#11 URI, refusing");

                        r = free_and_strdup(&arg_pkcs11_uri, val);
                        if (r < 0)
                                return log_oom();

                        arg_pkcs11_uri_auto = false;
                }

        } else if ((val = startswith(option, "fido2-device="))) {

                if (streq(val, "auto")) {
                        arg_fido2_device = mfree(arg_fido2_device);
                        arg_fido2_device_auto = true;
                } else {
                        r = free_and_strdup(&arg_fido2_device, val);
                        if (r < 0)
                                return log_oom();

                        arg_fido2_device_auto = false;
                }

        } else if ((val = startswith(option, "fido2-cid="))) {

                if (streq(val, "auto"))
                        arg_fido2_cid = mfree(arg_fido2_cid);
                else {
                        _cleanup_free_ void *cid = NULL;
                        size_t cid_size;

                        r = unbase64mem(val, SIZE_MAX, &cid, &cid_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to decode FIDO2 CID data: %m");

                        free(arg_fido2_cid);
                        arg_fido2_cid = TAKE_PTR(cid);
                        arg_fido2_cid_size = cid_size;
                }

                /* Turn on FIDO2 as side-effect, if not turned on yet. */
                if (!arg_fido2_device && !arg_fido2_device_auto)
                        arg_fido2_device_auto = true;

        } else if ((val = startswith(option, "fido2-rp="))) {

                r = free_and_strdup(&arg_fido2_rp_id, val);
                if (r < 0)
                        return log_oom();

        } else if ((val = startswith(option, "tpm2-device="))) {

                if (streq(val, "auto")) {
                        arg_tpm2_device = mfree(arg_tpm2_device);
                        arg_tpm2_device_auto = true;
                } else {
                        r = free_and_strdup(&arg_tpm2_device, val);
                        if (r < 0)
                                return log_oom();

                        arg_tpm2_device_auto = false;
                }

        } else if ((val = startswith(option, "tpm2-pcrs="))) {

                if (isempty(val))
                        arg_tpm2_pcr_mask = 0;
                else {
                        uint32_t mask;

                        r = tpm2_parse_pcrs(val, &mask);
                        if (r < 0)
                                return r;

                        if (arg_tpm2_pcr_mask == UINT32_MAX)
                                arg_tpm2_pcr_mask = mask;
                        else
                                arg_tpm2_pcr_mask |= mask;
                }

        } else if ((val = startswith(option, "try-empty-password="))) {

                r = parse_boolean(val);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

                arg_try_empty_password = r;

        } else if (streq(option, "try-empty-password"))
                arg_try_empty_password = true;
        else if ((val = startswith(option, "headless="))) {

                r = parse_boolean(val);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

                arg_headless = r;
        } else if (streq(option, "headless"))
                arg_headless = true;

        else if ((val = startswith(option, "token-timeout="))) {

                r = parse_sec_fix_0(val, &arg_token_timeout_usec);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse %s, ignoring: %m", option);
                        return 0;
                }

        } else if (!streq(option, "x-initrd.attach"))
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

        if (sd_device_new_from_stat_rdev(&device, &st) < 0)
                return NULL;

        if (sd_device_get_property_value(device, "ID_PART_ENTRY_NAME", &name) >= 0) {
                _cleanup_free_ char *unescaped = NULL;
                ssize_t l;

                /* ID_PART_ENTRY_NAME uses \x style escaping, using libblkid's blkid_encode_string(). Let's
                 * reverse this here to make the string more human friendly in case people embed spaces or
                 * other weird stuff. */

                l = cunescape(name, UNESCAPE_RELAX, &unescaped);
                if (l < 0) {
                        log_debug_errno(l, "Failed to unescape ID_PART_ENTRY_NAME, skipping device: %m");
                        return NULL;
                }

                if (!isempty(unescaped) && !string_has_cc(unescaped, NULL))
                        return TAKE_PTR(unescaped);
        }

        /* These need no unescaping. */
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
        AskPasswordFlags flags = arg_ask_password_flags | ASK_PASSWORD_PUSH_CACHE;

        assert(vol);
        assert(src);
        assert(ret);

        if (arg_headless)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "Password querying disabled via 'headless' option.");

        friendly = friendly_disk_name(src, vol);
        if (!friendly)
                return log_oom();

        if (asprintf(&text, "Please enter passphrase for disk %s:", friendly) < 0)
                return log_oom();

        disk_path = cescape(src);
        if (!disk_path)
                return log_oom();

        id = strjoina("cryptsetup:", disk_path);

        r = ask_password_auto(text, "drive-harddisk", id, "cryptsetup", "cryptsetup.passphrase", until,
                              flags | (accept_cached*ASK_PASSWORD_ACCEPT_CACHED),
                              &passwords);
        if (r < 0)
                return log_error_errno(r, "Failed to query password: %m");

        if (arg_verify) {
                _cleanup_strv_free_erase_ char **passwords2 = NULL;

                assert(strv_length(passwords) == 1);

                if (asprintf(&text, "Please enter passphrase for disk %s (verification):", friendly) < 0)
                        return log_oom();

                id = strjoina("cryptsetup-verification:", disk_path);

                r = ask_password_auto(text, "drive-harddisk", id, "cryptsetup", "cryptsetup.passphrase", until, flags, &passwords2);
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
                erase_and_free(*p);
                *p = TAKE_PTR(c);
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
        _cleanup_(erase_and_freep) char *passphrase = NULL;
        struct crypt_params_tcrypt params = {
                .flags = CRYPT_TCRYPT_LEGACY_MODES,
                .keyfiles = (const char **)arg_tcrypt_keyfiles,
                .keyfiles_count = strv_length(arg_tcrypt_keyfiles)
        };

        assert(cd);
        assert(name);
        assert(key_file || key_data || !strv_isempty(passwords));

        if (arg_pkcs11_uri || arg_pkcs11_uri_auto || arg_fido2_device || arg_fido2_device_auto || arg_tpm2_device || arg_tpm2_device_auto)
                /* Ask for a regular password */
                return log_error_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "Sorry, but tcrypt devices are currently not supported in conjunction with pkcs11/fido2/tpm2 support.");

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

static char *make_bindname(const char *volume) {
        char *s;

        if (asprintf(&s, "@%" PRIx64"/cryptsetup/%s", random_u64(), volume) < 0)
                return NULL;

        return s;
}

static int make_security_device_monitor(
                sd_event **ret_event,
                sd_device_monitor **ret_monitor) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert(ret_event);
        assert(ret_monitor);

        /* Waits for a device with "security-device" tag to show up in udev */

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_add_time_relative(event, NULL, CLOCK_MONOTONIC, arg_token_timeout_usec, USEC_PER_SEC, NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return log_error_errno(r, "Failed to install timeout event source: %m");

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

        *ret_event = TAKE_PTR(event);
        *ret_monitor = TAKE_PTR(monitor);
        return 0;
}

static int run_security_device_monitor(
                sd_event *event,
                sd_device_monitor *monitor) {
        bool processed = false;
        int r;

        assert(event);
        assert(monitor);

        /* Runs the event loop for the device monitor until either something happens, or the time-out is
         * hit. */

        for (;;) {
                int x;

                r = sd_event_get_exit_code(event, &x);
                if (r < 0) {
                        if (r != -ENODATA)
                                return log_error_errno(r, "Failed to query exit code from event loop: %m");

                        /* On ENODATA we aren't told to exit yet. */
                } else {
                        assert(x == -ETIMEDOUT);
                        return log_notice_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                "Timed out waiting for security device, aborting security device based authentication attempt.");
                }

                /* Wait for one event, and then eat all subsequent events until there are no further ones */
                r = sd_event_run(event, processed ? 0 : UINT64_MAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to run event loop: %m");
                if (r == 0) /* no events queued anymore */
                        return 0;

                processed = true;
        }
}

static bool libcryptsetup_plugins_support(void) {
#if HAVE_LIBCRYPTSETUP_PLUGINS
        int r;

        /* Permit a way to disable libcryptsetup token module support, for debugging purposes. */
        r = getenv_bool("SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE env var: %m");
        if (r == 0)
                return false;

        return crypt_token_external_path();
#else
        return false;
#endif
}

#if HAVE_LIBCRYPTSETUP_PLUGINS
static int acquire_pins_from_env_variable(char ***ret_pins) {
        char *e;
        _cleanup_strv_free_erase_ char **pins = NULL;

        assert(ret_pins);

        e = getenv("PIN");
        if (e) {
                pins = strv_new(e);
                if (!pins)
                        return log_oom();

                string_erase(e);
                if (unsetenv("PIN") < 0)
                        return log_error_errno(errno, "Failed to unset $PIN: %m");
        }

        *ret_pins = TAKE_PTR(pins);

        return 0;
}
#endif

static int attach_luks2_by_fido2(
                struct crypt_device *cd,
                const char *name,
                usec_t until,
                bool headless,
                void *usrptr,
                uint32_t activation_flags) {

#if HAVE_LIBCRYPTSETUP_PLUGINS
        AskPasswordFlags flags = ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_ACCEPT_CACHED;
        _cleanup_strv_free_erase_ char **pins = NULL;
        char **p;
        int r;

        r = crypt_activate_by_token_pin(cd, name, "systemd-fido2", CRYPT_ANY_TOKEN, NULL, 0, usrptr, activation_flags);
        if (r > 0) /* returns unlocked keyslot id on success */
                r = 0;
        if (r != -ENOANO) /* needs pin or pin is wrong */
                return r;

        r = acquire_pins_from_env_variable(&pins);
        if (r < 0)
                return r;

        STRV_FOREACH(p, pins) {
                r = crypt_activate_by_token_pin(cd, name, "systemd-fido2", CRYPT_ANY_TOKEN, *p, strlen(*p), usrptr, activation_flags);
                if (r > 0) /* returns unlocked keyslot id on success */
                        r = 0;
                if (r != -ENOANO) /* needs pin or pin is wrong */
                        return r;
        }

        if (headless)
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "PIN querying disabled via 'headless' option. Use the '$PIN' environment variable.");

        for (;;) {
                pins = strv_free_erase(pins);
                r = ask_password_auto("Please enter security token PIN:", "drive-harddisk", NULL, "fido2-pin", "cryptsetup.fido2-pin", until, flags, &pins);
                if (r < 0)
                        return r;

                STRV_FOREACH(p, pins) {
                        r = crypt_activate_by_token_pin(cd, name, "systemd-fido2", CRYPT_ANY_TOKEN, *p, strlen(*p), usrptr, activation_flags);
                        if (r > 0) /* returns unlocked keyslot id on success */
                                r = 0;
                        if (r != -ENOANO) /* needs pin or pin is wrong */
                                return r;
                }

                flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
        }
        return r;
#else
        return -EOPNOTSUPP;
#endif
}

static int attach_luks_or_plain_or_bitlk_by_fido2(
                struct crypt_device *cd,
                const char *name,
                const char *key_file,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                uint32_t flags,
                bool pass_volume_key) {

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_free_ void *discovered_salt = NULL, *discovered_cid = NULL;
        size_t discovered_salt_size, discovered_cid_size, decrypted_key_size, cid_size = 0;
        _cleanup_free_ char *friendly = NULL, *discovered_rp_id = NULL;
        int keyslot = arg_key_slot, r;
        const char *rp_id = NULL;
        const void *cid = NULL;
        Fido2EnrollFlags required;
        bool use_libcryptsetup_plugin = libcryptsetup_plugins_support();

        assert(cd);
        assert(name);
        assert(arg_fido2_device || arg_fido2_device_auto);

        if (arg_fido2_cid) {
                if (!key_file && !key_data)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 mode with manual parameters selected, but no keyfile specified, refusing.");

                rp_id = arg_fido2_rp_id;
                cid = arg_fido2_cid;
                cid_size = arg_fido2_cid_size;

                /* For now and for compatibility, if the user explicitly configured FIDO2 support and we do
                 * not read FIDO2 metadata off the LUKS2 header, default to the systemd 248 logic, where we
                 * use PIN + UP when needed, and do not configure UV at all. Eventually, we should make this
                 * explicitly configurable. */
                required = FIDO2ENROLL_PIN_IF_NEEDED | FIDO2ENROLL_UP_IF_NEEDED | FIDO2ENROLL_UV_OMIT;
        } else if (!use_libcryptsetup_plugin) {
                r = find_fido2_auto_data(
                                cd,
                                &discovered_rp_id,
                                &discovered_salt,
                                &discovered_salt_size,
                                &discovered_cid,
                                &discovered_cid_size,
                                &keyslot,
                                &required);

                if (IN_SET(r, -ENOTUNIQ, -ENXIO))
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "Automatic FIDO2 metadata discovery was not possible because missing or not unique, falling back to traditional unlocking.");
                if (r < 0)
                        return r;

                if ((required & (FIDO2ENROLL_PIN | FIDO2ENROLL_UP | FIDO2ENROLL_UV)) && arg_headless)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                               "Local verification is required to unlock this volume, but the 'headless' parameter was set.");

                rp_id = discovered_rp_id;
                key_data = discovered_salt;
                key_data_size = discovered_salt_size;
                cid = discovered_cid;
                cid_size = discovered_cid_size;
        }

        friendly = friendly_disk_name(crypt_get_device_name(cd), name);
        if (!friendly)
                return log_oom();

        for (;;) {
                if (use_libcryptsetup_plugin && !arg_fido2_cid) {
                        r = attach_luks2_by_fido2(cd, name, until, arg_headless, arg_fido2_device, flags);
                        if (IN_SET(r, -ENOTUNIQ, -ENXIO, -ENOENT))
                                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                       "Automatic FIDO2 metadata discovery was not possible because missing or not unique, falling back to traditional unlocking.");

                } else {
                        r = acquire_fido2_key(
                                        name,
                                        friendly,
                                        arg_fido2_device,
                                        rp_id,
                                        cid, cid_size,
                                        key_file, arg_keyfile_size, arg_keyfile_offset,
                                        key_data, key_data_size,
                                        until,
                                        arg_headless,
                                        required,
                                        &decrypted_key, &decrypted_key_size,
                                        arg_ask_password_flags);
                        if (r >= 0)
                                break;
                }

                if (r != -EAGAIN) /* EAGAIN means: token not found */
                        return r;

                if (!monitor) {
                        /* We didn't find the token. In this case, watch for it via udev. Let's
                         * create an event loop and monitor first. */

                        assert(!event);

                        r = make_security_device_monitor(&event, &monitor);
                        if (r < 0)
                                return r;

                        log_notice("Security token not present for unlocking volume %s, please plug it in.", friendly);

                        /* Let's immediately rescan in case the token appeared in the time we needed
                         * to create and configure the monitor */
                        continue;
                }

                r = run_security_device_monitor(event, monitor);
                if (r < 0)
                        return r;

                log_debug("Got one or more potentially relevant udev events, rescanning FIDO2...");
        }

        if (pass_volume_key)
                r = crypt_activate_by_volume_key(cd, name, decrypted_key, decrypted_key_size, flags);
        else {
                _cleanup_(erase_and_freep) char *base64_encoded = NULL;

                /* Before using this key as passphrase we base64 encode it, for compat with homed */

                r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
                if (r < 0)
                        return log_oom();

                r = crypt_activate_by_passphrase(cd, name, keyslot, base64_encoded, strlen(base64_encoded), flags);
        }
        if (r == -EPERM) {
                log_error_errno(r, "Failed to activate with FIDO2 decrypted key. (Key incorrect?)");
                return -EAGAIN; /* log actual error, but return EAGAIN */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to activate with FIDO2 acquired key: %m");

        return 0;
}

static int attach_luks2_by_pkcs11(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                usec_t until,
                bool headless,
                uint32_t flags) {

#if HAVE_LIBCRYPTSETUP_PLUGINS
        int r;

        if (!streq_ptr(crypt_get_type(cd), CRYPT_LUKS2))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Automatic PKCS#11 metadata requires LUKS2 device.");

        systemd_pkcs11_plugin_params params = {
                .friendly_name = friendly_name,
                .until = until,
                .headless = headless
        };

        r = crypt_activate_by_token_pin(cd, name, "systemd-pkcs11", CRYPT_ANY_TOKEN, NULL, 0, &params, flags);
        if (r > 0) /* returns unlocked keyslot id on success */
                r = 0;

        return r;
#else
        return -EOPNOTSUPP;
#endif
}

static int attach_luks_or_plain_or_bitlk_by_pkcs11(
                struct crypt_device *cd,
                const char *name,
                const char *key_file,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                uint32_t flags,
                bool pass_volume_key) {

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_free_ char *friendly = NULL, *discovered_uri = NULL;
        size_t decrypted_key_size = 0, discovered_key_size = 0;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_free_ void *discovered_key = NULL;
        int keyslot = arg_key_slot, r;
        const char *uri = NULL;
        bool use_libcryptsetup_plugin = libcryptsetup_plugins_support();

        assert(cd);
        assert(name);
        assert(arg_pkcs11_uri || arg_pkcs11_uri_auto);

        if (arg_pkcs11_uri_auto) {
                if (!use_libcryptsetup_plugin) {
                        r = find_pkcs11_auto_data(cd, &discovered_uri, &discovered_key, &discovered_key_size, &keyslot);
                        if (IN_SET(r, -ENOTUNIQ, -ENXIO))
                                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                       "Automatic PKCS#11 metadata discovery was not possible because missing or not unique, falling back to traditional unlocking.");
                        if (r < 0)
                                return r;

                        uri = discovered_uri;
                        key_data = discovered_key;
                        key_data_size = discovered_key_size;
                }
        } else {
                uri = arg_pkcs11_uri;

                if (!key_file && !key_data)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "PKCS#11 mode selected but no key file specified, refusing.");
        }

        friendly = friendly_disk_name(crypt_get_device_name(cd), name);
        if (!friendly)
                return log_oom();

        for (;;) {
                if (use_libcryptsetup_plugin && arg_pkcs11_uri_auto)
                        r = attach_luks2_by_pkcs11(cd, name, friendly, until, arg_headless, flags);
                else {
                        r = decrypt_pkcs11_key(
                                        name,
                                        friendly,
                                        uri,
                                        key_file, arg_keyfile_size, arg_keyfile_offset,
                                        key_data, key_data_size,
                                        until,
                                        arg_headless,
                                        &decrypted_key, &decrypted_key_size);
                        if (r >= 0)
                                break;
                }

                if (r != -EAGAIN) /* EAGAIN means: token not found */
                        return r;

                if (!monitor) {
                        /* We didn't find the token. In this case, watch for it via udev. Let's
                         * create an event loop and monitor first. */

                        assert(!event);

                        r = make_security_device_monitor(&event, &monitor);
                        if (r < 0)
                                return r;

                        log_notice("Security token %s not present for unlocking volume %s, please plug it in.",
                                   uri, friendly);

                        /* Let's immediately rescan in case the token appeared in the time we needed
                         * to create and configure the monitor */
                        continue;
                }

                r = run_security_device_monitor(event, monitor);
                if (r < 0)
                        return r;

                log_debug("Got one or more potentially relevant udev events, rescanning PKCS#11...");
        }
        assert(decrypted_key);

        if (pass_volume_key)
                r = crypt_activate_by_volume_key(cd, name, decrypted_key, decrypted_key_size, flags);
        else {
                _cleanup_(erase_and_freep) char *base64_encoded = NULL;

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

                r = crypt_activate_by_passphrase(cd, name, keyslot, base64_encoded, strlen(base64_encoded), flags);
        }
        if (r == -EPERM) {
                log_error_errno(r, "Failed to activate with PKCS#11 decrypted key. (Key incorrect?)");
                return -EAGAIN; /* log actual error, but return EAGAIN */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to activate with PKCS#11 acquired key: %m");

        return 0;
}

static int make_tpm2_device_monitor(
                sd_event **ret_event,
                sd_device_monitor **ret_monitor) {

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert(ret_event);
        assert(ret_monitor);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_add_time_relative(event, NULL, CLOCK_MONOTONIC, arg_token_timeout_usec, USEC_PER_SEC, NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return log_error_errno(r, "Failed to install timeout event source: %m");

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device monitor: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, "tpmrm", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to configure device monitor: %m");

        r = sd_device_monitor_attach_event(monitor, event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach device monitor: %m");

        r = sd_device_monitor_start(monitor, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        *ret_event = TAKE_PTR(event);
        *ret_monitor = TAKE_PTR(monitor);
        return 0;
}

static int attach_luks2_by_tpm2(
                struct crypt_device *cd,
                const char *name,
                uint32_t flags) {

#if HAVE_LIBCRYPTSETUP_PLUGINS
        int r;

        systemd_tpm2_plugin_params params = {
                .search_pcr_mask = arg_tpm2_pcr_mask,
                .device = arg_tpm2_device
        };

        if (!crypt_token_external_path())
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Libcryptsetup has external plugins support disabled.");

        r = crypt_activate_by_token_pin(cd, name, "systemd-tpm2", CRYPT_ANY_TOKEN, NULL, 0, &params, flags);
        if (r > 0) /* returns unlocked keyslot id on success */
                r = 0;

        return r;
#else
        return -EOPNOTSUPP;
#endif
}

static int attach_luks_or_plain_or_bitlk_by_tpm2(
                struct crypt_device *cd,
                const char *name,
                const char *key_file,
                const void *key_data,
                size_t key_data_size,
                usec_t until,
                uint32_t flags,
                bool pass_volume_key) {

        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_free_ char *friendly = NULL;
        int keyslot = arg_key_slot, r;
        size_t decrypted_key_size;

        assert(cd);
        assert(name);
        assert(arg_tpm2_device || arg_tpm2_device_auto);

        friendly = friendly_disk_name(crypt_get_device_name(cd), name);
        if (!friendly)
                return log_oom();

        for (;;) {
                if (key_file || key_data) {
                        /* If key data is specified, use that */

                        r = acquire_tpm2_key(
                                        name,
                                        arg_tpm2_device,
                                        arg_tpm2_pcr_mask == UINT32_MAX ? TPM2_PCR_MASK_DEFAULT : arg_tpm2_pcr_mask,
                                        UINT16_MAX,
                                        0,
                                        key_file, arg_keyfile_size, arg_keyfile_offset,
                                        key_data, key_data_size,
                                        NULL, 0, /* we don't know the policy hash */
                                        &decrypted_key, &decrypted_key_size);
                        if (r >= 0)
                                break;
                        if (ERRNO_IS_NOT_SUPPORTED(r)) /* TPM2 support not compiled in? */
                                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "TPM2 support not available, falling back to traditional unlocking.");
                        if (r != -EAGAIN) /* EAGAIN means: no tpm2 chip found */
                                return r;
                } else {
                        r = attach_luks2_by_tpm2(cd, name, flags);
                        /* EAGAIN     means: no tpm2 chip found
                         * EOPNOTSUPP means: no libcryptsetup plugins support */
                        if (r == -ENXIO)
                                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                       "No TPM2 metadata matching the current system state found in LUKS2 header, falling back to traditional unlocking.");
                        if (r == -ENOENT)
                                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                       "No TPM2 metadata enrolled in LUKS2 header or TPM2 support not available, falling back to traditional unlocking.");
                        if (!IN_SET(r, -EOPNOTSUPP, -EAGAIN))
                                return r;
                }

                if (r == -EOPNOTSUPP) {
                        _cleanup_free_ void *blob = NULL, *policy_hash = NULL;
                        size_t blob_size, policy_hash_size;
                        bool found_some = false;
                        int token = 0; /* first token to look at */

                        /* If no key data is specified, look for it in the header. In order to support
                         * software upgrades we'll iterate through all suitable tokens, maybe one of them
                         * works. */

                        for (;;) {
                                uint32_t pcr_mask;
                                uint16_t pcr_bank, primary_alg;

                                r = find_tpm2_auto_data(
                                                cd,
                                                arg_tpm2_pcr_mask, /* if != UINT32_MAX we'll only look for tokens with this PCR mask */
                                                token, /* search for the token with this index, or any later index than this */
                                                &pcr_mask,
                                                &pcr_bank,
                                                &primary_alg,
                                                &blob, &blob_size,
                                                &policy_hash, &policy_hash_size,
                                                &keyslot,
                                                &token);
                                if (r == -ENXIO)
                                        /* No further TPM2 tokens found in the LUKS2 header. */
                                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                               found_some
                                                               ? "No TPM2 metadata matching the current system state found in LUKS2 header, falling back to traditional unlocking."
                                                               : "No TPM2 metadata enrolled in LUKS2 header, falling back to traditional unlocking.");
                                if (ERRNO_IS_NOT_SUPPORTED(r))  /* TPM2 support not compiled in? */
                                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "TPM2 support not available, falling back to traditional unlocking.");
                                if (r < 0)
                                        return r;

                                found_some = true;

                                r = acquire_tpm2_key(
                                                name,
                                                arg_tpm2_device,
                                                pcr_mask,
                                                pcr_bank,
                                                primary_alg,
                                                NULL, 0, 0, /* no key file */
                                                blob, blob_size,
                                                policy_hash, policy_hash_size,
                                                &decrypted_key, &decrypted_key_size);
                                if (r != -EPERM)
                                        break;

                                token++; /* try a different token next time */
                        }

                        if (r >= 0)
                                break;
                        if (r != -EAGAIN) /* EAGAIN means: no tpm2 chip found */
                                return r;
                }

                if (!monitor) {
                        /* We didn't find the TPM2 device. In this case, watch for it via udev. Let's create
                         * an event loop and monitor first. */

                        assert(!event);

                        if (is_efi_boot() && !efi_has_tpm2())
                                return log_notice_errno(SYNTHETIC_ERRNO(EAGAIN),
                                                        "No TPM2 hardware discovered and EFI bios indicates no support for it either, assuming TPM2-less system, falling back to traditional unocking.");

                        r = make_tpm2_device_monitor(&event, &monitor);
                        if (r < 0)
                                return r;

                        log_info("TPM2 device not present for unlocking %s, waiting for it to become available.", friendly);

                        /* Let's immediately rescan in case the device appeared in the time we needed
                         * to create and configure the monitor */
                        continue;
                }

                r = run_security_device_monitor(event, monitor);
                if (r < 0)
                        return r;

                log_debug("Got one or more potentially relevant udev events, rescanning for TPM2...");
        }
        assert(decrypted_key);

        if (pass_volume_key)
                r = crypt_activate_by_volume_key(cd, name, decrypted_key, decrypted_key_size, flags);
        else {
                _cleanup_(erase_and_freep) char *base64_encoded = NULL;

                /* Before using this key as passphrase we base64 encode it, for compat with homed */

                r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
                if (r < 0)
                        return log_oom();

                r = crypt_activate_by_passphrase(cd, name, keyslot, base64_encoded, strlen(base64_encoded), flags);
        }
        if (r == -EPERM) {
                log_error_errno(r, "Failed to activate with TPM2 decrypted key. (Key incorrect?)");
                return -EAGAIN; /* log actual error, but return EAGAIN */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to activate with TPM2 acquired key: %m");

        return 0;
}

static int attach_luks_or_plain_or_bitlk_by_key_data(
                struct crypt_device *cd,
                const char *name,
                const void *key_data,
                size_t key_data_size,
                uint32_t flags,
                bool pass_volume_key) {

        int r;

        assert(cd);
        assert(name);
        assert(key_data);

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

        return 0;
}

static int attach_luks_or_plain_or_bitlk_by_key_file(
                struct crypt_device *cd,
                const char *name,
                const char *key_file,
                uint32_t flags,
                bool pass_volume_key) {

        _cleanup_(erase_and_freep) char *kfdata = NULL;
        _cleanup_free_ char *bindname = NULL;
        size_t kfsize;
        int r;

        assert(cd);
        assert(name);
        assert(key_file);

        /* If we read the key via AF_UNIX, make this client recognizable */
        bindname = make_bindname(name);
        if (!bindname)
                return log_oom();

        r = read_full_file_full(
                        AT_FDCWD, key_file,
                        arg_keyfile_offset == 0 ? UINT64_MAX : arg_keyfile_offset,
                        arg_keyfile_size == 0 ? SIZE_MAX : arg_keyfile_size,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                        bindname,
                        &kfdata, &kfsize);
        if (r == -E2BIG) {
                log_error_errno(r, "Failed to activate, key file '%s' too large.", key_file);
                return -EAGAIN;
        }
        if (r == -ENOENT) {
                log_error_errno(r, "Failed to activate, key file '%s' missing.", key_file);
                return -EAGAIN; /* Log actual error, but return EAGAIN */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read key file '%s': %m", key_file);

        if (pass_volume_key)
                r = crypt_activate_by_volume_key(cd, name, kfdata, kfsize, flags);
        else
                r = crypt_activate_by_passphrase(cd, name, arg_key_slot, kfdata, kfsize, flags);
        if (r == -EPERM) {
                log_error_errno(r, "Failed to activate with key file '%s'. (Key data incorrect?)", key_file);
                return -EAGAIN; /* Log actual error, but return EAGAIN */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to activate with key file '%s': %m", key_file);

        return 0;
}

static int attach_luks_or_plain_or_bitlk_by_passphrase(
                struct crypt_device *cd,
                const char *name,
                char **passwords,
                uint32_t flags,
                bool pass_volume_key) {

        char **p;
        int r;

        assert(cd);
        assert(name);

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

        bool pass_volume_key = false;
        int r;

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

                if (streq_ptr(arg_hash, "plain"))
                        /* plain isn't a real hash type. it just means "use no hash" */
                        params.hash = NULL;
                else if (arg_hash)
                        params.hash = arg_hash;
                else if (!key_file)
                        /* for CRYPT_PLAIN, the behaviour of cryptsetup package is to not hash when a key
                         * file is provided */
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
                pass_volume_key = !params.hash;
        }

        log_info("Set cipher %s, mode %s, key size %i bits for device %s.",
                 crypt_get_cipher(cd),
                 crypt_get_cipher_mode(cd),
                 crypt_get_volume_key_size(cd)*8,
                 crypt_get_device_name(cd));

        if (arg_tpm2_device || arg_tpm2_device_auto)
                return attach_luks_or_plain_or_bitlk_by_tpm2(cd, name, key_file, key_data, key_data_size, until, flags, pass_volume_key);
        if (arg_fido2_device || arg_fido2_device_auto)
                return attach_luks_or_plain_or_bitlk_by_fido2(cd, name, key_file, key_data, key_data_size, until, flags, pass_volume_key);
        if (arg_pkcs11_uri || arg_pkcs11_uri_auto)
                return attach_luks_or_plain_or_bitlk_by_pkcs11(cd, name, key_file, key_data, key_data_size, until, flags, pass_volume_key);
        if (key_data)
                return attach_luks_or_plain_or_bitlk_by_key_data(cd, name, key_data, key_data_size, flags, pass_volume_key);
        if (key_file)
                return attach_luks_or_plain_or_bitlk_by_key_file(cd, name, key_file, flags, pass_volume_key);

        return attach_luks_or_plain_or_bitlk_by_passphrase(cd, name, passwords, flags, pass_volume_key);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cryptsetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME SOURCEDEVICE [KEY-FILE] [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an encrypted block device.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               link);

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

        if (arg_no_read_workqueue)
                flags |= CRYPT_ACTIVATE_NO_READ_WORKQUEUE;

        if (arg_no_write_workqueue)
                flags |= CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE;

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
        const char *verb;
        int r;

        if (argc <= 1)
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires at least two arguments.");

        log_setup();

        cryptsetup_enable_logging(NULL);

        umask(0022);

        verb = argv[1];

        if (streq(verb, "attach")) {
                _unused_ _cleanup_(remove_and_erasep) const char *destroy_key_file = NULL;
                _cleanup_(erase_and_freep) void *key_data = NULL;
                const char *volume, *source, *key_file, *options;
                crypt_status_info status;
                size_t key_data_size = 0;
                uint32_t flags = 0;
                unsigned tries;
                usec_t until;

                /* Arguments: systemd-cryptsetup attach VOLUME SOURCE-DEVICE [KEY-FILE] [OPTIONS] */

                if (argc < 4)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least two arguments.");

                volume = argv[2];
                source = argv[3];
                key_file = argc >= 5 && !STR_IN_SET(argv[4], "", "-", "none") ? argv[4] : NULL;
                options = argc >= 6 && !STR_IN_SET(argv[5], "", "-", "none") ? argv[5] : NULL;

                if (!filename_is_valid(volume))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

                if (key_file && !path_is_absolute(key_file)) {
                        log_warning("Password file path '%s' is not absolute. Ignoring.", key_file);
                        key_file = NULL;
                }

                if (options) {
                        r = parse_options(options);
                        if (r < 0)
                                return r;
                }

                log_debug("%s %s ← %s type=%s cipher=%s", __func__,
                          volume, source, strempty(arg_type), strempty(arg_cipher));

                /* A delicious drop of snake oil */
                (void) mlockall(MCL_FUTURE);

                if (!key_file) {
                        _cleanup_free_ char *bindname = NULL;
                        const char *fn;

                        bindname = make_bindname(volume);
                        if (!bindname)
                                return log_oom();

                        /* If a key file is not explicitly specified, search for a key in a well defined
                         * search path, and load it. */

                        fn = strjoina(volume, ".key");
                        r = find_key_file(
                                        fn,
                                        STRV_MAKE("/etc/cryptsetup-keys.d", "/run/cryptsetup-keys.d"),
                                        bindname,
                                        &key_data, &key_data_size);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                log_debug("Automatically discovered key for volume '%s'.", volume);
                } else if (arg_keyfile_erase)
                        destroy_key_file = key_file; /* let's get this baby erased when we leave */

                if (arg_header) {
                        log_debug("LUKS header: %s", arg_header);
                        r = crypt_init(&cd, arg_header);
                } else
                        r = crypt_init(&cd, source);
                if (r < 0)
                        return log_error_errno(r, "crypt_init() failed: %m");

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, volume);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", volume);
                        return 0;
                }

                flags = determine_flags();

                until = usec_add(now(CLOCK_MONOTONIC), arg_timeout);
                if (until == USEC_INFINITY)
                        until = 0;

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
                                r = crypt_set_data_device(cd, source);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set LUKS data device %s: %m", source);
                        }

                        /* Tokens are available in LUKS2 only, but it is ok to call (and fail) with LUKS1. */
                        if (!key_file && !key_data) {
                                r = crypt_activate_by_token(cd, volume, CRYPT_ANY_TOKEN, NULL, flags);
                                if (r >= 0) {
                                        log_debug("Volume %s activated with LUKS token id %i.", volume, r);
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
                         *    1. A key acquired via PKCS#11 or FIDO2 token, or TPM2 chip
                         *    2. The discovered key: i.e. key_data + key_data_size
                         *    3. The configured key: i.e. key_file + arg_keyfile_offset + arg_keyfile_size
                         *    4. The empty password, in case arg_try_empty_password is set
                         *    5. We enquire the user for a password
                         */

                        if (!key_file && !key_data && !arg_pkcs11_uri && !arg_pkcs11_uri_auto && !arg_fido2_device && !arg_fido2_device_auto && !arg_tpm2_device && !arg_tpm2_device_auto) {

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

                                        r = get_password(volume, source, until, tries == 0 && !arg_verify, &passwords);
                                        if (r == -EAGAIN)
                                                continue;
                                        if (r < 0)
                                                return r;
                                }
                        }

                        if (streq_ptr(arg_type, CRYPT_TCRYPT))
                                r = attach_tcrypt(cd, volume, key_file, key_data, key_data_size, passwords, flags);
                        else
                                r = attach_luks_or_plain_or_bitlk(cd, volume, key_file, key_data, key_data_size, passwords, flags, until);
                        if (r >= 0)
                                break;
                        if (r != -EAGAIN)
                                return r;

                        /* Key not correct? Let's try again! */

                        key_file = NULL;
                        key_data = erase_and_free(key_data);
                        key_data_size = 0;
                        arg_pkcs11_uri = mfree(arg_pkcs11_uri);
                        arg_pkcs11_uri_auto = false;
                        arg_fido2_device = mfree(arg_fido2_device);
                        arg_fido2_device_auto = false;
                        arg_tpm2_device = mfree(arg_tpm2_device);
                        arg_tpm2_device_auto = false;
                }

                if (arg_tries != 0 && tries >= arg_tries)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Too many attempts to activate; giving up.");

        } else if (streq(verb, "detach")) {
                const char *volume;

                volume = argv[2];

                if (!filename_is_valid(volume))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", verb);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

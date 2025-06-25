/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "cryptsetup-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "fstab-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"

static char *arg_hash = NULL; /* the hash algorithm */
static bool arg_superblock = true;
static int arg_format = 1;
static uint64_t arg_data_block_size = 4096;
static uint64_t arg_hash_block_size = 4096;
static uint64_t arg_data_blocks = 0;
static uint64_t arg_hash_offset = 0;
static void *arg_salt = NULL;
static uint64_t arg_salt_size = 32;
static char *arg_uuid = NULL;
static uint32_t arg_activate_flags = CRYPT_ACTIVATE_READONLY;
static char *arg_fec_what = NULL;
static uint64_t arg_fec_offset = 0;
static uint64_t arg_fec_roots = 2;
static void *arg_root_hash_signature = NULL;
static size_t arg_root_hash_signature_size = 0;
static bool arg_root_hash_signature_auto = false;

STATIC_DESTRUCTOR_REGISTER(arg_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_salt, freep);
STATIC_DESTRUCTOR_REGISTER(arg_uuid, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fec_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash_signature, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-veritysetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME DATADEVICE HASHDEVICE ROOTHASH [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attach or detach a verity protected block device.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_roothashsig_option(const char *option, bool strict) {
        _cleanup_free_ void *rhs = NULL;
        size_t rhss = 0;
        bool set_auto = false;
        int r;

        assert(option);

        const char *value = startswith(option, "base64:");
        if (value) {
                r = unbase64mem(value, &rhs, &rhss);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", option);

        } else if (path_is_absolute(option)) {
                r = read_full_file_full(
                                AT_FDCWD,
                                option,
                                /* offset= */ UINT64_MAX,
                                /* size= */ SIZE_MAX,
                                READ_FULL_FILE_CONNECT_SOCKET,
                                /* bind_name= */ NULL,
                                (char**) &rhs,
                                &rhss);
                if (r < 0)
                        return log_error_errno(r, "Failed to read root hash signature: %m");

        } else if (streq(option, "auto"))
                /* auto → Derive signature from udev property ID_DISSECT_PART_ROOTHASH_SIG */
                set_auto = true;
        else if (strict)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "root-hash-signature= expects either full path to signature file or "
                                       "base64 string encoding signature prefixed by base64:.");
        else
                return false;

        if (!HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Activation of verity device with signature requested, but cryptsetup does not support crypt_activate_by_signed_key().");

        free_and_replace(arg_root_hash_signature, rhs);
        arg_root_hash_signature_size = rhss;
        arg_root_hash_signature_auto = set_auto;

        return true;
}

static int parse_block_size(const char *t, uint64_t *size) {
        uint64_t u;
        int r;

        r = parse_size(t, 1024, &u);
        if (r < 0)
                return r;

        if (u < 512 || u > (512 * 1024))
                return -ERANGE;

        if ((u % 512) != 0 || !ISPOWEROF2(u))
                return -EINVAL;

        *size = u;

        return 0;
}

static int parse_options(const char *options) {
        int r;

        /* backward compatibility with the obsolete ROOTHASHSIG positional argument */
        r = parse_roothashsig_option(options, /* strict= */ false);
        if (r < 0)
                return r;
        if (r > 0) {
                log_warning("Usage of ROOTHASHSIG positional argument is deprecated. "
                            "Please use the option root-hash-signature=%s instead.", options);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *val;

                r = extract_first_word(&options, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse options: %m");
                if (r == 0)
                        break;

                if (STR_IN_SET(word, "noauto", "auto", "nofail", "fail", "_netdev"))
                        continue;

                if (isempty(word))
                        continue;
                else if (streq(word, "ignore-corruption"))
                        arg_activate_flags |= CRYPT_ACTIVATE_IGNORE_CORRUPTION;
                else if (streq(word, "restart-on-corruption"))
                        arg_activate_flags |= CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
                else if (streq(word, "ignore-zero-blocks"))
                        arg_activate_flags |= CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS;
#ifdef CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE
                else if (streq(word, "check-at-most-once"))
                        arg_activate_flags |= CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE;
#endif
#ifdef CRYPT_ACTIVATE_PANIC_ON_CORRUPTION
                else if (streq(word, "panic-on-corruption"))
                        arg_activate_flags |= CRYPT_ACTIVATE_PANIC_ON_CORRUPTION;
#endif
                else if ((val = startswith(word, "superblock="))) {

                        r = parse_boolean(val);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse boolean '%s': %m", word);

                        arg_superblock = r;
                } else if ((val = startswith(word, "format="))) {

                        if (!STR_IN_SET(val, "0", "1"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "format= expects either 0 (original Chrome OS version) or "
                                                                                "1 (modern version).");

                        arg_format = val[0] - '0';
                } else if ((val = startswith(word, "data-block-size="))) {
                        uint64_t sz;

                        r = parse_block_size(val, &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse size '%s': %m", word);

                        arg_data_block_size = sz;
                } else if ((val = startswith(word, "hash-block-size="))) {
                        uint64_t sz;

                        r = parse_block_size(val, &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse size '%s': %m", word);

                        arg_hash_block_size = sz;
                } else if ((val = startswith(word, "data-blocks="))) {
                        uint64_t u;

                        r = safe_atou64(val, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse number '%s': %m", word);

                        arg_data_blocks = u;
                } else if ((val = startswith(word, "hash-offset="))) {
                        uint64_t off;

                        r = parse_size(val, 1024, &off);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse offset '%s': %m", word);
                        if (off % 512 != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "hash-offset= expects a 512-byte aligned value.");

                        arg_hash_offset = off;
                } else if ((val = startswith(word, "salt="))) {

                        if (!string_is_safe(val))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "salt= is not valid.");

                        if (isempty(val)) {
                                arg_salt = mfree(arg_salt);
                                arg_salt_size = 32;
                        } else if (streq(val, "-")) {
                                arg_salt = mfree(arg_salt);
                                arg_salt_size = 0;
                        } else {
                                size_t l;
                                void *m;

                                r = unhexmem(val, &m, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse salt '%s': %m", word);

                                free_and_replace(arg_salt, m);
                                arg_salt_size = l;
                        }
                } else if ((val = startswith(word, "uuid="))) {

                        r = sd_id128_from_string(val, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse UUID '%s': %m", word);

                        r = free_and_strdup(&arg_uuid, val);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "hash="))) {

                        r = free_and_strdup(&arg_hash, val);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "fec-device="))) {
                        _cleanup_free_ char *what = NULL;

                        what = fstab_node_to_udev_node(val);
                        if (!what)
                                return log_oom();

                        if (!path_is_absolute(what))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "fec-device= expects an absolute path.");

                        if (!path_is_normalized(what))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "fec-device= expects an normalized path.");

                        r = free_and_strdup(&arg_fec_what, what);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "fec-offset="))) {
                        uint64_t off;

                        r = parse_size(val, 1024, &off);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse offset '%s': %m", word);
                        if (off % 512 != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "fec-offset= expects a 512-byte aligned value.");

                        arg_fec_offset = off;
                } else if ((val = startswith(word, "fec-roots="))) {
                        uint64_t u;

                        r = safe_atou64(val, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse number '%s', ignoring: %m", word);
                        if (u < 2 || u > 24)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "fec-rootfs= expects a value between 2 and 24 (including).");

                        arg_fec_roots = u;
                } else if ((val = startswith(word, "root-hash-signature="))) {
                        r = parse_roothashsig_option(val, /* strict= */ true);
                        if (r < 0)
                                return r;

                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}

static int verb_attach(int argc, char *argv[], void *userdata) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_free_ void *rh = NULL;
        struct crypt_params_verity p = {};
        crypt_status_info status;
        size_t rh_size = 0;
        int r;

        assert(argc >= 5);

        const char *volume = argv[1],
                *data_device = argv[2],
                *verity_device = argv[3],
                *root_hash = argv[4],
                *options = mangle_none(argc > 5 ? argv[5] : NULL);

        if (!filename_is_valid(volume))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

        if (options) {
                r = parse_options(options);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse options: %m");
        }

        if (empty_or_dash(root_hash) || streq_ptr(root_hash, "auto"))
                root_hash = NULL;

        _cleanup_(sd_device_unrefp) sd_device *datadev = NULL;
        if (!root_hash || arg_root_hash_signature_auto) {
                r = sd_device_new_from_path(&datadev, data_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire udev object for data device '%s': %m", data_device);
        }

        if (!root_hash) {
                /* If no literal root hash is specified try to determine it automatically from the
                 * ID_DISSECT_PART_ROOTHASH udev property. */
                r = sd_device_get_property_value(ASSERT_PTR(datadev), "ID_DISSECT_PART_ROOTHASH", &root_hash);
                if (r < 0)
                        return log_error_errno(r, "No root hash specified, and device doesn't carry ID_DISSECT_PART_ROOTHASH property, cannot determine root hash.");
        }

        r = unhexmem(root_hash, &rh, &rh_size);
        if (r < 0)
                return log_error_errno(r, "Failed to parse root hash: %m");

        if (arg_root_hash_signature_auto) {
                assert(!arg_root_hash_signature);
                assert(arg_root_hash_signature_size == 0);

                const char *t;
                r = sd_device_get_property_value(ASSERT_PTR(datadev), "ID_DISSECT_PART_ROOTHASH_SIG", &t);
                if (r < 0)
                        return log_error_errno(r, "Automatic root hash signature pick up requested, and device doesn't carry ID_DISSECT_PART_ROOTHASH_SIG property, cannot determine root hash signature.");

                r = unbase64mem(t, &arg_root_hash_signature, &arg_root_hash_signature_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode root hash signature data from udev data device: %m");
        }

        r = crypt_init(&cd, verity_device);
        if (r < 0)
                return log_error_errno(r, "Failed to open verity device %s: %m", verity_device);

        cryptsetup_enable_logging(cd);

        status = crypt_status(cd, volume);
        if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                log_info("Volume %s already active.", volume);
                return 0;
        }

        if (arg_superblock) {
                p = (struct crypt_params_verity) {
                        .fec_device = arg_fec_what,
                        .hash_area_offset = arg_hash_offset,
                        .fec_area_offset = arg_fec_offset,
                        .fec_roots = arg_fec_roots,
                };

                r = crypt_load(cd, CRYPT_VERITY, &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to load verity superblock: %m");
        } else {
                p = (struct crypt_params_verity) {
                        .hash_name = arg_hash,
                        .data_device = data_device,
                        .fec_device = arg_fec_what,
                        .salt = arg_salt,
                        .salt_size = arg_salt_size,
                        .hash_type = arg_format,
                        .data_block_size = arg_data_block_size,
                        .hash_block_size = arg_hash_block_size,
                        .data_size = arg_data_blocks,
                        .hash_area_offset = arg_hash_offset,
                        .fec_area_offset = arg_fec_offset,
                        .fec_roots = arg_fec_roots,
                        .flags = CRYPT_VERITY_NO_HEADER,
                };

                r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, arg_uuid, NULL, 0, &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to format verity superblock: %m");
        }

        r = crypt_set_data_device(cd, data_device);
        if (r < 0)
                return log_error_errno(r, "Failed to configure data device: %m");

        if (arg_root_hash_signature_size > 0) {
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                r = crypt_activate_by_signed_key(cd, volume, rh, rh_size, arg_root_hash_signature, arg_root_hash_signature_size, arg_activate_flags);
                if (r < 0) {
                        log_info_errno(r, "Unable to activate verity device '%s' with root hash signature (%m), retrying without.", volume);

                        r = crypt_activate_by_volume_key(cd, volume, rh, rh_size, arg_activate_flags);
                        if (r < 0)
                                return log_error_errno(r, "Failed to activate verity device '%s' both with and without root hash signature: %m", volume);

                        log_info("Activation of verity device '%s' succeeded without root hash signature.", volume);
                }
#else
                assert_not_reached();
#endif
        } else
                r = crypt_activate_by_volume_key(cd, volume, rh, rh_size, arg_activate_flags);
        if (r < 0)
                return log_error_errno(r, "Failed to set up verity device '%s': %m", volume);

        return 0;
}

static int verb_detach(int argc, char *argv[], void *userdata) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(argc == 2);

        const char *volume = argv[1];

        if (!filename_is_valid(volume))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

        r = crypt_init_by_name(&cd, volume);
        if (r == -ENODEV) {
                log_info("Volume %s 'already' inactive.", volume);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "crypt_init_by_name() for volume '%s' failed: %m", volume);

        cryptsetup_enable_logging(cd);

        r = crypt_deactivate(cd, volume);
        if (r < 0)
                return log_error_errno(r, "Failed to deactivate volume '%s': %m", volume);

        return 0;
}

static int run(int argc, char *argv[]) {
        if (argv_looks_like_help(argc, argv))
                return help();

        log_setup();

        cryptsetup_enable_logging(NULL);

        umask(0022);

        static const Verb verbs[] = {
                { "attach", 5, 6, 0, verb_attach },
                { "detach", 2, 2, 0, verb_detach },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);

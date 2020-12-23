/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"

static char *arg_hash = NULL;
static bool arg_no_superblock = false;
static int arg_format = 1;
static uint64_t arg_data_block_size = 4096;
static uint64_t arg_hash_block_size = 4096;
static uint64_t arg_data_blocks = 0;
static uint64_t arg_hash_offset = 0;
static void *arg_salt = NULL;
static uint64_t arg_salt_size = 32;
static char *arg_uuid = NULL;
static uint32_t arg_activate_flags = CRYPT_ACTIVATE_READONLY;
static char *arg_root_hash_signature = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_salt, freep);
STATIC_DESTRUCTOR_REGISTER(arg_uuid, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash_signature, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-veritysetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME DATADEVICE HASHDEVICE ROOTHASH [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an integrity protected block device.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               link);

        return 0;
}

static int block_size_is_valid(uint64_t block_size) {
        return (block_size % 512) == 0 && (block_size & (block_size-1)) != 0 &&
               (block_size >= 512) && (block_size <= (512 * 1024));
}

static int looks_like_roothashsig(const char *option) {
        const char *val;
        int r;

        if (path_is_absolute(option)) {

                r = free_and_strdup(&arg_root_hash_signature, option);
                if (r < 0)
                        return log_oom();

                return 1;
        }

        val = startswith(option, "base64:");
        if (val) {

                r = free_and_strdup(&arg_root_hash_signature, val);
                if (r < 0)
                        return log_oom();

                return 1;
        }

        return 0;
}

static int parse_options(const char *options) {
        int r;

        /* backward compatibility with the obsolete ROOTHASHSIG positional argument */
        r = looks_like_roothashsig(options);
        if (r < 0)
                return r;
        if (r == 1) {
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
                else if ((val = startswith(word, "no-superblock="))) {

                        r = parse_boolean(val);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);

                        arg_no_superblock = r;
                } else if ((val = startswith(word, "format="))) {

                        r = safe_atoi(val, &arg_format);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);
                } else if ((val = startswith(word, "data-block-size="))) {
                        uint64_t sz;

                        r = safe_atou64(val, &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);
                        if (!block_size_is_valid(sz))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s: %m", word);

                        arg_data_block_size = sz;
                } else if ((val = startswith(word, "hash-block-size="))) {
                        uint64_t sz;

                        r = parse_size(val, 1024, &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);
                        if (!block_size_is_valid(sz))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse %s: %m", word);

                        arg_hash_block_size = sz;
                } else if ((val = startswith(word, "data-blocks="))) {

                        r = safe_atou64(val, &arg_data_blocks);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);
                } else if ((val = startswith(word, "hash-offset="))) {

                        r = safe_atou64(val, &arg_hash_offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);
                } else if ((val = startswith(word, "salt="))) {

                        if (isempty(val)) {
                                arg_salt = mfree(arg_salt);
                                arg_salt_size = 32;
                        } else if (streq(val, "-")) {
                                arg_salt = mfree(arg_salt);
                                arg_salt_size = 0;
                        } else {
                                r = unhexmem(val, strlen(val), &arg_salt, &arg_salt_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse %s: %m", word);
                        }
                } else if ((val = startswith(word, "uuid="))) {
                        sd_id128_t id;

                        r = sd_id128_from_string(val, &id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s: %m", word);

                        r = free_and_strdup(&arg_hash, val);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "hash="))) {

                        r = free_and_strdup(&arg_hash, val);
                        if (r < 0)
                                return log_oom();
                } else if ((val = startswith(word, "root-hash-signature="))) {

                        r = looks_like_roothashsig(val);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "root-hash-signature expects either full path to signature file or "
                                                                                "base64 string encoding signature prefixed by base64:.");

                        r = free_and_strdup(&arg_root_hash_signature, val);
                        if (r < 0)
                                return log_oom();
                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        if (argc <= 1)
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires at least two arguments.");

        log_setup();

        umask(0022);

        if (streq(argv[1], "attach")) {
                struct crypt_params_verity params = {};
                _cleanup_free_ void *m = NULL;
                struct crypt_params_verity p = {};
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

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, argv[2]);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", argv[2]);
                        return 0;
                }

                if (argc > 6) {
                        r = parse_options(argv[6]);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse options: %m");

                        p.hash_area_offset = arg_hash_offset;
                }

                if (!arg_no_superblock) {
                        p.hash_area_offset = arg_hash_offset;

                        r = crypt_load(cd, CRYPT_VERITY, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to load verity superblock: %m");
                } else {
                        p.hash_name = arg_hash;
                        p.data_device = argv[3];
                        p.salt = arg_salt;
                        p.salt_size = arg_salt_size;
                        p.hash_type = arg_format;
                        p.data_block_size = arg_data_block_size;
                        p.hash_block_size = arg_hash_block_size;
                        p.data_size = arg_data_blocks;
                        p.hash_area_offset = arg_hash_offset;
                        p.flags = CRYPT_VERITY_NO_HEADER;

                        r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, arg_uuid, NULL, 0, &params);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format verity superblock: %m");
                }


                r = crypt_set_data_device(cd, argv[3]);
                if (r < 0)
                        return log_error_errno(r, "Failed to configure data device: %m");

                if (arg_root_hash_signature && *arg_root_hash_signature) {
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        _cleanup_free_ char *hash_sig = NULL;
                        size_t hash_sig_size;
                        char *value;

                        if ((value = startswith(arg_root_hash_signature, "base64:"))) {
                                r = unbase64mem(value, strlen(value), (void *)&hash_sig, &hash_sig_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", arg_root_hash_signature);
                        } else {
                                r = read_full_file_full(
                                                AT_FDCWD, arg_root_hash_signature, UINT64_MAX, SIZE_MAX,
                                                READ_FULL_FILE_CONNECT_SOCKET,
                                                NULL,
                                                &hash_sig, &hash_sig_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read root hash signature: %m");
                        }

                        r = crypt_activate_by_signed_key(cd, argv[2], m, l, hash_sig, hash_sig_size, arg_activate_flags);
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "activation of verity device with signature %s requested, but not supported by cryptsetup due to missing crypt_activate_by_signed_key()", argv[6]);
#endif
                } else
                        r = crypt_activate_by_volume_key(cd, argv[2], m, l, arg_activate_flags);
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

                cryptsetup_enable_logging(cd);

                r = crypt_deactivate(cd, argv[2]);
                if (r < 0)
                        return log_error_errno(r, "Failed to deactivate: %m");

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", argv[1]);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

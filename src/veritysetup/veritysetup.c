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
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "string-util.h"
#include "terminal-util.h"

static uint32_t arg_activate_flags = CRYPT_ACTIVATE_READONLY;
static char *arg_root_hash_signature = NULL;

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

static int save_roothashsig_option(const char *option, bool strict) {
        int r;

        if (path_is_absolute(option) || startswith(option, "base64:")) {
                if (!HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Activation of verity device with signature requested, but cryptsetup does not support crypt_activate_by_signed_key().");

                r = free_and_strdup_warn(&arg_root_hash_signature, option);
                if (r < 0)
                        return r;

                return true;
        }

        if (!strict)
                return false;
        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                               "root-hash-signature= expects either full path to signature file or "
                               "base64 string encoding signature prefixed by base64:.");
}

static int parse_options(const char *options) {
        int r;

        /* backward compatibility with the obsolete ROOTHASHSIG positional argument */
        r = save_roothashsig_option(options, /* strict= */ false);
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
                else if ((val = startswith(word, "root-hash-signature="))) {
                        r = save_roothashsig_option(val, /* strict= */ true);
                        if (r < 0)
                                return r;

                } else
                        log_warning("Encountered unknown option '%s', ignoring.", word);
        }

        return r;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        const char *verb;
        int r;

        if (argv_looks_like_help(argc, argv))
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires at least two arguments.");

        log_setup();

        cryptsetup_enable_logging(NULL);

        umask(0022);

        verb = argv[1];

        if (streq(verb, "attach")) {
                const char *volume, *data_device, *verity_device, *root_hash, *options;
                _cleanup_free_ void *m = NULL;
                crypt_status_info status;
                size_t l;

                if (argc < 6)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least four arguments.");

                volume = argv[2];
                data_device = argv[3];
                verity_device = argv[4];
                root_hash = argv[5];
                options = mangle_none(argc > 6 ? argv[6] : NULL);

                if (!filename_is_valid(volume))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

                r = unhexmem(root_hash, SIZE_MAX, &m, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse root hash: %m");

                r = crypt_init(&cd, verity_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to open verity device %s: %m", verity_device);

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, volume);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", volume);
                        return 0;
                }

                if (options) {
                        r = parse_options(options);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse options: %m");
                }

                r = crypt_load(cd, CRYPT_VERITY, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to load verity superblock: %m");

                r = crypt_set_data_device(cd, data_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to configure data device: %m");

                if (arg_root_hash_signature) {
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

                        r = crypt_activate_by_signed_key(cd, volume, m, l, hash_sig, hash_sig_size, arg_activate_flags);
#else
                        assert_not_reached();
#endif
                } else
                        r = crypt_activate_by_volume_key(cd, volume, m, l, arg_activate_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up verity device: %m");

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

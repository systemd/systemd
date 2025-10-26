/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "cryptsetup-util.h"
#include "fileio.h"
#include "integrity-util.h"
#include "log.h"
#include "main-func.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "time-util.h"
#include "verbs.h"

static uint32_t arg_activate_flags;
static int arg_percent;
static usec_t arg_commit_time;
static char *arg_existing_data_device;
static char *arg_integrity_algorithm;

STATIC_DESTRUCTOR_REGISTER(arg_existing_data_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_integrity_algorithm, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-integritysetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME DEVICE [HMAC_KEY_FILE|-] [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attach or detach an integrity protected block device.\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               program_invocation_short_name,
               link);

        return 0;
}

static int load_key_file(
                const char *key_file,
                void **ret_key_file_contents,
                size_t *ret_key_file_size) {
        int r;
        _cleanup_(erase_and_freep) char *tmp_key_file_contents = NULL;
        size_t tmp_key_file_size;

        if (!path_is_absolute(key_file))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "key file not absolute path: %s", key_file);

        r = read_full_file_full(
                        AT_FDCWD, key_file, UINT64_MAX, DM_MAX_KEY_SIZE,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        NULL,
                        &tmp_key_file_contents, &tmp_key_file_size);
        if (r < 0)
                return log_error_errno(r, "Failed to process key file: %m");

        if (ret_key_file_contents && ret_key_file_size) {
                *ret_key_file_contents = TAKE_PTR(tmp_key_file_contents);
                *ret_key_file_size = tmp_key_file_size;
        }

        return 0;
}

static const char *integrity_algorithm_select(const void *key_file_buf) {
        /*  To keep a bit of sanity for end users, the subset of integrity
            algorithms we support will match what is used in integritysetup */
        if (arg_integrity_algorithm) {
                if (streq("hmac-sha256", arg_integrity_algorithm))
                        return DM_HMAC_256;
                return arg_integrity_algorithm;
        } else if (key_file_buf)
                return DM_HMAC_256;
        return "crc32c";
}

static int verb_attach(int argc, char *argv[], void *userdata) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        crypt_status_info status;
        _cleanup_(erase_and_freep) void *key_buf = NULL;
        size_t key_buf_size = 0;
        int r;

        /* attach name device optional_key_file optional_options */

        assert(argc >= 3 && argc <= 5);

        const char *volume = argv[1],
                *device = argv[2],
                *key_file = mangle_none(argc > 3 ? argv[3] : NULL),
                *options = mangle_none(argc > 4 ? argv[4] : NULL);

        if (!filename_is_valid(volume))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

        if (key_file) {
                r = load_key_file(key_file, &key_buf, &key_buf_size);
                if (r < 0)
                        return r;
        }

        if (options) {
                r = parse_integrity_options(options, &arg_activate_flags, &arg_percent,
                                            &arg_commit_time, &arg_existing_data_device, &arg_integrity_algorithm);
                if (r < 0)
                        return r;
        }

        r = sym_crypt_init(&cd, device);
        if (r < 0)
                return log_error_errno(r, "Failed to open integrity device %s: %m", device);

        cryptsetup_enable_logging(cd);

        status = sym_crypt_status(cd, volume);
        if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                log_info("Volume %s already active.", volume);
                return 0;
        }

        r = sym_crypt_load(cd,
                       CRYPT_INTEGRITY,
                       &(struct crypt_params_integrity) {
                               .journal_watermark = arg_percent,
                               .journal_commit_time = DIV_ROUND_UP(arg_commit_time, USEC_PER_SEC),
                               .integrity = integrity_algorithm_select(key_buf),
                       });
        if (r < 0)
                return log_error_errno(r, "Failed to load integrity superblock: %m");

        if (!isempty(arg_existing_data_device)) {
                r = sym_crypt_set_data_device(cd, arg_existing_data_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to add separate data device: %m");
        }

        r = sym_crypt_activate_by_volume_key(cd, volume, key_buf, key_buf_size, arg_activate_flags);
        if (r < 0)
                return log_error_errno(r, "Failed to set up integrity device: %m");

        return 0;
}

static int verb_detach(int argc, char *argv[], void *userdata) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(argc == 2);

        const char *volume = argv[1];

        if (!filename_is_valid(volume))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Volume name '%s' is not valid.", volume);

        r = sym_crypt_init_by_name(&cd, volume);
        if (r == -ENODEV) {
                log_info("Volume %s already inactive.", volume);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "crypt_init_by_name() failed: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_deactivate(cd, volume);
        if (r < 0)
                return log_error_errno(r, "Failed to deactivate: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        if (argv_looks_like_help(argc, argv))
                return help();

        log_setup();

        r = dlopen_cryptsetup();
        if (r < 0)
                return log_error_errno(r, "Failed to load libcryptsetup: %m");

        cryptsetup_enable_logging(NULL);

        umask(0022);

        static const Verb verbs[] = {
                { "attach", 3, 5, 0, verb_attach },
                { "detach", 2, 2, 0, verb_detach },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);

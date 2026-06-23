/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "sd-device.h"

#include "blockdev-list.h"
#include "blockdev-util.h"
#include "build.h"
#include "cpu-set-util.h"
#include "cryptenroll.h"
#include "cryptenroll-fido2.h"
#include "cryptenroll-list.h"
#include "cryptenroll-password.h"
#include "cryptenroll-pkcs11.h"
#include "cryptenroll-recovery.h"
#include "cryptenroll-tpm2.h"
#include "cryptenroll-wipe.h"
#include "cryptsetup-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "format-table.h"
#include "libfido2-util.h"
#include "limits-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pkcs11-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"

#define ARGON2ID_BENCHMARK_DEFAULT_TARGET_MS 2000U
#define ARGON2ID_BENCHMARK_MAX_ATTEMPTS      8U
#define ARGON2ID_BENCHMARK_MIN_MEMORY        (64ULL * 1024 * 1024)
#define ARGON2ID_BENCHMARK_MIN_MS            250U
#define ARGON2ID_BENCHMARK_PERCENT_MAX       110U
#define ARGON2ID_BENCHMARK_PERCENT_MIN       95U

typedef enum Tpm2WithPin {
        TPM2_WITH_PIN_NO,
        TPM2_WITH_PIN_YES,
        TPM2_WITH_PIN_DIRECT,
        _TPM2_WITH_PIN_MAX,
        _TPM2_WITH_PIN_INVALID = -EINVAL,
} Tpm2WithPin;

static const char * const tpm2_with_pin_table[_TPM2_WITH_PIN_MAX] = {
        [TPM2_WITH_PIN_NO]     = "no",
        [TPM2_WITH_PIN_YES]    = "yes",       /* with argon2id */
        [TPM2_WITH_PIN_DIRECT] = "direct",    /* without argon2id, i.e. traditional mode as in v251 and before */
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(tpm2_with_pin, Tpm2WithPin, TPM2_WITH_PIN_YES);

static EnrollType arg_enroll_type = _ENROLL_TYPE_INVALID;
static char *arg_unlock_keyfile = NULL;
static UnlockType arg_unlock_type = UNLOCK_PASSWORD;
static char *arg_unlock_fido2_device = NULL;
static char *arg_unlock_tpm2_device = NULL;
static char *arg_pkcs11_token_uri = NULL;
static char *arg_fido2_device = NULL;
static char *arg_fido2_salt_file = NULL;
static bool arg_fido2_parameters_in_header = true;
static char *arg_tpm2_device = NULL;
static uint32_t arg_tpm2_seal_key_handle = 0;
static char *arg_tpm2_device_key = NULL;
static Tpm2PCRValue *arg_tpm2_hash_pcr_values = NULL;
static size_t arg_tpm2_n_hash_pcr_values = 0;
static Tpm2WithPin arg_tpm2_pin = _TPM2_WITH_PIN_INVALID;
static Argon2IdParameters arg_tpm2_argon2id_params = ARGON2ID_PARAMETERS_DEFAULT;
static usec_t arg_tpm2_argon2id_iter_time = 0;
static char *arg_tpm2_public_key = NULL;
static bool arg_tpm2_load_public_key = true;
static uint32_t arg_tpm2_public_key_pcr_mask = 0;
static char *arg_tpm2_signature = NULL;
static char *arg_tpm2_pcrlock = NULL;
static char *arg_node = NULL;
static PagerFlags arg_pager_flags = 0;
static int *arg_wipe_slots = NULL;
static size_t arg_n_wipe_slots = 0;
static WipeScope arg_wipe_slots_scope = WIPE_EXPLICIT;
static unsigned arg_wipe_slots_mask = 0; /* Bitmask of (1U << EnrollType), for wiping all slots of specific types */
static Fido2EnrollFlags arg_fido2_lock_with = FIDO2ENROLL_PIN | FIDO2ENROLL_UP;
#if HAVE_LIBFIDO2
static int arg_fido2_cred_alg = COSE_ES256;
#else
static int arg_fido2_cred_alg = 0;
#endif

assert_cc(sizeof(arg_wipe_slots_mask) * 8 >= _ENROLL_TYPE_MAX);

STATIC_DESTRUCTOR_REGISTER(arg_unlock_keyfile, freep);
STATIC_DESTRUCTOR_REGISTER(arg_unlock_fido2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_unlock_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_token_uri, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_salt_file, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_hash_pcr_values, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_public_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_signature, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_pcrlock, freep);
STATIC_DESTRUCTOR_REGISTER(arg_node, freep);
STATIC_DESTRUCTOR_REGISTER(arg_wipe_slots, freep);

static bool wipe_requested(void) {
        return arg_n_wipe_slots > 0 ||
                arg_wipe_slots_scope != WIPE_EXPLICIT ||
                arg_wipe_slots_mask != 0;
}

static const char* const enroll_type_table[_ENROLL_TYPE_MAX] = {
        [ENROLL_PASSWORD] = "password",
        [ENROLL_RECOVERY] = "recovery",
        [ENROLL_PKCS11]   = "pkcs11",
        [ENROLL_FIDO2]    = "fido2",
        [ENROLL_TPM2]     = "tpm2",
};

DEFINE_STRING_TABLE_LOOKUP(enroll_type, EnrollType);

static const char *const luks2_token_type_table[_ENROLL_TYPE_MAX] = {
        /* ENROLL_PASSWORD has no entry here, as slots of this type do not have a token in the LUKS2 header */
        [ENROLL_RECOVERY] = "systemd-recovery",
        [ENROLL_PKCS11]   = "systemd-pkcs11",
        [ENROLL_FIDO2]    = "systemd-fido2",
        [ENROLL_TPM2]     = "systemd-tpm2",
};

DEFINE_STRING_TABLE_LOOKUP(luks2_token_type, EnrollType);

static int determine_default_node(void) {
        int r;

        /* If no device is specified we'll default to the backing device of /var/.
         *
         * Why /var/ and not just / you ask?
         *
         * On most systems /var/ is going to be on the root fs, hence the outcome is usually the same.
         *
         * However, on systems where / and /var/ are separate it makes more sense to default to /var/ because
         * that's where the persistent and variable data is placed (i.e. where LUKS should be used) while /
         * doesn't really have to be variable and could as well be immutable or ephemeral. Hence /var/ should
         * be a better default.
         *
         * Or to say this differently: it makes sense to support well systems with /var/ being on /. It also
         * makes sense to support well systems with them being separate, and /var/ being variable and
         * persistent. But any other kind of system appears much less interesting to support, and in that
         * case people should just specify the device name explicitly. */

        dev_t devno;
        r = get_block_device("/var", &devno);
        if (r < 0)
                return log_error_errno(r, "Failed to determine block device backing /var/: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "File system /var/ is on not backed by a (single) whole block device.");

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_devnum(&dev, 'b', devno);
        if (r < 0)
                return log_error_errno(r, "Unable to access backing block device for /var/: %m");

        const char *dm_uuid;
        r = sd_device_get_property_value(dev, "DM_UUID", &dm_uuid);
        if (r == -ENOENT)
                return log_error_errno(r, "Backing block device of /var/ is not a DM device: %m");
        if (r < 0)
                return log_error_errno(r, "Unable to query DM_UUID udev property of backing block device for /var/: %m");

        if (!startswith(dm_uuid, "CRYPT-LUKS2-"))
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Block device backing /var/ is not a LUKS2 device.");

        _cleanup_(sd_device_unrefp) sd_device *origin = NULL;
        r = block_device_get_originating(dev, &origin, /* recursive= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to get originating device of LUKS2 device backing /var/: %m");

        const char *dp;
        r = sd_device_get_devname(origin, &dp);
        if (r < 0)
                return log_error_errno(r, "Failed to get device path for LUKS2 device backing /var/: %m");

        r = free_and_strdup_warn(&arg_node, dp);
        if (r < 0)
                return r;

        log_info("No device specified, defaulting to '%s'.", arg_node);
        return 0;
}

static int parse_wipe_slot(const char *arg) {
        int r;

        assert(arg);

        if (isempty(arg)) {
                arg_wipe_slots_mask = 0;
                arg_wipe_slots_scope = WIPE_EXPLICIT;
                return 0;
        }

        for (const char *p = arg;;) {
                _cleanup_free_ char *slot = NULL;

                r = extract_first_word(&p, &slot, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == 0)
                        return 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to parse slot list: %s", arg);

                if (streq(slot, "all"))
                        arg_wipe_slots_scope = WIPE_ALL;
                else if (streq(slot, "empty")) {
                        if (arg_wipe_slots_scope != WIPE_ALL) /* if "all" was specified before, that wins */
                                arg_wipe_slots_scope = WIPE_EMPTY_PASSPHRASE;
                } else if (streq(slot, "password"))
                        arg_wipe_slots_mask |= 1U << ENROLL_PASSWORD;
                else if (streq(slot, "recovery"))
                        arg_wipe_slots_mask |= 1U << ENROLL_RECOVERY;
                else if (streq(slot, "pkcs11"))
                        arg_wipe_slots_mask |= 1U << ENROLL_PKCS11;
                else if (streq(slot, "fido2"))
                        arg_wipe_slots_mask |= 1U << ENROLL_FIDO2;
                else if (streq(slot, "tpm2"))
                        arg_wipe_slots_mask |= 1U << ENROLL_TPM2;
                else {
                        unsigned n;

                        r = safe_atou(slot, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse slot index: %s", slot);
                        if (n > INT_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Slot index out of range: %u", n);

                        if (!GREEDY_REALLOC(arg_wipe_slots, arg_n_wipe_slots + 1))
                                return log_oom();

                        arg_wipe_slots[arg_n_wipe_slots++] = (int) n;
                }
        }
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-cryptenroll", "1", &link);
        if (r < 0)
                return log_oom();

        static const char* const groups[] = {
                NULL,
                "Unlocking",
                "Simple Enrollment",
                "PKCS#11 Enrollment",
                "FIDO2 Enrollment",
                "TPM2 Enrollment",
        };

        Table *tables[ELEMENTSOF(groups)] = {};
        CLEANUP_ELEMENTS(tables, table_unref_array_clear);

        for (size_t i = 0; i < ELEMENTSOF(groups); i++) {
                r = option_parser_get_help_table_group(groups[i], &tables[i]);
                if (r < 0)
                        return r;
        }

        (void) table_sync_column_widths(0, tables[0], tables[1], tables[2], tables[3], tables[4], tables[5]);

        printf("%s [OPTIONS...] [BLOCK-DEVICE]\n\n"
               "%sEnroll a security token or authentication credential to a LUKS volume.%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        for (size_t i = 0; i < ELEMENTSOF(groups); i++) {
                printf("\n%s%s:%s\n", ansi_underline(), groups[i] ?: "Options", ansi_normal());

                r = table_print_or_warn(tables[i]);
                if (r < 0)
                        return r;
        }

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        bool auto_public_key_pcr_mask = true, auto_pcrlock = true;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_LONG("list-devices", NULL,
                            "List candidate block devices to operate on"):
                        return blockdev_list(BLOCKDEV_LIST_SHOW_SYMLINKS|BLOCKDEV_LIST_REQUIRE_LUKS,
                                             /* ret_devices= */ NULL,
                                             /* ret_n_devices= */ NULL);

                OPTION_LONG("wipe-slot", "SLOT1,SLOT2,…",
                            "Wipe specified slots"):
                        r = parse_wipe_slot(opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Unlocking"): {}

                OPTION_LONG("unlock-key-file", "PATH",
                            "Use a file to unlock the volume"):
                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_unlock_keyfile);
                        if (r < 0)
                                return r;

                        arg_unlock_type = UNLOCK_KEYFILE;
                        break;

                OPTION_LONG("unlock-fido2-device", "PATH",
                            "Use a FIDO2 device to unlock the volume"): {
                        _cleanup_free_ char *device = NULL;

                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        assert(!arg_unlock_fido2_device);

                        if (!streq(opts.arg, "auto")) {
                                device = strdup(opts.arg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_unlock_type = UNLOCK_FIDO2;
                        arg_unlock_fido2_device = TAKE_PTR(device);
                        break;
                }

                OPTION_LONG("unlock-tpm2-device", "PATH",
                            "Use a TPM2 device to unlock the volume"): {
                        _cleanup_free_ char *device = NULL;

                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        assert(!arg_unlock_tpm2_device);

                        if (!streq(opts.arg, "auto")) {
                                device = strdup(opts.arg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_unlock_type = UNLOCK_TPM2;
                        arg_unlock_tpm2_device = TAKE_PTR(device);
                        break;
                }

                OPTION_GROUP("Simple Enrollment"): {}

                OPTION_LONG("password", NULL,
                            "Enroll a user-supplied password"):
                        if (arg_enroll_type >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        arg_enroll_type = ENROLL_PASSWORD;
                        break;

                OPTION_LONG("recovery-key", NULL,
                            "Enroll a recovery key"):
                        if (arg_enroll_type >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        arg_enroll_type = ENROLL_RECOVERY;
                        break;

                OPTION_GROUP("PKCS#11 Enrollment"): {}

                OPTION_LONG("pkcs11-token-uri", "URI|auto|list",
                            "Enroll a PKCS#11 security token or list them"): {
                        _cleanup_free_ char *uri = NULL;

                        if (streq(opts.arg, "list"))
                                return pkcs11_list_tokens();

                        if (arg_enroll_type >= 0 || arg_pkcs11_token_uri)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (streq(opts.arg, "auto")) {
                                r = pkcs11_find_token_auto(&uri);
                                if (r < 0)
                                        return r;
                        } else {
                                if (!pkcs11_uri_valid(opts.arg))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid PKCS#11 URI: %s", opts.arg);

                                uri = strdup(opts.arg);
                                if (!uri)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_PKCS11;
                        arg_pkcs11_token_uri = TAKE_PTR(uri);
                        break;
                }

                OPTION_GROUP("FIDO2 Enrollment"): {}

                OPTION_LONG("fido2-device", "PATH|auto|list",
                            "Enroll a FIDO2-HMAC security token or list them"): {
                        _cleanup_free_ char *device = NULL;

                        if (streq(opts.arg, "list"))
                                return fido2_list_devices();

                        if (arg_enroll_type >= 0 || arg_fido2_device)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (!streq(opts.arg, "auto")) {
                                device = strdup(opts.arg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_FIDO2;
                        arg_fido2_device = TAKE_PTR(device);
                        break;
                }

                OPTION_LONG("fido2-salt-file", "PATH",
                            "Use salt from a file instead of generating one"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_fido2_salt_file);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("fido2-parameters-in-header", "BOOL",
                            "Whether to store FIDO2 parameters in the LUKS2 header"):
                        r = parse_boolean_argument("--fido2-parameters-in-header=", opts.arg, &arg_fido2_parameters_in_header);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("fido2-credential-algorithm", "STRING",
                            "Specify COSE algorithm for FIDO2 credential"):
                        r = parse_fido2_algorithm(opts.arg, &arg_fido2_cred_alg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse COSE algorithm: %s", opts.arg);
                        break;

                OPTION_LONG("fido2-with-client-pin", "BOOL",
                            "Whether to require entering a PIN to unlock the volume"):
                        r = parse_boolean_argument("--fido2-with-client-pin=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_PIN, r);
                        break;

                OPTION_LONG("fido2-with-user-presence", "BOOL",
                            "Whether to require user presence to unlock the volume"):
                        r = parse_boolean_argument("--fido2-with-user-presence=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UP, r);
                        break;

                OPTION_LONG("fido2-with-user-verification", "BOOL",
                            "Whether to require user verification to unlock the volume"):
                        r = parse_boolean_argument("--fido2-with-user-verification=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UV, r);
                        break;

                OPTION_GROUP("TPM2 Enrollment"): {}

                OPTION_LONG("tpm2-device", "PATH|auto|list",
                            "Enroll a TPM2 device or list them"): {
                        _cleanup_free_ char *device = NULL;

                        if (streq(opts.arg, "list"))
                                return tpm2_list_devices(/* legend= */ true, /* quiet= */ false);

                        if (arg_enroll_type >= 0 || arg_tpm2_device)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (!streq(opts.arg, "auto")) {
                                device = strdup(opts.arg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_TPM2;
                        arg_tpm2_device = TAKE_PTR(device);
                        break;
                }

                OPTION_LONG("tpm2-device-key", "PATH",
                            "Enroll a TPM2 device using its public key"):
                        if (arg_enroll_type >= 0 || arg_tpm2_device_key)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_tpm2_device_key);
                        if (r < 0)
                                return r;

                        arg_enroll_type = ENROLL_TPM2;
                        break;

                OPTION_LONG("tpm2-seal-key-handle", "HANDLE",
                            "Specify handle of key to use for sealing"):
                        r = safe_atou32_full(opts.arg, 16, &arg_tpm2_seal_key_handle);
                        if (r < 0)
                                return log_error_errno(r, "Could not parse TPM2 seal key handle index '%s': %m", opts.arg);
                        break;

                OPTION_LONG("tpm2-pcrs", "PCR1+PCR2+PCR3+…",
                            "Specify TPM2 PCRs to seal against"):
                        r = tpm2_parse_pcr_argument_append(opts.arg, &arg_tpm2_hash_pcr_values, &arg_tpm2_n_hash_pcr_values);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tpm2-public-key", "PATH",
                            "Enroll signed TPM2 PCR policy against PEM public key"):
                        /* an empty argument disables loading a public key */
                        if (isempty(opts.arg)) {
                                arg_tpm2_load_public_key = false;
                                arg_tpm2_public_key = mfree(arg_tpm2_public_key);
                                break;
                        }

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_tpm2_public_key);
                        if (r < 0)
                                return r;
                        arg_tpm2_load_public_key = true;
                        break;

                OPTION_LONG("tpm2-public-key-pcrs", "PCR1+PCR2+PCR3+…",
                            "Enroll signed TPM2 PCR policy for specified TPM2 PCRs"):
                        auto_public_key_pcr_mask = false;
                        r = tpm2_parse_pcr_argument_to_mask(opts.arg, &arg_tpm2_public_key_pcr_mask);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tpm2-signature", "PATH",
                            "Validate public key enrollment works with JSON signature file"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_tpm2_signature);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tpm2-pcrlock", "PATH",
                            "Specify pcrlock policy to lock against"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_tpm2_pcrlock);
                        if (r < 0)
                                return r;
                        auto_pcrlock = false;
                        break;

                OPTION_LONG("tpm2-with-pin", "BOOL|direct",
                            "Whether to require entering a PIN to unlock the volume. "
                            "Takes a boolean or the special value \"direct\". "
                            "When enabled (true), Argon2id is used for PIN hardening. "
                            "When \"direct\", the PIN is used directly without Argon2id "
                            "(compatible with older systemd versions)"): {
                        Tpm2WithPin v = tpm2_with_pin_from_string(opts.arg);
                        if (v < 0)
                                return log_error_errno(v, "Failed to parse --tpm2-with-pin=: %s", opts.arg);
                        arg_tpm2_pin = v;
                        break;
                }

                OPTION_LONG("tpm2-argon2id-memory", "BYTES",
                            "Argon2id memory cost in bytes (default: 64M)"): {
                        uint64_t mem;
                        r = parse_size(opts.arg, 1024, &mem);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tpm2-argon2id-memory=: %s", opts.arg);
                        if (mem == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argon2id memory must be non-zero.");
                        arg_tpm2_argon2id_params.memcost_bytes = mem;
                        break;
                }

                OPTION_LONG("tpm2-argon2id-iterations", "NUM",
                            "Argon2id iteration count (default: 8)"):
                        r = safe_atou(opts.arg, &arg_tpm2_argon2id_params.iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tpm2-argon2id-iterations=: %s", opts.arg);
                        if (arg_tpm2_argon2id_params.iterations == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argon2id iterations must be non-zero.");
                        break;

                OPTION_LONG("tpm2-argon2id-parallelism", "NUM",
                            "Argon2id parallelism/lane count (default: 4)"):
                        r = safe_atou(opts.arg, &arg_tpm2_argon2id_params.lanes);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tpm2-argon2id-parallelism=: %s", opts.arg);
                        if (arg_tpm2_argon2id_params.lanes == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argon2id parallelism must be non-zero.");
                        break;

                OPTION_LONG("tpm2-argon2id-iter-time", "TIME",
                            "Target Argon2id benchmark time in seconds (default: 2s)"):
                        r = parse_sec(opts.arg, &arg_tpm2_argon2id_iter_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tpm2-argon2id-iter-time=: %s", opts.arg);
                        if (arg_tpm2_argon2id_iter_time == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Target time must be non-zero.");
                        break;
                }

        if (option_parser_get_n_args(&opts) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments, refusing.");

        const char *arg = option_parser_get_arg(&opts, 0);
        if (arg)
                r = parse_path_argument(arg, false, &arg_node);
        else if (!wipe_requested())
                r = determine_default_node();
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Wiping requested and no block device node specified, refusing.");
        if (r < 0)
                return r;

        if (arg_enroll_type == ENROLL_FIDO2) {
                if (arg_unlock_type == UNLOCK_FIDO2 && !(arg_fido2_device && arg_unlock_fido2_device))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "When both enrolling and unlocking with FIDO2 tokens, automatic discovery is unsupported. "
                                               "Please specify device paths for enrolling and unlocking respectively.");

                if (!arg_fido2_parameters_in_header && !arg_fido2_salt_file)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 parameters' storage in the LUKS2 header was disabled, but no salt file provided, refusing.");

                if (!arg_fido2_device) {
                        r = fido2_find_device_auto(&arg_fido2_device);
                        if (r < 0)
                                return r;
                }
        }

        if (arg_enroll_type == ENROLL_TPM2) {
                if (auto_pcrlock) {
                        assert(!arg_tpm2_pcrlock);

                        r = tpm2_pcrlock_search_file(NULL, NULL, &arg_tpm2_pcrlock);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        log_warning_errno(r, "Search for pcrlock.json failed, assuming it does not exist: %m");
                        } else
                                log_info("Automatically using pcrlock policy '%s'.", arg_tpm2_pcrlock);
                }

                if (auto_public_key_pcr_mask) {
                        assert(arg_tpm2_public_key_pcr_mask == 0);
                        arg_tpm2_public_key_pcr_mask = INDEX_TO_MASK(uint32_t, TPM2_PCR_KERNEL_BOOT);
                }

                if (arg_tpm2_n_hash_pcr_values == 0 &&
                    arg_tpm2_pin <= 0 &&
                    arg_tpm2_public_key_pcr_mask == 0 &&
                    !arg_tpm2_pcrlock)
                        log_notice("Notice: enrolling TPM2 with an empty policy, i.e. without any state or access restrictions.\n"
                                   "Use --tpm2-public-key=, --tpm2-pcrlock=, --tpm2-with-pin= or --tpm2-pcrs= to enable one or more restrictions.");
        }

        if (arg_tpm2_pin < 0)
                arg_tpm2_pin = TPM2_WITH_PIN_NO;

        if (arg_tpm2_pin == TPM2_WITH_PIN_YES && !dlopen_libcrypto_has_argon2id()) {
                log_warning("Argon2id not supported by libcrypto (OpenSSL >= 3.2 required), "
                            "falling back to direct PIN mode.");
                arg_tpm2_pin = TPM2_WITH_PIN_DIRECT;
        }

        return 1;
}

static int check_for_homed(struct crypt_device *cd) {
        int r;

        assert_se(cd);

        /* Politely refuse operating on homed volumes. The enrolled tokens for the user record and the LUKS2
         * volume should not get out of sync. */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                r = cryptsetup_get_token_as_json(cd, token, "systemd-homed", NULL);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                return log_error_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                       "LUKS2 volume is managed by systemd-homed, please use homectl to enroll tokens.");
        }

        return 0;
}

static int load_volume_key_keyfile(
                struct crypt_device *cd,
                void *ret_vk,
                size_t *ret_vks) {

        _cleanup_(erase_and_freep) char *password = NULL;
        size_t password_len;
        int r;

        assert_se(cd);
        assert_se(ret_vk);
        assert_se(ret_vks);

        r = read_full_file_full(
                        AT_FDCWD,
                        arg_unlock_keyfile,
                        UINT64_MAX,
                        SIZE_MAX,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                        NULL,
                        &password,
                        &password_len);
        if (r < 0)
                return log_error_errno(r, "Reading keyfile %s failed: %m", arg_unlock_keyfile);

        r = sym_crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk,
                        ret_vks,
                        password,
                        password_len);
        if (r < 0)
                return log_error_errno(r, "Unlocking via keyfile failed: %m");

        return r;
}

static int prepare_luks(
                struct crypt_device **ret_cd,
                struct iovec *ret_volume_key) {

        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(ret_cd);

        r = sym_crypt_init(&cd, arg_node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS2 superblock of %s: %m", arg_node);

        r = check_for_homed(cd);
        if (r < 0)
                return r;

        if (!ret_volume_key) {
                *ret_cd = TAKE_PTR(cd);
                return 0;
        }

        r = sym_crypt_get_volume_key_size(cd);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine LUKS volume key size");

        _cleanup_(iovec_done_erase) struct iovec vk = {};

        vk.iov_base = malloc(r);
        if (!vk.iov_base)
                return log_oom();

        vk.iov_len = (size_t) r;

        switch (arg_unlock_type) {

        case UNLOCK_PASSWORD:
                r = load_volume_key_password(cd, arg_node, vk.iov_base, &vk.iov_len);
                break;

        case UNLOCK_KEYFILE:
                r = load_volume_key_keyfile(cd, vk.iov_base, &vk.iov_len);
                break;

        case UNLOCK_FIDO2:
                r = load_volume_key_fido2(cd, arg_node, arg_unlock_fido2_device, vk.iov_base, &vk.iov_len);
                break;

        case UNLOCK_TPM2:
                r = load_volume_key_tpm2(cd, arg_node, arg_unlock_tpm2_device, vk.iov_base, &vk.iov_len);
                break;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown LUKS unlock method");
        }

        if (r < 0)
                return r;

        *ret_cd = TAKE_PTR(cd);
        *ret_volume_key = TAKE_STRUCT(vk);

        return 0;
}

static void argon2id_parameters_init_defaults(Argon2IdParameters *ret_params) {
        assert(ret_params);

        *ret_params = ARGON2ID_PARAMETERS_DEFAULT;
        ret_params->iterations = 0; /* handled by benchmark below */

        unsigned n_cpus;
        if (cpus_online(&n_cpus) >= 0)
                ret_params->lanes = n_cpus;

        ret_params->memcost_bytes = 0;
}

static void argon2id_parameters_benchmark(Argon2IdParameters *p, usec_t target_time) {
        bool mem_fixed = p->memcost_bytes > 0;
        bool iter_fixed = p->iterations > 0;
        int r;

        assert(p);
        assert(target_time > 0);

        if (mem_fixed && iter_fixed)
                return;

        struct iovec password = IOVEC_MAKE_STRING("benchmark");
        struct iovec salt = IOVEC_MAKE_STRING("benchmark-salt");

        uint32_t target_ms = (uint32_t) MIN(target_time / USEC_PER_MSEC, (usec_t) UINT32_MAX);
        if (target_ms == 0)
                target_ms = ARGON2ID_BENCHMARK_DEFAULT_TARGET_MS;

        uint32_t iterations = iter_fixed ? p->iterations : 2;
        uint64_t memcost_bytes = mem_fixed ? p->memcost_bytes : ARGON2ID_BENCHMARK_MIN_MEMORY;

        uint64_t max_mem_bytes;
        if (mem_fixed)
                max_mem_bytes = memcost_bytes;
        else {
                max_mem_bytes = physical_memory_scale(1, 2);
                if (max_mem_bytes == 0 || max_mem_bytes == UINT64_MAX)
                        max_mem_bytes = ARGON2ID_PARAMETERS_DEFAULT.memcost_bytes;
                if (memcost_bytes > max_mem_bytes)
                        memcost_bytes = max_mem_bytes;
        }

        usec_t actual_elapsed = 0;

        for (;;) {
                _cleanup_(iovec_done_erase) struct iovec result = {};
                Argon2IdParameters bp = {
                        .memcost_bytes = memcost_bytes,
                        .iterations = iterations,
                        .lanes = p->lanes,
                };

                usec_t start = now(CLOCK_MONOTONIC);
                r = kdf_argon2id_derive(&password, &salt, &bp, /* derive_size= */ 64, &result);
                usec_t elapsed = now(CLOCK_MONOTONIC) - start;
                if (r < 0) {
                        log_debug_errno(r, "Argon2id benchmark failed, using default parameters: %m");
                        *p = ARGON2ID_PARAMETERS_DEFAULT;
                        return;
                }

                actual_elapsed = elapsed;

                if (elapsed >= ARGON2ID_BENCHMARK_MIN_MS * USEC_PER_MSEC)
                        break;

                if (!mem_fixed && memcost_bytes < max_mem_bytes) {
                        uint64_t new_mem = MIN(memcost_bytes * 2, max_mem_bytes);
                        if (new_mem > memcost_bytes)
                                memcost_bytes = new_mem;
                        else
                                memcost_bytes = max_mem_bytes;
                } else if (!iter_fixed) {
                        uint32_t new_iter = MIN(2u * iterations, UINT32_MAX / 2u);
                        if (new_iter > iterations)
                                iterations = new_iter;
                        else
                                break;
                } else
                        break;
        }

        p->memcost_bytes = memcost_bytes;

        for (unsigned attempt = 0; attempt < ARGON2ID_BENCHMARK_MAX_ATTEMPTS; attempt++) {
                _cleanup_(iovec_done_erase) struct iovec result = {};
                Argon2IdParameters bp = {
                        .memcost_bytes = memcost_bytes,
                        .iterations = iterations,
                        .lanes = p->lanes,
                };

                usec_t start = now(CLOCK_MONOTONIC);
                r = kdf_argon2id_derive(&password, &salt, &bp, /* derive_size= */ 64, &result);
                usec_t elapsed = now(CLOCK_MONOTONIC) - start;
                if (r < 0) {
                        log_debug_errno(r, "Argon2id fine-tuning failed, keeping coarse parameters: %m");
                        break;
                }

                actual_elapsed = elapsed;

                uint32_t ms = (uint32_t) (elapsed / USEC_PER_MSEC);
                if (ms == 0)
                        ms = 1;

                uint64_t lower = (uint64_t) target_ms * ARGON2ID_BENCHMARK_PERCENT_MIN / 100;
                uint64_t upper = (uint64_t) target_ms * ARGON2ID_BENCHMARK_PERCENT_MAX / 100;
                if (ms >= lower && ms <= upper)
                        break;

                uint64_t new_mem = memcost_bytes;
                uint32_t new_iter = iterations;

                if (ms < target_ms) {
                        if (!mem_fixed) {
                                new_mem = MIN((uint64_t) memcost_bytes * target_ms / ms, max_mem_bytes);
                                if (new_mem >= max_mem_bytes && !iter_fixed)
                                        new_iter = (uint32_t) MIN(
                                                        (uint64_t) iterations * target_ms / ms,
                                                        (uint64_t) UINT32_MAX);
                        } else if (!iter_fixed)
                                new_iter = (uint32_t) MIN(
                                                (uint64_t) iterations * target_ms / ms,
                                                (uint64_t) UINT32_MAX);
                } else {
                        if (!iter_fixed) {
                                new_iter = MAX((uint64_t) iterations * target_ms / ms, 2ULL);
                                if (new_iter <= 2 && !mem_fixed)
                                        new_mem = MAX(
                                                        (uint64_t) memcost_bytes * target_ms / ms,
                                                        (uint64_t) ARGON2ID_BENCHMARK_MIN_MEMORY);
                        } else if (!mem_fixed)
                                new_mem = MAX(
                                                (uint64_t) memcost_bytes * target_ms / ms,
                                                (uint64_t) ARGON2ID_BENCHMARK_MIN_MEMORY);
                }

                if (new_iter == iterations && new_mem == memcost_bytes)
                        break;

                iterations = new_iter;
                memcost_bytes = new_mem;
        }

        p->memcost_bytes = memcost_bytes;
        p->iterations = iterations;

        log_notice("Argon2id benchmark: %u iterations, %"PRIu64" MiB, %u lanes, ~%ums.",
                   p->iterations, p->memcost_bytes / 1024 / 1024, p->lanes,
                   actual_elapsed > 0 ? (unsigned) (actual_elapsed / USEC_PER_MSEC) : target_ms);
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(iovec_done_erase) struct iovec vk = {};
        int slot, slot_to_wipe, r;

        log_setup();

        argon2id_parameters_init_defaults(&arg_tpm2_argon2id_params);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = DLOPEN_CRYPTSETUP(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_REQUIRED);
        if (r < 0)
                return r;

        /* A delicious drop of snake oil */
        (void) safe_mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT);

        if (arg_enroll_type < 0)
                r = prepare_luks(&cd, /* ret_volume_key= */ NULL); /* No need to unlock device if we don't need the volume key because we don't need to enroll anything */
        else
                r = prepare_luks(&cd, &vk);
        if (r < 0)
                return r;

        switch (arg_enroll_type) {

        case ENROLL_PASSWORD:
                slot = enroll_password(cd, &vk);
                break;

        case ENROLL_RECOVERY:
                slot = enroll_recovery(cd, &vk);
                break;

        case ENROLL_PKCS11:
                slot = enroll_pkcs11(cd, &vk, arg_pkcs11_token_uri);
                break;

        case ENROLL_FIDO2:
                slot = enroll_fido2(cd, &vk, arg_fido2_device, arg_fido2_lock_with, arg_fido2_cred_alg, arg_fido2_salt_file, arg_fido2_parameters_in_header);
                break;

        case ENROLL_TPM2:
                if (arg_tpm2_pin == TPM2_WITH_PIN_YES)
                        argon2id_parameters_benchmark(
                                        &arg_tpm2_argon2id_params,
                                        arg_tpm2_argon2id_iter_time > 0
                                                ? arg_tpm2_argon2id_iter_time
                                                : 2000 * USEC_PER_MSEC);
                slot = enroll_tpm2(cd, &vk, arg_tpm2_device, arg_tpm2_seal_key_handle, arg_tpm2_device_key, arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values, arg_tpm2_public_key, arg_tpm2_load_public_key, arg_tpm2_public_key_pcr_mask, arg_tpm2_signature, arg_tpm2_pin >= TPM2_WITH_PIN_YES, arg_tpm2_pcrlock, arg_tpm2_pin == TPM2_WITH_PIN_YES, &arg_tpm2_argon2id_params, &slot_to_wipe);

                if (slot >= 0 && slot_to_wipe >= 0) {
                        assert(slot != slot_to_wipe);

                        /* Updating PIN on an existing enrollment */
                        r = wipe_slots(
                                        cd,
                                        &slot_to_wipe,
                                        /* n_explicit_slots= */ 1,
                                        WIPE_EXPLICIT,
                                        /* by_mask= */ 0,
                                        /* except_slot= */ -1);
                        if (r < 0)
                                return r;
                }
                break;
        case _ENROLL_TYPE_INVALID:
                /* List enrolled slots if we are called without anything to enroll or wipe */
                if (!wipe_requested())
                        return list_enrolled(cd);

                /* Only slot wiping selected */
                return wipe_slots(cd, arg_wipe_slots, arg_n_wipe_slots, arg_wipe_slots_scope, arg_wipe_slots_mask, -1);

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Operation not implemented yet.");
        }
        if (slot < 0)
                return slot;

        /* After we completed enrolling, remove user selected slots */
        r = wipe_slots(cd, arg_wipe_slots, arg_n_wipe_slots, arg_wipe_slots_scope, arg_wipe_slots_mask, slot);
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

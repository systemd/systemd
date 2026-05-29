/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "sd-device.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "blockdev-list.h"
#include "blockdev-util.h"
#include "build.h"
#include "cryptenroll.h"
#include "cryptenroll-fido2.h"
#include "cryptenroll-list.h"
#include "cryptenroll-password.h"
#include "cryptenroll-pkcs11.h"
#include "cryptenroll-recovery.h"
#include "cryptenroll-tpm2.h"
#include "cryptenroll-varlink.h"
#include "cryptenroll-wipe.h"
#include "cryptsetup-util.h"
#include "extract-word.h"
#include "format-table.h"
#include "libfido2-util.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pkcs11-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"

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
static bool arg_tpm2_pin = false;
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

void enroll_context_done(EnrollContext *c) {
        if (!c)
                return;

        c->node = mfree(c->node);
        c->unlock_keyfile = mfree(c->unlock_keyfile);
        c->unlock_fido2_device = mfree(c->unlock_fido2_device);
        c->unlock_tpm2_device = mfree(c->unlock_tpm2_device);
        c->unlock_password = erase_and_free(c->unlock_password);
        c->passphrase = erase_and_free(c->passphrase);
        c->fido2_device = mfree(c->fido2_device);
        c->fido2_salt_file = mfree(c->fido2_salt_file);
        c->fido2_pin = erase_and_free(c->fido2_pin);
        c->pkcs11_token_uri = mfree(c->pkcs11_token_uri);
        c->tpm2_device = mfree(c->tpm2_device);
        c->tpm2_device_key = mfree(c->tpm2_device_key);
        c->tpm2_hash_pcr_values = mfree(c->tpm2_hash_pcr_values);
        c->tpm2_public_key = mfree(c->tpm2_public_key);
        c->tpm2_signature = mfree(c->tpm2_signature);
        c->tpm2_pcrlock = mfree(c->tpm2_pcrlock);
        c->wipe_slots = mfree(c->wipe_slots);
        c->link = sd_varlink_unref(c->link);
}

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

                OPTION_LONG("unlock-empty", NULL, "Use an empty password to unlock the volume"):
                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        arg_unlock_type = UNLOCK_EMPTY;
                        break;

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

                OPTION_LONG("unlock-headless", NULL, "Try the 'headless' unlock mechanisms in turn"):
                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        arg_unlock_type = UNLOCK_HEADLESS;
                        break;

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

                OPTION_LONG("tpm2-with-pin", "BOOL",
                            "Whether to require entering a PIN to unlock the volume"):
                        r = parse_boolean_argument("--tpm2-with-pin=", opts.arg, &arg_tpm2_pin);
                        if (r < 0)
                                return r;
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
                    !arg_tpm2_pin &&
                    arg_tpm2_public_key_pcr_mask == 0 &&
                    !arg_tpm2_pcrlock)
                        log_notice("Notice: enrolling TPM2 with an empty policy, i.e. without any state or access restrictions.\n"
                                   "Use --tpm2-public-key=, --tpm2-pcrlock=, --tpm2-with-pin= or --tpm2-pcrs= to enable one or more restrictions.");
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

int prepare_luks(
                const EnrollContext *c,
                struct crypt_device **ret_cd,
                struct iovec *ret_volume_key) {

        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        assert(c);
        assert(ret_cd);

        r = sym_crypt_init(&cd, c->node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = sym_crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS2 superblock of %s: %m", c->node);

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

        switch (c->unlock_type) {

        case UNLOCK_EMPTY:
                r = load_volume_key_empty(c, cd, &vk);
                break;

        case UNLOCK_PASSWORD:
                r = load_volume_key_password(c, cd, &vk);
                break;

        case UNLOCK_KEYFILE:
                r = load_volume_key_keyfile(c, cd, &vk);
                break;

        case UNLOCK_FIDO2:
                r = load_volume_key_fido2(c, cd, &vk);
                break;

        case UNLOCK_TPM2:
                r = load_volume_key_tpm2(c, cd, &vk);
                break;

        case UNLOCK_HEADLESS:
                if (tpm2_is_mostly_supported()) {
                        log_info("TPM2 support available, trying unlocking via TPM2…");

                        r = load_volume_key_tpm2(c, cd, &vk);
                        if (r >= 0)
                                break;

                        log_info("TPM2 unlocking didn't work, trying unlocking via empty password…");
                } else
                        log_info("TPM2 support not available, trying unlocking via empty password…");

                r = load_volume_key_empty(c, cd, &vk);
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

static int enroll_context_from_args(EnrollContext *c) {
        assert(c);

        /* Copies the parsed command line parameters from the static arg_* globals into a self-contained
         * EnrollContext. The context owns its own copies of all strings/arrays, so it can be torn down
         * independently of the arg_* destructors. */

        *c = ENROLL_CONTEXT_NULL;

        c->enroll_type = arg_enroll_type;
        c->unlock_type = arg_unlock_type;
        c->fido2_parameters_in_header = arg_fido2_parameters_in_header;
        c->fido2_lock_with = arg_fido2_lock_with;
        c->fido2_cred_alg = arg_fido2_cred_alg;
        c->tpm2_seal_key_handle = arg_tpm2_seal_key_handle;
        c->tpm2_pin = arg_tpm2_pin;
        c->tpm2_load_public_key = arg_tpm2_load_public_key;
        c->tpm2_public_key_pcr_mask = arg_tpm2_public_key_pcr_mask;
        c->wipe_slots_scope = arg_wipe_slots_scope;
        c->wipe_slots_mask = arg_wipe_slots_mask;

        if (strdup_to(&c->node, arg_node) < 0 ||
            strdup_to(&c->unlock_keyfile, arg_unlock_keyfile) < 0 ||
            strdup_to(&c->unlock_fido2_device, arg_unlock_fido2_device) < 0 ||
            strdup_to(&c->unlock_tpm2_device, arg_unlock_tpm2_device) < 0 ||
            strdup_to(&c->fido2_device, arg_fido2_device) < 0 ||
            strdup_to(&c->fido2_salt_file, arg_fido2_salt_file) < 0 ||
            strdup_to(&c->pkcs11_token_uri, arg_pkcs11_token_uri) < 0 ||
            strdup_to(&c->tpm2_device, arg_tpm2_device) < 0 ||
            strdup_to(&c->tpm2_device_key, arg_tpm2_device_key) < 0 ||
            strdup_to(&c->tpm2_public_key, arg_tpm2_public_key) < 0 ||
            strdup_to(&c->tpm2_signature, arg_tpm2_signature) < 0 ||
            strdup_to(&c->tpm2_pcrlock, arg_tpm2_pcrlock) < 0)
                return log_oom();

        if (arg_n_wipe_slots > 0) {
                c->wipe_slots = newdup(int, arg_wipe_slots, arg_n_wipe_slots);
                if (!c->wipe_slots)
                        return log_oom();
                c->n_wipe_slots = arg_n_wipe_slots;
        }

        if (arg_tpm2_n_hash_pcr_values > 0) {
                c->tpm2_hash_pcr_values = newdup(Tpm2PCRValue, arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values);
                if (!c->tpm2_hash_pcr_values)
                        return log_oom();
                c->tpm2_n_hash_pcr_values = arg_tpm2_n_hash_pcr_values;
        }

        return 0;
}

int enroll_now(
                const EnrollContext *c,
                struct crypt_device *cd,
                const struct iovec *volume_key,
                char **ret_recovery_key) {

        int slot, slot_to_wipe = -1, r;

        assert(c);
        assert(cd);
        assert(iovec_is_set(volume_key));

        switch (c->enroll_type) {

        case ENROLL_PASSWORD:
                return enroll_password(c, cd, volume_key);

        case ENROLL_RECOVERY:
                return enroll_recovery(c, cd, volume_key, ret_recovery_key);

        case ENROLL_PKCS11:
                return enroll_pkcs11(c, cd, volume_key);

        case ENROLL_FIDO2:
                return enroll_fido2(c, cd, volume_key);

        case ENROLL_TPM2:
                slot = enroll_tpm2(c, cd, volume_key, &slot_to_wipe);
                if (slot < 0)
                        return slot;

                if (slot_to_wipe >= 0) {
                        assert(slot != slot_to_wipe);

                        /* Updating the PIN on an existing enrollment: wipe just that one slot. This is an
                         * internal one-off wipe, unrelated to the user's wipe selection, so use a throwaway
                         * context referencing a single explicit slot. */
                        _cleanup_(enroll_context_done) EnrollContext wipe_ctx = ENROLL_CONTEXT_NULL;
                        wipe_ctx.wipe_slots = newdup(int, &slot_to_wipe, 1);
                        if (!wipe_ctx.wipe_slots)
                                return log_oom();

                        wipe_ctx.n_wipe_slots = 1;

                        r = wipe_slots(&wipe_ctx, cd, /* ret_wiped_slots= */ NULL, /* ret_n_wiped_slots= */ NULL);
                        if (r < 0)
                                return r;
                }

                return slot;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Operation not implemented yet.");
        }
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(iovec_done_erase) struct iovec vk = {};
        _cleanup_(enroll_context_done) EnrollContext c = ENROLL_CONTEXT_NULL;
        int slot, r;

        log_setup();

        /* A delicious drop of snake oil */
        (void) safe_mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT);

        /* If invoked as a Varlink service, hand off to the Varlink server and don't process the command
         * line any further. */
        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                return cryptenroll_varlink_server();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = DLOPEN_CRYPTSETUP(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_REQUIRED);
        if (r < 0)
                return r;

        r = enroll_context_from_args(&c);
        if (r < 0)
                return r;

        /* If we are called without anything to enroll, we just need the LUKS device, not the volume key. */
        if (c.enroll_type < 0) {
                r = prepare_luks(&c, &cd, /* ret_volume_key= */ NULL);
                if (r < 0)
                        return r;

                /* List enrolled slots if we are called without anything to enroll or wipe */
                if (!wipe_requested())
                        return list_enrolled(cd);

                /* Only slot wiping selected */
                return wipe_slots(&c, cd, /* ret_wiped_slots= */ NULL, /* ret_n_wiped_slots= */ NULL);
        }

        r = prepare_luks(&c, &cd, &vk);
        if (r < 0)
                return r;

        slot = enroll_now(&c, cd, &vk, /* ret_recovery_key= */ NULL);
        if (slot < 0)
                return slot;

        /* After we completed enrolling, remove user selected slots (keeping the one we just added) */
        c.wipe_except_slot = slot;
        r = wipe_slots(&c, cd, /* ret_wiped_slots= */ NULL, /* ret_n_wiped_slots= */ NULL);
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

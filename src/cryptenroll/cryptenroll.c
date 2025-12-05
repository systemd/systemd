/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/mman.h>

#include "sd-device.h"

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
#include "cryptenroll-wipe.h"
#include "cryptsetup-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "libfido2-util.h"
#include "log.h"
#include "main-func.h"
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
PagerFlags arg_pager_flags = 0;
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

/* Only used when parsing options */
static bool arg_auto_public_key_pcr_mask = true;
static bool arg_auto_pcrlock = true;

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

#include "cryptenroll.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-cryptenroll", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [BLOCK-DEVICE]\n\n"
               "%5$sEnroll a security token or authentication credential to a LUKS volume.%6$s\n\n"
               OPTION_HELP_GENERATED
               "\n%3$sUnlocking:%4$s\n"
               OPTION_HELP_GENERATED_UNLOCKING
               "\n%3$sEnrollment:%4$s\n"
               OPTION_HELP_GENERATED_ENROLLMENT
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

        if (argc > optind+1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments, refusing.");

        if (optind < argc) {
                r = parse_path_argument(argv[optind], false, &arg_node);
                if (r < 0)
                        return r;
        } else {
                if (wipe_requested())
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Wiping requested and no block device node specified, refusing.");

                r = determine_default_node();
                if (r < 0)
                        return r;
        }

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
                if (arg_auto_pcrlock) {
                        assert(!arg_tpm2_pcrlock);

                        r = tpm2_pcrlock_search_file(NULL, NULL, &arg_tpm2_pcrlock);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        log_warning_errno(r, "Search for pcrlock.json failed, assuming it does not exist: %m");
                        } else
                                log_info("Automatically using pcrlock policy '%s'.", arg_tpm2_pcrlock);
                }

                if (arg_auto_public_key_pcr_mask) {
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

        for (int token = 0; token < crypt_token_max(CRYPT_LUKS2); token++) {
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

        r = crypt_volume_key_get(
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

        r = crypt_init(&cd, arg_node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS2 superblock of %s: %m", arg_node);

        r = check_for_homed(cd);
        if (r < 0)
                return r;

        if (!ret_volume_key) {
                *ret_cd = TAKE_PTR(cd);
                return 0;
        }

        r = crypt_get_volume_key_size(cd);
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

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(iovec_done_erase) struct iovec vk = {};
        int slot, slot_to_wipe, r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* A delicious drop of snake oil */
        (void) safe_mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT);

        cryptsetup_enable_logging(NULL);

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
                slot = enroll_tpm2(cd, &vk, arg_tpm2_device, arg_tpm2_seal_key_handle, arg_tpm2_device_key, arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values, arg_tpm2_public_key, arg_tpm2_load_public_key, arg_tpm2_public_key_pcr_mask, arg_tpm2_signature, arg_tpm2_pin, arg_tpm2_pcrlock, &slot_to_wipe);

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

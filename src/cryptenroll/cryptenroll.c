/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "ask-password-api.h"
#include "build.h"
#include "cryptenroll-fido2.h"
#include "cryptenroll-list.h"
#include "cryptenroll-password.h"
#include "cryptenroll-pkcs11.h"
#include "cryptenroll-recovery.h"
#include "cryptenroll-tpm2.h"
#include "cryptenroll-wipe.h"
#include "cryptenroll.h"
#include "cryptsetup-util.h"
#include "env-util.h"
#include "escape.h"
#include "fileio.h"
#include "libfido2-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pkcs11-util.h"
#include "pretty-print.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "tpm2-pcr.h"

static EnrollType arg_enroll_type = _ENROLL_TYPE_INVALID;
static char *arg_unlock_keyfile = NULL;
static UnlockType arg_unlock_type = UNLOCK_PASSWORD;
static char *arg_unlock_fido2_device = NULL;
static char *arg_pkcs11_token_uri = NULL;
static char *arg_fido2_device = NULL;
static char *arg_tpm2_device = NULL;
static uint32_t arg_tpm2_seal_key_handle = 0;
static char *arg_tpm2_device_key = NULL;
static Tpm2PCRValue *arg_tpm2_hash_pcr_values = NULL;
static size_t arg_tpm2_n_hash_pcr_values = 0;
static bool arg_tpm2_pin = false;
static char *arg_tpm2_public_key = NULL;
static uint32_t arg_tpm2_public_key_pcr_mask = 0;
static char *arg_tpm2_signature = NULL;
static char *arg_tpm2_pcrlock = NULL;
static char *arg_node = NULL;
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
STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_token_uri, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_device, freep);
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
        [ENROLL_KEYRING]  = "keyring",
};

DEFINE_STRING_TABLE_LOOKUP(enroll_type, EnrollType);

static const char *const luks2_token_type_table[_ENROLL_TYPE_MAX] = {
        /* ENROLL_PASSWORD has no entry here, as slots of this type do not have a token in the LUKS2 header */
        [ENROLL_RECOVERY] = "systemd-recovery",
        [ENROLL_PKCS11]   = "systemd-pkcs11",
        [ENROLL_FIDO2]    = "systemd-fido2",
        [ENROLL_TPM2]     = "systemd-tpm2",
        [ENROLL_KEYRING]  = "luks2-keyring",
};

DEFINE_STRING_TABLE_LOOKUP(luks2_token_type, EnrollType);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cryptenroll", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] BLOCK-DEVICE\n\n"
               "%5$sEnroll a security token or authentication credential to a LUKS volume.%6$s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --wipe-slot=SLOT1,SLOT2,…\n"
               "                       Wipe specified slots\n"
               "\n%3$sUnlocking:%4$s\n"
               "     --unlock-key-file=PATH\n"
               "                       Use a file to unlock the volume\n"
               "     --unlock-fido2-device=PATH\n"
               "                       Use a FIDO2 device to unlock the volume\n"
               "\n%3$sSimple Enrollment:%4$s\n"
               "     --password        Enroll a user-supplied password\n"
               "     --recovery-key    Enroll a recovery key\n"
               "\n%3$sPKCS11 Enrollment:%4$s\n"
               "     --pkcs11-token-uri=URI\n"
               "                       Specify PKCS#11 security token URI\n"
               "\n%3$sFIDO2 Enrollment:%4$s\n"
               "     --fido2-device=PATH\n"
               "                       Enroll a FIDO2-HMAC security token\n"
               "     --fido2-credential-algorithm=STRING\n"
               "                       Specify COSE algorithm for FIDO2 credential\n"
               "     --fido2-with-client-pin=BOOL\n"
               "                       Whether to require entering a PIN to unlock the volume\n"
               "     --fido2-with-user-presence=BOOL\n"
               "                       Whether to require user presence to unlock the volume\n"
               "     --fido2-with-user-verification=BOOL\n"
               "                       Whether to require user verification to unlock the volume\n"
               "\n%3$sTPM2 Enrollment:%4$s\n"
               "     --tpm2-device=PATH\n"
               "                       Enroll a TPM2 device\n"
               "     --tpm2-device-key=PATH\n"
               "                       Enroll a TPM2 device using its public key\n"
               "     --tpm2-seal-key-handle=HANDLE\n"
               "                       Specify handle of key to use for sealing\n"
               "     --tpm2-pcrs=PCR1+PCR2+PCR3+…\n"
               "                       Specify TPM2 PCRs to seal against\n"
               "     --tpm2-public-key=PATH\n"
               "                       Enroll signed TPM2 PCR policy against PEM public key\n"
               "     --tpm2-public-key-pcrs=PCR1+PCR2+PCR3+…\n"
               "                       Enroll signed TPM2 PCR policy for specified TPM2 PCRs\n"
               "     --tpm2-signature=PATH\n"
               "                       Validate public key enrollment works with JSON signature\n"
               "                       file\n"
               "     --tpm2-pcrlock=PATH\n"
               "                       Specify pcrlock policy to lock against\n"
               "     --tpm2-with-pin=BOOL\n"
               "                       Whether to require entering a PIN to unlock the volume\n"
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
        enum {
                ARG_VERSION = 0x100,
                ARG_PASSWORD,
                ARG_RECOVERY_KEY,
                ARG_UNLOCK_KEYFILE,
                ARG_UNLOCK_FIDO2_DEVICE,
                ARG_PKCS11_TOKEN_URI,
                ARG_FIDO2_DEVICE,
                ARG_TPM2_DEVICE,
                ARG_TPM2_DEVICE_KEY,
                ARG_TPM2_SEAL_KEY_HANDLE,
                ARG_TPM2_PCRS,
                ARG_TPM2_PUBLIC_KEY,
                ARG_TPM2_PUBLIC_KEY_PCRS,
                ARG_TPM2_SIGNATURE,
                ARG_TPM2_PCRLOCK,
                ARG_TPM2_WITH_PIN,
                ARG_WIPE_SLOT,
                ARG_FIDO2_WITH_PIN,
                ARG_FIDO2_WITH_UP,
                ARG_FIDO2_WITH_UV,
                ARG_FIDO2_CRED_ALG,
        };

        static const struct option options[] = {
                { "help",                         no_argument,       NULL, 'h'                       },
                { "version",                      no_argument,       NULL, ARG_VERSION               },
                { "password",                     no_argument,       NULL, ARG_PASSWORD              },
                { "recovery-key",                 no_argument,       NULL, ARG_RECOVERY_KEY          },
                { "unlock-key-file",              required_argument, NULL, ARG_UNLOCK_KEYFILE        },
                { "unlock-fido2-device",          required_argument, NULL, ARG_UNLOCK_FIDO2_DEVICE   },
                { "pkcs11-token-uri",             required_argument, NULL, ARG_PKCS11_TOKEN_URI      },
                { "fido2-credential-algorithm",   required_argument, NULL, ARG_FIDO2_CRED_ALG        },
                { "fido2-device",                 required_argument, NULL, ARG_FIDO2_DEVICE          },
                { "fido2-with-client-pin",        required_argument, NULL, ARG_FIDO2_WITH_PIN        },
                { "fido2-with-user-presence",     required_argument, NULL, ARG_FIDO2_WITH_UP         },
                { "fido2-with-user-verification", required_argument, NULL, ARG_FIDO2_WITH_UV         },
                { "tpm2-device",                  required_argument, NULL, ARG_TPM2_DEVICE           },
                { "tpm2-device-key",              required_argument, NULL, ARG_TPM2_DEVICE_KEY       },
                { "tpm2-seal-key-handle",         required_argument, NULL, ARG_TPM2_SEAL_KEY_HANDLE  },
                { "tpm2-pcrs",                    required_argument, NULL, ARG_TPM2_PCRS             },
                { "tpm2-public-key",              required_argument, NULL, ARG_TPM2_PUBLIC_KEY       },
                { "tpm2-public-key-pcrs",         required_argument, NULL, ARG_TPM2_PUBLIC_KEY_PCRS  },
                { "tpm2-signature",               required_argument, NULL, ARG_TPM2_SIGNATURE        },
                { "tpm2-pcrlock",                 required_argument, NULL, ARG_TPM2_PCRLOCK          },
                { "tpm2-with-pin",                required_argument, NULL, ARG_TPM2_WITH_PIN         },
                { "wipe-slot",                    required_argument, NULL, ARG_WIPE_SLOT             },
                {}
        };

        bool auto_hash_pcr_values = true, auto_public_key_pcr_mask = true, auto_pcrlock = true;
        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_FIDO2_WITH_PIN:
                        r = parse_boolean_argument("--fido2-with-client-pin=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_PIN, r);
                        break;

                case ARG_FIDO2_WITH_UP:
                        r = parse_boolean_argument("--fido2-with-user-presence=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UP, r);
                        break;

                case ARG_FIDO2_WITH_UV:
                        r = parse_boolean_argument("--fido2-with-user-verification=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UV, r);
                        break;

                case ARG_PASSWORD:
                        if (arg_enroll_type >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        arg_enroll_type = ENROLL_PASSWORD;
                        break;

                case ARG_RECOVERY_KEY:
                        if (arg_enroll_type >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        arg_enroll_type = ENROLL_RECOVERY;
                        break;

                case ARG_UNLOCK_KEYFILE:
                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_unlock_keyfile);
                        if (r < 0)
                                return r;

                        arg_unlock_type = UNLOCK_KEYFILE;
                        break;

                case ARG_UNLOCK_FIDO2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (arg_unlock_type != UNLOCK_PASSWORD)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple unlock methods specified at once, refusing.");

                        assert(!arg_unlock_fido2_device);

                        if (!streq(optarg, "auto")) {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_unlock_type = UNLOCK_FIDO2;
                        arg_unlock_fido2_device = TAKE_PTR(device);
                        break;
                }

                case ARG_PKCS11_TOKEN_URI: {
                        _cleanup_free_ char *uri = NULL;

                        if (streq(optarg, "list"))
                                return pkcs11_list_tokens();

                        if (arg_enroll_type >= 0 || arg_pkcs11_token_uri)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (streq(optarg, "auto")) {
                                r = pkcs11_find_token_auto(&uri);
                                if (r < 0)
                                        return r;
                        } else {
                                if (!pkcs11_uri_valid(optarg))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid PKCS#11 URI: %s", optarg);

                                uri = strdup(optarg);
                                if (!uri)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_PKCS11;
                        arg_pkcs11_token_uri = TAKE_PTR(uri);
                        break;
                }

                case ARG_FIDO2_CRED_ALG:
                        r = parse_fido2_algorithm(optarg, &arg_fido2_cred_alg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse COSE algorithm: %s", optarg);
                        break;

                case ARG_FIDO2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return fido2_list_devices();

                        if (arg_enroll_type >= 0 || arg_fido2_device)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (!streq(optarg, "auto")) {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_FIDO2;
                        arg_fido2_device = TAKE_PTR(device);
                        break;
                }

                case ARG_TPM2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return tpm2_list_devices();

                        if (arg_enroll_type >= 0 || arg_tpm2_device)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (!streq(optarg, "auto")) {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_TPM2;
                        arg_tpm2_device = TAKE_PTR(device);
                        break;
                }

                case ARG_TPM2_DEVICE_KEY:
                        if (arg_enroll_type >= 0 || arg_tpm2_device_key)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");


                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_device_key);
                        if (r < 0)
                                return r;

                        arg_enroll_type = ENROLL_TPM2;
                        break;

                case ARG_TPM2_SEAL_KEY_HANDLE:
                        r = safe_atou32_full(optarg, 16, &arg_tpm2_seal_key_handle);
                        if (r < 0)
                                return log_error_errno(r, "Could not parse TPM2 seal key handle index '%s': %m", optarg);

                        break;

                case ARG_TPM2_PCRS:
                        auto_hash_pcr_values = false;
                        r = tpm2_parse_pcr_argument_append(optarg, &arg_tpm2_hash_pcr_values, &arg_tpm2_n_hash_pcr_values);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PUBLIC_KEY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_public_key);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PUBLIC_KEY_PCRS:
                        auto_public_key_pcr_mask = false;
                        r = tpm2_parse_pcr_argument_to_mask(optarg, &arg_tpm2_public_key_pcr_mask);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_SIGNATURE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_signature);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PCRLOCK:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_pcrlock);
                        if (r < 0)
                                return r;

                        auto_pcrlock = false;
                        break;

                case ARG_TPM2_WITH_PIN:
                        r = parse_boolean_argument("--tpm2-with-pin=", optarg, &arg_tpm2_pin);
                        if (r < 0)
                                return r;

                        break;

                case ARG_WIPE_SLOT: {
                        const char *p = optarg;

                        if (isempty(optarg)) {
                                arg_wipe_slots_mask = 0;
                                arg_wipe_slots_scope = WIPE_EXPLICIT;
                                break;
                        }

                        for (;;) {
                                _cleanup_free_ char *slot = NULL;
                                unsigned n;

                                r = extract_first_word(&p, &slot, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                                if (r == 0)
                                        break;
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse slot list: %s", optarg);

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
                                        int *a;

                                        r = safe_atou(slot, &n);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse slot index: %s", slot);
                                        if (n > INT_MAX)
                                                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Slot index out of range: %u", n);

                                        a = reallocarray(arg_wipe_slots, sizeof(int), arg_n_wipe_slots + 1);
                                        if (!a)
                                                return log_oom();

                                        arg_wipe_slots = a;
                                        arg_wipe_slots[arg_n_wipe_slots++] = (int) n;
                                }
                        }
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No block device node specified, refusing.");

        if (argc > optind+1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments, refusing.");

        r = parse_path_argument(argv[optind], false, &arg_node);
        if (r < 0)
                return r;

        if (arg_enroll_type == ENROLL_FIDO2) {

                if (arg_unlock_type == UNLOCK_FIDO2 && !(arg_fido2_device && arg_unlock_fido2_device))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "When both enrolling and unlocking with FIDO2 tokens, automatic discovery is unsupported. "
                                               "Please specify device paths for enrolling and unlocking respectively.");

                if (!arg_fido2_device) {
                        r = fido2_find_device_auto(&arg_fido2_device);
                        if (r < 0)
                                return r;
                }
        }

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

        if (auto_hash_pcr_values && !arg_tpm2_pcrlock) { /* Only lock to PCR 7 by default if no pcrlock policy is around (which is a better replacement) */
                assert(arg_tpm2_n_hash_pcr_values == 0);

                if (!GREEDY_REALLOC_APPEND(
                                    arg_tpm2_hash_pcr_values,
                                    arg_tpm2_n_hash_pcr_values,
                                    &TPM2_PCR_VALUE_MAKE(TPM2_PCR_INDEX_DEFAULT, /* hash= */ 0, /* value= */ {}),
                                    1))
                        return log_oom();
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
                        0,
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
                void **ret_volume_key,
                size_t *ret_volume_key_size) {

        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        size_t vks;
        int r;

        assert(ret_cd);
        assert(!ret_volume_key == !ret_volume_key_size);

        r = crypt_init(&cd, arg_node);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libcryptsetup context: %m");

        cryptsetup_enable_logging(cd);

        r = crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS2 superblock: %m");

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
        vks = (size_t) r;

        vk = malloc(vks);
        if (!vk)
                return log_oom();

        switch (arg_unlock_type) {

        case UNLOCK_KEYFILE:
                r = load_volume_key_keyfile(cd, vk, &vks);
                break;

        case UNLOCK_FIDO2:
                r = load_volume_key_fido2(cd, arg_node, arg_unlock_fido2_device, vk, &vks);
                break;

        case UNLOCK_PASSWORD:
                r = load_volume_key_password(cd, arg_node, vk, &vks);
                break;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown LUKS unlock method");
        }

        if (r < 0)
                return r;

        *ret_cd = TAKE_PTR(cd);
        *ret_volume_key = TAKE_PTR(vk);
        *ret_volume_key_size = vks;

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        size_t vks;
        int slot, r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        cryptsetup_enable_logging(NULL);

        if (arg_enroll_type < 0)
                r = prepare_luks(&cd, NULL, NULL); /* No need to unlock device if we don't need the volume key because we don't need to enroll anything */
        else
                r = prepare_luks(&cd, &vk, &vks);
        if (r < 0)
                return r;

        switch (arg_enroll_type) {

        case ENROLL_PASSWORD:
                slot = enroll_password(cd, vk, vks);
                break;

        case ENROLL_RECOVERY:
                slot = enroll_recovery(cd, vk, vks);
                break;

        case ENROLL_PKCS11:
                slot = enroll_pkcs11(cd, vk, vks, arg_pkcs11_token_uri);
                break;

        case ENROLL_FIDO2:
                slot = enroll_fido2(cd, vk, vks, arg_fido2_device, arg_fido2_lock_with, arg_fido2_cred_alg);
                break;

        case ENROLL_TPM2:
                slot = enroll_tpm2(cd, vk, vks, arg_tpm2_device, arg_tpm2_seal_key_handle, arg_tpm2_device_key, arg_tpm2_hash_pcr_values, arg_tpm2_n_hash_pcr_values, arg_tpm2_public_key, arg_tpm2_public_key_pcr_mask, arg_tpm2_signature, arg_tpm2_pin, arg_tpm2_pcrlock);
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

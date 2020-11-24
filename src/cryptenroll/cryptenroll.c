/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "ask-password-api.h"
#include "cryptenroll-fido2.h"
#include "cryptenroll-password.h"
#include "cryptenroll-pkcs11.h"
#include "cryptenroll-recovery.h"
#include "cryptsetup-util.h"
#include "escape.h"
#include "libfido2-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "path-util.h"
#include "pkcs11-util.h"
#include "pretty-print.h"
#include "strv.h"
#include "terminal-util.h"

typedef enum EnrollType {
        ENROLL_PASSWORD,
        ENROLL_RECOVERY,
        ENROLL_PKCS11,
        ENROLL_FIDO2,
        _ENROLL_TYPE_MAX,
        _ENROLL_TYPE_INVALID = -1,
} EnrollType;

static EnrollType arg_enroll_type = _ENROLL_TYPE_INVALID;
static char *arg_pkcs11_token_uri = NULL;
static char *arg_fido2_device = NULL;
static char *arg_tpm2_device = NULL;
static char *arg_node = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_token_uri, freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_node, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-cryptenroll", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] BLOCK-DEVICE\n"
               "\n%sEnroll a security token or authentication credential to a LUKS volume.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "     --password        Enroll a user-supplied password\n"
               "     --recovery-key    Enroll a recovery key\n"
               "     --pkcs11-token-uri=URI\n"
               "                       Specify PKCS#11 security token URI\n"
               "     --fido2-device=PATH\n"
               "                       Enroll a FIDO2-HMAC security token\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , ansi_highlight(), ansi_normal()
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_PASSWORD,
                ARG_RECOVERY_KEY,
                ARG_PKCS11_TOKEN_URI,
                ARG_FIDO2_DEVICE,
        };

        static const struct option options[] = {
                { "help",             no_argument,       NULL, 'h'                  },
                { "version",          no_argument,       NULL, ARG_VERSION          },
                { "password",         no_argument,       NULL, ARG_PASSWORD         },
                { "recovery-key",     no_argument,       NULL, ARG_RECOVERY_KEY     },
                { "pkcs11-token-uri", required_argument, NULL, ARG_PKCS11_TOKEN_URI },
                { "fido2-device",     required_argument, NULL, ARG_FIDO2_DEVICE     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

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

                case ARG_FIDO2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return fido2_list_devices();

                        if (arg_enroll_type >= 0 || arg_fido2_device)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Multiple operations specified at once, refusing.");

                        if (streq(optarg, "auto")) {
                                r = fido2_find_device_auto(&device);
                                if (r < 0)
                                        return r;
                        } else {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        arg_enroll_type = ENROLL_FIDO2;
                        arg_fido2_device = TAKE_PTR(device);
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (arg_enroll_type < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No operation specified, refusing.");

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No block device node specified, refusing.");

        if (argc > optind+1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too many arguments, refusing.");

        r = parse_path_argument_and_warn(argv[optind], false, &arg_node);
        if (r < 0)
                return r;

        return 1;
}

static int prepare_luks(
                struct crypt_device **ret_cd,
                void **ret_volume_key,
                size_t *ret_volume_key_size) {

        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        char *e = NULL;
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

        e = getenv("PASSWORD");
        if (e) {
                _cleanup_(erase_and_freep) char *password = NULL;

                password = strdup(e);
                if (!password)
                        return log_oom();

                string_erase(e);
                assert_se(unsetenv("PASSWORD") >= 0);

                r = crypt_volume_key_get(
                                cd,
                                CRYPT_ANY_SLOT,
                                vk,
                                &vks,
                                password,
                                strlen(password));
                if (r < 0)
                        return log_error_errno(r, "Password from environent variable $PASSWORD did not work.");
        } else {
                AskPasswordFlags ask_password_flags = ASK_PASSWORD_PUSH_CACHE|ASK_PASSWORD_ACCEPT_CACHED;
                _cleanup_free_ char *question = NULL, *disk_path = NULL;
                unsigned i = 5;
                const char *id;

                question = strjoin("Please enter current passphrase for disk ", arg_node, ":");
                if (!question)
                        return log_oom();

                disk_path = cescape(arg_node);
                if (!disk_path)
                        return log_oom();

                id = strjoina("cryptsetup:", disk_path);

                for (;;) {
                        _cleanup_strv_free_erase_ char **passwords = NULL;
                        char **p;

                        if (--i == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "Too many attempts, giving up:");

                        r = ask_password_auto(
                                        question, "drive-harddisk", id, "cryptenroll", USEC_INFINITY,
                                        ask_password_flags,
                                        &passwords);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query password: %m");

                        r = -EPERM;
                        STRV_FOREACH(p, passwords) {
                                r = crypt_volume_key_get(
                                                cd,
                                                CRYPT_ANY_SLOT,
                                                vk,
                                                &vks,
                                                *p,
                                                strlen(*p));
                                if (r >= 0)
                                        break;
                        }
                        if (r >= 0)
                                break;

                        log_error_errno(r, "Password not correct, please try again.");
                        ask_password_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
                }
        }

        *ret_cd = TAKE_PTR(cd);
        *ret_volume_key = TAKE_PTR(vk);
        *ret_volume_key_size = vks;

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        size_t vks;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = prepare_luks(&cd, &vk, &vks);
        if (r < 0)
                return r;

        switch (arg_enroll_type) {

        case ENROLL_PASSWORD:
                r = enroll_password(cd, vk, vks);
                break;

        case ENROLL_RECOVERY:
                r = enroll_recovery(cd, vk, vks);
                break;

        case ENROLL_PKCS11:
                r = enroll_pkcs11(cd, vk, vks, arg_pkcs11_token_uri);
                break;

        case ENROLL_FIDO2:
                r = enroll_fido2(cd, vk, vks, arg_fido2_device);
                break;

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Operation not implemented yet.");
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);

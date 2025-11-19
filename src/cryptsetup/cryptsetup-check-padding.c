/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <getopt.h>

#include "sd-json.h"
#include "cryptsetup-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "string-util.h"

static char *arg_device = NULL;
STATIC_DESTRUCTOR_REGISTER(arg_device, freep);

static int help(void) {
        printf("%s [OPTIONS...] DEVICE\n\n"
               "Check LUKS device for legacy PKCS#11 padding.\n\n"
               "  -h --help        Show this help\n"
               "     --version     Show package version\n",
               program_invocation_short_name);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",    no_argument, NULL, 'h'         },
                { "version", no_argument, NULL, ARG_VERSION },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind + 1 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                      "Expected exactly one argument (device name).");

        arg_device = strdup(argv[optind]);
        if (!arg_device)
                return log_oom();

        return 1;
}

static int check_pkcs11_padding(struct crypt_device *cd) {
        int legacy_count = 0, oaep_count = 0, r;

        assert(cd);

        for (int token = 0; token < crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                sd_json_variant *w, *alg_field;
                const char *type, *algorithm = NULL;

                r = cryptsetup_get_token_as_json(cd, token, NULL, &v);
                if (IN_SET(r, -ENOENT, -EINVAL))
                        continue;
                if (r < 0)
                        continue;

                w = sd_json_variant_by_key(v, "type");
                if (!w || !sd_json_variant_is_string(w))
                        continue;

                type = sd_json_variant_string(w);
                if (!streq(type, "systemd-pkcs11"))
                        continue;

                alg_field = sd_json_variant_by_key(v, "pkcs11-key-algorithm");
                if (alg_field) {
                        algorithm = sd_json_variant_string(alg_field);
                        if (algorithm && streq(algorithm, "rsa-oaep-sha256")) {
                                oaep_count++;
                                continue;
                        }
                }

                legacy_count++;
                log_warning("Token %i uses legacy RSA-PKCS#1 v1.5 padding (vulnerable to padding oracle attacks).", token);
        }

        if (legacy_count > 0) {
                log_warning("Found %i PKCS#11 token(s) using legacy padding on %s",
                           legacy_count, crypt_get_device_name(cd));
                log_warning("Run 'systemd-cryptenroll --migrate-to-oaep %s' to migrate to secure RSA-OAEP.",
                           crypt_get_device_name(cd));

                if (oaep_count > 0)
                        log_info("%i token(s) already use RSA-OAEP.", oaep_count);

                return 1;  /* Exit with warning status */
        }

        if (oaep_count > 0)
                log_info("All %i PKCS#11 token(s) on %s use secure RSA-OAEP padding.",
                        oaep_count, crypt_get_device_name(cd));

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        const char *device;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Support both /dev/mapper/name and name formats */
        if (startswith(arg_device, "/dev/"))
                device = arg_device;
        else {
                char *mapped;
                if (asprintf(&mapped, "/dev/mapper/%s", arg_device) < 0)
                        return log_oom();
                free(arg_device);
                arg_device = mapped;
                device = arg_device;
        }

        r = crypt_init(&cd, device);
        if (r < 0)
                return log_error_errno(r, "Failed to open LUKS device %s: %m", device);

        cryptsetup_enable_logging(cd);

        r = crypt_load(cd, CRYPT_LUKS2, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load LUKS2 header from %s: %m", device);

        return check_pkcs11_padding(cd);
}

DEFINE_MAIN_FUNCTION(run);
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "fd-util.h"
#include "main-func.h"
#include "memstream-util.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "verbs.h"

static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;
static char *arg_certificate = NULL;
static char *arg_certificate_source = NULL;
static CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;

STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-keyutil", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sPerform various operations on private keys and certificates.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  validate               Load and validate the given certificate and private key\n"
               "  public                 Extract a public key\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Print version\n"
               "     --private-key=KEY   Private key in PEM format\n"
               "     --private-key-source=file|provider:PROVIDER|engine:ENGINE\n"
               "                         Specify how to use KEY for --private-key=. Allows\n"
               "                         an OpenSSL engine/provider to be used for signing\n"
               "     --certificate=PATH|URI\n"
               "                         PEM certificate to use for signing, or a provider\n"
               "                         specific designation if --certificate-source= is used\n"
               "     --certificate-source=file|provider:PROVIDER\n"
               "                         Specify how to interpret the certificate from\n"
               "                         --certificate=. Allows the certificate to be loaded\n"
               "                         from an OpenSSL provider\n"
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
                ARG_PRIVATE_KEY,
                ARG_PRIVATE_KEY_SOURCE,
                ARG_CERTIFICATE,
                ARG_CERTIFICATE_SOURCE,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "private-key",        required_argument, NULL, ARG_PRIVATE_KEY        },
                { "private-key-source", required_argument, NULL, ARG_PRIVATE_KEY_SOURCE },
                { "certificate",        required_argument, NULL, ARG_CERTIFICATE        },
                { "certificate-source", required_argument, NULL, ARG_CERTIFICATE_SOURCE },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_PRIVATE_KEY:
                        r = free_and_strdup_warn(&arg_private_key, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        optarg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;

                        break;

                case ARG_CERTIFICATE:
                        r = free_and_strdup_warn(&arg_certificate, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        optarg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        return 1;
}

static int verb_validate(int argc, char *argv[], void *userdata) {
        _cleanup_(X509_freep) X509 *certificate = NULL;
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = NULL;
        int r;

        if (!arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No certificate specified, use --certificate=");

        if (!arg_private_key)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No private key specified, use --private-key=.");

        if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                r = parse_path_argument(arg_certificate, /*suppress_root=*/ false, &arg_certificate);
                if (r < 0)
                        return r;
        }

        r = openssl_load_x509_certificate(
                        arg_certificate_source_type,
                        arg_certificate_source,
                        arg_certificate,
                        &certificate);
        if (r < 0)
                return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);

        if (arg_private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                r = parse_path_argument(arg_private_key, /* suppress_root= */ false, &arg_private_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse private key path %s: %m", arg_private_key);
        }

        r = openssl_load_private_key(
                        arg_private_key_source_type,
                        arg_private_key_source,
                        arg_private_key,
                        &(AskPasswordRequest) {
                                .tty_fd = -EBADF,
                                .id = "keyutil-private-key-pin",
                                .keyring = arg_private_key,
                                .credential = "keyutil.private-key-pin",
                                .until = USEC_INFINITY,
                                .hup_fd = -EBADF,
                        },
                        &private_key,
                        &ui);
        if (r < 0)
                return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);

        puts("OK");
        return 0;
}

static int verb_public(int argc, char *argv[], void *userdata) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *public_key = NULL;
        int r;

        if (arg_certificate) {
                _cleanup_(X509_freep) X509 *certificate = NULL;

                if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                        r = parse_path_argument(arg_certificate, /*suppress_root=*/ false, &arg_certificate);
                        if (r < 0)
                                return r;
                }

                r = openssl_load_x509_certificate(
                                arg_certificate_source_type,
                                arg_certificate_source,
                                arg_certificate,
                                &certificate);
                if (r < 0)
                        return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);

                public_key = X509_get_pubkey(certificate);
                if (!public_key)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EIO),
                                        "Failed to extract public key from certificate %s.",
                                        arg_certificate);

        } else if (arg_private_key) {
                _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
                _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = NULL;

                if (arg_private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                        r = parse_path_argument(arg_private_key, /* suppress_root= */ false, &arg_private_key);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse private key path %s: %m", arg_private_key);
                }

                r = openssl_load_private_key(
                                arg_private_key_source_type,
                                arg_private_key_source,
                                arg_private_key,
                                &(AskPasswordRequest) {
                                        .tty_fd = -EBADF,
                                        .id = "keyutil-private-key-pin",
                                        .keyring = arg_private_key,
                                        .credential = "keyutil.private-key-pin",
                                        .until = USEC_INFINITY,
                                        .hup_fd = -EBADF,
                                },
                                &private_key,
                                &ui);
                if (r < 0)
                        return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);

                _cleanup_(memstream_done) MemStream m = {};
                FILE *tf = memstream_init(&m);
                if (!tf)
                        return log_oom();

                if (i2d_PUBKEY_fp(tf, private_key) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to extract public key from private key file '%s'.", arg_private_key);

                fflush(tf);
                rewind(tf);

                if (!d2i_PUBKEY_fp(tf, &public_key))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to parse extracted public key of private key file '%s'.", arg_private_key);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "One of --certificate=, or --private-key= must be specified");

        if (PEM_write_PUBKEY(stdout, public_key) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write public key to stdout");

        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",     VERB_ANY, VERB_ANY, 0, help          },
                { "validate", VERB_ANY, 1,        0, verb_validate },
                { "public",   VERB_ANY, 1,        0, verb_public   },
                {}
        };
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "memstream-util.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "verbs.h"

static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;
static char *arg_certificate = NULL;
static char *arg_certificate_source = NULL;
static CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;
static char *arg_signature = NULL;
static char *arg_content = NULL;
static char *arg_hash_algorithm = NULL;
static char *arg_output = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_signature, freep);
STATIC_DESTRUCTOR_REGISTER(arg_content, freep);
STATIC_DESTRUCTOR_REGISTER(arg_output, freep);

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
               "  pkcs7                  Generate a PKCS#7 signature\n"
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
               "     --content=PATH      Raw data content to embed in PKCS#7 signature\n"
               "     --signature=PATH    PKCS#1 signature to embed in PKCS#7 signature\n"
               "     --hash-algorithm=ALGORITHM\n"
               "                         Hash algorithm used to create the PKCS#1 signature\n"
               "     --output=PATH       Where to write the PKCS#7 signature\n"
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
                ARG_SIGNATURE,
                ARG_CONTENT,
                ARG_HASH_ALGORITHM,
                ARG_OUTPUT,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "private-key",        required_argument, NULL, ARG_PRIVATE_KEY        },
                { "private-key-source", required_argument, NULL, ARG_PRIVATE_KEY_SOURCE },
                { "certificate",        required_argument, NULL, ARG_CERTIFICATE        },
                { "certificate-source", required_argument, NULL, ARG_CERTIFICATE_SOURCE },
                { "signature",          required_argument, NULL, ARG_SIGNATURE          },
                { "content",            required_argument, NULL, ARG_CONTENT            },
                { "hash-algorithm",     required_argument, NULL, ARG_HASH_ALGORITHM     },
                { "output",             required_argument, NULL, ARG_OUTPUT             },
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

                case ARG_SIGNATURE:
                        r = parse_path_argument(optarg, /*suppress_root=*/ false, &arg_signature);
                        if (r < 0)
                                return r;

                        break;

                case ARG_CONTENT:
                        r = parse_path_argument(optarg, /*suppress_root=*/ false, &arg_content);
                        if (r < 0)
                                return r;

                        break;

                case ARG_HASH_ALGORITHM:
                        arg_hash_algorithm = optarg;
                        break;

                case ARG_OUTPUT:
                        r = parse_path_argument(optarg, /*suppress_root=*/ false, &arg_output);
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

static int verb_pkcs7(int argc, char *argv[], void *userdata) {
        _cleanup_(X509_freep) X509 *certificate = NULL;
        _cleanup_free_ char *pkcs1 = NULL;
        size_t pkcs1_len = 0;
        int r;

        if (!arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--certificate= must be specified");

        if (!arg_signature)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--signature= must be specified");

        if (!arg_output)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--output= must be specified");

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

        r = read_full_file(arg_signature, &pkcs1, &pkcs1_len);
        if (r < 0)
                return log_error_errno(r, "Failed to read PKCS#1 file %s: %m", arg_signature);
        if (pkcs1_len == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "PKCS#1 file %s is empty", arg_signature);

        _cleanup_(PKCS7_freep) PKCS7 *pkcs7 = NULL;
        PKCS7_SIGNER_INFO *signer_info;
        r = pkcs7_new(certificate, /* private_key= */ NULL, arg_hash_algorithm, &pkcs7, &signer_info);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate PKCS#7 context: %m");

        if (arg_content) {
                _cleanup_free_ char *content = NULL;
                size_t content_len = 0;

                r = read_full_file(arg_content, &content, &content_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to read content file %s: %m", arg_content);
                if (content_len == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Content file %s is empty", arg_content);

                if (!PKCS7_content_new(pkcs7, NID_pkcs7_data))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Error creating new PKCS7 content field");

                ASN1_STRING_set0(pkcs7->d.sign->contents->d.data, TAKE_PTR(content), content_len);
        } else
                if (PKCS7_set_detached(pkcs7, true) == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to set PKCS#7 detached attribute: %s",
                                               ERR_error_string(ERR_get_error(), NULL));

        /* Add PKCS1 signature to PKCS7_SIGNER_INFO */
        ASN1_STRING_set0(signer_info->enc_digest, TAKE_PTR(pkcs1), pkcs1_len);

        _cleanup_fclose_ FILE *output = NULL;
        _cleanup_(unlink_and_freep) char *tmp = NULL;
        r = fopen_tmpfile_linkable(arg_output, O_WRONLY|O_CLOEXEC, &tmp, &output);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary file: %m");

        if (!i2d_PKCS7_fp(output, pkcs7))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write PKCS#7 file: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        r = flink_tmpfile(output, tmp, arg_output, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to link temporary file to %s: %m", arg_output);

        tmp = mfree(tmp);

        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",     VERB_ANY, VERB_ANY, 0, help          },
                { "validate", VERB_ANY, 1,        0, verb_validate },
                { "public",   VERB_ANY, 1,        0, verb_public   },
                { "pkcs7",    VERB_ANY, VERB_ANY, 0, verb_pkcs7    },
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

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "crypto-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
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
static const char *arg_hash_algorithm = NULL;
static char *arg_output = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_signature, freep);
STATIC_DESTRUCTOR_REGISTER(arg_content, freep);
STATIC_DESTRUCTOR_REGISTER(arg_output, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = terminal_urlify_man("systemd-keyutil", "1", &link);
        if (r < 0)
                return log_oom();

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s  [OPTIONS...] COMMAND ...\n\n"
               "%sPerform various operations on private keys and certificates.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_PRIVATE_KEY("Private key in PEM format"):
                        r = free_and_strdup_warn(&arg_private_key, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        opts.arg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE("PEM certificate to use for signing"):
                        r = free_and_strdup_warn(&arg_certificate, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        opts.arg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("signature", "PATH", "PKCS#1 signature to embed in PKCS#7 signature"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_signature);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("content", "PATH", "Raw data content to embed in PKCS#7 signature"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_content);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("hash-algorithm", "ALGORITHM",
                            "Hash algorithm used to create the PKCS#1 signature"):
                        arg_hash_algorithm = opts.arg;
                        break;

                OPTION_LONG("output", "PATH", "Where to write the PKCS#7 signature"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_output);
                        if (r < 0)
                                return r;
                        break;
                }

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

VERB_NOARG(verb_validate, "validate",
           "Load and validate the given certificate and private key");
static int verb_validate(int argc, char *argv[], uintptr_t _data, void *userdata) {
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
                r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
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
                        return r;
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

VERB_NOARG(verb_extract_public, "extract-public",
           "Extract a public key");
VERB_NOARG(verb_extract_public, "public", /* help= */ NULL); /* Deprecated but kept for backward compat. */
static int verb_extract_public(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *public_key = NULL;
        int r;

        if (arg_certificate) {
                _cleanup_(X509_freep) X509 *certificate = NULL;

                if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                        r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
                        if (r < 0)
                                return r;
                }

                r = dlopen_libcrypto(LOG_ERR);
                if (r < 0)
                        return r;

                r = openssl_load_x509_certificate(
                                arg_certificate_source_type,
                                arg_certificate_source,
                                arg_certificate,
                                &certificate);
                if (r < 0)
                        return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);

                public_key = sym_X509_get_pubkey(certificate);
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
                                return r;
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

                r = openssl_extract_public_key(private_key, &public_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract public key from private key file '%s': %m", arg_private_key);
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "One of --certificate=, or --private-key= must be specified");

        if (sym_PEM_write_PUBKEY(stdout, public_key) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write public key to stdout");

        return 0;
}

VERB_NOARG(verb_extract_certificate, "extract-certificate",
           "Extract a certificate");
static int verb_extract_certificate(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(X509_freep) X509 *certificate = NULL;
        int r;

        if (!arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--certificate= must be specified.");

        if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
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

        if (sym_PEM_write_X509(stdout, certificate) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write certificate to stdout.");

        return 0;
}

VERB(verb_pkcs7, "pkcs7", NULL, VERB_ANY, VERB_ANY, 0,
     "Generate a PKCS#7 signature");
static int verb_pkcs7(int argc, char *argv[], uintptr_t _data, void *userdata) {
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
                r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
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

                if (!sym_PKCS7_content_new(pkcs7, NID_pkcs7_data))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Error creating new PKCS7 content field");

                sym_ASN1_STRING_set0(pkcs7->d.sign->contents->d.data, TAKE_PTR(content), content_len);
        } else
                if (sym_PKCS7_set_detached(pkcs7, true) == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to set PKCS#7 detached attribute: %s",
                                               sym_ERR_error_string(sym_ERR_get_error(), NULL));

        /* Add PKCS1 signature to PKCS7_SIGNER_INFO */
        sym_ASN1_STRING_set0(signer_info->enc_digest, TAKE_PTR(pkcs1), pkcs1_len);

        _cleanup_fclose_ FILE *output = NULL;
        _cleanup_(unlink_and_freep) char *tmp = NULL;
        r = fopen_tmpfile_linkable(arg_output, O_WRONLY|O_CLOEXEC, &tmp, &output);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary file: %m");

        if (!sym_i2d_PKCS7_fp(output, pkcs7))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write PKCS#7 file: %s",
                                       sym_ERR_error_string(sym_ERR_get_error(), NULL));

        r = flink_tmpfile(output, tmp, arg_output, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to link temporary file to %s: %m", arg_output);

        tmp = mfree(tmp);

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);

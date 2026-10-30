/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "authenticode.h"
#include "build.h"
#include "copy.h"
#include "crypto-util.h"
#include "data-fd-util.h"
#include "dlopen-note.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pe-binary.h"
#include "pe-writer.h"
#include "string-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "verbs.h"

static char *arg_output = NULL;
static char *arg_certificate = NULL;
static CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;
static char *arg_certificate_source = NULL;
static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;
static bool arg_prepare_offline_signing = false;
static char *arg_signed_data = NULL;
static char *arg_signed_data_signature = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_output, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_signed_data, freep);
STATIC_DESTRUCTOR_REGISTER(arg_signed_data_signature, freep);

COMMAND(
        "systemd-sbsign\0",
        "Sign PE binaries for EFI Secure Boot.",
        .man_pages = "systemd-sbsign(1)\0",
);

VERB_COMMON_HELP_AUTO_HIDDEN();

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("output", "PATH",
                            "Where to write the signed PE binary"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_output);
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

                OPTION_COMMON_PRIVATE_KEY("Private key (PEM) to sign with"):
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

                OPTION_LONG("prepare-offline-signing", NULL, /* help= */ NULL):
                        arg_prepare_offline_signing = true;
                        break;

                OPTION_LONG("signed-data", "PATH", /* help= */ NULL):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_signed_data);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("signed-data-signature", "PATH", /* help= */ NULL):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_signed_data_signature);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        if (!!arg_signed_data != !!arg_signed_data_signature)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--signed-data= and --signed-data-signature= must always be used together.");

        if (arg_prepare_offline_signing && (arg_private_key || arg_signed_data || arg_signed_data_signature))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--prepare-offline-signing cannot be used with --private-key=, --signed-data= or --signed-data-signature=");

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

VERB(verb_sign, "sign", "EXEFILE\0", 2, 2, 0,
     "Sign the given binary for EFI Secure Boot");
static int verb_sign(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = NULL;
        _cleanup_(X509_freep) X509 *certificate = NULL;
        _cleanup_(x509_attribute_free_manyp) STACK_OF(X509_ATTRIBUTE) *signed_attributes = NULL;
        _cleanup_(iovec_done) struct iovec signed_attributes_signature = {};
        int r;

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        if (argc < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No input file specified");

        if (!arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No certificate specified, use --certificate=");

        if (!arg_private_key && !arg_signed_data_signature && !arg_prepare_offline_signing)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No private key or signed data signature specified, use --private-key= or --signed-data-signature=.");

        if (!arg_output)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No output specified, use --output=");

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

        if (arg_private_key) {
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
                                        .id = "sbsign-private-key-pin",
                                        .keyring = arg_private_key,
                                        .credential = "sbsign.private-key-pin",
                                        .until = USEC_INFINITY,
                                        .hup_fd = -EBADF,
                                },
                                &private_key,
                                &ui);
                if (r < 0)
                        return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);
        }

        if (arg_signed_data) {
                _cleanup_free_ void *content = NULL;
                size_t contentsz;

                r = read_full_file(arg_signed_data, (char**) &content, &contentsz);
                if (r < 0)
                        return log_error_errno(r, "Failed to read signed attributes file '%s': %m", arg_signed_data);

                const uint8_t *p = content;
                if (!sym_ASN1_item_d2i((ASN1_VALUE **) &signed_attributes, &p, contentsz, sym_PKCS7_ATTR_SIGN_it()))
                        return log_openssl_errors(LOG_ERR, "Failed to parse signed attributes");
        }

        if (arg_signed_data_signature) {
                _cleanup_free_ void *content = NULL;
                size_t contentsz;

                r = read_full_file(arg_signed_data_signature, (char**) &content, &contentsz);
                if (r < 0)
                        return log_error_errno(r, "Failed to read signed attributes signature file '%s': %m", arg_signed_data_signature);

                signed_attributes_signature = IOVEC_MAKE(TAKE_PTR(content), contentsz);
        }

        _cleanup_close_ int srcfd = open_seekable_data_fd(AT_FDCWD, argv[1], PE_IMAGE_SIZE_MAX);
        if (srcfd < 0)
                return log_error_errno(srcfd, "Failed to open %s: %m", argv[1]);

        _cleanup_(unlink_and_freep) char *tmp = NULL;
        _cleanup_close_ int dstfd = open_tmpfile_linkable(arg_output, O_RDWR|O_CLOEXEC, &tmp);
        if (dstfd < 0)
                return log_error_errno(dstfd, "Failed to open temporary file: %m");

        r = fchmod_umask(dstfd, 0666);
        if (r < 0)
                log_debug_errno(r, "Failed to change temporary file mode: %m");

        _cleanup_free_ void *pehash = NULL;
        size_t pehashsz;
        r = pe_hash(srcfd, sym_EVP_sha256(), &pehash, &pehashsz);
        if (r < 0)
                return log_error_errno(r, "Failed to hash PE binary %s: %m", argv[1]);

        _cleanup_free_ uint8_t *idcraw = NULL;
        size_t idcrawsz = 0; /* avoid false maybe-uninitialized warning */
        r = authenticode_spc_indirect_data_content_new(pehash, pehashsz, &idcraw, &idcrawsz);
        if (r < 0)
                return log_error_errno(r, "Failed to create SpcIndirectDataContent: %m");

        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        PKCS7_SIGNER_INFO *si = NULL; /* avoid false maybe-uninitialized warning */
        r = authenticode_pkcs7_new(certificate, private_key, signed_attributes, &p7, &si);
        if (r < 0)
                return log_error_errno(r, "Failed to create PKCS#7 signing context: %m");

        TAKE_PTR(signed_attributes);

        if (arg_prepare_offline_signing) {
                _cleanup_(BIO_free_allp) BIO *bio = NULL;
                r = authenticode_pkcs7_data_bio(p7, idcraw, idcrawsz, &bio);
                if (r < 0)
                        return log_error_errno(r, "Failed to populate PKCS#7 data: %m");

                r = authenticode_pkcs7_add_digest_attribute(bio, si);
                if (r < 0)
                        return log_error_errno(r, "Failed to add digest attribute: %m");

                _cleanup_free_ unsigned char *abuf = NULL;
                int alen = sym_ASN1_item_i2d((ASN1_VALUE *)si->auth_attr, &abuf, sym_PKCS7_ATTR_SIGN_it());
                if (alen < 0 || !abuf)
                        return log_openssl_errors(LOG_ERR, "Failed to convert signed attributes ASN.1 to DER");

                r = loop_write(dstfd, abuf, alen);
                if (r < 0)
                        return log_error_errno(r, "Failed to write PKCS#7 DER-encoded signed attributes blob to temporary file: %m");

                r = link_tmpfile(dstfd, tmp, arg_output, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
                if (r < 0)
                        return log_error_errno(r, "Failed to link temporary file to %s: %m", arg_output);

                log_info("Wrote PKCS#7 DER-encoded signed attributes blob to %s", arg_output);
                return 0;
        }

        if (iovec_is_set(&signed_attributes_signature))
                sym_ASN1_STRING_set0(si->enc_digest, TAKE_PTR(signed_attributes_signature.iov_base), signed_attributes_signature.iov_len);
        else {
                _cleanup_(BIO_free_allp) BIO *bio = NULL;
                r = authenticode_pkcs7_data_bio(p7, idcraw, idcrawsz, &bio);
                if (r < 0)
                        return log_error_errno(r, "Failed to populate PKCS#7 data: %m");

                if (sym_PKCS7_dataFinal(p7, bio) == 0)
                        return log_openssl_errors(LOG_ERR, "Failed to sign data");
        }

        _cleanup_free_ uint8_t *sig = NULL;
        size_t sigsz;
        r = authenticode_pkcs7_finalize(p7, idcraw, idcrawsz, &sig, &sigsz);
        if (r < 0)
                return log_error_errno(r, "Failed to finalize PKCS#7 signature: %m");

        r = copy_bytes(srcfd, dstfd, UINT64_MAX, /* copy_flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to copy %s to %s: %m", argv[1], tmp);

        r = pe_append_signature(dstfd, sig, sigsz);
        if (r < 0)
                return log_error_errno(r, "Failed to append signature to %s: %m", arg_output);

        r = link_tmpfile(dstfd, tmp, arg_output, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to link temporary file to %s: %m", arg_output);

        log_info("Wrote signed PE binary to %s", arg_output);
        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBCRYPTO_NOTE(required);

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);

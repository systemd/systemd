/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "authenticode.h"
#include "build.h"
#include "copy.h"
#include "efi-fundamental.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "install-file.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "openssl-util.h"
#include "options.h"
#include "parse-argument.h"
#include "pe-binary.h"
#include "pretty-print.h"
#include "stat-util.h"
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

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = terminal_urlify_man("systemd-sbsign", "1", &link);
        if (r < 0)
                return log_oom();

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] COMMAND ...\n"
               "\n%sSign binaries for EFI Secure Boot%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(), ansi_normal(),
               ansi_underline(), ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n", ansi_underline(), ansi_normal());
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

        OptionParser state = { argc, argv };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("output", "PATH",
                            "Where to write the signed PE binary"):
                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_output);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_CERTIFICATE("PEM certificate to use for signing"):
                        r = free_and_strdup_warn(&arg_certificate, arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        arg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_PRIVATE_KEY("Private key (PEM) to sign with"):
                        r = free_and_strdup_warn(&arg_private_key, arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        arg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("prepare-offline-signing", NULL, /* help= */ NULL):
                        arg_prepare_offline_signing = true;
                        break;

                OPTION_LONG("signed-data", "PATH", /* help= */ NULL):
                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_signed_data);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("signed-data-signature", "PATH", /* help= */ NULL):
                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_signed_data_signature);
                        if (r < 0)
                                return r;

                        break;
                }

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        if (!!arg_signed_data != !!arg_signed_data_signature)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--signed-data= and --signed-data-signature= must always be used together.");

        if (arg_prepare_offline_signing && (arg_private_key || arg_signed_data || arg_signed_data_signature))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--prepare-offline-signing cannot be used with --private-key=, --signed-data= or --signed-data-signature=");

        *ret_args = option_parser_get_args(&state);
        return 1;
}

static int spc_indirect_data_content_new(const void *digest, size_t digestsz, uint8_t **ret_idc, size_t *ret_idcsz) {
        assert(digest);
        assert(ret_idc);
        assert(ret_idcsz);

        /* This function allocates and populates a new SpcIndirectDataContent object. See the authenticode
         * spec https://aka.ms/AuthenticodeSpec for more information on the individual fields. */

        /* <<<Obsolete>>> in unicode bytes. */
        static const uint8_t obsolete[] = {
                0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f,
                0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c,
                0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3e,
                0x00, 0x3e, 0x00, 0x3e
        };

        _cleanup_(SpcLink_freep) SpcLink *link = SpcLink_new();
        if (!link)
                return log_oom();

        link->type = 2;
        link->value.file = SpcString_new();
        if (!link->value.file)
                return log_oom();

        link->value.file->type = 0;
        link->value.file->value.unicode = ASN1_BMPSTRING_new();
        if (!link->value.file->value.unicode)
                return log_oom();

        if (ASN1_STRING_set(link->value.file->value.unicode, obsolete, sizeof(obsolete)) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set ASN1 string: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_(SpcPeImageData_freep) SpcPeImageData *peid = SpcPeImageData_new();
        if (!peid)
                return log_oom();

        peid->file = TAKE_PTR(link);

        _cleanup_free_ uint8_t *peidraw = NULL;
        int peidrawsz = i2d_SpcPeImageData(peid, &peidraw);
        if (peidrawsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert SpcPeImageData to BER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_(SpcIndirectDataContent_freep) SpcIndirectDataContent *idc = SpcIndirectDataContent_new();
        idc->data->value = ASN1_TYPE_new();
        if (!idc->data->value)
                return log_oom();

        idc->data->value->type = V_ASN1_SEQUENCE;
        idc->data->value->value.sequence = ASN1_STRING_new();
        if (!idc->data->value->value.sequence)
                return log_oom();

        idc->data->type = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, /* no_name= */ 1);
        if (!idc->data->type)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get SpcPeImageData object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (!ASN1_STRING_set(idc->data->value->value.sequence, peidraw, peidrawsz))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set ASN1_STRING data.");

        idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(NID_sha256);
        if (!idc->messageDigest->digestAlgorithm->algorithm)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get SHA256 object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
        if (!idc->messageDigest->digestAlgorithm->parameters)
                return log_oom();

        idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

        if (ASN1_OCTET_STRING_set(idc->messageDigest->digest, digest, digestsz) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set digest: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_free_ uint8_t *idcraw = NULL;
        int idcrawsz = i2d_SpcIndirectDataContent(idc, &idcraw);
        if (idcrawsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert SpcIndirectDataContent to BER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        *ret_idc = TAKE_PTR(idcraw);
        *ret_idcsz = (size_t) idcrawsz;

        return 0;
}

static int asn1_timestamp(ASN1_TIME **ret) {
        ASN1_TIME *time;

        assert(ret);

        usec_t epoch = parse_source_date_epoch();

        if (epoch == USEC_INFINITY) {
                time = X509_gmtime_adj(NULL, 0);
                if (!time)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get current time: %s",
                                               ERR_error_string(ERR_get_error(), NULL));
        } else {
                time = ASN1_TIME_set(NULL, (time_t) (epoch / USEC_PER_SEC));
                if (!time)
                        return log_oom();
        }

        *ret = TAKE_PTR(time);

        return 0;
}

static int pkcs7_new_with_attributes(
                X509 *certificate,
                EVP_PKEY *private_key,
                const char *hash_algorithm,
                STACK_OF(X509_ATTRIBUTE) *signed_attributes,
                PKCS7 **ret_p7,
                PKCS7_SIGNER_INFO **ret_si) {

        int r;

        /* This function sets up a new PKCS#7 signing context with the signed attributes required for
         * authenticode signing. */

        assert(certificate);
        assert(ret_p7);
        assert(ret_si);

        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        PKCS7_SIGNER_INFO *si = NULL; /* avoid false maybe-uninitialized warning */
        r = pkcs7_new(certificate, private_key, hash_algorithm, &p7, &si);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate PKCS# context: %m");

        if (signed_attributes) {
                si->auth_attr = signed_attributes;

                *ret_p7 = TAKE_PTR(p7);
                *ret_si = TAKE_PTR(si);
                return 0;
        }

        /* Add an empty SMIMECAP attribute to indicate we don't have any SMIME capabilities. */
        _cleanup_(x509_algor_free_manyp) STACK_OF(X509_ALGOR) *smcap = sk_X509_ALGOR_new_null();
        if (!smcap)
                return log_oom();

        if (PKCS7_add_attrib_smimecap(si, smcap) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to add smimecap signed attribute to signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (PKCS7_add_attrib_content_type(si, NULL) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to add content type signed attribute to signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_(ASN1_TIME_freep) ASN1_TIME *time = NULL;
        r = asn1_timestamp(&time);
        if (r < 0)
                return r;

        if (PKCS7_add0_attrib_signing_time(si, time) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to add signing time signed attribute to signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        TAKE_PTR(time);

        ASN1_OBJECT *idc = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, /* no_name= */ true);
        if (!idc)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get SpcIndirectDataContent object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, idc) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to add signed attribute to pkcs7 signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        *ret_p7 = TAKE_PTR(p7);
        *ret_si = TAKE_PTR(si);
        return 0;
}

static int pkcs7_populate_data_bio(PKCS7* p7, const void *data, size_t size, BIO **ret) {
        assert(ret);

        _cleanup_(BIO_free_allp) BIO *bio = PKCS7_dataInit(p7, NULL);
        if (!bio)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to create PKCS7 data bio: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        int tag, class;
        long psz;
        const uint8_t *p = data;

        /* This function weirdly enough reports errors by setting the 0x80 bit in its return value. */
        if (ASN1_get_object(&p, &psz, &tag, &class, size) & 0x80)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse ASN.1 object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (BIO_write(bio, p, psz) < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write to PKCS7 data bio: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        *ret = TAKE_PTR(bio);

        return 0;
}

static int pkcs7_add_digest_attribute(PKCS7 *p7, BIO *data, PKCS7_SIGNER_INFO *si) {
        assert(p7);
        assert(data);
        assert(si);

        BIO *mdbio = BIO_find_type(data, BIO_TYPE_MD);
        if (!mdbio)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to find digest bio: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        EVP_MD_CTX *mdc;
        if (BIO_get_md_ctx(mdbio, &mdc) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get digest context from bio: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned digestsz;

        if (EVP_DigestFinal_ex(mdc, digest, &digestsz) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get digest: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (PKCS7_add1_attrib_digest(si, digest, digestsz) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to add PKCS9 message digest signed attribute to signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        return 0;
}

VERB(verb_sign, "sign", "EXEFILE", 2, 2, 0,
     "Sign the given binary for EFI Secure Boot");
static int verb_sign(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = NULL;
        _cleanup_(X509_freep) X509 *certificate = NULL;
        _cleanup_(x509_attribute_free_manyp) STACK_OF(X509_ATTRIBUTE) *signed_attributes = NULL;
        _cleanup_(iovec_done) struct iovec signed_attributes_signature = {};
        int r;

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
                                return log_error_errno(r, "Failed to parse private key path %s: %m", arg_private_key);
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
                if (!ASN1_item_d2i((ASN1_VALUE **) &signed_attributes, &p, contentsz, ASN1_ITEM_rptr(PKCS7_ATTR_SIGN)))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse signed attributes: %s",
                                               ERR_error_string(ERR_get_error(), NULL));
        }

        if (arg_signed_data_signature) {
                _cleanup_free_ void *content = NULL;
                size_t contentsz;

                r = read_full_file(arg_signed_data_signature, (char**) &content, &contentsz);
                if (r < 0)
                        return log_error_errno(r, "Failed to read signed attributes signature file '%s': %m", arg_signed_data_signature);

                signed_attributes_signature = IOVEC_MAKE(TAKE_PTR(content), contentsz);
        }

        _cleanup_close_ int srcfd = open(argv[1], O_RDONLY|O_CLOEXEC);
        if (srcfd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", argv[1]);

        struct stat st;
        if (fstat(srcfd, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", argv[1]);

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "%s is not a regular file: %m", argv[1]);

        _cleanup_(unlink_and_freep) char *tmp = NULL;
        _cleanup_close_ int dstfd = open_tmpfile_linkable(arg_output, O_RDWR|O_CLOEXEC, &tmp);
        if (dstfd < 0)
                return log_error_errno(dstfd, "Failed to open temporary file: %m");

        r = fchmod_umask(dstfd, 0666);
        if (r < 0)
                log_debug_errno(r, "Failed to change temporary file mode: %m");

        _cleanup_free_ void *pehash = NULL;
        size_t pehashsz;
        r = pe_hash(srcfd, EVP_sha256(), &pehash, &pehashsz);
        if (r < 0)
                return log_error_errno(r, "Failed to hash PE binary %s: %m", argv[0]);

        _cleanup_free_ uint8_t *idcraw = NULL;
        size_t idcrawsz = 0; /* avoid false maybe-uninitialized warning */
        r = spc_indirect_data_content_new(pehash, pehashsz, &idcraw, &idcrawsz);
        if (r < 0)
                return r;

        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        PKCS7_SIGNER_INFO *si = NULL; /* avoid false maybe-uninitialized warning */
        r = pkcs7_new_with_attributes(certificate, private_key, /* hash_algorithm= */ NULL, signed_attributes, &p7, &si);
        if (r < 0)
                return r;

        TAKE_PTR(signed_attributes);

        if (arg_prepare_offline_signing) {
                _cleanup_(BIO_free_allp) BIO *bio = NULL;
                r = pkcs7_populate_data_bio(p7, idcraw, idcrawsz, &bio);
                if (r < 0)
                        return r;

                r = pkcs7_add_digest_attribute(p7, bio, si);
                if (r < 0)
                        return r;

                _cleanup_free_ unsigned char *abuf = NULL;
                int alen = ASN1_item_i2d((ASN1_VALUE *)si->auth_attr, &abuf, ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
                if (alen < 0 || !abuf)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert signed attributes ASN.1 to DER: %s",
                                               ERR_error_string(ERR_get_error(), NULL));

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
                ASN1_STRING_set0(si->enc_digest, TAKE_PTR(signed_attributes_signature.iov_base), signed_attributes_signature.iov_len);
        else {
                _cleanup_(BIO_free_allp) BIO *bio = NULL;
                r = pkcs7_populate_data_bio(p7, idcraw, idcrawsz, &bio);
                if (r < 0)
                        return r;

                if (PKCS7_dataFinal(p7, bio) == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to sign data: %s",
                                               ERR_error_string(ERR_get_error(), NULL));
        }

        _cleanup_(PKCS7_freep) PKCS7 *p7c = PKCS7_new();
        if (!p7c)
                return log_oom();

        p7c->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, /* no_name= */ true);
        if (!p7c->type)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get SpcIndirectDataContent object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        p7c->d.other = ASN1_TYPE_new();
        if (!p7c->d.other)
                return log_oom();

        p7c->d.other->type = V_ASN1_SEQUENCE;
        p7c->d.other->value.sequence = ASN1_STRING_new();
        if (!p7c->d.other->value.sequence)
                return log_oom();

        if (ASN1_STRING_set(p7c->d.other->value.sequence, idcraw, idcrawsz) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set ASN1 string: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (PKCS7_set_content(p7, p7c) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set PKCS7 data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        TAKE_PTR(p7c);

        _cleanup_free_ uint8_t *sig = NULL;
        int sigsz = i2d_PKCS7(p7, &sig);
        if (sigsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert PKCS7 signature to DER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        r = pe_load_headers(srcfd, &dos_header, &pe_header);
        if (r < 0)
                return log_error_errno(r, "Failed to load headers from PE file: %m");

        const IMAGE_DATA_DIRECTORY *certificate_table;
        certificate_table = pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        if (!certificate_table)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks certificate table.");

        r = copy_bytes(srcfd, dstfd, UINT64_MAX, COPY_REFLINK);
        if (r < 0)
                return log_error_errno(r, "Failed to copy %s to %s: %m", argv[1], tmp);

        off_t end = st.st_size;
        ssize_t n;

        if (st.st_size % 8 != 0) {
                if (certificate_table->VirtualAddress != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Certificate table is not aligned to 8 bytes");

                n = pwrite(dstfd, (const uint8_t[8]) {}, 8 - (st.st_size % 8), st.st_size);
                if (n < 0)
                        return log_error_errno(errno, "Failed to write zero padding: %m");
                if (n != 8 - (st.st_size % 8))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing zero padding.");

                end += n;
        }

        uint32_t certsz = sizeof(WIN_CERTIFICATE_HEADER) + sigsz;
        n = pwrite(dstfd,
                   &(WIN_CERTIFICATE_HEADER) {
                           .wRevision = htole16(0x200),
                           .wCertificateType = htole16(0x0002), /* PKCS7 signedData */
                           .dwLength = htole32(ROUND_UP(certsz, 8)),
                   },
                   sizeof(WIN_CERTIFICATE_HEADER),
                   end);
        if (n < 0)
                return log_error_errno(errno, "Failed to write certificate header: %m");
        if (n != sizeof(WIN_CERTIFICATE_HEADER))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing certificate header.");

        end += n;

        n = pwrite(dstfd, sig, sigsz, end);
        if (n < 0)
                return log_error_errno(errno, "Failed to write signature: %m");
        if (n != sigsz)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing signature.");

        end += n;

        if (certsz % 8 != 0) {
                n = pwrite(dstfd, (const uint8_t[8]) {}, 8 - (certsz % 8), end);
                if (n < 0)
                        return log_error_errno(errno, "Failed to write zero padding: %m");
                if ((size_t) n != 8 - (certsz % 8))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing zero padding.");
        }

        n = pwrite(dstfd,
                   &(IMAGE_DATA_DIRECTORY) {
                           .VirtualAddress = certificate_table->VirtualAddress ?: htole32(ROUND_UP(st.st_size, 8)),
                           .Size = htole32(le32toh(certificate_table->Size) + ROUND_UP(certsz, 8)),
                   },
                   sizeof(IMAGE_DATA_DIRECTORY),
                   le32toh(dos_header->e_lfanew) + PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory[IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE]));
        if (n < 0)
                return log_error_errno(errno, "Failed to update PE certificate table: %m");
        if ((size_t) n != sizeof(IMAGE_DATA_DIRECTORY))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while updating PE certificate table.");

        uint32_t checksum;
        r = pe_checksum(dstfd, &checksum);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate PE file checksum: %m");

        n = pwrite(dstfd,
                   &(le32_t) { htole32(checksum) },
                   sizeof(le32_t),
                   le32toh(dos_header->e_lfanew) + offsetof(PeHeader, optional.CheckSum));
        if (n < 0)
                return log_error_errno(errno, "Failed to update PE checksum: %m");
        if ((size_t) n != sizeof(le32_t))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while updating PE checksum.");

        r = link_tmpfile(dstfd, tmp, arg_output, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return log_error_errno(r, "Failed to link temporary file to %s: %m", arg_output);

        log_info("Wrote signed PE binary to %s", arg_output);
        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);

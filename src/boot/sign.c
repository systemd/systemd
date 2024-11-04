/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <openssl/asn1t.h>

#include "log.h"
#include "main-func.h"
#include "ansi-color.h"
#include "pretty-print.h"
#include "build.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "verbs.h"
#include "fd-util.h"
#include "pe-binary.h"
#include "io-util.h"
#include "efi-fundamental.h"
#include "hexdecoct.h"

#define SPC_INDIRECT_DATA_OBJID "1.3.6.1.4.1.311.2.1.4"
#define SPC_PE_IMAGE_DATA_OBJID "1.3.6.1.4.1.311.2.1.15"

static PagerFlags arg_pager_flags = 0;
static char *arg_certificate = NULL;
static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);

typedef struct {
    ASN1_OBJECT *type;
    ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue);

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
    ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
    ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue);

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue);

typedef struct {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier);

ASN1_SEQUENCE(AlgorithmIdentifier) = {
    ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
    ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier);

typedef struct {
    AlgorithmIdentifier *digestAlgorithm;
    ASN1_OCTET_STRING *digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo);

ASN1_SEQUENCE(DigestInfo) = {
    ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
    ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo);

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo);

typedef struct {
    SpcAttributeTypeAndOptionalValue *data;
    DigestInfo *messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent);

ASN1_SEQUENCE(SpcIndirectDataContent) = {
    ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
    ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent);

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcIndirectDataContent*, SpcIndirectDataContent_free, NULL);

typedef struct {
    int type;
    union {
        ASN1_BMPSTRING *unicode;
        ASN1_IA5STRING *ascii;
    } value;
} SpcString;

DECLARE_ASN1_FUNCTIONS(SpcString);

ASN1_CHOICE(SpcString) = {
    ASN1_IMP_OPT(SpcString, value.unicode, ASN1_BMPSTRING, 0),
    ASN1_IMP_OPT(SpcString, value.ascii, ASN1_IA5STRING, 1)
} ASN1_CHOICE_END(SpcString);

IMPLEMENT_ASN1_FUNCTIONS(SpcString);

typedef struct {
    ASN1_OCTET_STRING *classId;
    ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

DECLARE_ASN1_FUNCTIONS(SpcSerializedObject);

ASN1_SEQUENCE(SpcSerializedObject) = {
    ASN1_SIMPLE(SpcSerializedObject, classId, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject);

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject);

typedef struct {
    int type;
    union {
        ASN1_IA5STRING *url;
        SpcSerializedObject *moniker;
        SpcString *file;
    } value;
} SpcLink;

DECLARE_ASN1_FUNCTIONS(SpcLink);

ASN1_CHOICE(SpcLink) = {
    ASN1_IMP_OPT(SpcLink, value.url, ASN1_IA5STRING, 0),
    ASN1_IMP_OPT(SpcLink, value.moniker, SpcSerializedObject, 1),
    ASN1_EXP_OPT(SpcLink, value.file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink);

IMPLEMENT_ASN1_FUNCTIONS(SpcLink);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcLink*, SpcLink_free, NULL);

typedef struct {
    ASN1_BIT_STRING *flags;
    SpcLink *file;
} SpcPeImageData;

DECLARE_ASN1_FUNCTIONS(SpcPeImageData);

ASN1_SEQUENCE(SpcPeImageData) = {
    ASN1_SIMPLE(SpcPeImageData, flags, ASN1_BIT_STRING),
    ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(SpcPeImageData*, SpcPeImageData_free, NULL);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ASN1_TYPE*, ASN1_TYPE_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ASN1_STRING*, ASN1_STRING_free, NULL);

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sbsign", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sSign binaries for secure boot%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  sign                   Calculate and sign expected PCR values\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Print version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --certificate=PATH  PEM certificate to use when signing with a URI\n"
               "     --private-key=KEY   Private key (PEM) to sign with\n"
               "     --private-key-source=file|provider:PROVIDER|engine:ENGINE\n"
               "                         Specify how to use KEY for --private-key=. Allows\n"
               "                         an OpenSSL engine/provider to be used for signing\n"
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
                ARG_NO_PAGER,
                ARG_CERTIFICATE,
                ARG_PRIVATE_KEY,
                ARG_PRIVATE_KEY_SOURCE,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "no-pager",           no_argument,       NULL, ARG_NO_PAGER           },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "certificate",        required_argument, NULL, ARG_CERTIFICATE        },
                { "private-key",        required_argument, NULL, ARG_PRIVATE_KEY        },
                { "private-key-source", required_argument, NULL, ARG_PRIVATE_KEY_SOURCE },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hjc", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_CERTIFICATE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_certificate);
                        if (r < 0)
                                return r;

                        break;

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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        return 1;
}

static int verb_sign(int argc, char *argv[], void *userdata) {
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *privkey = NULL, *pubkey = NULL;
        _cleanup_(X509_freep) X509 *certificate = NULL;
        int r;

        if (argc < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No input file specified");

        if (!arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No certificate specified, use --certificate=");

        if (!arg_private_key)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No private key specified, use --private-key=.");

        r = openssl_load_x509_certificate(arg_certificate, &certificate);
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
                                .id = "sbsign-private-key-pin",
                                .keyring = arg_private_key,
                                .credential = "sbsign.private-key-pin",
                        },
                        &privkey,
                        &ui);
        if (r < 0)
                return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);

        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        p7 = PKCS7_sign(certificate, privkey, /*certs=*/ NULL, /*data=*/ NULL, PKCS7_BINARY|PKCS7_PARTIAL);
        if (!p7)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate pkcs7 signing context: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        STACK_OF(PKCS7_SIGNER_INFO) *si_stack = PKCS7_get_signer_info(p7);
        if (!si_stack)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get pkcs7 signer info stack: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(si_stack, 0);
        if (!si)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get pkcs7 signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        int idcnid = OBJ_create("1.3.6.1.4.1.311.2.1.4", "spcIndirectDataContext", "Indirect Data Context");

        if (PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(idcnid)) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to add signed attribute to pkcs7 signer info: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_close_ int fd = open(argv[1], O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", argv[1]);

        _cleanup_free_ void *hash = NULL;
        size_t hashsz;
        r = pe_hash(fd, EVP_sha256(), &hash, &hashsz);
        if (r < 0)
                return log_error_errno(r, "Failed to hash PE binary %s: %m", argv[0]);

        static const u_char obsolete[] = {
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

        if (ASN1_BIT_STRING_set_bit(peid->flags, 0, 1) == 0)
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

        idc->data->type = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1);
        if (!idc->data->type)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get SpcPeImageData object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        idc->data->value->value.sequence->data = TAKE_PTR(peidraw);
        idc->data->value->value.sequence->length = peidrawsz;
        idc->messageDigest->digestAlgorithm->algorithm = OBJ_nid2obj(NID_sha256);
        if (!idc->messageDigest->digestAlgorithm->algorithm)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get SHA256 object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        idc->messageDigest->digestAlgorithm->parameters = ASN1_TYPE_new();
        if (!idc->messageDigest->digestAlgorithm->parameters)
                return log_oom();

        idc->messageDigest->digestAlgorithm->parameters->type = V_ASN1_NULL;

        if (ASN1_OCTET_STRING_set(idc->messageDigest->digest, hash, hashsz) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set digest: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_free_ uint8_t *idcraw = NULL;
        int idcrawsz = i2d_SpcIndirectDataContent(idc, &idcraw);
        if (idcrawsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert SpcIndirectDataContent to BER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_(BIO_freep) BIO *bio = PKCS7_dataInit(p7, NULL);
        if (!bio)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to create PKCS7 data bio: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (BIO_write(bio, idcraw + 2, idcrawsz - 2) < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write to PKCS7 data bio: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (PKCS7_final(p7, bio, PKCS7_BINARY) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to sign data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_(ASN1_TYPE_freep) ASN1_TYPE *t = ASN1_TYPE_new();
        if (!t)
                return log_oom();

        _cleanup_(ASN1_STRING_freep) ASN1_STRING *s = ASN1_STRING_new();
        if (!s)
                return log_oom();

        if (ASN1_STRING_set(s, idcraw, idcrawsz) == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set ASN1 string: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        ASN1_TYPE_set(t, V_ASN1_SEQUENCE, TAKE_PTR(s));
        PKCS7_set0_type_other(p7->d.sign->contents, idcnid, TAKE_PTR(t));

        _cleanup_free_ uint8_t *sig = NULL;
        int sigsz = i2d_PKCS7(p7, &sig);
        if (sigsz < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to convert PKCS7 signature to DER: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return log_error_errno(r, "Failed to load headers from PE file: %m");

        const IMAGE_DATA_DIRECTORY *certificate_table;
        certificate_table = pe_header_get_data_directory(pe_header, IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE);
        if (!certificate_table)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "File lacks certificate table.");

        off_t end = lseek(fd, 0, SEEK_END);
        if (end < 0)
                return log_error_errno(errno, "Failed to seek to end of file: %m");

        if (end % 8 != 0) {
                if (certificate_table->VirtualAddress != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Certificate table is not aligned to 8 bytes");

                r = loop_write(fd, (const uint8_t[8]) {}, 8 - (end % 8));
                if (r < 0)
                        return log_error_errno(r, "Failed to write zero padding: %m");
        }

        uint32_t certsz = offsetof(WIN_CERTIFICATE, bCertificate) + sigsz;
        r = loop_write(fd,
                       &(WIN_CERTIFICATE) {
                                .wRevision = htole16(0x200),
                                .wCertificateType = htole16(0x0002), /* PKCS7 signedData */
                                .dwLength = htole32(ROUND_UP(certsz, 8)),
                       },
                       sizeof(WIN_CERTIFICATE));
        if (r < 0)
                return log_error_errno(r, "Failed to write certificate header: %m");

        r = loop_write(fd, sig, sigsz);
        if (r < 0)
                return log_error_errno(r, "Failed to append signature: %m");

        if (certsz % 8 != 0) {
                r = loop_write(fd, (const uint8_t[8]) {}, 8 - (certsz % 8));
                if (r < 0)
                        return log_error_errno(r, "Failed to write zero padding: %m");
        }

        ssize_t n = pwrite(fd,
                           &(IMAGE_DATA_DIRECTORY) {
                                .VirtualAddress = certificate_table->VirtualAddress ?: htole32(ROUND_UP(end, 8)),
                                .Size = htole32(le32toh(certificate_table->Size) + ROUND_UP(certsz, 8)),
                           },
                           sizeof(IMAGE_DATA_DIRECTORY),
                           le32toh(dos_header->e_lfanew) + PE_HEADER_OPTIONAL_FIELD_OFFSET(pe_header, DataDirectory[IMAGE_DATA_DIRECTORY_INDEX_CERTIFICATION_TABLE]));
        if (n < 0)
                return log_error_errno(errno, "Failed to update PE certificate table: %m");
        if ((size_t) n != sizeof(IMAGE_DATA_DIRECTORY))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while updating PE certificate table.");

        if (lseek(fd, SEEK_SET, 0) < 0)
                return log_error_errno(errno, "Failed to reset to beginning of file: %m");

        uint32_t checksum;
        r = pe_checksum(fd, &checksum);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate PE file checksum: %m");

        n = pwrite(fd,
                   &(le32_t) { htole32(checksum) },
                   sizeof(le32_t),
                   le32toh(dos_header->e_lfanew) + offsetof(PeHeader, optional.CheckSum));
        if (n < 0)
                return log_error_errno(errno, "Failed to update PE checksum: %m");
        if ((size_t) n != sizeof(le32_t))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while updating PE checksum.");

        log_info("Added secure boot signature to %s", argv[1]);
        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",      VERB_ANY, VERB_ANY, 0,    help       },
                { "sign",      2,        2,        0,    verb_sign  },
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

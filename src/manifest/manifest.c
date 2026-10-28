/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-json.h"

#include "ansi-color.h"
#include "ask-password-api.h"
#include "build.h"
#include "crypto-util.h"
#include "dlopen-note.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "manifest-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "uapi16-manifest.h"
#include "verbs.h"
#include "voa-util.h"

static ManifestFormat arg_format = _MANIFEST_FORMAT_INVALID;
static ManifestField arg_fields = _MANIFEST_FIELD_DEFAULT;
static ManifestHash arg_hash = _MANIFEST_HASH_INVALID;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;
static char *arg_certificate = NULL;
static char *arg_certificate_source = NULL;
static CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;
static bool arg_graceful = false;
static int arg_verify = -1;
static char *arg_voa_context = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_voa_context, freep);

COMMAND(
        "systemd-manifest\0",
        "Generate and verify file manifests of directory trees.",
        .man_pages = "systemd-manifest(1)\0",
        .pager_flags = &arg_pager_flags,
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

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("format", "FORMAT", "Manifest format (list, sha256sums, mtree, uapi16)"):
                        arg_format = manifest_format_from_string(opts.arg);
                        if (arg_format < 0)
                                return log_error_errno(arg_format, "Unknown manifest format: %s", opts.arg);
                        break;

                OPTION_LONG("field", "FIELDS", "Fields to include (mode, uid, gid, size, hash, symlink, device, hardlink, mtime, user-xattr, all, default, none, or +/- prefixed to adjust)"):
                        r = manifest_fields_from_string(opts.arg, &arg_fields);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse field list: %s", opts.arg);
                        break;

                OPTION_LONG("hash", "ALGORITHM", "Hash algorithm to use for mtree manifests (sha256, sha512)"):
                        arg_hash = manifest_hash_from_string(opts.arg);
                        if (arg_hash < 0)
                                return log_error_errno(arg_hash, "Unknown hash algorithm: %s", opts.arg);
                        break;

                OPTION_LONG("graceful", NULL, "Don't fail if inodes had to be skipped or metadata omitted"):
                        arg_graceful = true;
                        break;

                OPTION_COMMON_PRIVATE_KEY("Private key to sign the manifest with (if not specified, it is not signed)"):
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

                OPTION_COMMON_CERTIFICATE("Certificate to sign with, or to verify the signature against"):
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

                OPTION_LONG("verify", "BOOL", "Verify the manifest signature (default: yes)"):
                        r = parse_boolean_argument("--verify=", opts.arg, /* ret= */ NULL);
                        if (r < 0)
                                return r;
                        arg_verify = r;
                        break;

                OPTION_LONG("voa-context", "CONTEXT", "VOA context to look up certificates in (default: default)"):
                        if (!voa_identifier_is_valid(opts.arg, /* allow_colon= */ false))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid VOA context: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_voa_context, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        if (arg_private_key && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key=, --certificate= must be specified.");

        if (arg_verify == 0 && arg_voa_context)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--voa-context= has no effect with --verify=no.");

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

#if HAVE_OPENSSL
static int load_certificate(X509 **ret) {
        int r;

        assert(ret);

        if (!arg_certificate) {
                *ret = NULL;
                return 0;
        }

        if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
                if (r < 0)
                        return r;
        }

        r = openssl_load_x509_certificate(
                        arg_certificate_source_type,
                        arg_certificate_source,
                        arg_certificate,
                        ret);
        if (r < 0)
                return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);

        return 1;
}

static int load_private_key(EVP_PKEY **ret, OpenSSLAskPasswordUI **ret_ui) {
        int r;

        assert(ret);
        assert(ret_ui);

        if (!arg_private_key) {
                *ret = NULL;
                *ret_ui = NULL;
                return 0;
        }

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
                                .id = "manifest-private-key-pin",
                                .keyring = arg_private_key,
                                .credential = "manifest.private-key-pin",
                                .until = USEC_INFINITY,
                                .hup_fd = -EBADF,
                        },
                        ret,
                        ret_ui);
        if (r < 0)
                return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);

        return 1;
}
#endif

static int open_directory(const char *path) {
        int fd;

        /* Opens the specified directory, or the current directory if none is specified */

        fd = open(path ?: ".", O_DIRECTORY|O_CLOEXEC|O_RDONLY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open directory '%s': %m", path ?: ".");

        return fd;
}

static void context_from_args(ManifestContext *c) {
        assert(c);

        *c = MANIFEST_CONTEXT_NULL;
        c->format = arg_format;
        c->fields = arg_fields;
        c->hash = arg_hash >= 0 ? arg_hash : MANIFEST_HASH_SHA256;
        c->json_format_flags = arg_json_format_flags;
        c->color = colors_enabled();
}

VERB(verb_make, "make", "[DIRECTORY [MANIFEST]]\0", 1, 3, 0, "Generate a manifest of a directory tree");
static int verb_make(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_close_ int dfd = open_directory(argc > 1 ? argv[1] : NULL);
        if (dfd < 0)
                return dfd;

        const char *manifest = argc > 2 && !streq(argv[2], "-") ? argv[2] : NULL;

        if (arg_format < 0)
                arg_format = MANIFEST_FORMAT_UAPI16;

        /* UAPI.16 is always JSON, hence default to a good JSON mode. We turn on color, but not pretty
         * alignment, so that each file is in one row */
        if (arg_format == MANIFEST_FORMAT_UAPI16 &&
            FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF))
                arg_json_format_flags = SD_JSON_FORMAT_COLOR_AUTO;

        /* We sign if a private key is specified, and only then. A certificate on its own is hence most likely
         * a mistake, refuse it rather than silently generating an unsigned manifest. */
        if (arg_certificate && !arg_private_key)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--certificate= specified without --private-key=, refusing to generate unsigned manifest.");

        _cleanup_(manifest_context_done) ManifestContext c;
        context_from_args(&c);

#if HAVE_OPENSSL
        _cleanup_(X509_freep) X509 *certificate = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *private_key = NULL;
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;

        if (arg_private_key) {
                r = load_certificate(&certificate);
                if (r < 0)
                        return r;

                r = load_private_key(&private_key, &ui);
                if (r < 0)
                        return r;

                c.certificate = certificate;
                c.private_key = private_key;
        }
#else
        if (arg_private_key)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Signing not supported, OpenSSL support disabled.");
#endif

        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        if (manifest) {
                r = fopen_tmpfile_linkable(manifest, O_WRONLY|O_CLOEXEC, &t, &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to create '%s': %m", manifest);

                c.output = f;
                c.color = false;
        } else
                pager_open(arg_pager_flags);

        r = manifest_make(&c, dfd);
        if (r < 0)
                return r;

        /* Even in graceful mode, insist that the top-level inode is covered, after all a manifest that
         * doesn't even cover that is useless. */
        if (!c.top_level_covered)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Top-level inode not covered by manifest, refusing.");

        int level = arg_graceful ? LOG_WARNING : LOG_ERR;
        if (c.n_skipped > 0)
                log_full(level, "%" PRIu64 " entries skipped, as they could not be read or were not representable in the manifest.", c.n_skipped);
        if (c.n_metadata_omitted > 0)
                log_full(level, "%" PRIu64 " metadata fields omitted, as they could not be read or were not representable in the manifest.", c.n_metadata_omitted);
        if (!arg_graceful && (c.n_skipped > 0 || c.n_metadata_omitted > 0))
                return -EUCLEAN;

        if (manifest) {
                r = flink_tmpfile(f, t, manifest, LINK_TMPFILE_REPLACE);
                if (r < 0)
                        return log_error_errno(r, "Failed to move '%s' into place: %m", manifest);

                t = mfree(t); /* disarm auto delete */
        }

        return 0;
}

static int guess_format(const char *path) {
        int r;

        if (!path)
                return _MANIFEST_FORMAT_INVALID;

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;

        if (streq(fn, "SHA256SUMS") || startswith(fn, "SHA256SUMS."))
                return MANIFEST_FORMAT_SHA256SUMS;

        if (uapi16_manifest_filename_is_reserved(fn) || uapi16_manifest_filename_is_suffixed(fn))
                return MANIFEST_FORMAT_UAPI16;

        if (endswith(fn, ".mtree"))
                return MANIFEST_FORMAT_MTREE;

        return _MANIFEST_FORMAT_INVALID;
}

VERB(verb_verify, "verify", "[DIRECTORY [MANIFEST]]\0", 1, 3, 0, "Verify a directory tree against a manifest");
static int verb_verify(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_close_ int dfd = open_directory(argc > 1 ? argv[1] : NULL);
        if (dfd < 0)
                return dfd;

        const char *manifest = argc > 2 && !streq(argv[2], "-") ? argv[2] : NULL;

        /* If the format is not specified explicitly, guess it from the file name, and otherwise default to
         * UAPI.16, like on "make". */
        if (arg_format < 0) {
                arg_format = guess_format(manifest);
                if (arg_format < 0)
                        arg_format = MANIFEST_FORMAT_UAPI16;
        }

        /* Only UAPI.16 manifests carry signatures. These are verified by default, either against the
         * certificate specified explicitly, or against the ones found in the VOA hierarchy. */
        bool verify;
        if (arg_format == MANIFEST_FORMAT_UAPI16)
                verify = arg_verify != 0;
        else {
                if (arg_verify > 0 || arg_certificate || arg_voa_context)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Signature verification is only supported for UAPI.16 manifests.");
                verify = false;
        }

        if (!verify && arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--certificate= has no effect with --verify=no.");
        if (arg_certificate && arg_voa_context)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--certificate= and --voa-context= are mutually exclusive.");

        _cleanup_(manifest_context_done) ManifestContext c;
        context_from_args(&c);

        X509 **certificates = NULL;
        size_t n_certificates = 0;
        CLEANUP_ARRAY(certificates, n_certificates, uapi16_certificates_free);

        if (verify) {
                if (arg_certificate) {
#if HAVE_OPENSSL
                        _cleanup_(X509_freep) X509 *certificate = NULL;
                        r = load_certificate(&certificate);
                        if (r < 0)
                                return r;

                        certificates = new(X509*, 1);
                        if (!certificates)
                                return log_oom();

                        certificates[n_certificates++] = TAKE_PTR(certificate);
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Signature verification not supported, OpenSSL support disabled.");
#endif
                } else {
                        const char *context = arg_voa_context ?: "default";

                        r = uapi16_load_voa_certificates(XAT_FDROOT, context, &certificates, &n_certificates);
                        if (r < 0)
                                return r;
                        if (n_certificates == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                                       "No certificates for verifying UAPI.16 manifests found in the VOA hierarchy (role '%s', context '%s'), refusing. Use --certificate= or --verify=no.",
                                                       UAPI16_VOA_ROLE, context);
                }

                c.certificates = certificates;
                c.n_certificates = n_certificates;
        }

        _cleanup_fclose_ FILE *f = NULL;
        if (manifest) {
                f = fopen(manifest, "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open manifest file '%s': %m", manifest);
        } else {
                r = fdopen_independent(STDIN_FILENO, "re", &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to open standard input: %m");
        }

        return manifest_verify(&c, dfd, f);
}

static int run(int argc, char *argv[]) {
        int r;

        LIBCRYPTO_NOTE(suggested);

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);

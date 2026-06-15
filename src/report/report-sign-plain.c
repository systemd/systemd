/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "crypto-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "help-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "lock-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "stat-util.h"
#include "tmpfile-util.h"
#include "varlink-io.systemd.Report.Sign.h"
#include "varlink-util.h"

#define REPORT_SIGN_PLAIN_DIR         "/var/lib/systemd/report.sign.plain"
#define REPORT_SIGN_PLAIN_PRIVATE_KEY "local.private"
#define REPORT_SIGN_PLAIN_PUBLIC_KEY  "local.public"

static int load_key(int dir_fd, EVP_PKEY **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        int r;

        assert(dir_fd >= 0);
        assert(ret);

        r = xfopenat(dir_fd, REPORT_SIGN_PLAIN_PRIVATE_KEY, "re", /* open_flags= */ 0, &f);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open private key file '%s/%s': %m",
                                       REPORT_SIGN_PLAIN_DIR, REPORT_SIGN_PLAIN_PRIVATE_KEY);

        if (fstat(fileno(f), &st) < 0)
                return log_error_errno(errno, "Failed to stat private key file: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "Private key file is not a regular file: %m");

        if (st.st_uid != 0 || (st.st_mode & 0077) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Private key file '%s/%s' is accessible by more than the root user, refusing.",
                                       REPORT_SIGN_PLAIN_DIR, REPORT_SIGN_PLAIN_PRIVATE_KEY);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = sym_PEM_read_PrivateKey(f, /* x= */ NULL, /* cb= */ NULL, /* u= */ NULL);
        if (!pkey)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to load private key from '%s/%s'.",
                                       REPORT_SIGN_PLAIN_DIR, REPORT_SIGN_PLAIN_PRIVATE_KEY);

        log_debug("Successfully loaded private key from '%s/%s'.", REPORT_SIGN_PLAIN_DIR, REPORT_SIGN_PLAIN_PRIVATE_KEY);

        *ret = TAKE_PTR(pkey);
        return 1;
}

static int write_key_file(int dir_fd, EVP_PKEY *pkey, bool private_key, const char *name, mode_t mode) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *temp = NULL;
        int r;

        assert(dir_fd >= 0);
        assert(pkey);
        assert(name);

        r = fopen_temporary_at(dir_fd, name, &f, &temp);
        if (r < 0)
                return log_error_errno(r, "Failed to open key file '%s/%s' for writing: %m", REPORT_SIGN_PLAIN_DIR, name);

        CLEANUP_TMPFILE_AT(dir_fd, temp);

        if (private_key)
                r = sym_PEM_write_PrivateKey(f, pkey, /* enc= */ NULL, /* kstr= */ NULL, /* klen= */ 0, /* cb= */ NULL, /* u= */ NULL);
        else
                r = sym_PEM_write_PUBKEY(f, pkey);
        if (r <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write %s key.", private_key ? "private" : "public");

        if (fchmod(fileno(f), mode) < 0)
                return log_error_errno(errno, "Failed to adjust key file access mode: %m");

        r = fflush_sync_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write key file: %m");

        f = safe_fclose(f);

        /* Never overwrite an existing private key: we must not destroy it. The public key is derived from the
         * private one and carries no secret, hence may be refreshed unconditionally. */
        if (private_key)
                r = rename_noreplace(dir_fd, temp, dir_fd, name);
        else
                r = RET_NERRNO(renameat(dir_fd, temp, dir_fd, name));
        if (r < 0) {
                if (private_key && r == -EEXIST)
                        return log_error_errno(r, "Private key file '%s/%s' appeared while generating a new one, refusing to overwrite it.",
                                               REPORT_SIGN_PLAIN_DIR, name);

                return log_error_errno(r, "Faialed to move key file '%s/%s' into place: %m", REPORT_SIGN_PLAIN_DIR, name);
        }

        return 0;
}

static int generate_key(int dir_fd, EVP_PKEY **ret) {
        int r;

        assert(dir_fd >= 0);
        assert(ret);

        /* Generate a new Ed25519 key pair. */

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = sym_EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, /* e= */ NULL);
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate Ed25519 key generation context.");

        if (sym_EVP_PKEY_keygen_init(ctx) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize Ed25519 key generation context.");

        log_info("Generating Ed25519 key pair for signing reports.");

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (sym_EVP_PKEY_keygen(ctx, &pkey) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate Ed25519 key pair.");

        log_info("Successfully generated Ed25519 key pair.");

        /* Write out the private key (PKCS#8 PEM; this includes the public key too), readable by root only. */
        r = write_key_file(dir_fd, pkey, /* private_key= */ true, REPORT_SIGN_PLAIN_PRIVATE_KEY, 0400);
        if (r < 0)
                return r;

        /* Write out the public key too, as a convenience for verification, world readable. */
        r = write_key_file(dir_fd, pkey, /* private_key= */ false, REPORT_SIGN_PLAIN_PUBLIC_KEY, 0444);
        if (r < 0)
                return r;

        r = RET_NERRNO(fsync(dir_fd));
        if (r < 0)
                return log_error_errno(r, "Failed to sync directory '%s': %m", REPORT_SIGN_PLAIN_DIR);

        *ret = TAKE_PTR(pkey);
        return 1;
}

static int acquire_key(EVP_PKEY **ret) {
        int r;

        assert(ret);

        /* Open (creating if necessary) and exclusively lock the key directory, so that loading/generating the
         * key is safe against parallel invocations (we are spawned once per connection). The directory is
         * created with mode 0700, so that nobody else can pre-create it with looser permissions. */
        _cleanup_close_ int dir_fd = xopenat_lock_full(
                        AT_FDCWD,
                        REPORT_SIGN_PLAIN_DIR,
                        O_CLOEXEC|O_DIRECTORY|O_CREAT,
                        /* xopen_flags= */ 0,
                        /* mode= */ 0700,
                        LOCK_BSD,
                        LOCK_EX);
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to open and lock directory '%s': %m", REPORT_SIGN_PLAIN_DIR);

        /* First try to load the key off disk. If loading fails for any reason other than the key not
         * existing yet (e.g. it is malformed or has bad permissions) we propagate the error and refuse to
         * touch the existing file. Only if the key is genuinely missing do we generate a fresh one. */
        r = load_key(dir_fd, ret);
        if (r != 0)
                return r;

        return generate_key(dir_fd, ret);
}

static int vl_method_sign(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",    SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec, 0, SD_JSON_MANDATORY },
                { "algorithm", SD_JSON_VARIANT_STRING, NULL,                      0, SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(iovec_done) struct iovec digest = {};
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &digest);
        if (r != 0)
                return r;

        if (!iovec_is_set(&digest))
                return sd_varlink_error_invalid_parameter_name(link, "digest");

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        r = acquire_key(&pkey);
        if (r < 0)
                return r;

        /* Sign the provided digest directly. We pass a NULL message digest algorithm, which for a suitable
         * signing algorithm such as Ed25519 means the input bytes are signed as-is, without hashing them
         * first. The caller already passes us a digest, hence we must not hash it again. */
        _cleanup_(iovec_done) struct iovec signature = {};
        r = digest_and_sign(/* md= */ NULL, pkey, digest.iov_base, digest.iov_len, &signature.iov_base, &signature.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to sign digest: %m");

        _cleanup_free_ char *pubkey = NULL;
        r = openssl_pubkey_to_pem(pkey, &pubkey);
        if (r < 0)
                return log_error_errno(r, "Failed to extract public key: %m");

        /* Return a single signature object, carrying the raw Ed25519 (EdDSA) signature and the public key it
         * was made with, in PEM form. */
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "data",
                                        SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_OBJECT(
                                                                        JSON_BUILD_PAIR_IOVEC_BASE64("signature", &signature),
                                                                        SD_JSON_BUILD_PAIR_STRING("key", pubkey)))));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = DLOPEN_LIBCRYPTO(LOG_ERR, SD_ELF_NOTE_DLOPEN_PRIORITY_REQUIRED);
        if (r < 0)
                return r;

        r = varlink_server_new(&vs, /* flags= */ 0, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Report_Sign);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(vs, "io.systemd.Report.Sign.Sign", vl_method_sign);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(vs);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("[OPTIONS...]");
        help_abstract("Sign system reports with a local software key.");
        help_section("Options");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-report-sign-plain@.service", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program can only run as a Varlink service.");
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);

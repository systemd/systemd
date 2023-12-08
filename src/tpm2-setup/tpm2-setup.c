/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "build.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "tpm2-util.h"

static char *arg_tpm2_device = NULL;
static bool arg_early = false;

STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);

#define TPM2_SRK_PEM_PERSISTENT_PATH "/var/lib/systemd/tpm2-srk-public-key.pem"
#define TPM2_SRK_PEM_RUNTIME_PATH "/run/systemd/tpm2-srk-public-key.pem"

#define TPM2_SRK_TPM2B_PUBLIC_PERSISTENT_PATH "/var/lib/systemd/tpm2-srk-public-key.tpm2b_public"
#define TPM2_SRK_TPM2B_PUBLIC_RUNTIME_PATH "/run/systemd/tpm2-srk-public-key.tpm2b_public"

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-tpm2-setup", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n"
               "\n%5$sSet up the TPM2 Storage Root Key (SRK).%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --tpm2-device=PATH\n"
               "                          Pick TPM2 device\n"
               "     --early=BOOL         Store SRK public key in /run/ rather than /var/lib/\n"
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
                ARG_TPM2_DEVICE,
                ARG_EARLY,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, ARG_VERSION     },
                { "tpm2-device", required_argument, NULL, ARG_TPM2_DEVICE },
                { "early",       required_argument, NULL, ARG_EARLY       },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_TPM2_DEVICE:
                        if (streq(optarg, "list"))
                                return tpm2_list_devices();

                        if (free_and_strdup(&arg_tpm2_device, streq(optarg, "auto") ? NULL : optarg) < 0)
                                return log_oom();

                        break;

                case ARG_EARLY:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --early= argument: %s", optarg);

                        arg_early = r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects no argument.");

        return 1;
}

struct public_key_data {
        EVP_PKEY *pkey;         /* as OpenSSL object */
        TPM2B_PUBLIC *public;   /* in TPM2 format */
        void *fingerprint;
        size_t fingerprint_size;
        char *fingerprint_hex;
        char *path;
};

static void public_key_data_done(struct public_key_data *d) {
        assert(d);

        if (d->pkey) {
                EVP_PKEY_free(d->pkey);
                d->pkey = NULL;
        }
        if (d->public) {
                Esys_Freep(&d->public);
                d->public = NULL;
        }
        d->fingerprint = mfree(d->fingerprint);
        d->fingerprint_size = 0;
        d->fingerprint_hex = mfree(d->fingerprint_hex);
        d->path = mfree(d->path);
}

static int public_key_make_fingerprint(struct public_key_data *d) {
        int r;

        assert(d);
        assert(d->pkey);
        assert(!d->fingerprint);
        assert(!d->fingerprint_hex);

        r = pubkey_fingerprint(d->pkey, EVP_sha256(), &d->fingerprint, &d->fingerprint_size);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate fingerprint of public key: %m");

        d->fingerprint_hex = hexmem(d->fingerprint, d->fingerprint_size);
        if (!d->fingerprint_hex)
                return log_oom();

        return 0;
}

static int load_public_key_disk(const char *path, struct public_key_data *ret) {
        _cleanup_(public_key_data_done) struct public_key_data data = {};
        _cleanup_free_ char *blob = NULL;
        size_t blob_size;
        int r;

        assert(path);
        assert(ret);

        r = read_full_file(path, &blob, &blob_size);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to read '%s': %m", path);

                log_debug("SRK public key file '%s' does not exist.", path);
        } else {
                log_debug("Loaded SRK public key from '%s'.", path);

                r = openssl_pkey_from_pem(blob, blob_size, &data.pkey);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse SRK public key file '%s': %m", path);

                r = public_key_make_fingerprint(&data);
                if (r < 0)
                        return r;

                log_debug("Loaded SRK public key fingerprint: %s", data.fingerprint_hex);
        }

        data.path = strdup(path);
        if (!data.path)
                return log_oom();

        *ret = data;
        data = (struct public_key_data) {};

        return 0;
}

static int load_public_key_tpm2(struct public_key_data *ret) {
        _cleanup_(public_key_data_done) struct public_key_data data = {};
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        assert(ret);

        r = tpm2_context_new(arg_tpm2_device, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to create TPM2 context: %m");

        r = tpm2_get_or_create_srk(
                        c,
                        /* session= */ NULL,
                        &data.public,
                        /* ret_name= */ NULL,
                        /* ret_qname= */ NULL,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to get or create SRK: %m");
        if (r > 0)
                log_info("New SRK generated and stored in the TPM.");
        else
                log_info("SRK already stored in the TPM.");

        r = tpm2_tpm2b_public_to_openssl_pkey(data.public, &data.pkey);
        if (r < 0)
                return log_error_errno(r, "Failed to convert TPM2 SRK public key to OpenSSL public key: %m");

        r = public_key_make_fingerprint(&data);
        if (r < 0)
                return r;

        log_info("SRK fingerprint is %s.", data.fingerprint_hex);

        *ret = data;
        data = (struct public_key_data) {};

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        _cleanup_(public_key_data_done) struct public_key_data runtime_key = {}, persistent_key = {}, tpm2_key = {};

        r = load_public_key_disk(TPM2_SRK_PEM_RUNTIME_PATH, &runtime_key);
        if (r < 0)
                return r;

        if (!arg_early) {
                r = load_public_key_disk(TPM2_SRK_PEM_PERSISTENT_PATH, &persistent_key);
                if (r < 0)
                        return r;

                if (runtime_key.pkey && persistent_key.pkey &&
                    memcmp_nn(runtime_key.fingerprint, runtime_key.fingerprint_size,
                              persistent_key.fingerprint, persistent_key.fingerprint_size) != 0) {

                        /* One of those days we might want to add a stricter policy option here, that refuses
                         * to boot when the SRK changes. For now, let's just warn and proceed, in order not
                         * to break OS images that are moved around PCs. */

                        log_notice("Saved persistent SRK (%s) and runtime SRK differ (fingerprint %s vs. %s), updating persistent SRK.",
                                   persistent_key.path, persistent_key.fingerprint_hex, runtime_key.fingerprint_hex);

                        public_key_data_done(&persistent_key);
                }
        }

        r = load_public_key_tpm2(&tpm2_key);
        if (r < 0)
                return r;

        assert(tpm2_key.pkey);

        if (runtime_key.pkey) {
                if (memcmp_nn(tpm2_key.fingerprint, tpm2_key.fingerprint_size,
                             runtime_key.fingerprint, runtime_key.fingerprint_size) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Saved runtime SRK differs from TPM SRK, refusing.");

                if (arg_early) {
                        log_info("SRK saved in '%s' matches SRK in TPM2.", runtime_key.path);
                        return 0;
                }
        }

        if (persistent_key.pkey) {
                if (memcmp_nn(tpm2_key.fingerprint, tpm2_key.fingerprint_size,
                              persistent_key.fingerprint, persistent_key.fingerprint_size) == 0) {
                        log_info("SRK saved in '%s' matches SRK in TPM2.", persistent_key.path);
                        return 0;
                }

                /* As above, we probably want a stricter policy option here, one day. */

                log_notice("Saved persistent SRK (%s) and TPM SRK differ (fingerprint %s vs. %s), updating persistent SRK.",
                           persistent_key.path, persistent_key.fingerprint_hex, tpm2_key.fingerprint_hex);

                public_key_data_done(&persistent_key);
        }

        const char *pem_path = arg_early ? TPM2_SRK_PEM_RUNTIME_PATH : TPM2_SRK_PEM_PERSISTENT_PATH;
        (void) mkdir_parents(pem_path, 0755);

        /* Write out public key (note that we only do that as a help to the user, we don't make use of this ever */
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable(pem_path, O_WRONLY, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open SRK public key file '%s' for writing: %m", pem_path);

        if (PEM_write_PUBKEY(f, tpm2_key.pkey) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write SRK public key file '%s'.", pem_path);

        if (fchmod(fileno(f), 0444) < 0)
                return log_error_errno(errno, "Failed to adjust access mode of SRK public key file '%s' to 0444: %m", pem_path);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to sync SRK key to disk: %m");

        r = flink_tmpfile(f, t, pem_path, LINK_TMPFILE_SYNC|LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move SRK public key file to '%s': %m", pem_path);

        f = safe_fclose(f);
        t = mfree(t);

        log_info("SRK public key saved to '%s' in PEM format.", pem_path);

        const char *tpm2b_public_path = arg_early ? TPM2_SRK_TPM2B_PUBLIC_RUNTIME_PATH : TPM2_SRK_TPM2B_PUBLIC_PERSISTENT_PATH;
        (void) mkdir_parents(tpm2b_public_path, 0755);

        /* Now also write this out in TPM2B_PUBLIC format */
        r = fopen_tmpfile_linkable(tpm2b_public_path, O_WRONLY, &t, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to open SRK public key file '%s' for writing: %m", tpm2b_public_path);

        _cleanup_free_ void *marshalled = NULL;
        size_t marshalled_size = 0;
        r = tpm2_marshal_public(tpm2_key.public, &marshalled, &marshalled_size);
        if (r < 0)
                return log_error_errno(r, "Failed to marshal TPM2_PUBLIC key.");

        if (fwrite(marshalled, 1, marshalled_size, f) != marshalled_size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to write SRK public key file '%s'.", tpm2b_public_path);

        if (fchmod(fileno(f), 0444) < 0)
                return log_error_errno(errno, "Failed to adjust access mode of SRK public key file '%s' to 0444: %m", tpm2b_public_path);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to sync SRK key to disk: %m");

        r = flink_tmpfile(f, t, tpm2b_public_path, LINK_TMPFILE_SYNC|LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move SRK public key file to '%s': %m", tpm2b_public_path);

        log_info("SRK public key saved to '%s' in TPM2B_PUBLIC format.", tpm2b_public_path);
        return 0;
}

DEFINE_MAIN_FUNCTION(run);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-messages.h"

#include "build.h"
#include "creds-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "recurse-dir.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "tpm2-util.h"

static char *arg_tpm2_device = NULL;
static bool arg_early = false;
static bool arg_graceful = false;

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
               "\n%5$sSet up the TPM2 Storage Root Key (SRK), and initialize NvPCRs.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --tpm2-device=PATH\n"
               "                          Pick TPM2 device\n"
               "     --early=BOOL         Store SRK public key in /run/ rather than /var/lib/\n"
               "     --graceful           Exit gracefully if no TPM2 device is found\n"
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
                ARG_GRACEFUL,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, ARG_VERSION     },
                { "tpm2-device", required_argument, NULL, ARG_TPM2_DEVICE },
                { "early",       required_argument, NULL, ARG_EARLY       },
                { "graceful",    no_argument,       NULL, ARG_GRACEFUL    },
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

                case ARG_GRACEFUL:
                        arg_graceful = true;
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

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        r = tpm2_get_or_create_srk(
                        c,
                        /* session= */ NULL,
                        &data.public,
                        /* ret_name= */ NULL,
                        /* ret_qname= */ NULL,
                        NULL);
        if (r == -EDEADLK)
                return r;
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

static int setup_srk(void) {
        int r;

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
        if (r == -EDEADLK) {
                log_struct_errno(LOG_INFO, r,
                                 LOG_MESSAGE("Insufficient permissions to access TPM, not generating SRK."),
                                 "MESSAGE_ID=" SD_MESSAGE_SRK_ENROLLMENT_NEEDS_AUTHORIZATION_STR);
                return 76; /* Special return value which means "Insufficient permissions to access TPM,
                            * cannot generate SRK". This isn't really an error when called at boot. */;
        }
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

typedef struct SetupNvPCRContext {
        Tpm2Context *tpm2_context;
        struct iovec anchor_secret;
        size_t n_already, n_anchored;
        Set *done;
} SetupNvPCRContext;

static void setup_nvpcr_context_done(SetupNvPCRContext *c) {
        assert(c);

        iovec_done_erase(&c->anchor_secret);
        c->tpm2_context = tpm2_context_unref(c->tpm2_context);
        c->done = set_free(c->done);
}

static int setup_nvpcr_one(
                SetupNvPCRContext *c,
                const char *name,
                struct iovec *text) {
        int r;

        assert(c);
        assert(name);
        assert(text);

        if (set_contains(c->done, name))
                return 0;

        /* Check that this can be used as valid C string, i.e. contains no NUL byte */
        _cleanup_free_ char *s = NULL;
        r = make_cstring(text->iov_base, text->iov_len, MAKE_CSTRING_REFUSE_TRAILING_NUL, &s);
        if (r < 0)
                return log_error_errno(r, "NvPCR JSON data contains NUL byte, refusing.");

        if (!c->tpm2_context) {
                r = tpm2_context_new_or_warn(arg_tpm2_device, &c->tpm2_context);
                if (r < 0)
                        return r;
        }

        r = tpm2_nvpcr_initialize_raw(c->tpm2_context, /* session= */ NULL, s, &c->anchor_secret, /* sync_secondary= */ !arg_early);
        if (r == -EUNATCH) {
                assert(!iovec_is_set(&c->anchor_secret));

                /* If we get EUNATCH this means we actually need to initialize this NvPCR
                 * now, and haven't provided the anchor secret yet. Hence acquire it now. */

                r = tpm2_nvpcr_acquire_anchor_secret(&c->anchor_secret, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire anchor secret: %m");

                r = tpm2_nvpcr_initialize_raw(c->tpm2_context, /* session= */ NULL, s, &c->anchor_secret, /* sync_secondary= */ !arg_early);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to extend NvPCR index with anchor secret: %m");

        if (r > 0)
                c->n_anchored++;
        else
                c->n_already++;

        if (set_put_strdup(&c->done, name) < 0)
                return log_oom();

        return 0;
}

static int setup_nvpcr_credentials(SetupNvPCRContext *c) {
        int r, ret = 0;

        assert(c);

        /* Iterates through all NvPCR definitions we find in the system credentials and initializes them. */

        const char *dp;
        r = get_encrypted_system_credentials_dir(&dp);
        if (r < 0)
                return log_error_errno(r, "Failed to get encrypted system credentials directory: %m");

        _cleanup_close_ int dfd = open(dp, O_CLOEXEC|O_DIRECTORY);
        if (dfd < 0) {
                if (errno == ENOENT) {
                        log_debug("No encrypted system credentials passed.");
                        return 0;
                }

                return log_error_errno(errno, "Failed to open system credentials directory.");
        }

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dfd, RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate system credentials: %m");

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                struct dirent *d = *i;

                if ((*i)->d_type != DT_REG)
                        continue;

                const char *e = startswith_no_case(d->d_name, "nvpcr."); /* VFAT is case-insensitive, hence don't be too strict here */
                if (!e)
                        continue;

                _cleanup_(iovec_done) struct iovec credential = {};
                r = read_full_file_full(
                                dfd,
                                d->d_name,
                                /* offset= */ UINT64_MAX,
                                CREDENTIAL_ENCRYPTED_SIZE_MAX,
                                READ_FULL_FILE_UNBASE64|READ_FULL_FILE_FAIL_WHEN_LARGER,
                                /* bind_name= */ NULL,
                                (char**) &credential.iov_base,
                                &credential.iov_len);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        RET_GATHER(ret, log_warning_errno(r, "Failed to read NvPCR credential file '%s/%s', skipping: %m", dp, d->d_name));
                        continue;
                }

                _cleanup_(iovec_done) struct iovec plaintext = {};
                r = decrypt_credential_and_warn(
                                d->d_name,
                                now(CLOCK_REALTIME),
                                /* tpm2_device= */ NULL,
                                /* tpm2_signature_path= */ NULL,
                                /* uid= */ UID_INVALID,
                                &credential,
                                CREDENTIAL_ALLOW_NULL, /* These are not actually supposed to be encrypted */
                                &plaintext);
                if (r < 0) {
                        RET_GATHER(ret, log_debug_errno(r, "Failed to decode NvPCR credential file '%s/%s' passed in as system credential, skipping: %m", dp, d->d_name));
                        continue;
                }

                r = setup_nvpcr_one(c, e, &plaintext);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to initialize NvPCR from credential file '%s/%s', skipping: %m", dp, d->d_name));
        }

        return ret;
}

static int setup_nvpcr_dir(SetupNvPCRContext *c, const char *path) {
        int r, ret = 0;

        assert(c);

        /* Iterates through all NvPCR definitions we find in /var/lib/systemd/nvpcr/ or /run/systemd/nvpcr/
         * and initializes them. */

        _cleanup_close_ int dfd = open(path, O_CLOEXEC|O_DIRECTORY);
        if (dfd < 0) {
                if (errno == ENOENT) {
                        log_debug("No NvPCR definitions found in '%s'.", path);
                        return 0;
                }

                return log_error_errno(errno, "Failed to open '%s': %m", path);
        }

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dfd, RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &de);
        if (r < 0)
                return log_debug_errno(r, "Failed to read directory '%s': %m", path);

        _cleanup_(iovec_done_erase) struct iovec anchor_secret = {};
        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                const char *e;

                if ((*i)->d_type != DT_REG)
                        continue;

                e = endswith((*i)->d_name, ".nvpcr");
                if (!e)
                        continue;

                _cleanup_(iovec_done) struct iovec data = {};
                r = read_full_file_full(
                                dfd,
                                (*i)->d_name,
                                /* offset= */ UINT64_MAX,
                                SIZE_MAX,
                                /* flags= */ 0,
                                /* bind_name= */ NULL,
                                (char**) &data.iov_base,
                                &data.iov_len);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        RET_GATHER(ret, log_warning_errno(r, "Failed to read NvPCR file '%s/%s', skipping: %m", path, (*i)->d_name));
                        continue;
                }

                _cleanup_free_ char *n = strndup((*i)->d_name, e - (*i)->d_name);
                if (!n)
                        return log_oom();

                r = setup_nvpcr_one(c, n, &data);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to initialize NvPCR from NvPCR file '%s/%s', skipping: %m", path, (*i)->d_name));
        }

        return ret;
}

static int setup_nvpcr(void) {
        _cleanup_(setup_nvpcr_context_done) SetupNvPCRContext c = {};
        int r = 0;

        /* First, acquire the anchor secret */
        r = tpm2_nvpcr_acquire_anchor_secret(&c.anchor_secret, /* sync_secondary= */ arg_early);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire anchor secret: %m");

        /* Second, set up NvPCRs rom /run/systemd/nvpcr data */
        RET_GATHER(r, setup_nvpcr_dir(&c, "/run/systemd/nvpcr"));

        /* Third, set up NvPCRs rom /var/lib/systemd/nvpcr data */
        if (!arg_early)
                RET_GATHER(r, setup_nvpcr_dir(&c, "/var/lib/systemd/nvpcr"));

        /* Fourth, set up NvPCR from system credentials */
        RET_GATHER(r, setup_nvpcr_credentials(&c));

        if (c.n_anchored > 0) {
                if (c.n_already == 0)
                        log_info("%zu NvPCRs initialized.", c.n_anchored);
                else
                        log_info("%zu NvPCRs initialized. (%zu NvPCRs were already initialized.)", c.n_anchored, c.n_already);
        } else if (c.n_already > 0)
                log_info("%zu NvPCRs already initialized.", c.n_already);
        else
                log_debug("No NvPCRs defined, nothing initialized.");

        return r;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_graceful && tpm2_support() != TPM2_SUPPORT_FULL) {
                log_notice("No complete TPM2 support detected, exiting gracefully.");
                return EXIT_SUCCESS;
        }

        umask(0022);

        r = setup_srk();
        RET_GATHER(r, setup_nvpcr());

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);

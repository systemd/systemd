/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "chase.h"
#include "conf-files.h"
#include "creds-util.h"
#include "crypto-util.h"
#include "dlopen-note.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "iovec-util.h"
#include "keyring-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "string-util.h"
#include "strv.h"
#include "verbs.h"
#include "voa-util.h"

static char **arg_keyrings = NULL;
static bool arg_dry_run = false;
static PagerFlags arg_pager_flags = 0;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

STATIC_DESTRUCTOR_REGISTER(arg_keyrings, strv_freep);

COMMAND(
        "systemd-keyring-setup\0",
        "Enroll certificates from the VOA hierarchy into the kernel's trust keyrings.",
        .argspec = "[KEYRING…]\0",
        .man_pages = "systemd-keyring-setup.service.8\0",
        .pager_flags = &arg_pager_flags,
);

/* The permission mask a keyring is left with: the kernel searches it as possessor, root may still look at
 * it */
#define KEYRING_PERM_LOCKED (KEY_POS_SEARCH|KEY_USR_VIEW)

#define CERTIFICATE_SIZE_MAX (1U*1024U*1024U)

#define CREDENTIAL_PREFIX "keyring-setup."

typedef struct KeyringSpec {
        const char *name;
        const char *role;        /* the VOA role its certificates come from */
        const char *param;       /* prefix of the kernel's keyring_unsealed= parameter, NULL if the kernel
                                  * never seals the keyring */
        const char *module;      /* the keyring exists once this module is loaded */
} KeyringSpec;

static const KeyringSpec keyring_specs[] = {
        {
                .name = ".dm-verity",
                .role = "image",
                .param = "dm_verity",
                .module = "dm_verity",
        },
        {
                .name = ".fs-verity",
                .role = "fs-verity",
        },
        {
                .name = ".bpf",
                .role = "bpf",
                .param = "bpf",
        },
};

typedef struct Certificate {
        char *path;
        struct iovec der;
        char *description;      /* as derived by the kernel */
} Certificate;

typedef struct Keyring {
        const KeyringSpec *spec;
        key_serial_t serial;    /* 0 while unknown */
        uint32_t perm;
        int unsealed;           /* the boot-time flag, -1 if unknown */
        Certificate *certificates;
        size_t n_certificates;
        size_t n_enrolled;
        size_t n_keys;          /* in the keyring, SIZE_MAX while unknown */
        bool sealed;
        bool locked;
        bool data_error;        /* a certificate could not be used */
        bool failed;            /* the kernel refused an operation, but the keyring can still be sealed */
} Keyring;

static void keyring_done(Keyring *k) {
        assert(k);

        FOREACH_ARRAY(c, k->certificates, k->n_certificates) {
                free(c->path);
                iovec_done(&c->der);
                free(c->description);
        }

        free(k->certificates);
}

static int load_certificate(Keyring *k, const ConfFile *f) {
        _cleanup_(X509_freep) X509 *x = NULL, *more = NULL;
        _cleanup_(BIO_freep) BIO *bio = NULL;
        _cleanup_(iovec_done) struct iovec der = {};
        _cleanup_free_ char *text = NULL;
        const char *path;
        size_t size;
        int r, n;

        assert(k);
        assert(f);

        path = f->original_path;

        r = read_full_file_full(f->fd, /* filename= */ NULL, UINT64_MAX, CERTIFICATE_SIZE_MAX,
                                READ_FULL_FILE_FAIL_WHEN_LARGER|READ_FULL_FILE_VERIFY_REGULAR,
                                /* bind_name= */ NULL, &text, &size);
        if (r < 0)
                return log_warning_errno(r, "Failed to read '%s', ignoring: %m", path);

        bio = sym_BIO_new_mem_buf(text, size);
        if (!bio)
                return log_oom();

        /* Skips anything before the first CERTIFICATE block, e.g. OpenSSL's "Bag Attributes" */
        x = sym_PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!x)
                return log_openssl_errors(LOG_WARNING, "Failed to parse '%s', ignoring", path);

        /* Only the first certificate counts, a chain file cannot smuggle intermediates in */
        more = sym_PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (more)
                log_warning("'%s' contains more than one certificate, using only the first. Store one "
                            "certificate per file, CA certificates below trust-anchor-%s/.",
                            path, k->spec->role);
        sym_ERR_clear_error();

        /* The kernel takes DER */
        n = sym_i2d_X509(x, NULL);
        if (n <= 0)
                return log_openssl_errors(LOG_WARNING, "Failed to encode '%s', ignoring", path);

        der.iov_base = malloc(n);
        if (!der.iov_base)
                return log_oom();
        der.iov_len = n;

        unsigned char *p = der.iov_base;
        if (sym_i2d_X509(x, &p) != n)
                return log_openssl_errors(LOG_WARNING, "Failed to encode '%s', ignoring", path);

        /* Every copy of a verifier counts, but the same certificate is enrolled once */
        FOREACH_ARRAY(c, k->certificates, k->n_certificates)
                if (iovec_memcmp(&c->der, &der) == 0) {
                        log_debug("'%s' is identical to '%s', skipping.", path, c->path);
                        return 0;
                }

        _cleanup_free_ char *copy = strdup(path);
        if (!copy)
                return log_oom();

        if (!GREEDY_REALLOC(k->certificates, k->n_certificates + 1))
                return log_oom();

        k->certificates[k->n_certificates++] = (Certificate) {
                .path = TAKE_PTR(copy),
                .der = TAKE_STRUCT(der),
        };

        return 1;
}

static int collect_certificates(Keyring *k, int root_fd, char **os) {
        int r;

        assert(k);

        /* Trust anchors and artifact verifiers end up in the same flat keyring, the kernel validates chains
         * itself */

        for (VoaMode mode = 0; mode < _VOA_MODE_MAX; mode++) {
                ConfFile **files = NULL;
                size_t n_files = 0;
                VoaLookup lookup = {
                        .os = os,
                        .role = k->spec->role,
                        .mode = mode,
                        .technology = "x509",
                        .suffix = "-certificate.pem",
                };

                CLEANUP_ARRAY(files, n_files, conf_file_free_array);

                r = voa_list_verifiers(/* root= */ NULL, root_fd, &lookup, VOA_WARN, &files, &n_files);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate certificates for keyring %s: %m",
                                               k->spec->name);

                FOREACH_ARRAY(f, files, n_files) {
                        r = load_certificate(k, *f);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                k->data_error = true;
                }
        }

        return 0;
}

/* Returns > 0 if the keyring exists and may be provisioned, 0 if there is nothing to do */
static int locate_keyring(Keyring *k) {
        int r;

        assert(k);

        r = keyring_find_by_name(k->spec->name, /* owner= */ 0, &k->serial);
        if (r == -ENOKEY) {
                const char *hint = "";

                if (k->n_certificates == 0) {
                        log_debug_errno(r, "Keyring %s not found, nothing to do: %m", k->spec->name);
                        return 0;
                }

                if (k->spec->module) {
                        const char *p = strjoina("/sys/module/", k->spec->module);

                        if (access(p, F_OK) < 0)
                                hint = strjoina(" Load the ", k->spec->module,
                                                " module first, e.g. via modprobe@", k->spec->module,
                                                ".service.");
                }

                log_notice("Keyring %s not found, %zu certificate(s) cannot be enrolled.%s",
                           k->spec->name, k->n_certificates, hint);
                return 0;
        }
        if (r == -ENOTUNIQ)
                return log_error_errno(r, "More than one keyring named %s, refusing.", k->spec->name);
        if (r < 0)
                return log_error_errno(r, "Failed to look up keyring %s in /proc/keys: %m", k->spec->name);

        r = keyring_perm(k->serial, &k->perm);
        if (r < 0)
                return log_error_errno(r, "Failed to read permissions of keyring %s: %m", k->spec->name);

        /* Restriction state is not observable, but the permission mask is: this is how an earlier boot
         * stage or the previous boot of a soft-rebooted kernel signals that it completed. */
        if (k->perm == KEYRING_PERM_LOCKED) {
                log_info("Keyring %s is sealed and locked down already.", k->spec->name);
                k->sealed = k->locked = true;
                return 0;
        }
        if (!FLAGS_SET(k->perm, KEY_USR_WRITE|KEY_USR_SETATTR))
                return log_warning_errno(SYNTHETIC_ERRNO(EPERM),
                                         "Keyring %s has an unexpected permission mask 0x%08" PRIx32 ", "
                                         "not touching it.", k->spec->name, k->perm);

        /* Unreadable once locked down */
        r = keyring_list(k->serial, /* ret= */ NULL, &k->n_keys);
        if (r < 0)
                return log_error_errno(r, "Failed to read keyring %s: %m", k->spec->name);

        return 1;
}

/* Returns > 0 if the keyring may be provisioned, 0 if the kernel sealed it at boot */
static int check_unsealed(Keyring *k) {
        _cleanup_free_ char *v = NULL;
        const char *p;
        int r;

        assert(k);

        if (!k->spec->param)
                return 1;

        p = strjoina("/sys/module/", k->spec->param, "/parameters/keyring_unsealed");
        r = read_one_line_file(p, &v);
        if (r >= 0)
                r = parse_boolean(v);
        if (r < 0) {
                /* A sealed keyring refuses additions, hence enrollment tells the state */
                log_debug_errno(r, "Cannot read keyring_unsealed parameter of %s, ignoring: %m",
                                k->spec->param);
                return 1;
        }

        k->unsealed = r;
        if (!k->unsealed) {
                if (k->n_certificates > 0)
                        log_notice("Keyring %s was sealed at boot, %zu certificate(s) cannot be enrolled. "
                                   "Pass %s.keyring_unsealed=1 on the kernel command line to provision it.",
                                   k->spec->name, k->n_certificates, k->spec->param);
                else
                        log_debug("Keyring %s was sealed at boot, nothing to do.", k->spec->name);

                k->sealed = true;
                return 0;
        }

        if (k->n_certificates == 0)
                log_warning("Keyring %s was left unsealed at boot, but no certificates are configured "
                            "for it.", k->spec->name);

        return 1;
}

/* Returns > 0 if the keyring is still open for sealing, 0 if it must not be touched further */
static int enroll_certificates(Keyring *k) {
        size_t n_after;
        int r;

        assert(k);

        FOREACH_ARRAY(c, k->certificates, k->n_certificates) {
                key_serial_t serial;

                r = keyring_add_asymmetric(k->serial, /* description= */ NULL, &c->der, &serial);
                if (r == -EPERM) {
                        /* Restricted by somebody else: the kernel at boot, a run that died before locking
                         * down, or a foreign recipe. Nothing more can be added, but it can still be
                         * locked down. */
                        if (k->unsealed < 0)
                                log_notice("Keyring %s is sealed, cannot enroll '%s'. Pass "
                                           "%s.keyring_unsealed=1 on the kernel command line to "
                                           "provision it.",
                                           k->spec->name, c->path, strempty(k->spec->param));
                        else
                                log_notice("Keyring %s is sealed already, cannot enroll '%s'.",
                                           k->spec->name, c->path);
                        k->sealed = true;
                        return 1;
                }
                if (IN_SET(r, -EKEYREVOKED, -EKEYEXPIRED))
                        return log_error_errno(r, "Keyring %s is unusable, nothing can be enrolled this "
                                               "boot: %m", k->spec->name);
                if (r == -EACCES)
                        return log_error_errno(r, "Adding to keyring %s denied: %m", k->spec->name);
                if (IN_SET(r, -EDQUOT, -ENOMEM)) {
                        /* Out of quota or memory: nothing more can be added now, but the keyring can and
                         * must still be sealed */
                        log_error_errno(r, "Failed to enroll '%s': %m", c->path);
                        k->failed = true;
                        break;
                }
                if (r < 0) {
                        if (r == -EKEYREJECTED)
                                log_warning_errno(r, "Kernel rejected certificate '%s' (blacklisted, or a "
                                                  "self-signed certificate whose signature does not "
                                                  "verify): %m", c->path);
                        else if (r == -ENOPKG)
                                log_warning_errno(r, "Kernel does not support the public key algorithm of "
                                                  "'%s': %m", c->path);
                        else
                                log_warning_errno(r, "Failed to enroll '%s': %m", c->path);

                        k->data_error = true;
                        continue;
                }

                k->n_enrolled++;

                r = keyring_description(serial, &c->description);
                if (r < 0)
                        log_debug_errno(r, "Failed to describe enrolled key, ignoring: %m");

                log_info("Enrolled '%s' into keyring %s%s%s.", c->path, k->spec->name,
                         c->description ? " as " : "", strempty(c->description));
        }

        /* Two certificates with the same subject and key identifier derive the same description, and the
         * second replaces the first without any error */
        FOREACH_ARRAY(c, k->certificates, k->n_certificates) {
                if (!c->description)
                        continue;

                FOREACH_ARRAY(d, k->certificates, c - k->certificates)
                        if (streq_ptr(c->description, d->description)) {
                                log_warning("'%s' and '%s' both derive the key description '%s', "
                                            "only one of them is enrolled.",
                                            d->path, c->path, c->description);
                                k->data_error = true;
                        }
        }

        r = keyring_list(k->serial, /* ret= */ NULL, &n_after);
        if (r < 0) {
                log_debug_errno(r, "Failed to read keyring %s, ignoring: %m", k->spec->name);
                return 1;
        }

        if (n_after - k->n_keys < k->n_enrolled)
                log_warning("Keyring %s gained fewer keys than certificates were enrolled, a certificate "
                            "replaced a key that was already in the keyring.", k->spec->name);
        else if (n_after - k->n_keys > k->n_enrolled)
                log_notice("Keyring %s was modified by somebody else during enrollment.", k->spec->name);

        k->n_keys = n_after;
        return 1;
}

static int seal_keyring(Keyring *k) {
        int r;

        assert(k);

        /* Sealing stops additions. Dropping every permission but the search the kernel needs and the view
         * that makes the state observable by later runs stops everything else, removals included. */

        if (!k->sealed) {
                /* Needs the setattr permission that goes away below */
                r = keyring_restrict(k->serial, /* type= */ NULL, /* restriction= */ NULL);
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Failed to seal keyring %s: %m", k->spec->name);

                k->sealed = true;
        }

        r = keyring_set_perm(k->serial, KEYRING_PERM_LOCKED);
        if (r < 0)
                return log_error_errno(r, "Failed to lock down keyring %s: %m", k->spec->name);

        k->locked = true;

        log_info("Sealed and locked down keyring %s with %zu key(s), %zu enrolled now.",
                 k->spec->name, k->n_keys, k->n_enrolled);

        /* Only a loaded module has a refcnt, and only on kernels that can unload it. Unloading takes the
         * keyring and its lockdown with it, reloading creates a fresh one. */
        if (k->spec->module) {
                const char *p = strjoina("/sys/module/", k->spec->module, "/refcnt");

                if (access(p, F_OK) >= 0)
                        log_warning("Keyring %s belongs to the loadable %s module: unloading the module "
                                    "may discard the keyring and its lockdown, and reloading it creates "
                                    "one that can be provisioned again. Build %s into the kernel to keep "
                                    "the enrolled set for the lifetime of the kernel.",
                                    k->spec->name, k->spec->module, k->spec->module);
        }

        return 0;
}

static int add_to_table(Table *t, const Keyring *k) {
        _cleanup_strv_free_ char **paths = NULL;
        uint64_t n;
        int r;

        assert(t);
        assert(k);

        FOREACH_ARRAY(c, k->certificates, k->n_certificates) {
                r = strv_extend(&paths, c->path);
                if (r < 0)
                        return log_oom();
        }

        r = table_add_many(t,
                           TABLE_STRING, k->spec->name,
                           TABLE_STRING, k->spec->role,
                           TABLE_BOOLEAN_CHECKMARK, k->serial > 0,
                           TABLE_STRING, k->unsealed < 0 ? "n/a" : yes_no(k->unsealed));
        if (r < 0)
                return table_log_add_error(r);

        if (k->n_keys == SIZE_MAX)
                r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
        else {
                n = k->n_keys;
                r = table_add_cell(t, NULL, TABLE_UINT64, &n);
        }
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(t,
                           TABLE_BOOLEAN_CHECKMARK, k->locked,
                           TABLE_STRV, paths);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int process_keyring(const KeyringSpec *spec, int root_fd, char **os, Table *t) {
        _cleanup_(keyring_done) Keyring k = { .spec = spec, .unsealed = -1, .n_keys = SIZE_MAX };
        int r;

        assert(spec);

        r = collect_certificates(&k, root_fd, os);
        if (r >= 0)
                r = locate_keyring(&k);
        if (r > 0)
                r = check_unsealed(&k);

        if (arg_dry_run) {
                if (r > 0)
                        log_info("Would enroll %zu certificate(s) into keyring %s.",
                                 k.n_certificates, spec->name);

                if (add_to_table(t, &k) < 0)
                        return EXIT_FAILURE;
        } else {
                if (r > 0)
                        r = enroll_certificates(&k);
                if (r > 0)
                        r = seal_keyring(&k);
        }

        if (r < 0 || k.failed)
                return EXIT_FAILURE;

        return k.data_error ? EX_DATAERR : EXIT_SUCCESS;
}

/* Credentials are the way to hand a certificate to an initrd without rebuilding it. Following the
 * specification's advice for verifiers retrieved from elsewhere, they are placed into the ephemeral load
 * path as artifact verifiers, so that masking, merging and everything else applies to them like to any
 * other file. */
static int materialize_credential(
                int root_fd,
                const char *cn,
                const KeyringSpec *spec,
                const char *name,
                char **os) {

        _cleanup_free_ char *contents = NULL, *fn = NULL, *path = NULL, *base = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(root_fd >= 0);
        assert(cn);
        assert(spec);
        assert(name);
        assert(!strv_isempty(os));

        fn = strjoin(name, "-certificate.pem");
        if (!fn)
                return log_oom();

        /* The exact OS identifier suffices */
        path = path_join("/run/voa", os[0], spec->role, "default", "x509", fn);
        if (!path)
                return log_oom();

        if (arg_dry_run) {
                log_info("Would place credential '%s' at '%s'.", cn, path);
                return 0;
        }

        r = read_credential(cn, (void**) &contents, /* ret_size= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", cn);

        dfd = chase_and_open_parent_at(root_fd, root_fd, path, CHASE_MKDIR_0755, &base);
        if (dfd < 0)
                return log_error_errno(dfd, "Failed to create the directory of '%s': %m", path);

        r = write_string_file_at(dfd, base, contents, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s': %m", path);

        log_debug("Placed credential '%s' at '%s'.", cn, path);
        return 0;
}

static int materialize_credentials(int root_fd, char **os) {
        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(root_fd >= 0);

        fd = open_credentials_dir();
        if (fd == -ENXIO)
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open credentials directory: %m");

        r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to read credentials directory: %m");

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                const char *cn = (*i)->d_name, *e, *name = NULL;
                const KeyringSpec *spec = NULL;

                e = startswith(cn, CREDENTIAL_PREFIX);
                if (!e || streq(e, "os"))
                        continue;

                /* keyring-setup.<keyring>.<name>, the keyring without its leading dot */
                FOREACH_ELEMENT(s, keyring_specs) {
                        name = startswith(e, s->name + 1);
                        if (name && name[0] == '.') {
                                spec = s;
                                name++;
                                break;
                        }
                }
                if (!spec) {
                        log_warning("Ignoring unrecognized credential '%s', expected "
                                    CREDENTIAL_PREFIX "<keyring>.<name>.", cn);
                        continue;
                }
                if (!voa_identifier_is_valid(name, /* allow_colon= */ false)) {
                        log_warning("Ignoring credential '%s', the name must consist of lowercase letters, "
                                    "digits, '.', '_' and '-'.", cn);
                        continue;
                }

                r = materialize_credential(root_fd, cn, spec, name, os);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Returns > 0 if the credential exists */
static int os_from_credential(char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *v = NULL;
        int r;

        assert(ret);

        r = read_credential(CREDENTIAL_PREFIX "os", (void**) &v, /* ret_size= */ NULL);
        if (IN_SET(r, -ENXIO, -ENOENT))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read credential " CREDENTIAL_PREFIX "os: %m");

        l = strv_split(v, WHITESPACE);
        if (!l)
                return log_oom();
        if (strv_isempty(l))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Credential " CREDENTIAL_PREFIX "os is empty.");

        STRV_FOREACH(i, l)
                if (!voa_os_is_valid(*i))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid OS identifier '%s' in credential "
                                               CREDENTIAL_PREFIX "os.", *i);

        *ret = TAKE_PTR(l);
        return 1;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("dry-run", NULL, "Only show what would be enrolled"):
                        arg_dry_run = true;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        STRV_FOREACH(a, option_parser_get_args(&opts)) {
                bool known = false;

                FOREACH_ELEMENT(spec, keyring_specs)
                        known = known || streq(spec->name, *a);
                if (!known)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown keyring: '%s'", *a);
        }

        arg_keyrings = strv_copy(option_parser_get_args(&opts));
        if (!arg_keyrings)
                return log_oom();

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_strv_free_ char **os = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        int r, ret = 0;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        LIBCRYPTO_NOTE(required);

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        root_fd = open("/", O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (root_fd < 0)
                return log_error_errno(errno, "Failed to open root directory: %m");

        r = os_from_credential(&os);
        if (r < 0)
                return r;
        if (r == 0) {
                r = voa_os_identifiers(root_fd, &os);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to determine the OS identifier from os-release: %m");
                if (r > 0)
                        log_warning("os-release contains characters the VOA specification does not permit, "
                                    "looking up the bare ID only. Pass the " CREDENTIAL_PREFIX "os "
                                    "credential to specify identifiers explicitly.");
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = strv_join(os, ", ");

                log_debug("Looking up VOA verifiers for OS identifier(s): %s", strna(joined));
        }

        r = materialize_credentials(root_fd, os);
        if (r < 0)
                return r;

        if (arg_dry_run) {
                t = table_new("keyring", "role", "exists", "unsealed", "keys", "locked", "certificates");
                if (!t)
                        return log_oom();

                table_set_ersatz_string(t, TABLE_ERSATZ_DASH);
        }

        FOREACH_ELEMENT(spec, keyring_specs) {
                if (!strv_isempty(arg_keyrings) && !strv_contains(arg_keyrings, spec->name))
                        continue;

                r = process_keyring(spec, root_fd, os, t);
                if (r == EXIT_FAILURE || (r == EX_DATAERR && ret == 0))
                        ret = r;
        }

        if (t) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags,
                                           /* show_header= */ true);
                if (r < 0)
                        return r;
        }

        return ret;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);

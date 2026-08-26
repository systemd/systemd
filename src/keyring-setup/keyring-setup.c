/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
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
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "iovec-util.h"
#include "keyring-util.h"
#include "log.h"
#include "main-func.h"
#include "module-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
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
        .man_pages = "systemd-keyring-setup.service(8)\0",
        .pager_flags = &arg_pager_flags,
);

/* The permission mask we are left with after we dropped SetAttr. */
#define KEYRING_PERM_SEALED (KEY_POS_SEARCH|KEY_USR_VIEW|KEY_USR_READ|KEY_USR_WRITE)

#define CERTIFICATE_SIZE_MAX (1U*1024U*1024U)

#define CREDENTIAL_PREFIX "keyring-setup."

/* Cap the number of possible OSes in both the exact and bare form. 64 OSes is plenty and we can always
 * increase. */
#define CREDENTIAL_OS_MAX 64U

typedef struct KeyringSpec {
        const char *name;
        const char *role;        /* the VOA role its certificates come from */
        const char *context;     /* the VOA context below the role */
        const char *param;       /* the module name the kernel's keyring_unsealed= parameter is scoped to,
                                  * i.e. /sys/module/<param>/, NULL if the kernel never seals the keyring */
        const char *module;      /* the keyring exists once this module is loaded */
        key_serial_t spec_id;    /* fixed KEY_SPEC_* ID, 0 if the keyring only goes by name */
} KeyringSpec;

static const KeyringSpec keyring_specs[] = {
        {
                .name = ".dm-verity",
                .role = "kernel-keyring",
                .context = "dm-verity",
                .param = "dm_verity",
                .module = "dm_verity",
        },
        {
                .name = ".fs-verity",
                .role = "kernel-keyring",
                .context = "fs-verity",
        },
        {
                .name = ".bpf",
                .role = "kernel-keyring",
                .context = "bpf",
                .param = "bpf",
                .spec_id = KEY_SPEC_BPF_KEYRING,
        },
};

static const KeyringSpec* keyring_spec_from_name(const char *name) {
        assert(name);

        FOREACH_ELEMENT(s, keyring_specs)
                if (streq(s->name, name))
                        return s;

        return NULL;
}

typedef struct Certificate {
        char *path;
        struct iovec der;
        char *description_suffix; /* the ": <hex>" tail of the kernel's description */
        key_serial_t serial;    /* 0 until enrolled */
} Certificate;

/* A key linked into the keyring */
typedef struct Member {
        key_serial_t serial;
        char *type;             /* NULL if the key could not be described */
        char *description;
} Member;

static void member_done(Member *m) {
        assert(m);

        free(m->type);
        free(m->description);
}

static void member_free_many(Member *m, size_t n) {
        assert(m || n == 0);

        FOREACH_ARRAY(i, m, n)
                member_done(i);

        free(m);
}

typedef struct Keyring {
        const KeyringSpec *spec;
        key_serial_t serial;    /* 0 while unknown */
        int exists;             /* -1 while unknown, a dry run cannot load the module providing it */
        int kernel_unsealed;    /* the boot-time flag, -1 if unknown */
        Certificate *certificates;
        size_t n_certificates;
        size_t n_enrolled;
        Member *members;        /* as last read */
        size_t n_members;
        bool members_known;     /* the members could be read */
        bool sealed;
        bool data_error;        /* a certificate could not be used */
        int failed;             /* a hard error that does not stop the sealing */
} Keyring;

static void keyring_done(Keyring *k) {
        assert(k);

        FOREACH_ARRAY(c, k->certificates, k->n_certificates) {
                free(c->path);
                free(c->description_suffix);
                iovec_done(&c->der);
        }

        free(k->certificates);
        member_free_many(k->members, k->n_members);
}

/* Reads the members along with their descriptions, they are unknown if that fails */
static int keyring_read_members(Keyring *k) {
        _cleanup_free_ key_serial_t *serials = NULL;
        Member *members = NULL;
        size_t n_serials, n_members = 0;
        int r;

        assert(k);

        CLEANUP_ARRAY(members, n_members, member_free_many);

        member_free_many(k->members, k->n_members);
        k->members = NULL;
        k->n_members = 0;
        k->members_known = false;

        r = keyring_list(k->serial, &serials, &n_serials);
        if (r < 0)
                return r;

        members = new0(Member, n_serials);
        if (!members)
                return -ENOMEM;
        n_members = n_serials;

        for (size_t i = 0; i < n_members; i++) {
                Member *m = members + i;

                m->serial = serials[i];

                /* A key that cannot be described still counts, it just matches nothing */
                r = keyring_describe_full(m->serial, &m->type, /* ret_uid= */ NULL, /* ret_perm= */ NULL,
                                          &m->description);
                if (r < 0)
                        log_debug_errno(r, "Failed to describe key %d of keyring %s, ignoring: %m",
                                        m->serial, k->spec->name);
        }

        k->members = TAKE_PTR(members);
        k->n_members = n_members;
        k->members_known = true;
        return 0;
}

static bool keyring_has_member(const Keyring *k, key_serial_t serial) {
        assert(k);

        FOREACH_ARRAY(m, k->members, k->n_members)
                if (m->serial == serial)
                        return true;

        return false;
}

/* The kernel describes a certificate as "<subject>: <hex>", with the subject key identifier or, lacking one,
 * the serial number as hex. Returns the ": <hex>" part, separator included. */
static int certificate_description_suffix(X509 *x, char **ret) {
        const ASN1_STRING *id;
        bool serial;

        assert(x);
        assert(ret);

        id = sym_X509_get0_subject_key_id(x);
        serial = !id;
        if (serial)
                id = sym_X509_get0_serialNumber(x);

        /* For a certificate with no subjectKeyIdentifier and a negative serial number
         * certificate_is_enrolled() will not be able to match the key the kernel created. So on every run
         * we would readd the certificate.
         * And once the keyring is sealed this would also fail. While such certificates are forbidden per
         * RFC 5280 they can still be created via openssl x509 -req -set_serial -1. For such certificates
         * openssl stores a negative V_ASN1_NEG_INTEGER plus the absolute value in ->data. Detect such
         * certificates and reject them. */
        if (serial && sym_ASN1_STRING_type(id) == V_ASN1_NEG_INTEGER)
                return -EBADMSG;

        const unsigned char *d = sym_ASN1_STRING_get0_data(id);
        int l = sym_ASN1_STRING_length(id);
        if (l <= 0)
                return -EBADMSG;

        _cleanup_free_ char *hex = hexmem(d, l);
        if (!hex)
                return -ENOMEM;

        /* DER pads a serial with the top bit set with a zero byte, which the kernel keeps */
        char *j = strjoin(": ", serial && (d[0] & 0x80) ? "00" : "", hex);
        if (!j)
                return -ENOMEM;

        *ret = j;
        return 0;
}

static int load_certificate(Keyring *k, const ConfFile *f) {
        _cleanup_(X509_freep) X509 *x = NULL;
        _cleanup_(iovec_done) struct iovec der = {};
        bool more = false;
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
        if (size == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "'%s' is empty, ignoring.", path);

        r = openssl_load_x509_certificate_from_pem(&IOVEC_MAKE(text, size), &x, &more);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse '%s', ignoring: %m", path);

        /* Don't allow certificate bundles. */
        if (more)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                "'%s' contains more than one certificate, ignoring. Store one certificate "
                                "per file, CA certificates below trust-anchor-%s/.",
                                path, k->spec->role);

        /* The kernel takes DER */
        _cleanup_(OPENSSL_freep) void *encoded = NULL;
        n = sym_i2d_X509(x, (unsigned char**) &encoded);
        if (n <= 0)
                return log_openssl_errors(LOG_WARNING, "Failed to encode '%s', ignoring", path);

        der.iov_base = memdup(encoded, n);
        if (!der.iov_base)
                return log_oom();
        der.iov_len = n;

        /* Every copy of a verifier counts, but the same certificate is enrolled once */
        FOREACH_ARRAY(c, k->certificates, k->n_certificates)
                if (iovec_equal(&c->der, &der)) {
                        log_debug("'%s' is identical to '%s', skipping.", path, c->path);
                        return 0;
                }

        _cleanup_free_ char *description_suffix = NULL;
        r = certificate_description_suffix(x, &description_suffix);
        if (r < 0)
                return log_warning_errno(r, "Failed to determine the description of '%s', ignoring: %m",
                                         path);

        _cleanup_free_ char *copy = strdup(path);
        if (!copy)
                return log_oom();

        if (!GREEDY_REALLOC(k->certificates, k->n_certificates + 1))
                return log_oom();

        k->certificates[k->n_certificates++] = (Certificate) {
                .path = TAKE_PTR(copy),
                .der = TAKE_STRUCT(der),
                .description_suffix = TAKE_PTR(description_suffix),
        };

        return 1;
}

static int collect_certificates(Keyring *k, int root_fd, char **os) {
        int r;

        assert(k);

        /* Without an identifier there is nothing to look up, the failure was reported once already and
         * the keyring is still sealed */
        if (strv_isempty(os)) {
                log_debug("No OS identifier, collecting nothing for keyring %s.", k->spec->name);
                return 0;
        }

        /* Trust anchors and artifact verifiers end up in the same flat keyring, the kernel validates chains
         * itself */
        for (VoaMode mode = 0; mode < _VOA_MODE_MAX; mode++) {
                ConfFile **files = NULL;
                size_t n_files = 0;
                VoaLookup lookup = {
                        .os = os,
                        .role = k->spec->role,
                        .context = k->spec->context,
                        .mode = mode,
                        .technology = VOA_TECHNOLOGY_X509,
                        .suffix = VOA_X509_CERTIFICATE_SUFFIX,
                };

                CLEANUP_ARRAY(files, n_files, conf_file_free_array);

                r = voa_list_verifiers(root_fd, &lookup, VOA_WARN, &files, &n_files);
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
static int locate_keyring(Keyring *k, struct kmod_ctx *kmod) {
        bool module_loaded = true;
        uint32_t perm;
        int r;

        assert(k);

        /* The keyring exists once the module is loaded. Like modprobe, libkmod applies the parameters
         * from the kernel command line. */
        if (k->spec->module) {
                if (arg_dry_run) {
                        const char *p = strjoina("/sys/module/", k->spec->module);

                        /* A dry run may not load the module and without it being loaded it has no way of
                         * figuring out whether the required keyring exists. */
                        module_loaded = access(p, F_OK) >= 0;
                } else if (kmod)
                        (void) module_load_and_warn(kmod, k->spec->module, /* verbose= */ false);
        }

        if (k->spec->spec_id != 0) {
                r = keyring_resolve(k->spec->spec_id);
                if (r > 0)
                        k->serial = r;
                if (r == -EINVAL)
                        r = -ENOKEY;
        } else
                r = keyring_find_by_name(k->spec->name, /* owner= */ 0, &k->serial);
        if (r == -ENOKEY) {
                /* Without the module loaded the keyring cannot exist yet, a dry run cannot tell */
                k->exists = module_loaded ? false : -1;

                if (k->n_certificates == 0) {
                        log_debug_errno(r, "Keyring %s not found, nothing to do: %m", k->spec->name);
                        return 0;
                }

                log_notice("Keyring %s not found, %zu certificate(s) cannot be enrolled.",
                           k->spec->name, k->n_certificates);
                return 0;
        }
        if (r == -ENOTUNIQ)
                return log_error_errno(r, "More than one keyring named %s, refusing.", k->spec->name);
        if (r == -ERFKILL)
                return log_error_errno(r, "Kernel keyrings are not accessible here, /proc/keys is masked.");
        if (r < 0)
                return log_error_errno(r, "Failed to look up keyring %s in /proc/keys: %m", k->spec->name);

        k->exists = true;

        r = keyring_perm(k->serial, &perm);
        if (r < 0)
                return log_error_errno(r, "Failed to read permissions of keyring %s: %m", k->spec->name);

        /* Restriction state is not observable only the permission mask is. So use that to figure out whether
         * a keyring is sealed. */
        if (perm == KEYRING_PERM_SEALED) {
                log_debug("Keyring %s is sealed already.", k->spec->name);
                k->sealed = true;
        } else if (!FLAGS_SET(perm, KEY_USR_SETATTR))
                /* If SetAttr is missing neither the permission mask nor the restrictions can be changed. We
                 * don't know what to do with that. So fail. */
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Keyring %s has permission mask 0x%08" PRIx32 " not set by us and "
                                       "SetAttr is gone, cannot repair it.", k->spec->name, perm);
        else if (!FLAGS_SET(perm, KEY_USR_WRITE))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Keyring %s has an unexpected permission mask 0x%08" PRIx32 ", "
                                       "not touching it.", k->spec->name, perm);

        r = keyring_read_members(k);
        if (r < 0)
                log_debug_errno(r, "Failed to read keyring %s, ignoring: %m", k->spec->name);

        return 1;
}

/* Returns > 0 if the keyring may be provisioned, 0 if the kernel sealed it at boot */
static int check_unsealed(Keyring *k) {
        const char *p;
        int r;

        assert(k);

        if (!k->spec->param)
                return 1;

        p = strjoina("/sys/module/", k->spec->param, "/parameters/keyring_unsealed");
        r = read_boolean_file(p);
        if (r < 0) {
                /* A sealed keyring refuses additions, hence enrollment tells the state, and a keyring the
                 * kernel sealed at boot is then sealed like any other */
                log_debug_errno(r, "Cannot read keyring_unsealed parameter of %s, ignoring: %m",
                                k->spec->param);
                return 1;
        }

        k->kernel_unsealed = r;
        if (!k->kernel_unsealed) {
                if (k->n_certificates > 0)
                        log_notice("Keyring %s was sealed at boot, %zu certificate(s) cannot be enrolled. "
                                   "Pass %s.keyring_unsealed=1 on the kernel command line to provision it.",
                                   k->spec->name, k->n_certificates, k->spec->param);
                else
                        log_debug("Keyring %s was sealed at boot, nothing to do.", k->spec->name);

                return 0;
        }

        if (k->n_certificates == 0)
                log_warning("Keyring %s was left unsealed at boot, but no certificates are configured "
                            "for it.", k->spec->name);

        return 1;
}

static bool certificate_is_enrolled(const Keyring *k, const Certificate *c) {
        assert(k);
        assert(c);

        /* For asymmetric keys the kernel creates a description of the form "<subject>: <id>" if the key is
         * added without a description. For other key types the description is whatever the creator of the
         * key added. Such descriptions must not count as a match. */
        FOREACH_ARRAY(m, k->members, k->n_members)
                if (streq_ptr(m->type, "asymmetric") && m->description &&
                    endswith(m->description, c->description_suffix))
                        return true;

        return false;
}

static void enroll_certificates(Keyring *k) {
        const char *hint = "";
        int r;

        assert(k);

        if (k->kernel_unsealed < 0 && k->spec->param)
                hint = strjoina(" Pass ", k->spec->param, ".keyring_unsealed=1 on the kernel command line to "
                                "provision it.");

        /* Not enrolled by this run, but sealed in with the rest. Under a seal the restriction vetted them. */
        if (!k->sealed)
                FOREACH_ARRAY(m, k->members, k->n_members)
                        log_warning("Keyring %s already held key %d%s%s, it is sealed in as well.",
                                    k->spec->name, m->serial, m->description ? ": " : "",
                                    strempty(m->description));

        /* In reverse: on a colliding subject and key identifier the kernel replaces the key, so the copy
         * from the highest-priority load path and the most specific OS identifier is enrolled last and
         * wins. */
        for (size_t i = k->n_certificates; i > 0; i--) {
                Certificate *c = k->certificates + i - 1;
                _cleanup_free_ char *description = NULL;

                if (certificate_is_enrolled(k, c)) {
                        log_debug("'%s' is in keyring %s already, skipping.", c->path, k->spec->name);
                        continue;
                }

                r = keyring_add_asymmetric(k->serial, /* description= */ NULL, &c->der, &c->serial);
                if (r == -EPERM) {
                        /* Sealed by the kernel at boot. Nothing can be added, but the mask can still be
                         * dropped. */
                        log_notice("Keyring %s is sealed, cannot enroll '%s'.%s", k->spec->name, c->path,
                                   hint);
                        break;
                }
                if (IN_SET(r, -EACCES, -EDQUOT, -ENOMEM, -EKEYREVOKED, -EKEYEXPIRED)) {
                        /* The keyring itself is the problem, sealing it is all that is left */
                        log_error_errno(r, "Failed to enroll '%s' into keyring %s, giving up: %m",
                                        c->path, k->spec->name);
                        RET_GATHER(k->failed, r);
                        break;
                }
                if (r < 0) {
                        if (r == -ENOKEY)
                                log_warning_errno(r, "Keyring %s is sealed and '%s' is not signed by a key "
                                                  "enrolled in it: %m", k->spec->name, c->path);
                        else if (r == -EKEYREJECTED)
                                log_warning_errno(r, "Kernel rejected certificate '%s' (blacklisted, or its "
                                                  "signature does not verify): %m", c->path);
                        else if (r == -ENOPKG)
                                log_warning_errno(r, "Kernel does not support the public key algorithm of "
                                                  "'%s': %m", c->path);
                        else
                                log_warning_errno(r, "Failed to enroll '%s': %m", c->path);

                        k->data_error = true;
                        continue;
                }

                k->n_enrolled++;

                r = keyring_description(c->serial, &description);
                if (r < 0)
                        log_debug_errno(r, "Failed to describe enrolled key, ignoring: %m");

                log_info("Enrolled '%s' into keyring %s%s%s.", c->path, k->spec->name,
                         description ? " as " : "", strempty(description));
        }

        /* A certificate with the same subject and key identifier as a key in the keyring replaces it, which
         * only reading the members again reveals */
        r = keyring_read_members(k);
        if (r < 0) {
                log_debug_errno(r, "Failed to read keyring %s, ignoring: %m", k->spec->name);
                return;
        }

        FOREACH_ARRAY(c, k->certificates, k->n_certificates)
                if (c->serial > 0 && !keyring_has_member(k, c->serial))
                        log_info("'%s' was superseded by a certificate of higher priority with the same "
                                 "subject and key identifier.", c->path);
}

static int seal_keyring(Keyring *k) {
        int r;

        assert(k);

        /* Sealing only allows certificates signed by a key already in the keyring to be added. Dropping
         * SetAttr makes the restriction and mask immutable. The read and write permissions have to stay so
         * keys can still be enrolled. */
        if (k->sealed)
                return 0;

        /* Needs the setattr permission that goes away below */
        r = keyring_restrict(k->serial, "asymmetric", "key_or_keyring:0:chain");
        if (r == -EEXIST) {
                /* Someone else already restricted this keyring. */
                log_warning("Keyring %s carries a restriction not installed by us.", k->spec->name);
                k->data_error = true;
        } else if (r < 0) {
                /* If we fail to enroll certificates drop every certificate we have enrolled in this
                 * invocation. We don't drop anything else so this tool may be called multiple times
                 * without wasting anyone else's keys. */
                int q = 0;
                FOREACH_ARRAY(c, k->certificates, k->n_certificates)
                        if (c->serial > 0)
                                RET_GATHER(q, keyring_unlink_key(k->serial, c->serial));
                if (q < 0)
                        log_error_errno(q, "Failed to remove the enrolled keys from keyring %s: %m",
                                        k->spec->name);
                return log_error_errno(r, "Failed to restrict keyring %s, leaving it unsealed "
                                       "and writable%s: %m", k->spec->name,
                                       q < 0 ? " with keys enrolled" : ", the enrolled keys removed");
        }

        /* Note that if we fail to restrict the keyring above we also skip permission changes. If we
         * were to remove permissions we would lose the ability to restrict the keyring completely. */
        r = keyring_set_perm(k->serial, KEYRING_PERM_SEALED);
        if (r < 0)
                return log_error_errno(r, "Failed to drop permissions of keyring %s: %m", k->spec->name);

        k->sealed = true;

        if (k->members_known)
                log_info("Sealed keyring %s with %zu key(s), %zu enrolled now.",
                         k->spec->name, k->n_members, k->n_enrolled);
        else
                log_info("Sealed keyring %s, %zu enrolled now.", k->spec->name, k->n_enrolled);

        /* Unloading a kernel module may destroy and keyring and circumvent the security model.
         * Warn about that. */
        if (k->spec->module) {
                const char *p = strjoina("/sys/module/", k->spec->module, "/refcnt");

                if (access(p, F_OK) >= 0)
                        log_warning("Keyring %s belongs to the loadable %s module: unloading the module "
                                    "may discard the keyring and its seal, and reloading it creates "
                                    "one that can be provisioned again. Build %s into the kernel to keep "
                                    "the enrolled set for the lifetime of the kernel.",
                                    k->spec->name, k->spec->module, k->spec->module);
        }

        return 0;
}

static int add_to_table(Table *t, const Keyring *k) {
        _cleanup_strv_free_ char **paths = NULL;
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
                           TABLE_STRING, k->spec->context);
        if (r < 0)
                return table_log_add_error(r);

        if (k->exists < 0)
                r = table_add_many(t, TABLE_EMPTY);
        else
                r = table_add_many(t, TABLE_BOOLEAN_CHECKMARK, k->exists > 0);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(t, TABLE_TRISTATE, k->kernel_unsealed);
        if (r < 0)
                return table_log_add_error(r);

        if (k->members_known)
                r = table_add_many(t, TABLE_UINT64, (uint64_t) k->n_members);
        else
                r = table_add_many(t, TABLE_EMPTY);
        if (r < 0)
                return table_log_add_error(r);

        r = table_add_many(t,
                           TABLE_BOOLEAN_CHECKMARK, k->sealed,
                           TABLE_STRV, paths);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

/* Returns > 0 if a certificate could not be used */
static int process_keyring(
                struct kmod_ctx *kmod,
                const KeyringSpec *spec,
                int root_fd,
                char **os,
                Table *t) {

        _cleanup_(keyring_done) Keyring k = {
                .spec = spec,
                .exists = -1,
                .kernel_unsealed = -1,
        };
        int r;

        assert(spec);

        /* An error enumerating the certificates does not stop the sealing */
        r = collect_certificates(&k, root_fd, os);
        if (r < 0)
                RET_GATHER(k.failed, r);

        r = locate_keyring(&k, kmod);
        if (r > 0)
                r = check_unsealed(&k);

        if (arg_dry_run) {
                if (r > 0) {
                        size_t n = 0;

                        FOREACH_ARRAY(c, k.certificates, k.n_certificates)
                                if (!certificate_is_enrolled(&k, c))
                                        n++;

                        log_info("Would enroll %zu certificate(s) into keyring %s.", n, spec->name);
                }

                RET_GATHER(r, add_to_table(t, &k));
        } else if (r > 0) {
                enroll_certificates(&k);
                r = seal_keyring(&k);
        }

        if (r < 0)
                return r;
        if (k.failed < 0)
                return k.failed;

        return k.data_error;
}

/* Credentials are the way to hand a certificate to an initrd without rebuilding it. Following the
 * specification's advice for verifiers retrieved from elsewhere, they are placed into the ephemeral load
 * path as artifact verifiers. Hence, masking, merging and everything else applies to them like to any
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

        fn = strjoin(name, VOA_X509_CERTIFICATE_SUFFIX);
        if (!fn)
                return log_oom();

        /* The exact OS identifier suffices */
        path = path_join(VOA_EPHEMERAL_LOAD_PATH, os[0], spec->role, spec->context, VOA_TECHNOLOGY_X509, fn);
        if (!path)
                return log_oom();

        if (arg_dry_run) {
                log_info("Would place credential '%s' at '%s'.", cn, path);
                return 0;
        }

        size_t size;
        r = read_credential(cn, (void**) &contents, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read credential '%s': %m", cn);

        dfd = chase_and_open_parent_at(root_fd, root_fd, path, CHASE_MKDIR_0755|CHASE_SAFE|CHASE_DIR_0755,
                                       &base);
        if (dfd < 0)
                return log_error_errno(dfd, "Failed to create the directory of '%s': %m", path);

        _cleanup_free_ char *tmp = NULL;
        _cleanup_close_ int fd = open_tmpfile_linkable_at(dfd, base, O_WRONLY|O_CLOEXEC, &tmp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create '%s': %m", path);

        CLEANUP_TMPFILE_AT(dfd, tmp);

        r = loop_write(fd, contents, size);
        if (r >= 0 && (size == 0 || contents[size - 1] != '\n'))
                /* Terminate with a newline like a PEM file conventionally does */
                r = loop_write(fd, "\n", 1);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s': %m", path);

        if (fchmod(fd, 0644) < 0)
                return log_error_errno(errno, "Failed to set the mode of '%s': %m", path);

        r = link_tmpfile_at(fd, dfd, tmp, base, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to link '%s' into place: %m", path);

        tmp = mfree(tmp); /* disarm CLEANUP_TMPFILE_AT() */

        log_debug("Placed credential '%s' at '%s'.", cn, path);
        return 0;
}

static int materialize_credentials(int root_fd, char **os) {
        _cleanup_free_ DirectoryEntries *de = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r, ret = 0;

        assert(root_fd >= 0);

        fd = open_credentials_dir();
        if (fd == -ENXIO)
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open credentials directory: %m");

        if (strv_isempty(os)) {
                log_warning("There is no OS identifier to place credentials under, ignoring them.");
                return 0;
        }

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
                if (!strv_isempty(arg_keyrings) && !strv_contains(arg_keyrings, spec->name)) {
                        log_debug("Skipping credential '%s', keyring %s is not selected.", cn, spec->name);
                        continue;
                }

                r = materialize_credential(root_fd, cn, spec, name, os);
                RET_GATHER(ret, r);
        }

        return ret;
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
                return log_warning_errno(r,
                                         "Failed to read credential " CREDENTIAL_PREFIX "os, ignoring: %m");

        l = strv_split(v, WHITESPACE);
        if (!l)
                return log_oom();
        if (strv_isempty(l))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Credential " CREDENTIAL_PREFIX "os is empty, ignoring.");
        if (strv_length(l) > CREDENTIAL_OS_MAX)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Credential " CREDENTIAL_PREFIX "os lists more than %u OS "
                                         "identifiers, ignoring it.", CREDENTIAL_OS_MAX);

        STRV_FOREACH(i, l)
                if (!voa_os_is_valid(*i))
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                                 "Invalid OS identifier '%s' in credential "
                                                 CREDENTIAL_PREFIX "os, ignoring it.", *i);

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

        STRV_FOREACH(a, option_parser_get_args(&opts))
                if (!keyring_spec_from_name(*a))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown keyring: '%s'", *a);

        arg_keyrings = strv_copy(option_parser_get_args(&opts));
        if (!arg_keyrings)
                return log_oom();

        if (sd_json_format_enabled(arg_json_format_flags) && !arg_dry_run)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--json= is only supported together with --dry-run.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_strv_free_ char **os = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        int r, ret = 0; /* negative: failed, EX_DATAERR: some input could not be used */

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        LIBCRYPTO_NOTE(required);

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        LIBKMOD_NOTE(recommended);

#if HAVE_KMOD
        _cleanup_(kmod_unrefp) struct kmod_ctx *kmod = NULL;
        r = module_setup_context(&kmod);
        if (r < 0)
                log_debug_errno(r, "Failed to initialize libkmod, not loading kernel modules: %m");
#else
        struct kmod_ctx *kmod = NULL;
#endif

        root_fd = open("/", O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (root_fd < 0)
                return log_error_errno(errno, "Failed to open root directory: %m");

        r = os_from_credential(&os);
        if (r < 0)
                ret = EX_DATAERR; /* bad input, but os-release is still there */
        if (r <= 0) {
                r = voa_os_identifiers(root_fd, &os);
                if (r < 0)
                        ret = log_error_errno(r, "Failed to determine the OS identifier from os-release, "
                                              "enrolling nothing: %m");
                else if (r > 0)
                        log_warning("os-release contains characters the VOA specification does not permit, "
                                    "looking up the bare ID only. Pass the " CREDENTIAL_PREFIX "os "
                                    "credential to specify identifiers explicitly.");
        }

        /* Sealing does not depend on it either */
        r = materialize_credentials(root_fd, os);
        RET_GATHER(ret, r);

        if (arg_dry_run) {
                t = table_new("keyring", "context", "exists", "kernel unsealed", "keys", "sealed",
                              "certificates");
                if (!t)
                        return log_oom();

                table_set_ersatz_string(t, TABLE_ERSATZ_DASH);
        }

        FOREACH_ELEMENT(spec, keyring_specs) {
                if (!strv_isempty(arg_keyrings) && !strv_contains(arg_keyrings, spec->name))
                        continue;

                r = process_keyring(kmod, spec, root_fd, os, t);
                if (r > 0 && ret == 0)
                        ret = EX_DATAERR;
                else
                        RET_GATHER(ret, r);
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

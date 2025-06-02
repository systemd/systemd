/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pwd.h>
#include <sys/file.h>
#include <unistd.h>
#include "efivars.h"
#include "time-util.h"

#if HAVE_OPENSSL
#include <openssl/err.h>
#endif

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "chattr-util.h"
#include "copy.h"
#include "creds-util.h"
#include "efi-api.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "format-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "json-util.h"
#include "log.h"
#include "memory-util.h"
#include "mkdir-label.h"
#include "openssl-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "random-util.h"
#include "recurse-dir.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "tpm2-util.h"
#include "user-util.h"

#define PUBLIC_KEY_MAX (UINT32_C(1024) * UINT32_C(1024))

bool credential_name_valid(const char *s) {
        /* We want that credential names are both valid in filenames (since that's our primary way to pass
         * them around) and as fdnames (which is how we might want to pass them around eventually) */
        return filename_is_valid(s) && fdname_is_valid(s);
}

bool credential_glob_valid(const char *s) {
        const char *e, *a;
        size_t n;

        /* Checks if a credential glob expression is valid. Note that this is more restrictive than
         * fnmatch()! We only allow trailing asterisk matches for now (simply because we want some freedom
         * with automatically extending the pattern in a systematic way to cover for unit instances getting
         * per-instance credentials or similar. Moreover, credential globbing expressions are also more
         * restrictive than credential names: we don't allow *, ?, [, ] in them (except for the asterisk
         * match at the end of the string), simply to not allow ambiguity. After all, we want the flexibility
         * to one day add full globbing should the need arise.  */

        if (isempty(s))
                return false;

        /* Find first glob (or NUL byte) */
        n = strcspn(s, "*?[]");
        e = s + n;

        /* For now, only allow asterisk wildcards, and only at the end of the string. If it's anything else, refuse. */
        if (isempty(e))
                return credential_name_valid(s);

        if (!streq(e, "*")) /* only allow trailing "*", no other globs */
                return false;

        if (n == 0) /* Explicitly allow the complete wildcard. */
                return true;

        if (n > NAME_MAX + strlen(e)) /* before we make a copy on the stack, let's check this is not overly large */
                return false;

        /* Make a copy of the string without the '*' suffix */
        a = strndupa_safe(s, n);

        return credential_name_valid(a);
}

static int get_credentials_dir_internal(const char *envvar, const char **ret) {
        const char *e;

        assert(ret);

        e = secure_getenv(envvar);
        if (!e)
                return -ENXIO;

        if (!path_is_absolute(e) || !path_is_normalized(e))
                return -EINVAL;

        *ret = e;
        return 0;
}

int get_credentials_dir(const char **ret) {
        return get_credentials_dir_internal("CREDENTIALS_DIRECTORY", ret);
}

int get_encrypted_credentials_dir(const char **ret) {
        return get_credentials_dir_internal("ENCRYPTED_CREDENTIALS_DIRECTORY", ret);
}

int open_credentials_dir(void) {
        const char *d;
        int r;

        r = get_credentials_dir(&d);
        if (r < 0)
                return r;

        return RET_NERRNO(open(d, O_CLOEXEC|O_DIRECTORY));
}

int read_credential(const char *name, void **ret, size_t *ret_size) {
        _cleanup_free_ char *fn = NULL;
        const char *d;
        int r;

        assert(ret);

        if (!credential_name_valid(name))
                return -EINVAL;

        r = get_credentials_dir(&d);
        if (r < 0)
                return r;

        fn = path_join(d, name);
        if (!fn)
                return -ENOMEM;

        return read_full_file_full(
                        AT_FDCWD, fn,
                        UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE,
                        NULL,
                        (char**) ret, ret_size);
}

int read_credential_with_decryption(const char *name, void **ret, size_t *ret_size) {
        _cleanup_(iovec_done_erase) struct iovec ret_iovec = {};
        _cleanup_(erase_and_freep) void *data = NULL;
        _cleanup_free_ char *fn = NULL;
        size_t sz = 0;
        const char *d;
        int r;

        /* Just like read_credential() but will also look for encrypted credentials. Note that services only
         * receive decrypted credentials, hence use read_credential() for those. This helper here is for
         * generators, i.e. code that runs outside of service context, and thus has no decrypted credentials
         * yet.
         *
         * Note that read_credential_harder_and_warn() logs on its own, while read_credential() does not!
         * (It's a lot more complex and error prone given its TPM2 connectivity, and is generally called from
         * generators only where logging is OK).
         *
         * Error handling is also a bit different: if we can't find a credential we'll return 0 and NULL
         * pointers/zero size, rather than -ENXIO/-ENOENT. */

        if (!credential_name_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid credential name: %s", name);

        r = read_credential(name, ret, ret_size);
        if (r >= 0)
                return 1; /* found */
        if (!IN_SET(r, -ENXIO, -ENOENT))
                return log_error_errno(r, "Failed read unencrypted credential '%s': %m", name);

        r = get_encrypted_credentials_dir(&d);
        if (r == -ENXIO)
                goto not_found;
        if (r < 0)
                return log_error_errno(r, "Failed to determine encrypted credentials directory: %m");

        fn = path_join(d, name);
        if (!fn)
                return log_oom();

        r = read_full_file_full(
                        AT_FDCWD, fn,
                        UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE,
                        NULL,
                        (char**) &data, &sz);
        if (r == -ENOENT)
                goto not_found;
        if (r < 0)
                return log_error_errno(r, "Failed to read encrypted credential data: %m");

        if (geteuid() != 0)
                r = ipc_decrypt_credential(
                                name,
                                now(CLOCK_REALTIME),
                                getuid(),
                                &IOVEC_MAKE(data, sz),
                                CREDENTIAL_ANY_SCOPE,
                                &ret_iovec);
        else
                r = decrypt_credential_and_warn(
                                name,
                                now(CLOCK_REALTIME),
                                /* tpm2_device= */ NULL,
                                /* tpm2_signature_path= */ NULL,
                                getuid(),
                                &IOVEC_MAKE(data, sz),
                                CREDENTIAL_ANY_SCOPE,
                                &ret_iovec);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(ret_iovec.iov_base);
        if (ret_size)
                *ret_size = ret_iovec.iov_len;

        return 1; /* found */

not_found:
        if (ret)
                *ret = NULL;
        if (ret_size)
                *ret_size = 0;

        return 0; /* not found */
}

int read_credential_strings_many_internal(
                const char *first_name, char **first_value,
                ...) {

        _cleanup_free_ void *b = NULL;
        bool all = true;
        int r, ret = 0;

        /* Reads a bunch of credentials into the specified buffers. If the specified buffers are already
         * non-NULL frees them if a credential is found. Only supports string-based credentials
         * (i.e. refuses embedded NUL bytes).
         *
         * 0 is returned when some or all credentials are missing.
         */

        if (!first_name)
                return 0;

        r = read_credential(first_name, &b, NULL);
        if (r == -ENXIO) /* No creds passed at all? Bail immediately. */
                return 0;
        if (r == -ENOENT)
                all = false;
        else if (r < 0)
                RET_GATHER(ret, r);
        else
                free_and_replace(*first_value, b);

        va_list ap;
        va_start(ap, first_value);

        for (;;) {
                _cleanup_free_ void *bb = NULL;
                const char *name;
                char **value;

                name = va_arg(ap, const char *);
                if (!name)
                        break;

                value = ASSERT_PTR(va_arg(ap, char **));

                r = read_credential(name, &bb, NULL);
                if (r == -ENOENT)
                        all = false;
                else if (r < 0)
                        RET_GATHER(ret, r);
                else
                        free_and_replace(*value, bb);
        }

        va_end(ap);
        return ret < 0 ? ret : all;
}

int read_credential_bool(const char *name) {
        _cleanup_free_ void *data = NULL;
        int r;

        r = read_credential(name, &data, NULL);
        if (r < 0)
                return IN_SET(r, -ENXIO, -ENOENT) ? 0 : r;

        return parse_boolean(data);
}

int get_credential_user_password(const char *username, char **ret_password, bool *ret_is_hashed) {
        _cleanup_(erase_and_freep) char *creds_password = NULL;
        _cleanup_free_ char *cn = NULL;
        int r;

        /* Try to pick up the password for this account via the credentials logic */
        cn = strjoin("passwd.hashed-password.", username);
        if (!cn)
                return -ENOMEM;

        r = read_credential(cn, (void**) &creds_password, NULL);
        if (r == -ENOENT) {
                free(cn);
                cn = strjoin("passwd.plaintext-password.", username);
                if (!cn)
                        return -ENOMEM;

                r = read_credential(cn, (void**) &creds_password, NULL);
                if (r < 0)
                        log_debug_errno(r, "Couldn't read credential '%s', ignoring: %m", cn);
                else
                        *ret_is_hashed = false;
        } else if (r < 0)
                log_debug_errno(r, "Couldn't read credential '%s', ignoring: %m", cn);
        else
                *ret_is_hashed = true;

        *ret_password = TAKE_PTR(creds_password);

        return r;
}

#if HAVE_OPENSSL

#define CREDENTIAL_HOST_SECRET_SIZE 4096

static const sd_id128_t credential_app_id =
        SD_ID128_MAKE(d3,ac,ec,ba,0d,ad,4c,df,b8,c9,38,15,28,93,6c,58);

struct credential_host_secret_format {
        /* The hashed machine ID of the machine this belongs to. Why? We want to ensure that each machine
         * gets its own secret, even if people forget to flush out this secret file. Hence we bind it to the
         * machine ID, for which there's hopefully a better chance it will be flushed out. We use a hashed
         * machine ID instead of the literal one, because it's trivial to, and it might be a good idea not
         * being able to directly associate a secret key file with a host. */
        sd_id128_t machine_id;

        /* The actual secret key */
        uint8_t data[CREDENTIAL_HOST_SECRET_SIZE];
} _packed_;

static void warn_not_encrypted(int fd, CredentialSecretFlags flags, const char *dirname, const char *filename) {
        int r;

        assert(fd >= 0);
        assert(dirname);
        assert(filename);

        if (!FLAGS_SET(flags, CREDENTIAL_SECRET_WARN_NOT_ENCRYPTED))
                return;

        r = fd_is_encrypted(fd);
        if (r < 0)
                log_debug_errno(r, "Failed to determine if credential secret file '%s/%s' is encrypted.",
                                dirname, filename);
        else if (r == 0)
                log_warning("Credential secret file '%s/%s' is not located on encrypted media, using anyway.",
                            dirname, filename);
}

static int make_credential_host_secret(
                int dfd,
                const sd_id128_t machine_id,
                CredentialSecretFlags flags,
                const char *dirname,
                const char *fn,
                struct iovec *ret) {

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dfd >= 0);
        assert(fn);

        fd = open_tmpfile_linkable_at(dfd, fn, O_CLOEXEC|O_WRONLY, &t);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to create temporary file for credential host secret: %m");

        r = chattr_secret(fd, 0);
        if (r < 0)
                log_debug_errno(r, "Failed to set file attributes for secrets file, ignoring: %m");

        struct credential_host_secret_format buf = {
                .machine_id = machine_id,
        };

        CLEANUP_ERASE(buf);

        r = crypto_random_bytes(buf.data, sizeof(buf.data));
        if (r < 0)
                goto fail;

        r = loop_write(fd, &buf, sizeof(buf));
        if (r < 0)
                goto fail;

        if (fchmod(fd, 0400) < 0) {
                r = -errno;
                goto fail;
        }

        if (fsync(fd) < 0) {
                r = -errno;
                goto fail;
        }

        warn_not_encrypted(fd, flags, dirname, fn);

        r = link_tmpfile_at(fd, dfd, t, fn, LINK_TMPFILE_SYNC);
        if (r < 0) {
                log_debug_errno(r, "Failed to link host key into place: %m");
                goto fail;
        }

        if (ret) {
                void *copy;

                copy = memdup(buf.data, sizeof(buf.data));
                if (!copy)
                        return -ENOMEM;

                *ret = IOVEC_MAKE(copy, sizeof(buf.data));
        }

        return 0;

fail:
        if (t && unlinkat(dfd, t, 0) < 0)
                log_debug_errno(errno, "Failed to remove temporary credential key: %m");

        return r;
}

int get_credential_host_secret(CredentialSecretFlags flags, struct iovec *ret) {
        _cleanup_free_ char *_dirname = NULL, *_filename = NULL;
        _cleanup_close_ int dfd = -EBADF;
        sd_id128_t machine_id;
        const char *dirname, *filename;
        int r;

        r = sd_id128_get_machine_app_specific(credential_app_id, &machine_id);
        if (r < 0)
                return r;

        const char *e = secure_getenv("SYSTEMD_CREDENTIAL_SECRET");
        if (e) {
                if (!path_is_normalized(e))
                        return -EINVAL;
                if (!path_is_absolute(e))
                        return -EINVAL;

                r = path_extract_directory(e, &_dirname);
                if (r < 0)
                        return r;

                r = path_extract_filename(e, &_filename);
                if (r < 0)
                        return r;

                dirname = _dirname;
                filename = _filename;
        } else {
                dirname = "/var/lib/systemd";
                filename = "credential.secret";
        }

        assert(dirname);
        assert(filename);

        mkdir_parents(dirname, 0755);
        dfd = open_mkdir(dirname, O_CLOEXEC, 0755);
        if (dfd < 0)
                return log_debug_errno(dfd, "Failed to create or open directory '%s': %m", dirname);

        if (FLAGS_SET(flags, CREDENTIAL_SECRET_FAIL_ON_TEMPORARY_FS)) {
                r = fd_is_temporary_fs(dfd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to check directory '%s': %m", dirname);
                if (r > 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                               "Directory '%s' is on a temporary file system, refusing.", dirname);
        }

        for (unsigned attempt = 0;; attempt++) {
                _cleanup_(erase_and_freep) struct credential_host_secret_format *f = NULL;
                _cleanup_close_ int fd = -EBADF;
                size_t l = 0;
                ssize_t n = 0;
                struct stat st;

                if (attempt >= 3) /* Somebody is playing games with us */
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                               "All attempts to create secret store in %s failed.", dirname);

                fd = openat(dfd, filename, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW);
                if (fd < 0) {
                        if (errno != ENOENT || !FLAGS_SET(flags, CREDENTIAL_SECRET_GENERATE))
                                return log_debug_errno(errno,
                                                       "Failed to open %s/%s: %m", dirname, filename);

                        r = make_credential_host_secret(dfd, machine_id, flags, dirname, filename, ret);
                        if (r == -EEXIST) {
                                log_debug_errno(r, "Credential secret %s/%s appeared while we were creating it, rereading.",
                                                dirname, filename);
                                continue;
                        }
                        if (r < 0)
                                return log_debug_errno(r, "Failed to create credential secret %s/%s: %m",
                                                       dirname, filename);
                        return 0;
                }

                if (fstat(fd, &st) < 0)
                        return log_debug_errno(errno, "Failed to stat %s/%s: %m", dirname, filename);

                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_debug_errno(r, "%s/%s is not a regular file: %m", dirname, filename);
                if (st.st_nlink == 0) /* Deleted by now, try again */
                        continue;
                if (st.st_nlink > 1)
                        /* Our deletion check won't work if hardlinked somewhere else */
                        return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                               "%s/%s has too many links, refusing.",
                                               dirname, filename);
                if ((st.st_mode & 07777) != 0400)
                        /* Don't use file if not 0400 access mode */
                        return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                               "%s/%s has permissive access mode, refusing.",
                                               dirname, filename);
                l = st.st_size;
                if (l < offsetof(struct credential_host_secret_format, data) + 1)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s/%s is too small, refusing.", dirname, filename);
                if (l > 16*1024*1024)
                        return log_debug_errno(SYNTHETIC_ERRNO(E2BIG),
                                               "%s/%s is too big, refusing.", dirname, filename);

                f = malloc(l+1);
                if (!f)
                        return log_oom_debug();

                n = read(fd, f, l+1);
                if (n < 0)
                        return log_debug_errno(errno,
                                               "Failed to read %s/%s: %m", dirname, filename);
                if ((size_t) n != l) /* What? The size changed? */
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to read %s/%s.", dirname, filename);

                if (sd_id128_equal(machine_id, f->machine_id)) {
                        size_t sz;

                        warn_not_encrypted(fd, flags, dirname, filename);

                        sz = l - offsetof(struct credential_host_secret_format, data);
                        assert(sz > 0);

                        if (ret) {
                                void *copy;

                                assert(sz <= sizeof(f->data)); /* Ensure we don't read past f->data bounds */

                                copy = memdup(f->data, sz);
                                if (!copy)
                                        return log_oom_debug();

                                *ret = IOVEC_MAKE(copy, sz);
                        }

                        return 0;
                }

                /* Hmm, this secret is from somewhere else. Let's delete the file. Let's first acquire a lock
                 * to ensure we are the only ones accessing the file while we delete it. */

                if (flock(fd, LOCK_EX) < 0)
                        return log_debug_errno(errno,
                                               "Failed to flock %s/%s: %m", dirname, filename);

                /* Before we delete it check that the file is still linked into the file system */
                if (fstat(fd, &st) < 0)
                        return log_debug_errno(errno, "Failed to stat %s/%s: %m", dirname, filename);
                if (st.st_nlink == 0) /* Already deleted by now? */
                        continue;
                if (st.st_nlink != 1) /* Safety check, someone is playing games with us */
                        return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                               "%s/%s unexpectedly has too many links.",
                                               dirname, filename);
                if (unlinkat(dfd, filename, 0) < 0)
                        return log_debug_errno(errno, "Failed to unlink %s/%s: %m", dirname, filename);

                /* And now try again */
        }
}

/* Construction is like this:
 *
 * A symmetric encryption key is derived from:
 *
 *      1. Either the "host" key (a key stored in /var/lib/credential.secret)
 *
 *      2. A key generated by letting the TPM2 calculate an HMAC hash of some nonce we pass to it, keyed
 *         by a key derived from its internal seed key.
 *
 *      3. The concatenation of the above.
 *
 *      4. Or a fixed "empty" key. This will not provide confidentiality or authenticity, of course, but is
 *         useful to encode credentials for the initrd on TPM-less systems, where we simply have no better
 *         concept to bind things to. Note that decryption of a key set up like this will be refused on
 *         systems that have a TPM and have SecureBoot enabled.
 *
 * The above is hashed with SHA256 which is then used as encryption key for AES256-GCM. The encrypted
 * credential is a short (unencrypted) header describing which of the three keys to use, the IV to use for
 * AES256-GCM and some more meta information (sizes of certain objects) that is strictly speaking redundant,
 * but kinda nice to have since we can have a more generic parser. If the TPM2 key is used this is followed
 * by another (unencrypted) header, with information about the TPM2 policy used (specifically: the PCR mask
 * to bind against, and a hash of the resulting policy — the latter being redundant, but speeding up things a
 * bit, since we can more quickly refuse PCR state), followed by a sealed/exported TPM2 HMAC key. This is
 * then followed by the encrypted data, which begins with a metadata header (which contains validity
 * timestamps as well as the credential name), followed by the actual credential payload. The file ends in
 * the AES256-GCM tag. To make things simple, the AES256-GCM AAD covers the main and the TPM2 header in
 * full. This means the whole file is either protected by AAD, or is ciphertext, or is the tag. No
 * unprotected data is included.
 */

struct _packed_ encrypted_credential_header {
        sd_id128_t id;
        le32_t key_size;
        le32_t block_size;
        le32_t iv_size;
        le32_t tag_size;
        uint8_t iv[];
        /* Followed by NUL bytes until next 8 byte boundary */
};

struct _packed_ tpm2_credential_header {
        le64_t pcr_mask;    /* Note that the spec for PC Clients only mandates 24 PCRs, and that's what systems
                             * generally have. But keep the door open for more. */
        le16_t pcr_bank;    /* For now, either TPM2_ALG_SHA256 or TPM2_ALG_SHA1 */
        le16_t primary_alg; /* Primary key algorithm (either TPM2_ALG_RSA or TPM2_ALG_ECC for now) */
        le32_t blob_size;
        le32_t policy_hash_size;
        uint8_t policy_hash_and_blob[];
        /* Followed by NUL bytes until next 8 byte boundary */
};

struct _packed_ tpm2_public_key_credential_header {
        le64_t pcr_mask;      /* PCRs used for the public key PCR policy (usually just PCR 11, i.e. the unified kernel) */
        le32_t size;          /* Size of DER public key */
        uint8_t data[];       /* DER public key */
        /* Followed by NUL bytes until next 8 byte boundary */
};

struct _packed_ scoped_credential_header {
        le64_t flags;         /* SCOPE_HASH_DATA_BASE_FLAGS for now */
};

/* This header is encrypted */
struct _packed_ metadata_credential_header {
        le64_t timestamp;
        le64_t not_after;
        le32_t name_size;
        char name[];
        /* Followed by NUL bytes until next 8 byte boundary */
};

struct _packed_ scoped_hash_data {
        le64_t flags;         /* copy of the scoped_credential_header.flags */
        le32_t uid;
        sd_id128_t machine_id;
        char username[];      /* followed by the username */
        /* Later on we might want to extend this: with a cgroup path to allow per-app secrets, and with the user's $HOME encryption key */
};

enum {
        /* Flags for scoped_hash_data.flags and scoped_credential_header.flags */
        SCOPE_HASH_DATA_HAS_UID      = 1 << 0,
        SCOPE_HASH_DATA_HAS_MACHINE  = 1 << 1,
        SCOPE_HASH_DATA_HAS_USERNAME = 1 << 2,

        SCOPE_HASH_DATA_BASE_FLAGS = SCOPE_HASH_DATA_HAS_UID | SCOPE_HASH_DATA_HAS_USERNAME | SCOPE_HASH_DATA_HAS_MACHINE,
};

/* Some generic limit for parts of the encrypted credential for which we don't know the right size ahead of
 * time, but where we are really sure it won't be larger than this. Should be larger than any possible IV,
 * padding, tag size and so on. This is purely used for early filtering out of invalid sizes. */
#define CREDENTIAL_FIELD_SIZE_MAX (16U*1024U)

static int sha256_hash_host_and_tpm2_key(
                const struct iovec *host_key,
                const struct iovec *tpm2_key,
                uint8_t ret[static SHA256_DIGEST_LENGTH]) {

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *md = NULL;
        unsigned l;

        assert(iovec_is_valid(host_key));
        assert(iovec_is_valid(tpm2_key));
        assert(ret);

        /* Combines the host key and the TPM2 HMAC hash into a SHA256 hash value we'll use as symmetric encryption key. */

        md = EVP_MD_CTX_new();
        if (!md)
                return log_oom();

        if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initial SHA256 context.");

        if (iovec_is_set(host_key) && EVP_DigestUpdate(md, host_key->iov_base, host_key->iov_len) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash host key.");

        if (iovec_is_set(tpm2_key) && EVP_DigestUpdate(md, tpm2_key->iov_base, tpm2_key->iov_len) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash TPM2 key.");

        assert(EVP_MD_CTX_size(md) == SHA256_DIGEST_LENGTH);

        if (EVP_DigestFinal_ex(md, ret, &l) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize SHA256 hash.");

        assert(l == SHA256_DIGEST_LENGTH);
        return 0;
}

static int mangle_uid_into_key(
                uid_t uid,
                uint8_t md[static SHA256_DIGEST_LENGTH]) {

        sd_id128_t mid;
        int r;

        assert(uid_is_valid(uid));
        assert(md);

        /* If we shall encrypt for a specific user, we HMAC() a structure with the user's credentials
         * (specifically, UID, user name, machine ID) with the key we'd otherwise use for system credentials,
         * and use the resulting hash as actual encryption key. */

        errno = 0;
        struct passwd *pw = getpwuid(uid);
        if (!pw)
                return log_error_errno(
                                IN_SET(errno, 0, ENOENT) ? SYNTHETIC_ERRNO(ESRCH) : errno,
                                "Failed to resolve UID " UID_FMT ": %m", uid);

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return log_error_errno(r, "Failed to read machine ID: %m");

        size_t sz = offsetof(struct scoped_hash_data, username) + strlen(pw->pw_name) + 1;
        _cleanup_free_ struct scoped_hash_data *d = malloc0(sz);
        if (!d)
                return log_oom();

        d->flags = htole64(SCOPE_HASH_DATA_BASE_FLAGS);
        d->uid = htole32(uid);
        d->machine_id = mid;

        strcpy(d->username, pw->pw_name);

        _cleanup_(erase_and_freep) void *buf = NULL;
        size_t buf_size = 0;
        r = openssl_hmac_many(
                        "sha256",
                        md, SHA256_DIGEST_LENGTH,
                        &IOVEC_MAKE(d, sz), 1,
                        &buf, &buf_size);
        if (r < 0)
                return r;

        assert(buf_size == SHA256_DIGEST_LENGTH);
        memcpy(md, buf, buf_size);

        return 0;
}

int encrypt_credential_and_warn(
                sd_id128_t with_key,
                const char *name,
                usec_t timestamp,
                usec_t not_after,
                const char *tpm2_device,
                uint32_t tpm2_hash_pcr_mask,
                const char *tpm2_pubkey_path,
                uint32_t tpm2_pubkey_pcr_mask,
                uid_t uid,
                const struct iovec *input,
                CredentialFlags flags,
                struct iovec *ret) {

        _cleanup_(iovec_done) struct iovec tpm2_blob = {}, tpm2_policy_hash = {}, iv = {}, pubkey = {};
        _cleanup_(iovec_done_erase) struct iovec tpm2_key = {}, output = {}, host_key = {};
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_free_ struct metadata_credential_header *m = NULL;
#if HAVE_TPM2
        uint16_t tpm2_pcr_bank = 0, tpm2_primary_alg = 0;
#endif
        struct encrypted_credential_header *h;
        int ksz, bsz, ivsz, tsz, added, r;
        uint8_t md[SHA256_DIGEST_LENGTH];
        const EVP_CIPHER *cc;
        sd_id128_t id;
        size_t p, ml;

        assert(iovec_is_valid(input));
        assert(ret);

        if (!sd_id128_in_set(with_key,
                             _CRED_AUTO,
                             _CRED_AUTO_INITRD,
                             _CRED_AUTO_SCOPED,
                             CRED_AES256_GCM_BY_HOST,
                             CRED_AES256_GCM_BY_HOST_SCOPED,
                             CRED_AES256_GCM_BY_TPM2_HMAC,
                             CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                             CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                             CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED,
                             CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK,
                             CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED,
                             CRED_AES256_GCM_BY_NULL))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid key type: " SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(with_key));

        if (name && !credential_name_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid credential name: %s", name);

        if (not_after != USEC_INFINITY && timestamp != USEC_INFINITY && not_after < timestamp)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential is invalidated before it is valid (" USEC_FMT " < " USEC_FMT ").", not_after, timestamp);

        if (DEBUG_LOGGING) {
                char buf[FORMAT_TIMESTAMP_MAX];

                if (name)
                        log_debug("Including credential name '%s' in encrypted credential.", name);
                if (timestamp != USEC_INFINITY)
                        log_debug("Including timestamp '%s' in encrypted credential.", format_timestamp(buf, sizeof(buf), timestamp));
                if (not_after != USEC_INFINITY)
                        log_debug("Including not-after timestamp '%s' in encrypted credential.", format_timestamp(buf, sizeof(buf), not_after));
        }

        if (sd_id128_in_set(with_key,
                            _CRED_AUTO_SCOPED,
                            CRED_AES256_GCM_BY_HOST_SCOPED,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED)) {
                if (!uid_is_valid(uid))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Scoped credential key type "SD_ID128_FORMAT_STR" selected, but no UID specified.", SD_ID128_FORMAT_VAL(with_key));
        } else
                uid = UID_INVALID;

        if (sd_id128_in_set(with_key,
                            _CRED_AUTO,
                            _CRED_AUTO_SCOPED,
                            CRED_AES256_GCM_BY_HOST,
                            CRED_AES256_GCM_BY_HOST_SCOPED,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED)) {

                r = get_credential_host_secret(
                                CREDENTIAL_SECRET_GENERATE|
                                CREDENTIAL_SECRET_WARN_NOT_ENCRYPTED|
                                (sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_SCOPED) ? CREDENTIAL_SECRET_FAIL_ON_TEMPORARY_FS : 0),
                                &host_key);
                if (r == -ENOMEDIUM && sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_SCOPED))
                        log_debug_errno(r, "Credential host secret location on temporary file system, not using.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to determine local credential host secret: %m");
        }

#if HAVE_TPM2
        bool try_tpm2;
        if (sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_INITRD, _CRED_AUTO_SCOPED)) {
                /* If automatic mode is selected lets see if a TPM2 it is present. If we are running in a
                 * container tpm2_support will detect this, and will return a different flag combination of
                 * TPM2_SUPPORT_FULL, effectively skipping the use of TPM2 when inside one. */

                try_tpm2 = tpm2_is_fully_supported();
                if (!try_tpm2)
                        log_debug("System lacks TPM2 support or running in a container, not attempting to use TPM2.");
        } else
                try_tpm2 = sd_id128_in_set(with_key,
                                           CRED_AES256_GCM_BY_TPM2_HMAC,
                                           CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                                           CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                                           CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED,
                                           CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK,
                                           CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED);

        if (try_tpm2) {
                if (sd_id128_in_set(with_key,
                                    _CRED_AUTO,
                                    _CRED_AUTO_INITRD,
                                    _CRED_AUTO_SCOPED,
                                    CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                                    CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK,
                                    CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED)) {

                        /* Load public key for PCR policies, if one is specified, or explicitly requested */

                        r = tpm2_load_pcr_public_key(tpm2_pubkey_path, &pubkey.iov_base, &pubkey.iov_len);
                        if (r < 0) {
                                if (tpm2_pubkey_path || r != -ENOENT || !sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_INITRD, _CRED_AUTO_SCOPED))
                                        return log_error_errno(r, "Failed read TPM PCR public key: %m");

                                log_debug_errno(r, "Failed to read TPM2 PCR public key, proceeding without: %m");
                        }
                }

                if (!iovec_is_set(&pubkey))
                        tpm2_pubkey_pcr_mask = 0;

                _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
                r = tpm2_context_new_or_warn(tpm2_device, &tpm2_context);
                if (r < 0)
                        return r;

                r = tpm2_get_best_pcr_bank(tpm2_context, tpm2_hash_pcr_mask | tpm2_pubkey_pcr_mask, &tpm2_pcr_bank);
                if (r < 0)
                        return log_error_errno(r, "Could not find best pcr bank: %m");

                TPML_PCR_SELECTION tpm2_hash_pcr_selection;
                tpm2_tpml_pcr_selection_from_mask(tpm2_hash_pcr_mask, tpm2_pcr_bank, &tpm2_hash_pcr_selection);

                _cleanup_free_ Tpm2PCRValue *tpm2_hash_pcr_values = NULL;
                size_t tpm2_n_hash_pcr_values;
                r = tpm2_pcr_read(tpm2_context, &tpm2_hash_pcr_selection, &tpm2_hash_pcr_values, &tpm2_n_hash_pcr_values);
                if (r < 0)
                        return log_error_errno(r, "Could not read PCR values: %m");

                TPM2B_PUBLIC public;
                if (iovec_is_set(&pubkey)) {
                        r = tpm2_tpm2b_public_from_pem(pubkey.iov_base, pubkey.iov_len, &public);
                        if (r < 0)
                                return log_error_errno(r, "Could not convert public key to TPM2B_PUBLIC: %m");
                }

                TPM2B_DIGEST tpm2_policy = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);
                r = tpm2_calculate_sealing_policy(
                                tpm2_hash_pcr_values,
                                tpm2_n_hash_pcr_values,
                                iovec_is_set(&pubkey) ? &public : NULL,
                                /* use_pin= */ false,
                                /* pcrlock_policy= */ NULL,
                                &tpm2_policy);
                if (r < 0)
                        return log_error_errno(r, "Could not calculate sealing policy digest: %m");

                struct iovec *blobs = NULL;
                size_t n_blobs = 0;
                CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);

                r = tpm2_seal(tpm2_context,
                              /* seal_key_handle= */ 0,
                              &tpm2_policy,
                              /* n_policy= */ 1,
                              /* pin= */ NULL,
                              &tpm2_key,
                              &blobs,
                              &n_blobs,
                              &tpm2_primary_alg,
                              /* ret_srk= */ NULL);
                if (r < 0) {
                        if (sd_id128_equal(with_key, _CRED_AUTO_INITRD))
                                log_warning("TPM2 present and used, but we didn't manage to talk to it. Credential will be refused if SecureBoot is enabled.");
                        else if (!sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_SCOPED))
                                return log_error_errno(r, "Failed to seal to TPM2: %m");

                        log_notice_errno(r, "TPM2 sealing didn't work, continuing without TPM2: %m");
                }

                if (!iovec_memdup(&IOVEC_MAKE(tpm2_policy.buffer, tpm2_policy.size), &tpm2_policy_hash))
                        return log_oom();

                assert(n_blobs == 1);
                tpm2_blob = TAKE_STRUCT(blobs[0]);

                assert(tpm2_blob.iov_len <= CREDENTIAL_FIELD_SIZE_MAX);
                assert(tpm2_policy_hash.iov_len <= CREDENTIAL_FIELD_SIZE_MAX);
        }
#endif

        if (sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_INITRD, _CRED_AUTO_SCOPED)) {
                /* Let's settle the key type in auto mode now. */

                if (iovec_is_set(&host_key) && iovec_is_set(&tpm2_key))
                        id = iovec_is_set(&pubkey) ? (sd_id128_equal(with_key, _CRED_AUTO_SCOPED) ?
                                                      CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED : CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK)
                                                   : (sd_id128_equal(with_key, _CRED_AUTO_SCOPED) ?
                                                      CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED : CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC);
                else if (iovec_is_set(&tpm2_key) && !sd_id128_equal(with_key, _CRED_AUTO_SCOPED))
                        id = iovec_is_set(&pubkey) ? CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK : CRED_AES256_GCM_BY_TPM2_HMAC;
                else if (iovec_is_set(&host_key))
                        id = sd_id128_equal(with_key, _CRED_AUTO_SCOPED) ? CRED_AES256_GCM_BY_HOST_SCOPED : CRED_AES256_GCM_BY_HOST;
                else if (sd_id128_equal(with_key, _CRED_AUTO_INITRD))
                        id = CRED_AES256_GCM_BY_NULL;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "TPM2 not available and host key located on temporary file system, no encryption key available.");
        } else
                id = with_key;

        if (sd_id128_equal(id, CRED_AES256_GCM_BY_NULL) && !FLAGS_SET(flags, CREDENTIAL_ALLOW_NULL))
                log_warning("Using a null key for encryption and signing. Confidentiality or authenticity will not be provided.");

        /* Let's now take the host key and the TPM2 key and hash it together, to use as encryption key for the data */
        r = sha256_hash_host_and_tpm2_key(&host_key, &tpm2_key, md);
        if (r < 0)
                return r;

        if (uid_is_valid(uid)) {
                r = mangle_uid_into_key(uid, md);
                if (r < 0)
                        return r;
        }

        assert_se(cc = EVP_aes_256_gcm());

        ksz = EVP_CIPHER_key_length(cc);
        assert(ksz == sizeof(md));

        bsz = EVP_CIPHER_block_size(cc);
        assert(bsz > 0);
        assert((size_t) bsz <= CREDENTIAL_FIELD_SIZE_MAX);

        ivsz = EVP_CIPHER_iv_length(cc);
        if (ivsz > 0) {
                assert((size_t) ivsz <= CREDENTIAL_FIELD_SIZE_MAX);

                r = crypto_random_bytes_allocate_iovec(ivsz, &iv);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquired randomized IV: %m");
        }

        tsz = 16; /* FIXME: On OpenSSL 3 there is EVP_CIPHER_CTX_get_tag_length(), until then let's hardcode this */

        context = EVP_CIPHER_CTX_new();
        if (!context)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to allocate encryption object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_EncryptInit_ex(context, cc, NULL, md, iv.iov_base) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize encryption context: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        /* Just an upper estimate */
        output.iov_len =
                ALIGN8(offsetof(struct encrypted_credential_header, iv) + ivsz) +
                ALIGN8(iovec_is_set(&tpm2_key) ? offsetof(struct tpm2_credential_header, policy_hash_and_blob) + tpm2_blob.iov_len + tpm2_policy_hash.iov_len : 0) +
                ALIGN8(iovec_is_set(&pubkey) ? offsetof(struct tpm2_public_key_credential_header, data) + pubkey.iov_len : 0) +
                ALIGN8(uid_is_valid(uid) ? sizeof(struct scoped_credential_header) : 0) +
                ALIGN8(offsetof(struct metadata_credential_header, name) + strlen_ptr(name)) +
                input->iov_len + 2U * (size_t) bsz +
                tsz;

        output.iov_base = malloc0(output.iov_len);
        if (!output.iov_base)
                return log_oom();

        h = (struct encrypted_credential_header*) output.iov_base;
        h->id = id;
        h->block_size = htole32(bsz);
        h->key_size = htole32(ksz);
        h->tag_size = htole32(tsz);
        h->iv_size = htole32(ivsz);
        memcpy(h->iv, iv.iov_base, ivsz);

        p = ALIGN8(offsetof(struct encrypted_credential_header, iv) + ivsz);

#if HAVE_TPM2
        if (iovec_is_set(&tpm2_key)) {
                struct tpm2_credential_header *t;

                t = (struct tpm2_credential_header*) ((uint8_t*) output.iov_base + p);
                t->pcr_mask = htole64(tpm2_hash_pcr_mask);
                t->pcr_bank = htole16(tpm2_pcr_bank);
                t->primary_alg = htole16(tpm2_primary_alg);
                t->blob_size = htole32(tpm2_blob.iov_len);
                t->policy_hash_size = htole32(tpm2_policy_hash.iov_len);
                memcpy(t->policy_hash_and_blob, tpm2_blob.iov_base, tpm2_blob.iov_len);
                memcpy(t->policy_hash_and_blob + tpm2_blob.iov_len, tpm2_policy_hash.iov_base, tpm2_policy_hash.iov_len);

                p += ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) + tpm2_blob.iov_len + tpm2_policy_hash.iov_len);
        }
#endif
        if (iovec_is_set(&pubkey)) {
                struct tpm2_public_key_credential_header *z;

                z = (struct tpm2_public_key_credential_header*) ((uint8_t*) output.iov_base + p);
                z->pcr_mask = htole64(tpm2_pubkey_pcr_mask);
                z->size = htole32(pubkey.iov_len);
                memcpy(z->data, pubkey.iov_base, pubkey.iov_len);

                p += ALIGN8(offsetof(struct tpm2_public_key_credential_header, data) + pubkey.iov_len);
        }

        if (uid_is_valid(uid)) {
                struct scoped_credential_header *w;

                w = (struct scoped_credential_header*) ((uint8_t*) output.iov_base + p);
                w->flags = htole64(SCOPE_HASH_DATA_BASE_FLAGS);

                p += ALIGN8(sizeof(struct scoped_credential_header));
        }

        /* Pass the encrypted + TPM2 header + scoped header as AAD */
        if (EVP_EncryptUpdate(context, NULL, &added, output.iov_base, p) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to write AAD data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        /* Now construct the metadata header */
        ml = strlen_ptr(name);
        m = malloc0(ALIGN8(offsetof(struct metadata_credential_header, name) + ml));
        if (!m)
                return log_oom();

        m->timestamp = htole64(timestamp);
        m->not_after = htole64(not_after);
        m->name_size = htole32(ml);
        memcpy_safe(m->name, name, ml);

        /* And encrypt the metadata header */
        if (EVP_EncryptUpdate(context, (uint8_t*) output.iov_base + p, &added, (const unsigned char*) m, ALIGN8(offsetof(struct metadata_credential_header, name) + ml)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt metadata header: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= output.iov_len - p);
        p += added;

        /* Then encrypt the plaintext */
        if (EVP_EncryptUpdate(context, (uint8_t*) output.iov_base + p, &added, input->iov_base, input->iov_len) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= output.iov_len - p);
        p += added;

        /* Finalize */
        if (EVP_EncryptFinal_ex(context, (uint8_t*) output.iov_base + p, &added) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize data encryption: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= output.iov_len - p);
        p += added;

        assert(p <= output.iov_len - tsz);

        /* Append tag */
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, tsz, (uint8_t*) output.iov_base + p) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get tag: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        p += tsz;
        assert(p <= output.iov_len);
        output.iov_len = p;

        if (DEBUG_LOGGING && input->iov_len > 0) {
                size_t base64_size;

                base64_size = DIV_ROUND_UP(output.iov_len * 4, 3); /* Include base64 size increase in debug output */
                assert(base64_size >= input->iov_len);
                log_debug("Input of %zu bytes grew to output of %zu bytes (+%2zu%%).", input->iov_len, base64_size, base64_size * 100 / input->iov_len - 100);
        }

        *ret = TAKE_STRUCT(output);
        return 0;
}

int decrypt_credential_and_warn(
                const char *validate_name,
                usec_t validate_timestamp,
                const char *tpm2_device,
                const char *tpm2_signature_path,
                uid_t uid,
                const struct iovec *input,
                CredentialFlags flags,
                struct iovec *ret) {

        _cleanup_(iovec_done_erase) struct iovec host_key = {}, plaintext = {}, tpm2_key = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *signature_json = NULL;
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        struct encrypted_credential_header *h;
        struct metadata_credential_header *m;
        uint8_t md[SHA256_DIGEST_LENGTH];
        bool with_tpm2, with_tpm2_pk, with_host_key, with_null, with_scope;
        const EVP_CIPHER *cc;
        size_t p, hs;
        int r, added;

        assert(iovec_is_valid(input));
        assert(ret);

        h = (struct encrypted_credential_header*) input->iov_base;

        /* The ID must fit in, for the current and all future formats */
        if (input->iov_len < sizeof(h->id))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

        with_host_key = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_HOST, CRED_AES256_GCM_BY_HOST_SCOPED, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED);
        with_tpm2_pk = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED);
        with_tpm2 = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_TPM2_HMAC, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED) || with_tpm2_pk;
        with_null = sd_id128_equal(h->id, CRED_AES256_GCM_BY_NULL);
        with_scope = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_HOST_SCOPED, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED);

        if (!with_host_key && !with_tpm2 && !with_null)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unknown encryption format, or corrupted data.");

        if (with_tpm2_pk) {
                r = tpm2_load_pcr_signature(tpm2_signature_path, &signature_json);
                if (r < 0)
                        return log_error_errno(r, "Failed to load pcr signature: %m");
        }

        if (with_null && !FLAGS_SET(flags, CREDENTIAL_ALLOW_NULL)) {
                /* So this is a credential encrypted with a zero length key. We support this to cover for the
                 * case where neither a host key not a TPM2 are available (specifically: initrd environments
                 * where the host key is not yet accessible and no TPM2 chip exists at all), to minimize
                 * different codeflow for TPM2 and non-TPM2 codepaths. Of course, credentials encoded this
                 * way offer no confidentiality nor authenticity. Because of that it's important we refuse to
                 * use them on systems that actually *do* have a TPM2 chip – if we are in SecureBoot
                 * mode. Otherwise an attacker could hand us credentials like this and we'd use them thinking
                 * they are trusted, even though they are not. */

                if (efi_has_tpm2()) {
                        if (is_efi_secure_boot())
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Credential uses fixed key for fallback use when TPM2 is absent — but TPM2 is present, and SecureBoot is enabled, refusing.");

                        log_warning("Credential uses fixed key for use when TPM2 is absent, but TPM2 is present! Accepting anyway, since SecureBoot is disabled.");
                } else
                        log_debug("Credential uses fixed key for use when TPM2 is absent, and TPM2 indeed is absent. Accepting.");
        }

        if (with_scope) {
                if (!uid_is_valid(uid))
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Encrypted file is scoped to a user, but no user selected.");
        } else {
                /* Refuse to unlock system credentials if user scope is requested. */
                if (uid_is_valid(uid) && !FLAGS_SET(flags, CREDENTIAL_ANY_SCOPE))
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Encrypted file is scoped to the system, but user scope selected.");

                uid = UID_INVALID;
        }

        /* Now we know the minimum header size */
        if (input->iov_len < offsetof(struct encrypted_credential_header, iv))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

        /* Verify some basic header values */
        if (le32toh(h->key_size) != sizeof(md))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected key size in header.");
        if (le32toh(h->block_size) <= 0 || le32toh(h->block_size) > CREDENTIAL_FIELD_SIZE_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected block size in header.");
        if (le32toh(h->iv_size) > CREDENTIAL_FIELD_SIZE_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "IV size too large.");
        if (le32toh(h->tag_size) != 16) /* FIXME: On OpenSSL 3, let's verify via EVP_CIPHER_CTX_get_tag_length() */
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected tag size in header.");

        /* Ensure we have space for the full header now (we don't know the size of the name hence this is a
         * lower limit only) */
        if (input->iov_len <
            ALIGN8(offsetof(struct encrypted_credential_header, iv) + le32toh(h->iv_size)) +
            ALIGN8(with_tpm2 ? offsetof(struct tpm2_credential_header, policy_hash_and_blob) : 0) +
            ALIGN8(with_tpm2_pk ? offsetof(struct tpm2_public_key_credential_header, data) : 0) +
            ALIGN8(with_scope ? sizeof(struct scoped_credential_header) : 0) +
            ALIGN8(offsetof(struct metadata_credential_header, name)) +
            le32toh(h->tag_size))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

        p = ALIGN8(offsetof(struct encrypted_credential_header, iv) + le32toh(h->iv_size));

        if (with_tpm2) {
#if HAVE_TPM2
                struct tpm2_credential_header* t = (struct tpm2_credential_header*) ((uint8_t*) input->iov_base + p);
                struct tpm2_public_key_credential_header *z = NULL;

                if (!TPM2_PCR_MASK_VALID(t->pcr_mask))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "TPM2 PCR mask out of range.");
                if (!tpm2_hash_alg_to_string(le16toh(t->pcr_bank)))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "TPM2 PCR bank invalid or not supported");
                if (!tpm2_asym_alg_to_string(le16toh(t->primary_alg)))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "TPM2 primary key algorithm invalid or not supported.");
                if (le32toh(t->blob_size) > CREDENTIAL_FIELD_SIZE_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected TPM2 blob size.");
                if (le32toh(t->policy_hash_size) > CREDENTIAL_FIELD_SIZE_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected TPM2 policy hash size.");

                /* Ensure we have space for the full TPM2 header now (still don't know the name, and its size
                 * though, hence still just a lower limit test only) */
                if (input->iov_len <
                    p +
                    ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) + le32toh(t->blob_size) + le32toh(t->policy_hash_size)) +
                    ALIGN8(with_tpm2_pk ? offsetof(struct tpm2_public_key_credential_header, data) : 0) +
                    ALIGN8(with_scope ? sizeof(struct scoped_credential_header) : 0) +
                    ALIGN8(offsetof(struct metadata_credential_header, name)) +
                    le32toh(h->tag_size))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

                p += ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) +
                            le32toh(t->blob_size) +
                            le32toh(t->policy_hash_size));

                if (with_tpm2_pk) {
                        z = (struct tpm2_public_key_credential_header*) ((uint8_t*) input->iov_base + p);

                        if (!TPM2_PCR_MASK_VALID(le64toh(z->pcr_mask)) || le64toh(z->pcr_mask) == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "TPM2 PCR mask out of range.");
                        if (le32toh(z->size) > PUBLIC_KEY_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected public key size.");

                        if (input->iov_len <
                            p +
                            ALIGN8(offsetof(struct tpm2_public_key_credential_header, data) + le32toh(z->size)) +
                            ALIGN8(with_scope ? sizeof(struct scoped_credential_header) : 0) +
                            ALIGN8(offsetof(struct metadata_credential_header, name)) +
                            le32toh(h->tag_size))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

                        p += ALIGN8(offsetof(struct tpm2_public_key_credential_header, data) +
                                    le32toh(z->size));
                }

                _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
                r = tpm2_context_new(tpm2_device, &tpm2_context);
                if (r < 0)
                        return r;

                 // TODO: Add the SRK data to the credential structure so it can be plumbed
                 // through and used to verify the TPM session.
                r = tpm2_unseal(tpm2_context,
                                le64toh(t->pcr_mask),
                                le16toh(t->pcr_bank),
                                z ? &IOVEC_MAKE(z->data, le32toh(z->size)) : NULL,
                                z ? le64toh(z->pcr_mask) : 0,
                                signature_json,
                                /* pin= */ NULL,
                                /* pcrlock_policy= */ NULL,
                                le16toh(t->primary_alg),
                                &IOVEC_MAKE(t->policy_hash_and_blob, le32toh(t->blob_size)),
                                /* n_blobs= */ 1,
                                &IOVEC_MAKE(t->policy_hash_and_blob + le32toh(t->blob_size), le32toh(t->policy_hash_size)),
                                /* n_known_policy_hash= */ 1,
                                /* srk= */ NULL,
                                &tpm2_key);
                if (r == -EREMOTE)
                        return log_error_errno(r, "TPM key integrity check failed. Key enrolled in superblock most likely does not belong to this TPM.");
                if (ERRNO_IS_NEG_TPM2_UNSEAL_BAD_PCR(r))
                        return log_error_errno(r, "TPM policy does not match current system state. Either system has been tempered with or policy out-of-date: %m");
                if (r < 0)
                        return log_error_errno(r, "Failed to unseal secret using TPM2: %m");
#else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Credential requires TPM2 support, but TPM2 support not available.");
#endif
        }

        if (with_scope) {
                struct scoped_credential_header* sh = (struct scoped_credential_header*) ((uint8_t*) input->iov_base + p);

                if (le64toh(sh->flags) != SCOPE_HASH_DATA_BASE_FLAGS)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Scoped credential with unsupported flags.");

                if (input->iov_len <
                    p +
                    sizeof(struct scoped_credential_header) +
                    ALIGN8(offsetof(struct metadata_credential_header, name)) +
                    le32toh(h->tag_size))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

                p += sizeof(struct scoped_credential_header);
        }

        if (with_host_key) {
                r = get_credential_host_secret(/* flags= */ 0, &host_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine local credential key: %m");
        }

        if (with_null && !FLAGS_SET(flags, CREDENTIAL_ALLOW_NULL))
                log_warning("Warning: using a null key for decryption and authentication. Confidentiality or authenticity are not provided.");

        sha256_hash_host_and_tpm2_key(&host_key, &tpm2_key, md);

        if (with_scope) {
                r = mangle_uid_into_key(uid, md);
                if (r < 0)
                        return r;
        }

        assert_se(cc = EVP_aes_256_gcm());

        /* Make sure cipher expectations match the header */
        if (EVP_CIPHER_key_length(cc) != (int) le32toh(h->key_size))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected key size in header.");
        if (EVP_CIPHER_block_size(cc) != (int) le32toh(h->block_size))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected block size in header.");

        context = EVP_CIPHER_CTX_new();
        if (!context)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to allocate decryption object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_DecryptInit_ex(context, cc, NULL, NULL, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize decryption context: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, le32toh(h->iv_size), NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set IV size on decryption context: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_DecryptInit_ex(context, NULL, NULL, md, h->iv) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set IV and key: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_DecryptUpdate(context, NULL, &added, input->iov_base, p) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to write AAD data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        plaintext.iov_base = malloc(input->iov_len - p - le32toh(h->tag_size));
        if (!plaintext.iov_base)
                return -ENOMEM;

        if (EVP_DecryptUpdate(
                            context,
                            plaintext.iov_base,
                            &added,
                            (uint8_t*) input->iov_base + p,
                            input->iov_len - p - le32toh(h->tag_size)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= input->iov_len - p - le32toh(h->tag_size));
        plaintext.iov_len = added;

        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, le32toh(h->tag_size), (uint8_t*) input->iov_base + input->iov_len - le32toh(h->tag_size)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set tag: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_DecryptFinal_ex(context, (uint8_t*) plaintext.iov_base + plaintext.iov_len, &added) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Decryption failed (incorrect key?): %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        plaintext.iov_len += added;

        if (plaintext.iov_len < ALIGN8(offsetof(struct metadata_credential_header, name)))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Metadata header incomplete.");

        m = plaintext.iov_base;

        if (le64toh(m->timestamp) != USEC_INFINITY &&
            le64toh(m->not_after) != USEC_INFINITY &&
            le64toh(m->timestamp) >= le64toh(m->not_after))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Timestamps of credential are not in order, refusing.");

        if (le32toh(m->name_size) > CREDENTIAL_NAME_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Embedded credential name too long, refusing.");

        hs = ALIGN8(offsetof(struct metadata_credential_header, name) + le32toh(m->name_size));
        if (plaintext.iov_len < hs)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Metadata header incomplete.");

        if (le32toh(m->name_size) > 0) {
                _cleanup_free_ char *embedded_name = NULL;

                r = make_cstring(m->name, le32toh(m->name_size), MAKE_CSTRING_REFUSE_TRAILING_NUL, &embedded_name);
                if (r < 0)
                        return log_error_errno(r, "Unable to convert embedded credential name to C string: %m");

                if (!credential_name_valid(embedded_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Embedded credential name is not valid, refusing.");

                if (validate_name && !streq(embedded_name, validate_name)) {

                        r = secure_getenv_bool("SYSTEMD_CREDENTIAL_VALIDATE_NAME");
                        if (r < 0 && r != -ENXIO)
                                log_debug_errno(r, "Failed to parse $SYSTEMD_CREDENTIAL_VALIDATE_NAME: %m");
                        if (r != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EREMOTE), "Embedded credential name '%s' does not match filename '%s', refusing.", embedded_name, validate_name);

                        log_debug("Embedded credential name '%s' does not match expected name '%s', but configured to use credential anyway.", embedded_name, validate_name);
                }
        }

        if (validate_timestamp != USEC_INFINITY) {
                if (le64toh(m->timestamp) != USEC_INFINITY && le64toh(m->timestamp) > validate_timestamp)
                        log_debug("Credential timestamp is from the future, assuming clock skew.");

                if (le64toh(m->not_after) != USEC_INFINITY && le64toh(m->not_after) < validate_timestamp) {

                        r = secure_getenv_bool("SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER");
                        if (r < 0 && r != -ENXIO)
                                log_debug_errno(r, "Failed to parse $SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER: %m");
                        if (r != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "Credential's time passed, refusing to use.");

                        log_debug("Credential not-after timestamp has passed, but configured to use credential anyway.");
                }
        }

        if (ret) {
                _cleanup_(iovec_done_erase) struct iovec without_metadata = {};

                without_metadata.iov_len = plaintext.iov_len - hs;
                without_metadata.iov_base = memdup_suffix0((uint8_t*) plaintext.iov_base + hs, without_metadata.iov_len);
                if (!without_metadata.iov_base)
                        return log_oom();

                *ret = TAKE_STRUCT(without_metadata);
        }

        return 0;
}

#else

int get_credential_host_secret(CredentialSecretFlags flags, struct iovec *ret) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Support for encrypted credentials not available.");
}

int encrypt_credential_and_warn(sd_id128_t with_key, const char *name, usec_t timestamp, usec_t not_after, const char *tpm2_device, uint32_t tpm2_hash_pcr_mask, const char *tpm2_pubkey_path, uint32_t tpm2_pubkey_pcr_mask, uid_t uid, const struct iovec *input, CredentialFlags flags, struct iovec *ret) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Support for encrypted credentials not available.");
}

int decrypt_credential_and_warn(const char *validate_name, usec_t validate_timestamp, const char *tpm2_device, const char *tpm2_signature_path, uid_t uid, const struct iovec *input, CredentialFlags flags, struct iovec *ret) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Support for encrypted credentials not available.");
}

#endif

int ipc_encrypt_credential(const char *name, usec_t timestamp, usec_t not_after, uid_t uid, const struct iovec *input, CredentialFlags flags, struct iovec *ret) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(input && iovec_is_valid(input));
        assert(ret);

        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Credentials");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to io.systemd.Credentials: %m");

        /* Mark anything we get from the service as sensitive, given that it might use a NULL cypher, at least in theory */
        r = sd_varlink_set_input_sensitive(vl);
        if (r < 0)
                return log_error_errno(r, "Failed to enable sensitive Varlink input: %m");

        /* Create the input data blob object separately, so that we can mark it as sensitive */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jinput = NULL;
        r = sd_json_build(&jinput, JSON_BUILD_IOVEC_BASE64(input));
        if (r < 0)
                return log_error_errno(r, "Failed to create input object: %m");

        sd_json_variant_sensitive(jinput);

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Credentials.Encrypt",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_CONDITION(!!name, "name", SD_JSON_BUILD_STRING(name)),
                        SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_VARIANT(jinput)),
                        SD_JSON_BUILD_PAIR_CONDITION(timestamp != USEC_INFINITY, "timestamp", SD_JSON_BUILD_UNSIGNED(timestamp)),
                        SD_JSON_BUILD_PAIR_CONDITION(not_after != USEC_INFINITY, "notAfter",  SD_JSON_BUILD_UNSIGNED(not_after)),
                        SD_JSON_BUILD_PAIR_CONDITION(!FLAGS_SET(flags, CREDENTIAL_ANY_SCOPE), "scope", SD_JSON_BUILD_STRING(uid_is_valid(uid) ? "user" : "system")),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(uid), "uid", SD_JSON_BUILD_UNSIGNED(uid)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", FLAGS_SET(flags, CREDENTIAL_IPC_ALLOW_INTERACTIVE)));
        if (r < 0)
                return log_error_errno(r, "Failed to call Encrypt() varlink call.");
        if (!isempty(error_id)) {
                if (streq(error_id, "io.systemd.Credentials.NoSuchUser"))
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "No such user.");

                return log_error_errno(sd_varlink_error_to_errno(error_id, reply), "Failed to encrypt: %s", error_id);
        }

        static const sd_json_dispatch_field dispatch_table[] = {
                { "blob", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec, 0, SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, ret);
        if (r < 0)
                return r;

        return 0;
}

int ipc_decrypt_credential(const char *validate_name, usec_t validate_timestamp, uid_t uid, const struct iovec *input, CredentialFlags flags, struct iovec *ret) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(input && iovec_is_valid(input));
        assert(ret);

        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Credentials");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to io.systemd.Credentials: %m");

        r = sd_varlink_set_input_sensitive(vl);
        if (r < 0)
                return log_error_errno(r, "Failed to enable sensitive Varlink input: %m");

        /* Create the input data blob object separately, so that we can mark it as sensitive (it's supposed
         * to be encrypted, but who knows maybe it uses the NULL cypher). */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jinput = NULL;
        r = sd_json_build(&jinput, JSON_BUILD_IOVEC_BASE64(input));
        if (r < 0)
                return log_error_errno(r, "Failed to create input object: %m");

        sd_json_variant_sensitive(jinput);

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Credentials.Decrypt",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_CONDITION(!!validate_name, "name", SD_JSON_BUILD_STRING(validate_name)),
                        SD_JSON_BUILD_PAIR("blob", SD_JSON_BUILD_VARIANT(jinput)),
                        SD_JSON_BUILD_PAIR_CONDITION(validate_timestamp != USEC_INFINITY, "timestamp", SD_JSON_BUILD_UNSIGNED(validate_timestamp)),
                        SD_JSON_BUILD_PAIR_CONDITION(!FLAGS_SET(flags, CREDENTIAL_ANY_SCOPE), "scope", SD_JSON_BUILD_STRING(uid_is_valid(uid) ? "user" : "system")),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(uid), "uid", SD_JSON_BUILD_UNSIGNED(uid)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", FLAGS_SET(flags, CREDENTIAL_IPC_ALLOW_INTERACTIVE)));
        if (r < 0)
                return log_error_errno(r, "Failed to call Decrypt() varlink call.");
        if (!isempty(error_id))  {
                if (streq(error_id, "io.systemd.Credentials.BadFormat"))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Bad credential format.");
                if (streq(error_id, "io.systemd.Credentials.NameMismatch"))
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE), "Name in credential doesn't match expectations.");
                if (streq(error_id, "io.systemd.Credentials.TimeMismatch"))
                        return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "Outside of credential validity time window.");
                if (streq(error_id, "io.systemd.Credentials.NoSuchUser"))
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "No such user.");
                if (streq(error_id, "io.systemd.Credentials.BadScope"))
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Scope mismtach.");

                return log_error_errno(sd_varlink_error_to_errno(error_id, reply), "Failed to decrypt: %s", error_id);
        }

        static const sd_json_dispatch_field dispatch_table[] = {
                { "data", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec, 0, SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, ret);
        if (r < 0)
                return r;

        return 0;
}

int get_global_boot_credentials_path(char **ret) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(ret);

        /* Determines where to put global boot credentials in. Returns the path to the "/loader/credentials/"
         * directory below the XBOOTLDR or ESP partition. Any credentials placed in this directory can be
         * picked up later in the initrd. */

        r = find_xbootldr_and_warn(
                        /* root= */ NULL,
                        /* path= */ NULL,
                        /* unprivileged_mode= */ false,
                        &path,
                        /* ret_uuid= */ NULL,
                        /* ret_devid= */ NULL);
        if (r < 0) {
                if (r != -ENOKEY)
                        return log_error_errno(r, "Failed to find XBOOTLDR partition: %m");

                r = find_esp_and_warn(
                                /* root= */ NULL,
                                /* path= */ NULL,
                                /* unprivileged_mode= */ false,
                                &path,
                                /* ret_part= */ NULL,
                                /* ret_pstart= */ NULL,
                                /* ret_psize= */ NULL,
                                /* ret_uuid= */ NULL,
                                /* ret_devid= */ NULL);
                if (r < 0) {
                        if (r != -ENOKEY)
                                return log_error_errno(r, "Failed to find ESP partition: %m");

                        *ret = NULL;
                        return 0; /* not found! */
                }
        }

        _cleanup_free_ char *joined = path_join(path, "loader/credentials");
        if (!joined)
                return log_oom();

        log_debug("Determined global boot credentials path as: %s", joined);

        *ret = TAKE_PTR(joined);
        return 1; /* found! */
}

static int pick_up_credential_one(
                int credential_dir_fd,
                const char *credential_name,
                const PickUpCredential *table_entry) {

        _cleanup_free_ char *fn = NULL, *target_path = NULL;
        const char *e;
        int r;

        assert(credential_dir_fd >= 0);
        assert(credential_name);
        assert(table_entry);

        e = startswith(credential_name, table_entry->credential_prefix);
        if (!e)
                return 0; /* unmatched */

        fn = strjoin(e, table_entry->filename_suffix);
        if (!fn)
                return log_oom();

        if (!filename_is_valid(fn))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Passed credential '%s' would result in invalid filename '%s'.",
                                         credential_name, fn);

        r = mkdir_p_label(table_entry->target_dir, 0755);
        if (r < 0)
                return log_warning_errno(r, "Failed to create '%s': %m", table_entry->target_dir);

        target_path = path_join(table_entry->target_dir, fn);
        if (!target_path)
                return log_oom();

        r = copy_file_at(
                        credential_dir_fd, credential_name,
                        AT_FDCWD, target_path,
                        /* open_flags= */ 0,
                        0644,
                        /* copy_flags= */ 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to copy credential %s → file %s: %m",
                                         credential_name, target_path);

        log_info("Installed %s from credential.", target_path);
        return 1; /* done */
}

int pick_up_credentials(const PickUpCredential *table, size_t n_table_entry) {
        _cleanup_close_ int credential_dir_fd = -EBADF;
        int r, ret = 0;

        assert(table);
        assert(n_table_entry > 0);

        credential_dir_fd = open_credentials_dir();
        if (IN_SET(credential_dir_fd, -ENXIO, -ENOENT)) {
                /* Credential env var not set, or dir doesn't exist. */
                log_debug("No credentials found.");
                return 0;
        }
        if (credential_dir_fd < 0)
                return log_error_errno(credential_dir_fd, "Failed to open credentials directory: %m");

        _cleanup_free_ DirectoryEntries *des = NULL;
        r = readdir_all(credential_dir_fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &des);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate credentials: %m");

        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                struct dirent *de = *i;

                if (de->d_type != DT_REG)
                        continue;

                FOREACH_ARRAY(t, table, n_table_entry) {
                        r = pick_up_credential_one(credential_dir_fd, de->d_name, t);
                        if (r != 0) {
                                RET_GATHER(ret, r);
                                break; /* Done, or failed. Let's move to the next credential. */
                        }
                }
        }

        return ret;
}

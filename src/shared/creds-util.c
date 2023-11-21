/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>

#if HAVE_OPENSSL
#include <openssl/err.h>
#endif

#include "sd-id128.h"

#include "blockdev-util.h"
#include "capability-util.h"
#include "chattr-util.h"
#include "constants.h"
#include "creds-util.h"
#include "efi-api.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "memory-util.h"
#include "mkdir.h"
#include "openssl-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "random-util.h"
#include "sparse-endian.h"
#include "stat-util.h"
#include "tpm2-util.h"
#include "virt.h"

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
         * restrictive then credential names: we don't allow *, ?, [, ] in them (except for the asterisk
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
        _cleanup_(erase_and_freep) void *data = NULL;
        _cleanup_free_ char *fn = NULL;
        size_t sz = 0;
        const char *d;
        int r;

        assert(ret);

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

        r = decrypt_credential_and_warn(
                        name,
                        now(CLOCK_REALTIME),
                        /* tpm2_device = */ NULL,
                        /* tpm2_signature_path = */ NULL,
                        data,
                        sz,
                        ret,
                        ret_size);
        if (r < 0)
                return r;

        return 1; /* found */

not_found:
        *ret = NULL;

        if (ret_size)
                *ret_size = 0;

        return 0; /* not found */
}

int read_credential_strings_many_internal(
                const char *first_name, char **first_value,
                ...) {

        _cleanup_free_ void *b = NULL;
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
        if (r < 0) {
                if (r != -ENOENT)
                        ret = r;
        } else
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

                value = va_arg(ap, char **);
                if (*value)
                        continue;

                r = read_credential(name, &bb, NULL);
                if (r < 0) {
                        if (ret >= 0 && r != -ENOENT)
                                ret = r;
                } else
                        free_and_replace(*value, bb);
        }

        va_end(ap);
        return ret;
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
                void **ret_data,
                size_t *ret_size) {

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dfd >= 0);
        assert(fn);

        /* For non-root users creating a temporary file using the openat(2) over "." will fail later, in the
         * linkat(2) step at the end.  The reason is that linkat(2) requires the CAP_DAC_READ_SEARCH
         * capability when it uses the AT_EMPTY_PATH flag. */
        if (have_effective_cap(CAP_DAC_READ_SEARCH) > 0) {
                fd = openat(dfd, ".", O_CLOEXEC|O_WRONLY|O_TMPFILE, 0400);
                if (fd < 0)
                        log_debug_errno(errno, "Failed to create temporary credential file with O_TMPFILE, proceeding without: %m");
        }
        if (fd < 0) {
                if (asprintf(&t, "credential.secret.%016" PRIx64, random_u64()) < 0)
                        return -ENOMEM;

                fd = openat(dfd, t, O_CLOEXEC|O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0400);
                if (fd < 0)
                        return -errno;
        }

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

        if (fsync(fd) < 0) {
                r = -errno;
                goto fail;
        }

        warn_not_encrypted(fd, flags, dirname, fn);

        if (t) {
                r = rename_noreplace(dfd, t, dfd, fn);
                if (r < 0)
                        goto fail;

                t = mfree(t);
        } else if (linkat(fd, "", dfd, fn, AT_EMPTY_PATH) < 0) {
                r = -errno;
                goto fail;
        }

        if (fsync(dfd) < 0) {
                r = -errno;
                goto fail;
        }

        if (ret_data) {
                void *copy;

                copy = memdup(buf.data, sizeof(buf.data));
                if (!copy) {
                        r = -ENOMEM;
                        goto fail;
                }

                *ret_data = copy;
        }

        if (ret_size)
                *ret_size = sizeof(buf.data);

        return 0;

fail:
        if (t && unlinkat(dfd, t, 0) < 0)
                log_debug_errno(errno, "Failed to remove temporary credential key: %m");

        return r;
}

int get_credential_host_secret(CredentialSecretFlags flags, void **ret, size_t *ret_size) {
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
        dfd = open_mkdir_at(AT_FDCWD, dirname, O_CLOEXEC, 0755);
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


                        r = make_credential_host_secret(dfd, machine_id, flags, dirname, filename, ret, ret_size);
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
                                               "Failed to read %s/%s: %m", dirname, filename);

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

                                *ret = copy;
                        }

                        if (ret_size)
                                *ret_size = sz;

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

struct _packed_ metadata_credential_header {
        le64_t timestamp;
        le64_t not_after;
        le32_t name_size;
        char name[];
        /* Followed by NUL bytes until next 8 byte boundary */
};

/* Some generic limit for parts of the encrypted credential for which we don't know the right size ahead of
 * time, but where we are really sure it won't be larger than this. Should be larger than any possible IV,
 * padding, tag size and so on. This is purely used for early filtering out of invalid sizes. */
#define CREDENTIAL_FIELD_SIZE_MAX (16U*1024U)

static int sha256_hash_host_and_tpm2_key(
                const void *host_key,
                size_t host_key_size,
                const void *tpm2_key,
                size_t tpm2_key_size,
                uint8_t ret[static SHA256_DIGEST_LENGTH]) {

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *md = NULL;
        unsigned l;

        assert(host_key_size == 0 || host_key);
        assert(tpm2_key_size == 0 || tpm2_key);
        assert(ret);

        /* Combines the host key and the TPM2 HMAC hash into a SHA256 hash value we'll use as symmetric encryption key. */

        md = EVP_MD_CTX_new();
        if (!md)
                return log_oom();

        if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initial SHA256 context.");

        if (host_key && EVP_DigestUpdate(md, host_key, host_key_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash host key.");

        if (tpm2_key && EVP_DigestUpdate(md, tpm2_key, tpm2_key_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash TPM2 key.");

        assert(EVP_MD_CTX_size(md) == SHA256_DIGEST_LENGTH);

        if (EVP_DigestFinal_ex(md, ret, &l) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize SHA256 hash.");

        assert(l == SHA256_DIGEST_LENGTH);
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
                const void *input,
                size_t input_size,
                void **ret,
                size_t *ret_size) {

        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        _cleanup_(erase_and_freep) void *host_key = NULL, *tpm2_key = NULL;
        size_t host_key_size = 0, tpm2_key_size = 0, tpm2_blob_size = 0, tpm2_policy_hash_size = 0, output_size, p, ml;
        _cleanup_free_ void *tpm2_blob = NULL, *tpm2_policy_hash = NULL, *iv = NULL, *output = NULL;
        _cleanup_free_ struct metadata_credential_header *m = NULL;
        uint16_t tpm2_pcr_bank = 0, tpm2_primary_alg = 0;
        struct encrypted_credential_header *h;
        int ksz, bsz, ivsz, tsz, added, r;
        _cleanup_free_ void *pubkey = NULL;
        size_t pubkey_size = 0;
        uint8_t md[SHA256_DIGEST_LENGTH];
        const EVP_CIPHER *cc;
        sd_id128_t id;

        assert(input || input_size == 0);
        assert(ret);
        assert(ret_size);

        if (!sd_id128_in_set(with_key,
                             _CRED_AUTO,
                             _CRED_AUTO_INITRD,
                             CRED_AES256_GCM_BY_HOST,
                             CRED_AES256_GCM_BY_TPM2_HMAC,
                             CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                             CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                             CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK,
                             CRED_AES256_GCM_BY_TPM2_ABSENT))
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
                            _CRED_AUTO,
                            CRED_AES256_GCM_BY_HOST,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                            CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK)) {

                r = get_credential_host_secret(
                                CREDENTIAL_SECRET_GENERATE|
                                CREDENTIAL_SECRET_WARN_NOT_ENCRYPTED|
                                (sd_id128_equal(with_key, _CRED_AUTO) ? CREDENTIAL_SECRET_FAIL_ON_TEMPORARY_FS : 0),
                                &host_key,
                                &host_key_size);
                if (r == -ENOMEDIUM && sd_id128_equal(with_key, _CRED_AUTO))
                        log_debug_errno(r, "Credential host secret location on temporary file system, not using.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to determine local credential host secret: %m");
        }

#if HAVE_TPM2
        bool try_tpm2;
        if (sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_INITRD)) {
                /* If automatic mode is selected lets see if a TPM2 it is present. If we are running in a
                 * container tpm2_support will detect this, and will return a different flag combination of
                 * TPM2_SUPPORT_FULL, effectively skipping the use of TPM2 when inside one. */

                try_tpm2 = tpm2_support() == TPM2_SUPPORT_FULL;
                if (!try_tpm2)
                        log_debug("System lacks TPM2 support or running in a container, not attempting to use TPM2.");
        } else
                try_tpm2 = sd_id128_in_set(with_key,
                                           CRED_AES256_GCM_BY_TPM2_HMAC,
                                           CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                                           CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                                           CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK);

        if (try_tpm2) {
                if (sd_id128_in_set(with_key,
                                    _CRED_AUTO,
                                    _CRED_AUTO_INITRD,
                                    CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                                    CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK)) {

                        /* Load public key for PCR policies, if one is specified, or explicitly requested */

                        r = tpm2_load_pcr_public_key(tpm2_pubkey_path, &pubkey, &pubkey_size);
                        if (r < 0) {
                                if (tpm2_pubkey_path || r != -ENOENT || !sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_INITRD))
                                        return log_error_errno(r, "Failed read TPM PCR public key: %m");

                                log_debug_errno(r, "Failed to read TPM2 PCR public key, proceeding without: %m");
                        }
                }

                if (!pubkey)
                        tpm2_pubkey_pcr_mask = 0;

                _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
                r = tpm2_context_new(tpm2_device, &tpm2_context);
                if (r < 0)
                        return log_error_errno(r, "Failed to create TPM2 context: %m");

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
                if (pubkey) {
                        r = tpm2_tpm2b_public_from_pem(pubkey, pubkey_size, &public);
                        if (r < 0)
                                return log_error_errno(r, "Could not convert public key to TPM2B_PUBLIC: %m");
                }

                TPM2B_DIGEST tpm2_policy = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);
                r = tpm2_calculate_sealing_policy(
                                tpm2_hash_pcr_values,
                                tpm2_n_hash_pcr_values,
                                pubkey ? &public : NULL,
                                /* use_pin= */ false,
                                /* pcrlock_policy= */ NULL,
                                &tpm2_policy);
                if (r < 0)
                        return log_error_errno(r, "Could not calculate sealing policy digest: %m");

                r = tpm2_seal(tpm2_context,
                              /* seal_key_handle= */ 0,
                              &tpm2_policy,
                              /* pin= */ NULL,
                              &tpm2_key, &tpm2_key_size,
                              &tpm2_blob, &tpm2_blob_size,
                              &tpm2_primary_alg,
                              /* ret_srk_buf= */ NULL,
                              /* ret_srk_buf_size= */ NULL);
                if (r < 0) {
                        if (sd_id128_equal(with_key, _CRED_AUTO_INITRD))
                                log_warning("TPM2 present and used, but we didn't manage to talk to it. Credential will be refused if SecureBoot is enabled.");
                        else if (!sd_id128_equal(with_key, _CRED_AUTO))
                                return log_error_errno(r, "Failed to seal to TPM2: %m");

                        log_notice_errno(r, "TPM2 sealing didn't work, continuing without TPM2: %m");
                }

                tpm2_policy_hash_size = tpm2_policy.size;
                tpm2_policy_hash = malloc(tpm2_policy_hash_size);
                if (!tpm2_policy_hash)
                        return log_oom();
                memcpy(tpm2_policy_hash, tpm2_policy.buffer, tpm2_policy_hash_size);

                assert(tpm2_blob_size <= CREDENTIAL_FIELD_SIZE_MAX);
                assert(tpm2_policy_hash_size <= CREDENTIAL_FIELD_SIZE_MAX);
        }
#endif

        if (sd_id128_in_set(with_key, _CRED_AUTO, _CRED_AUTO_INITRD)) {
                /* Let's settle the key type in auto mode now. */

                if (host_key && tpm2_key)
                        id = pubkey ? CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK : CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC;
                else if (tpm2_key)
                        id = pubkey ? CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK : CRED_AES256_GCM_BY_TPM2_HMAC;
                else if (host_key)
                        id = CRED_AES256_GCM_BY_HOST;
                else if (sd_id128_equal(with_key, _CRED_AUTO_INITRD))
                        id = CRED_AES256_GCM_BY_TPM2_ABSENT;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "TPM2 not available and host key located on temporary file system, no encryption key available.");
        } else
                id = with_key;

        if (sd_id128_equal(id, CRED_AES256_GCM_BY_TPM2_ABSENT))
                log_warning("Using a null key for encryption and signing. Confidentiality or authenticity will not be provided.");

        /* Let's now take the host key and the TPM2 key and hash it together, to use as encryption key for the data */
        r = sha256_hash_host_and_tpm2_key(host_key, host_key_size, tpm2_key, tpm2_key_size, md);
        if (r < 0)
                return r;

        assert_se(cc = EVP_aes_256_gcm());

        ksz = EVP_CIPHER_key_length(cc);
        assert(ksz == sizeof(md));

        bsz = EVP_CIPHER_block_size(cc);
        assert(bsz > 0);
        assert((size_t) bsz <= CREDENTIAL_FIELD_SIZE_MAX);

        ivsz = EVP_CIPHER_iv_length(cc);
        if (ivsz > 0) {
                assert((size_t) ivsz <= CREDENTIAL_FIELD_SIZE_MAX);

                iv = malloc(ivsz);
                if (!iv)
                        return log_oom();

                r = crypto_random_bytes(iv, ivsz);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquired randomized IV: %m");
        }

        tsz = 16; /* FIXME: On OpenSSL 3 there is EVP_CIPHER_CTX_get_tag_length(), until then let's hardcode this */

        context = EVP_CIPHER_CTX_new();
        if (!context)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to allocate encryption object: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_EncryptInit_ex(context, cc, NULL, md, iv) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize encryption context: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        /* Just an upper estimate */
        output_size =
                ALIGN8(offsetof(struct encrypted_credential_header, iv) + ivsz) +
                ALIGN8(tpm2_key ? offsetof(struct tpm2_credential_header, policy_hash_and_blob) + tpm2_blob_size + tpm2_policy_hash_size : 0) +
                ALIGN8(pubkey ? offsetof(struct tpm2_public_key_credential_header, data) + pubkey_size : 0) +
                ALIGN8(offsetof(struct metadata_credential_header, name) + strlen_ptr(name)) +
                input_size + 2U * (size_t) bsz +
                tsz;

        output = malloc0(output_size);
        if (!output)
                return log_oom();

        h = (struct encrypted_credential_header*) output;
        h->id = id;
        h->block_size = htole32(bsz);
        h->key_size = htole32(ksz);
        h->tag_size = htole32(tsz);
        h->iv_size = htole32(ivsz);
        memcpy(h->iv, iv, ivsz);

        p = ALIGN8(offsetof(struct encrypted_credential_header, iv) + ivsz);

        if (tpm2_key) {
                struct tpm2_credential_header *t;

                t = (struct tpm2_credential_header*) ((uint8_t*) output + p);
                t->pcr_mask = htole64(tpm2_hash_pcr_mask);
                t->pcr_bank = htole16(tpm2_pcr_bank);
                t->primary_alg = htole16(tpm2_primary_alg);
                t->blob_size = htole32(tpm2_blob_size);
                t->policy_hash_size = htole32(tpm2_policy_hash_size);
                memcpy(t->policy_hash_and_blob, tpm2_blob, tpm2_blob_size);
                memcpy(t->policy_hash_and_blob + tpm2_blob_size, tpm2_policy_hash, tpm2_policy_hash_size);

                p += ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) + tpm2_blob_size + tpm2_policy_hash_size);
        }

        if (pubkey) {
                struct tpm2_public_key_credential_header *z;

                z = (struct tpm2_public_key_credential_header*) ((uint8_t*) output + p);
                z->pcr_mask = htole64(tpm2_pubkey_pcr_mask);
                z->size = htole32(pubkey_size);
                memcpy(z->data, pubkey, pubkey_size);

                p += ALIGN8(offsetof(struct tpm2_public_key_credential_header, data) + pubkey_size);
        }

        /* Pass the encrypted + TPM2 header as AAD */
        if (EVP_EncryptUpdate(context, NULL, &added, output, p) != 1)
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
        if (EVP_EncryptUpdate(context, (uint8_t*) output + p, &added, (const unsigned char*) m, ALIGN8(offsetof(struct metadata_credential_header, name) + ml)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt metadata header: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= output_size - p);
        p += added;

        /* Then encrypt the plaintext */
        if (EVP_EncryptUpdate(context, (uint8_t*) output + p, &added, input, input_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to encrypt data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= output_size - p);
        p += added;

        /* Finalize */
        if (EVP_EncryptFinal_ex(context, (uint8_t*) output + p, &added) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize data encryption: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= output_size - p);
        p += added;

        assert(p <= output_size - tsz);

        /* Append tag */
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, tsz, (uint8_t*) output + p) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get tag: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        p += tsz;
        assert(p <= output_size);

        if (DEBUG_LOGGING && input_size > 0) {
                size_t base64_size;

                base64_size = DIV_ROUND_UP(p * 4, 3); /* Include base64 size increase in debug output */
                assert(base64_size >= input_size);
                log_debug("Input of %zu bytes grew to output of %zu bytes (+%2zu%%).", input_size, base64_size, base64_size * 100 / input_size - 100);
        }

        *ret = TAKE_PTR(output);
        *ret_size = p;

        return 0;
}

int decrypt_credential_and_warn(
                const char *validate_name,
                usec_t validate_timestamp,
                const char *tpm2_device,
                const char *tpm2_signature_path,
                const void *input,
                size_t input_size,
                void **ret,
                size_t *ret_size) {

        _cleanup_(erase_and_freep) void *host_key = NULL, *tpm2_key = NULL, *plaintext = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *signature_json = NULL;
        _cleanup_(EVP_CIPHER_CTX_freep) EVP_CIPHER_CTX *context = NULL;
        size_t host_key_size = 0, tpm2_key_size = 0, plaintext_size, p, hs;
        struct encrypted_credential_header *h;
        struct metadata_credential_header *m;
        uint8_t md[SHA256_DIGEST_LENGTH];
        bool with_tpm2, with_host_key, is_tpm2_absent, with_tpm2_pk;
        const EVP_CIPHER *cc;
        int r, added;

        assert(input || input_size == 0);
        assert(ret);
        assert(ret_size);

        h = (struct encrypted_credential_header*) input;

        /* The ID must fit in, for the current and all future formats */
        if (input_size < sizeof(h->id))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

        with_host_key = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_HOST, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK);
        with_tpm2_pk = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK);
        with_tpm2 = sd_id128_in_set(h->id, CRED_AES256_GCM_BY_TPM2_HMAC, CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC) || with_tpm2_pk;
        is_tpm2_absent = sd_id128_equal(h->id, CRED_AES256_GCM_BY_TPM2_ABSENT);

        if (!with_host_key && !with_tpm2 && !is_tpm2_absent)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unknown encryption format, or corrupted data: %m");

        if (with_tpm2_pk) {
                r = tpm2_load_pcr_signature(tpm2_signature_path, &signature_json);
                if (r < 0)
                        return log_error_errno(r, "Failed to load pcr signature: %m");
        }

        if (is_tpm2_absent) {
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

        /* Now we know the minimum header size */
        if (input_size < offsetof(struct encrypted_credential_header, iv))
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
        if (input_size <
            ALIGN8(offsetof(struct encrypted_credential_header, iv) + le32toh(h->iv_size)) +
            ALIGN8(with_tpm2 ? offsetof(struct tpm2_credential_header, policy_hash_and_blob) : 0) +
            ALIGN8(with_tpm2_pk ? offsetof(struct tpm2_public_key_credential_header, data) : 0) +
            ALIGN8(offsetof(struct metadata_credential_header, name)) +
            le32toh(h->tag_size))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

        p = ALIGN8(offsetof(struct encrypted_credential_header, iv) + le32toh(h->iv_size));

        if (with_tpm2) {
#if HAVE_TPM2
                struct tpm2_credential_header* t = (struct tpm2_credential_header*) ((uint8_t*) input + p);
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
                if (input_size <
                    ALIGN8(offsetof(struct encrypted_credential_header, iv) + le32toh(h->iv_size)) +
                    ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) + le32toh(t->blob_size) + le32toh(t->policy_hash_size)) +
                    ALIGN8(with_tpm2_pk ? offsetof(struct tpm2_public_key_credential_header, data) : 0) +
                    ALIGN8(offsetof(struct metadata_credential_header, name)) +
                    le32toh(h->tag_size))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Encrypted file too short.");

                p += ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) +
                            le32toh(t->blob_size) +
                            le32toh(t->policy_hash_size));

                if (with_tpm2_pk) {
                        z = (struct tpm2_public_key_credential_header*) ((uint8_t*) input + p);

                        if (!TPM2_PCR_MASK_VALID(le64toh(z->pcr_mask)) || le64toh(z->pcr_mask) == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "TPM2 PCR mask out of range.");
                        if (le32toh(z->size) > PUBLIC_KEY_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected public key size.");

                        if (input_size <
                            ALIGN8(offsetof(struct encrypted_credential_header, iv) + le32toh(h->iv_size)) +
                            ALIGN8(offsetof(struct tpm2_credential_header, policy_hash_and_blob) + le32toh(t->blob_size) + le32toh(t->policy_hash_size)) +
                            ALIGN8(offsetof(struct tpm2_public_key_credential_header, data) + le32toh(z->size)) +
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
                                z ? z->data : NULL,
                                z ? le32toh(z->size) : 0,
                                z ? le64toh(z->pcr_mask) : 0,
                                signature_json,
                                /* pin= */ NULL,
                                /* pcrlock_policy= */ NULL,
                                le16toh(t->primary_alg),
                                t->policy_hash_and_blob,
                                le32toh(t->blob_size),
                                t->policy_hash_and_blob + le32toh(t->blob_size),
                                le32toh(t->policy_hash_size),
                                /* srk_buf= */ NULL,
                                /* srk_buf_size= */ 0,
                                &tpm2_key,
                                &tpm2_key_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to unseal secret using TPM2: %m");
#else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Credential requires TPM2 support, but TPM2 support not available.");
#endif
        }

        if (with_host_key) {
                r = get_credential_host_secret(
                                0,
                                &host_key,
                                &host_key_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine local credential key: %m");
        }

        if (is_tpm2_absent)
                log_warning("Warning: using a null key for decryption and authentication. Confidentiality or authenticity are not provided.");

        sha256_hash_host_and_tpm2_key(host_key, host_key_size, tpm2_key, tpm2_key_size, md);

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

        if (EVP_DecryptUpdate(context, NULL, &added, input, p) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to write AAD data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        plaintext = malloc(input_size - p - le32toh(h->tag_size));
        if (!plaintext)
                return -ENOMEM;

        if (EVP_DecryptUpdate(
                            context,
                            plaintext,
                            &added,
                            (uint8_t*) input + p,
                            input_size - p - le32toh(h->tag_size)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to decrypt data: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        assert(added >= 0);
        assert((size_t) added <= input_size - p - le32toh(h->tag_size));
        plaintext_size = added;

        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, le32toh(h->tag_size), (uint8_t*) input + input_size - le32toh(h->tag_size)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set tag: %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        if (EVP_DecryptFinal_ex(context, (uint8_t*) plaintext + plaintext_size, &added) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Decryption failed (incorrect key?): %s",
                                       ERR_error_string(ERR_get_error(), NULL));

        plaintext_size += added;

        if (plaintext_size < ALIGN8(offsetof(struct metadata_credential_header, name)))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Metadata header incomplete.");

        m = plaintext;

        if (le64toh(m->timestamp) != USEC_INFINITY &&
            le64toh(m->not_after) != USEC_INFINITY &&
            le64toh(m->timestamp) >= le64toh(m->not_after))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Timestamps of credential are not in order, refusing.");

        if (le32toh(m->name_size) > CREDENTIAL_NAME_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Embedded credential name too long, refusing.");

        hs = ALIGN8(offsetof(struct metadata_credential_header, name) + le32toh(m->name_size));
        if (plaintext_size < hs)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Metadata header incomplete.");

        if (le32toh(m->name_size) > 0) {
                _cleanup_free_ char *embedded_name = NULL;

                r = make_cstring(m->name, le32toh(m->name_size), MAKE_CSTRING_REFUSE_TRAILING_NUL, &embedded_name);
                if (r < 0)
                        return log_error_errno(r, "Unable to convert embedded credential name to C string: %m");

                if (!credential_name_valid(embedded_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Embedded credential name is not valid, refusing.");

                if (validate_name && !streq(embedded_name, validate_name)) {

                        r = getenv_bool_secure("SYSTEMD_CREDENTIAL_VALIDATE_NAME");
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

                        r = getenv_bool_secure("SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER");
                        if (r < 0 && r != -ENXIO)
                                log_debug_errno(r, "Failed to parse $SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER: %m");
                        if (r != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "Credential's time passed, refusing to use.");

                        log_debug("Credential not-after timestamp has passed, but configured to use credential anyway.");
                }
        }

        if (ret) {
                char *without_metadata;

                without_metadata = memdup_suffix0((uint8_t*) plaintext + hs, plaintext_size - hs);
                if (!without_metadata)
                        return log_oom();

                *ret = without_metadata;
        }

        if (ret_size)
                *ret_size = plaintext_size - hs;

        return 0;
}

#else

int get_credential_host_secret(CredentialSecretFlags flags, void **ret, size_t *ret_size) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Support for encrypted credentials not available.");
}

int encrypt_credential_and_warn(sd_id128_t with_key, const char *name, usec_t timestamp, usec_t not_after, const char *tpm2_device, uint32_t tpm2_hash_pcr_mask, const char *tpm2_pubkey_path, uint32_t tpm2_pubkey_pcr_mask, const void *input, size_t input_size, void **ret, size_t *ret_size) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Support for encrypted credentials not available.");
}

int decrypt_credential_and_warn(const char *validate_name, usec_t validate_timestamp, const char *tpm2_device, const char *tpm2_signature_path, const void *input, size_t input_size, void **ret, size_t *ret_size) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Support for encrypted credentials not available.");
}

#endif

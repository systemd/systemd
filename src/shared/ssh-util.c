/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "path-util.h"
#include "process-util.h"
#include "ssh-util.h"
#include "string-table.h"
#include "strv.h"
#include "unaligned.h"

#define MAX_PUB_FILE_SIZE 16384U

void ssh_wire_buf_done(SshWireBuf *b) {
        if (!b)
                return;

        b->data = mfree(b->data);
        b->size = 0;
}

int ssh_wire_buf_append_bytes(SshWireBuf *b, const void *p, size_t n) {
        assert(b);
        assert(p || n == 0);

        if (n == 0)
                return 0;

        if (!GREEDY_REALLOC(b->data, b->size + n))
                return -ENOMEM;

        memcpy(b->data + b->size, p, n);
        b->size += n;
        return 0;
}

int ssh_wire_buf_append_byte(SshWireBuf *b, uint8_t v) {
        assert(b);

        if (!GREEDY_REALLOC(b->data, b->size + 1))
                return -ENOMEM;

        b->data[b->size++] = v;
        return 0;
}

int ssh_wire_buf_append_u32(SshWireBuf *b, uint32_t v) {
        assert(b);

        if (!GREEDY_REALLOC(b->data, b->size + 4))
                return -ENOMEM;

        unaligned_write_be32(b->data + b->size, v);
        b->size += 4;
        return 0;
}

int ssh_wire_buf_append_string(SshWireBuf *b, const void *p, size_t n) {
        int r;

        assert(b);

        if (n == SIZE_MAX) {
                assert(p);
                n = strlen(p);
        }

        if (n > UINT32_MAX)
                return -EMSGSIZE;

        r = ssh_wire_buf_append_u32(b, n);
        if (r < 0)
                return r;

        return ssh_wire_buf_append_bytes(b, p, n);
}

/* Append a positive BIGNUM as SSH mpint (length-prefixed, big-endian, with a leading 0
 * byte when the MSB is set so the value remains unsigned). */
int ssh_wire_buf_append_mpint(SshWireBuf *b, const BIGNUM *bn) {
#if HAVE_OPENSSL
        int r;

        assert(b);
        assert(bn);

        size_t n = sym_BN_num_bytes(bn);
        if (n == 0)
                return -EBADMSG; /* In a signing context, both r and s must always be non-zero. */

        _cleanup_free_ uint8_t *tmp = new(uint8_t, n);
        if (!tmp)
                return -ENOMEM;
        if (sym_BN_bn2bin(bn, tmp) != (int) n)
                return -EIO;

        bool pad = (tmp[0] & 0x80) != 0;
        r = ssh_wire_buf_append_u32(b, n + (pad ? 1 : 0));
        if (r < 0)
                return r;

        if (pad) {
                r = ssh_wire_buf_append_byte(b, 0);
                if (r < 0)
                        return r;
        }

        return ssh_wire_buf_append_bytes(b, tmp, n);
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "openssl support is not compiled in.");
#endif
}

int ssh_wire_cursor_read_u32(SshWireCursor *c, uint32_t *ret) {
        assert(c);
        assert(ret);

        if (c->pos + 4 > c->size)
                return -EBADMSG;

        *ret = unaligned_read_be32(c->data + c->pos);
        c->pos += 4;
        return 0;
}

int ssh_wire_cursor_read_string(SshWireCursor *c, const uint8_t **ret_data, size_t *ret_size) {
        int r;

        assert(c);
        assert(ret_data);
        assert(ret_size);

        uint32_t len;
        r = ssh_wire_cursor_read_u32(c, &len);
        if (r < 0)
                return r;

        if (c->pos + len > c->size)
                return -EBADMSG;

        *ret_data = c->data + c->pos;
        *ret_size = len;
        c->pos += len;
        return 0;
}

static const char* const openssh_key_type_table[_OPENSSH_KEY_TYPE_MAX] = {
        [OPENSSH_KEY_TYPE_ED25519]    = "ssh-ed25519",
        [OPENSSH_KEY_TYPE_RSA]        = "ssh-rsa",
        [OPENSSH_KEY_TYPE_ECDSA_P256] = "ecdsa-sha2-nistp256",
};

DEFINE_STRING_TABLE_LOOKUP(openssh_key_type, OpenSSHKeyType);

static const char* const openssh_key_keygen_type_table[_OPENSSH_KEY_TYPE_MAX] = {
        [OPENSSH_KEY_TYPE_ED25519]    = "ed25519",
        [OPENSSH_KEY_TYPE_RSA]        = "rsa",
        [OPENSSH_KEY_TYPE_ECDSA_P256] = "ecdsa",
};

DEFINE_STRING_TABLE_LOOKUP(openssh_key_keygen_type, OpenSSHKeyType);

int openssh_key_generate(const char *priv_path, OpenSSHKeyType type) {
        int r;

        assert(priv_path);

        const char *keygen_name = openssh_key_keygen_type_to_string(type);
        if (!keygen_name)
                return -EINVAL;

        _cleanup_free_ char *ssh_keygen = NULL;
        r = find_executable("ssh-keygen", &ssh_keygen);
        if (r < 0)
                return log_debug_errno(r, "Failed to find ssh-keygen: %m");

        /* -m PKCS8 writes the private key in PEM/PKCS#8 so OpenSSL can read it directly. */
        _cleanup_strv_free_ char **cmdline = strv_new(
                        ssh_keygen,
                        "-q",
                        "-f", priv_path,
                        "-N", "",
                        "-m", "PKCS8",
                        "-t", keygen_name);
        if (!cmdline)
                return -ENOMEM;

        r = pidref_safe_fork_full(
                        "(ssh-keygen)",
                        (int[]) { -EBADF, -EBADF, STDERR_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_WAIT|FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|
                        FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO|FORK_REOPEN_LOG,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(ssh_keygen, cmdline);
                log_debug_errno(errno, "Failed to execve %s: %m", ssh_keygen);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

int openssh_pubkey_load(
                const char *pub_path,
                OpenSSHKeyType *ret_type,
                void **ret_blob,
                size_t *ret_blob_size,
                char **ret_comment) {

        int r;

        assert(pub_path);
        assert(ret_type);
        assert(ret_blob);
        assert(ret_blob_size);
        assert(ret_comment);

        _cleanup_free_ char *text = NULL;
        r = read_full_file_full(AT_FDCWD, pub_path, UINT64_MAX, MAX_PUB_FILE_SIZE,
                                READ_FULL_FILE_FAIL_WHEN_LARGER,
                                /* bind_name= */ NULL, &text, /* ret_size= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to read SSH public key from %s: %m", pub_path);

        /* "<type> <base64-blob> [<comment>]\n" — strip trailing newline(s) and split. */
        char *nl = strchr(text, '\n');
        if (nl)
                *nl = '\0';

        const char *space1 = strchr(text, ' ');
        if (!space1)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Malformed SSH public key in %s", pub_path);

        _cleanup_free_ char *type_str = strndup(text, space1 - text);
        if (!type_str)
                return -ENOMEM;

        OpenSSHKeyType type = openssh_key_type_from_string(type_str);
        if (type < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Unsupported SSH key type in %s: %s", pub_path, type_str);

        const char *b64 = space1 + 1;
        const char *space2 = strchr(b64, ' ');
        size_t b64_len = space2 ? (size_t) (space2 - b64) : strlen(b64);

        _cleanup_free_ void *blob = NULL;
        size_t blob_size = 0;
        r = unbase64mem_full(b64, b64_len, /* secure= */ false, &blob, &blob_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to decode base64 in %s: %m", pub_path);

        _cleanup_free_ char *comment = NULL;
        if (space2 && space2[1]) {
                comment = strdup(space2 + 1);
                if (!comment)
                        return -ENOMEM;
        }

        *ret_type = type;
        *ret_blob = TAKE_PTR(blob);
        *ret_blob_size = blob_size;
        *ret_comment = TAKE_PTR(comment);
        return 0;
}

#if HAVE_OPENSSL
/* Sanity-check the loaded EVP_PKEY's base id against the type we parsed from the .pub. */
static int validate_pkey_matches(OpenSSHKeyType t, EVP_PKEY *pkey) {

        int id = sym_EVP_PKEY_get_base_id(pkey);

        switch (t) {
        case OPENSSH_KEY_TYPE_ED25519:
                if (id != EVP_PKEY_ED25519)
                        return -EBADMSG;
                return 0;
        case OPENSSH_KEY_TYPE_RSA:
                if (id != EVP_PKEY_RSA && id != EVP_PKEY_RSA_PSS)
                        return -EBADMSG;
                return 0;
        case OPENSSH_KEY_TYPE_ECDSA_P256:
                if (id != EVP_PKEY_EC)
                        return -EBADMSG;
                return 0;
        default:
                return -EBADMSG;
        }
}
#endif

int openssh_key_load(const char *priv_path, const char *pub_path, OpenSSHKey **ret) {
#if HAVE_OPENSSL
        int r;

        assert(priv_path);
        assert(pub_path);
        assert(ret);

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(openssh_key_freep) OpenSSHKey *k = new0(OpenSSHKey, 1);
        if (!k)
                return -ENOMEM;

        r = openssh_pubkey_load(pub_path, &k->type, &k->pubkey_blob, &k->pubkey_blob_size, &k->comment);
        if (r < 0)
                return r;

        r = openssl_load_private_key_from_file(priv_path, &k->pkey);
        if (r < 0)
                return log_debug_errno(r, "Failed to load PEM private key from %s: %m", priv_path);

        r = validate_pkey_matches(k->type, k->pkey);
        if (r < 0)
                return log_debug_errno(r, "Private key in %s doesn't match advertised type in %s",
                                       priv_path, pub_path);

        *ret = TAKE_PTR(k);
        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "openssl support is not compiled in.");
#endif
}

static int frame_ed25519(EVP_PKEY *pkey, const void *data, size_t size, SshWireBuf *out) {
#if HAVE_OPENSSL
        int r;

        _cleanup_free_ void *sig = NULL;
        size_t sig_size = 0;
        r = digest_and_sign(/* md= */ NULL, pkey, data, size, &sig, &sig_size);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(out, "ssh-ed25519", SIZE_MAX);
        if (r < 0)
                return r;

        return ssh_wire_buf_append_string(out, sig, sig_size);
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "openssl support is not compiled in.");
#endif
}

static int frame_rsa(EVP_PKEY *pkey, uint32_t flags, const void *data, size_t size, SshWireBuf *out) {
#if HAVE_OPENSSL
        const char *algo;
        const EVP_MD *md;
        int r;

        if (flags & SSH_AGENT_RSA_SHA2_512) {
                md = sym_EVP_sha512();
                algo = "rsa-sha2-512";
        } else if (flags & SSH_AGENT_RSA_SHA2_256) {
                md = sym_EVP_sha256();
                algo = "rsa-sha2-256";
        } else {
                md = sym_EVP_sha1();
                algo = "ssh-rsa";
        }
        if (!md)
                return -EOPNOTSUPP;

        _cleanup_free_ void *sig = NULL;
        size_t sig_size = 0;
        r = digest_and_sign(md, pkey, data, size, &sig, &sig_size);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(out, algo, SIZE_MAX);
        if (r < 0)
                return r;

        return ssh_wire_buf_append_string(out, sig, sig_size);
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "openssl support is not compiled in.");
#endif
}

static int frame_ecdsa_p256(EVP_PKEY *pkey, const void *data, size_t size, SshWireBuf *out) {
#if HAVE_OPENSSL
        int r;

        const EVP_MD *md = sym_EVP_sha256();
        if (!md)
                return -EOPNOTSUPP;

        _cleanup_free_ uint8_t *der = NULL;
        size_t der_size = 0;
        r = digest_and_sign(md, pkey, data, size, (void**) &der, &der_size);
        if (r < 0)
                return r;

        /* OpenSSL returns DER SEQUENCE { r, s }; SSH wants mpint(r) || mpint(s) wrapped in a string. */
        const uint8_t *dp = der;
        _cleanup_(ECDSA_SIG_freep) ECDSA_SIG *sig = sym_d2i_ECDSA_SIG(NULL, &dp, der_size);
        if (!sig)
                return -EBADMSG;

        const BIGNUM *bn_r = sym_ECDSA_SIG_get0_r(sig);
        const BIGNUM *bn_s = sym_ECDSA_SIG_get0_s(sig);
        if (!bn_r || !bn_s)
                return -EIO;

        _cleanup_(ssh_wire_buf_done) SshWireBuf inner = {};
        r = ssh_wire_buf_append_mpint(&inner, bn_r);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_mpint(&inner, bn_s);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(out, "ecdsa-sha2-nistp256", SIZE_MAX);
        if (r < 0)
                return r;

        return ssh_wire_buf_append_string(out, inner.data, inner.size);
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "openssl support is not compiled in.");
#endif
}

int openssh_key_sign(
                OpenSSHKey *k,
                uint32_t flags,
                const void *data,
                size_t size,
                void **ret_blob,
                size_t *ret_blob_size) {

        _cleanup_(ssh_wire_buf_done) SshWireBuf out = {};
        int r;

        assert(k);
        assert(ret_blob);
        assert(ret_blob_size);

        switch (k->type) {
        case OPENSSH_KEY_TYPE_ED25519:
                r = frame_ed25519(k->pkey, data, size, &out);
                break;
        case OPENSSH_KEY_TYPE_RSA:
                r = frame_rsa(k->pkey, flags, data, size, &out);
                break;
        case OPENSSH_KEY_TYPE_ECDSA_P256:
                r = frame_ecdsa_p256(k->pkey, data, size, &out);
                break;
        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        *ret_blob = TAKE_PTR(out.data);
        *ret_blob_size = out.size;
        out.size = 0;
        return 0;
}

OpenSSHKey* openssh_key_free(OpenSSHKey *k) {
        if (!k)
                return NULL;

#if HAVE_OPENSSL
        if (k->pkey)
                sym_EVP_PKEY_free(k->pkey);
#endif

        free(k->pubkey_blob);
        free(k->comment);
        return mfree(k);
}

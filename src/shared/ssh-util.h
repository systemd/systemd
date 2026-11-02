/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "forward.h"

/* PROTOCOL.agent defines the flags of the agent sign request. */
#define SSH_AGENT_RSA_SHA2_256 0x00000002u
#define SSH_AGENT_RSA_SHA2_512 0x00000004u

/* The ssh_wire_*() functions encode and decode the SSH wire format from RFC 4251 §5. The append
 * functions grow an iovec that owns its memory. The read functions advance the iovec past the bytes
 * that they read, so pass them a view into a buffer, never the owning iovec. */

int ssh_wire_append_u32(struct iovec *iovec, uint32_t v);
/* ssh_wire_append_string() appends the length of `s` as uint32, followed by the bytes of `s`. */
int ssh_wire_append_string(struct iovec *iovec, const struct iovec *s);
/* Appends a positive BIGNUM as SSH mpint. Only available under HAVE_OPENSSL. */
int ssh_wire_append_mpint(struct iovec *iovec, const BIGNUM *bn);

int ssh_wire_read_u32(struct iovec *iovec, uint32_t *ret);
/* The returned iovec points into the memory of `iovec`. */
int ssh_wire_read_string(struct iovec *iovec, struct iovec *ret);

typedef enum OpenSSHKeyType {
        OPENSSH_KEY_TYPE_ED25519,
        OPENSSH_KEY_TYPE_RSA,
        OPENSSH_KEY_TYPE_ECDSA_P256,
        _OPENSSH_KEY_TYPE_MAX,
        _OPENSSH_KEY_TYPE_INVALID = -EINVAL,
} OpenSSHKeyType;

/* SSH wire format type tag: "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256". */
DECLARE_STRING_TABLE_LOOKUP(openssh_key_type, OpenSSHKeyType);

/* Name accepted by `ssh-keygen -t`: "ed25519", "rsa", "ecdsa". */
DECLARE_STRING_TABLE_LOOKUP(openssh_key_keygen_type, OpenSSHKeyType);

typedef struct OpenSSHKey {
        OpenSSHKeyType type;
        EVP_PKEY *pkey;
        struct iovec pubkey_blob; /* pubkey_blob contains the public key in SSH wire format. */
        char *comment;
} OpenSSHKey;

/* Runs `ssh-keygen` to generate an unencrypted key pair. ssh-keygen writes the private key to
 * `priv_path` in PKCS#8 format, which openssl_load_private_key_from_file() can read. It writes the
 * public key to `priv_path` with ".pub" appended. */
int openssh_key_generate(const char *priv_path, OpenSSHKeyType type);

/* Parses an OpenSSH public key file ("ssh-ed25519 AAAA… comment"). `ret_type` and `ret_comment` may
 * be NULL. */
int openssh_pubkey_load(
                const char *pub_path,
                OpenSSHKeyType *ret_type,
                struct iovec *ret_blob,
                char **ret_comment);

/* The private key in `priv_path` has to be in PKCS#8 format, as openssh_key_generate() writes it.
 * OpenSSL can't read the native OpenSSH format. */
int openssh_key_load(const char *priv_path, const char *pub_path, OpenSSHKey **ret);

/* Signs `data` with the loaded private key. `flags` is the flags field of the agent SIGN_REQUEST. It
 * has to contain exactly one of the SSH_AGENT_RSA_SHA2_* flags for RSA keys, and has to be 0 for other
 * key types. Returns the inner SSH-format signature blob: string type-name || string sig. */
int openssh_key_sign(OpenSSHKey *k, uint32_t flags, const struct iovec *data, struct iovec *ret);

OpenSSHKey* openssh_key_free(OpenSSHKey *k);
DEFINE_TRIVIAL_CLEANUP_FUNC(OpenSSHKey*, openssh_key_free);

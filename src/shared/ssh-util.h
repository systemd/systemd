/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"

#if HAVE_LIBSSH

#include <libssh/libssh.h>

typedef enum ssh_keytypes_e SshKeyType;
#define DEFAULT_SSH_KEY_TYPE SSH_KEYTYPE_ED25519

int dlopen_libssh(void);

#else

typedef enum ssh_keytypes_e { SSH_KEYTYPE_UNKNOWN } SshKeyType;
#define DEFAULT_SSH_KEY_TYPE SSH_KEYTYPE_UNKNOWN

#endif

int generate_ssh_keypair_full(
                SshKeyType key_type,
                int param, /* for RSA keys the number of bits, for ECDSA keys the curve to use */
                char **ret_private_key,
                char **ret_public_key);

int ssh_key_type_from_string(const char *s, SshKeyType *ret);
const char* ssh_key_type_to_string(SshKeyType kt);

static inline int generate_ssh_keypair(
                SshKeyType key_type,
                char **ret_private_key,
                char **ret_public_key) {

        int p = 0;

#if HAVE_LIBSSH
        /* bit width of the RSA key */
        if (key_type == SSH_KEYTYPE_RSA)
                p = 2048;

        /* the elliptic curve group to use, 256 = NIST P-256 */
        else if (key_type == SSH_KEYTYPE_ECDSA)
                p = 256;
#endif

        return generate_ssh_keypair_full(key_type, p, ret_private_key, ret_public_key);
}

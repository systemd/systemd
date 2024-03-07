/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ssh-util.h"
#include "alloc-util.h"
#include "string-util.h"

#if HAVE_LIBSSH

int generate_ssh_keypair_full(
                SshKeyType key_type,
                int param,
                char **ret_private_key,
                char **ret_public_key) {

        _cleanup_(ssh_key_freep) ssh_key key = NULL;
        _cleanup_free_ char *b64_pubkey = NULL, *b64_privkey = NULL, *full_pubkey = NULL;
        int r;

        assert(ret_private_key);
        assert(ret_public_key);

        if (ssh_pki_generate(key_type, param, &key) != SSH_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to generate %s SSH key.", ssh_key_type_to_char(key_type));

        /* returns a full key that can be saved to a file */
        r = ssh_pki_export_privkey_base64(key, /* passphrase= */ NULL, /* auth_fn= */ NULL, /* auth_data= */ NULL, &b64_privkey);
        if (r != SSH_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to export private SSH key as base64.");

        /* returns only the base64 representing the key data */
        if (ssh_pki_export_pubkey_base64(key, &b64_pubkey) != SSH_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to export public SSH key as base64.");

        /* omit user and host as they aren't required */
        full_pubkey = strjoin(ssh_key_type_to_char(key_type), " ", b64_pubkey);
        if (!full_pubkey)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to create the full SSH public key");

        *ret_private_key = TAKE_PTR(b64_privkey);
        *ret_public_key = TAKE_PTR(full_pubkey);

        return 0;
}

int ssh_key_type_from_string(const char *s, SshKeyType *ret) {
        assert(ret);

        SshKeyType kt = ssh_key_type_from_name(s);
        if (kt == SSH_KEYTYPE_UNKNOWN)
                return -EINVAL;

        *ret = kt;
        return 0;
}

const char* ssh_key_type_to_string(SshKeyType kt) {
        return ssh_key_type_to_char(kt);
}

#else

int generate_ssh_keypair_full(
                SshKeyType key_type,
                int param,
                char **ret_private_key,
                char **ret_public_key) {

        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libssh not supported, cannot generate an SSH keypair.");
}

int ssh_key_type_from_string(const char *s, SshKeyType *ret) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libssh not supported, cannot convert parse SSH key type.");
}

const char* ssh_key_type_to_string(SshKeyType kt) {
        return NULL;
}

#endif

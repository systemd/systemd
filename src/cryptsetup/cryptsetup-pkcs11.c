/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptsetup-pkcs11.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "macro.h"
#include "memory-util.h"
#include "parse-util.h"
#include "pkcs11-util.h"
#include "random-util.h"
#include "stat-util.h"
#include "strv.h"

int decrypt_pkcs11_key(
                const char *volume_name,
                const char *friendly_name,
                const char *pkcs11_uri,
                const char *key_file,         /* We either expect key_file and associated parameters to be set (for file keys) … */
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec *key_data, /* … or literal keys via key_data */
                usec_t until,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(pkcs11_crypt_device_callback_data_release) pkcs11_crypt_device_callback_data data = {
                .friendly_name = friendly_name,
                .askpw_flags = askpw_flags,
                .until = until,
        };
        int r;

        assert(friendly_name);
        assert(pkcs11_uri);
        assert(key_file || iovec_is_set(key_data));
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        /* The functions called here log about all errors, except for EAGAIN which means "token not found right now" */

        if (iovec_is_set(key_data)) {
                data.encrypted_key = (void*) key_data->iov_base;
                data.encrypted_key_size = key_data->iov_len;

                data.free_encrypted_key = false;
        } else {
                _cleanup_free_ char *bindname = NULL;

                /* If we read the key via AF_UNIX, make this client recognizable */
                if (asprintf(&bindname, "@%" PRIx64"/cryptsetup-pkcs11/%s", random_u64(), volume_name) < 0)
                        return log_oom();

                r = read_full_file_full(
                                AT_FDCWD, key_file,
                                key_file_offset == 0 ? UINT64_MAX : key_file_offset,
                                key_file_size == 0 ? SIZE_MAX : key_file_size,
                                READ_FULL_FILE_CONNECT_SOCKET,
                                bindname,
                                (char**) &data.encrypted_key, &data.encrypted_key_size);
                if (r < 0)
                        return r;

                data.free_encrypted_key = true;
        }

        r = pkcs11_find_token(pkcs11_uri, pkcs11_crypt_device_callback, &data);
        if (r < 0)
                return r;

        *ret_decrypted_key = TAKE_PTR(data.decrypted_key);
        *ret_decrypted_key_size = data.decrypted_key_size;

        return 0;
}

int find_pkcs11_auto_data(
                struct crypt_device *cd,
                char **ret_uri,
                void **ret_encrypted_key,
                size_t *ret_encrypted_key_size,
                int *ret_keyslot) {

        _cleanup_free_ char *uri = NULL;
        _cleanup_free_ void *key = NULL;
        int r, keyslot = -1;
        size_t key_size = 0;

        assert(cd);
        assert(ret_uri);
        assert(ret_encrypted_key);
        assert(ret_encrypted_key_size);
        assert(ret_keyslot);

        /* Loads PKCS#11 metadata from LUKS2 JSON token headers. */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                sd_json_variant *w;
                int ks;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-pkcs11", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                ks = cryptsetup_get_keyslot_from_token(v);
                if (ks < 0) {
                        /* Handle parsing errors of the keyslots field gracefully, since it's not 'owned' by
                         * us, but by the LUKS2 spec */
                        log_warning_errno(ks, "Failed to extract keyslot index from PKCS#11 JSON data token %i, skipping: %m", token);
                        continue;
                }

                if (uri)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                               "Multiple PKCS#11 tokens enrolled, cannot automatically determine token.");

                assert(keyslot < 0);
                keyslot = ks;

                w = sd_json_variant_by_key(v, "pkcs11-uri");
                if (!w || !sd_json_variant_is_string(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "PKCS#11 token data lacks 'pkcs11-uri' field.");

                uri = strdup(sd_json_variant_string(w));
                if (!uri)
                        return log_oom();

                if (!pkcs11_uri_valid(uri))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "PKCS#11 token data contains invalid PKCS#11 URI.");

                w = sd_json_variant_by_key(v, "pkcs11-key");
                if (!w)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "PKCS#11 token data lacks 'pkcs11-key' field.");

                assert(!key);
                assert(key_size == 0);
                r = sd_json_variant_unbase64(w, &key, &key_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode base64 encoded key: %m");
        }

        if (!uri)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "No valid PKCS#11 token data found.");

        log_info("Automatically discovered security PKCS#11 token '%s' unlocks volume.", uri);

        *ret_uri = TAKE_PTR(uri);
        *ret_encrypted_key = TAKE_PTR(key);
        *ret_encrypted_key_size = key_size;
        *ret_keyslot = keyslot;
        return 0;
}

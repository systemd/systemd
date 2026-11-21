/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "alloc-util.h"
#include "dhcp-rkap.h"
#include "hmac.h"
#include "memory-util.h"

assert_cc(sizeof(DHCPRKAPAuth) == 28);
assert_cc(DHCP_RKAP_KEY_SIZE == MD5_DIGEST_SIZE);

void dhcp_rkap_key_clear(DHCPRKAPKey *key) {
        assert(key);

        explicit_bzero_safe(key, sizeof(*key));
}

static int dhcp_rkap_parse(const void *auth, size_t auth_len, DHCPRKAPType type, const DHCPRKAPAuth **ret) {
        const DHCPRKAPAuth *a = auth;

        assert(auth || auth_len == 0);
        assert(ret);

        /* protocol, algorithm and RDM come first, check them before the length so that other protocols are
         * reported as unsupported rather than as malformed. */
        if (auth_len < offsetof(DHCPRKAPAuth, replay))
                return -EBADMSG;

        if (a->protocol != DHCP_RKAP_PROTOCOL ||
            a->algorithm != DHCP_RKAP_ALGORITHM_HMAC_MD5 ||
            a->rdm != DHCP_RKAP_RDM_MONOTONIC)
                return -EOPNOTSUPP;

        if (auth_len != sizeof(DHCPRKAPAuth))
                return -EBADMSG;

        if (a->type != type)
                return -ENOKEY;

        *ret = a;
        return 0;
}

int dhcp_rkap_key_set_from_auth(DHCPRKAPKey *key, const void *auth, size_t auth_len) {
        const DHCPRKAPAuth *a;
        int r;

        assert(key);

        r = dhcp_rkap_parse(auth, auth_len, DHCP_RKAP_TYPE_KEY, &a);
        if (r < 0)
                return r;

        /* A new key replaces the previous one, together with the replay detection value: the replay check
         * is skipped for the first value received from a server (RFC 9915 section 20.3). */
        key->set = true;
        memcpy(key->key, a->value, sizeof(key->key));
        key->replay = be64toh(a->replay);
        return 0;
}

static bool memeq_constant_time(const uint8_t *a, const uint8_t *b, size_t n) {
        uint8_t d = 0;

        for (size_t i = 0; i < n; i++)
                d |= a[i] ^ b[i];

        return d == 0;
}

int dhcp_rkap_verify(DHCPRKAPKey *key, const void *message, size_t message_len, const void *auth, size_t auth_len) {
        const DHCPRKAPAuth *a;
        int r;

        assert(key);
        assert(message);
        assert(auth);
        assert((const uint8_t*) auth >= (const uint8_t*) message);
        assert((const uint8_t*) auth + auth_len <= (const uint8_t*) message + message_len);

        if (!key->set)
                return -ENOKEY;

        r = dhcp_rkap_parse(auth, auth_len, DHCP_RKAP_TYPE_HMAC_MD5, &a);
        if (r < 0)
                return r;

        uint64_t replay = be64toh(a->replay);
        if (replay <= key->replay)
                return -ESTALE;

        /* RFC 9915 section 20.4.3: the HMAC-MD5 is computed over the whole message, with the HMAC-MD5 field
         * set to zero. RFC 6704 section 3.1.4 refers to the same procedure. */
        _cleanup_free_ uint8_t *copy = memdup(message, message_len);
        if (!copy)
                return -ENOMEM;

        size_t digest_offset = (const uint8_t*) a->value - (const uint8_t*) message;
        memzero(copy + digest_offset, sizeof(a->value));

        uint8_t digest[MD5_DIGEST_SIZE];
        hmac_md5(key->key, sizeof(key->key), copy, message_len, digest);

        if (!memeq_constant_time(digest, a->value, sizeof(digest)))
                return -EPERM;

        key->replay = replay;
        return 0;
}

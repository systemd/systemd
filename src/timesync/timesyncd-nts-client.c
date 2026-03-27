/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "random-util.h"
#include "timesyncd-ntske-client.h"
#include "timesyncd-nts-client.h"
#include "timesyncd-ntp-extension.h"
#include "timesyncd-ntp-message.h"

#if HAVE_GNUTLS
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#endif

int ntp_extension_build_request_packet(Manager *m, struct ntp_msg *ntpmsg, size_t *size) {
        _cleanup_(ntp_extension_packet_freep) NTPExtensionPacket *packet = NULL;
        size_t i;
        void *d;
        int r;

        assert_return(m, -EINVAL);
        assert_return(ntpmsg, -EINVAL);

        assert(m->n_cookies > 0);

        r = ntp_extension_packet_new(0, ntpmsg->extensions, &packet);
        if (r < 0)
                return r;

        /* UID */
        r = ntp_extension_append_field(packet, NTP_EXTENSION_FIELD_NTS_UNIQUE_IDENTIFIER, &m->uid, sizeof(m->uid));
        if (r < 0)
                return r;

        i = random_u64() % m->n_cookies;
        r = ntp_extension_append_field(packet, NTP_EXTENSION_FIELD_NTS_COOKIE, m->cookies[i].cookie, m->cookies[i].size);
        if (r < 0)
                return r;

        r = ntp_extension_append_empty_field(packet, NTP_EXTENSION_FIELD_NTS_COOKIE_PLACEHOLDER, m->cookies[i].size, &d);
        if (r < 0)
                return r;

        memset(d, 0, m->cookies[i].size);

        r = ntp_extension_encrypt_auth_field(m, ntpmsg, packet);
        if (r < 0)
                return r;

        *size = packet->size + NTP_HEADER_SIZE;
        return 0;
}

int ntp_extension_encrypt_auth_field(Manager *m, struct ntp_msg *ntpmsg, NTPExtensionPacket *packet) {
#if HAVE_GNUTLS
        size_t auth_size, ctext_size, assoc_size, nonce_size;
        gnutls_cipher_algorithm_t algorithm;
        gnutls_datum_t dkey;
        uint8_t *b, *ctext;
        uint16_t *p;
        int r;

        assert(m);
        assert(ntpmsg);
        assert(packet);

        assoc_size = packet->size + NTP_HEADER_SIZE;

        algorithm = aead_ciphers_to_gnu_tls_cipher_algorithm(m->aead_algorithm);
        if (algorithm < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTSUP), "NTS: GnuTLS Unsupported cipher: %m");

        if (!m->c2s_hd) {
                dkey = (gnutls_datum_t) {
                        .data = (void *) m->c2s_key,
                        .size = m->c2s_key_size,
                };

                r = gnutls_aead_cipher_init(&m->c2s_hd, algorithm, &dkey);
                if (r < 0)
                        return log_warning_errno(r, "NTS: GnuTLS failed to init cipher: %s", gnutls_strerror(r));
        }

        nonce_size = sizeof(m->nonce);

        ctext_size = gnutls_cipher_get_tag_size(algorithm);
        if (!ctext_size)
                return log_warning_errno(SYNTHETIC_ERRNO(EIO),
                                         "NTS: GnuTLS failed to get the tag size of an authenticated encryption algorithm");

        auth_size = NTP_EXTENSION_AUTH_HEADER_SIZE + nonce_size + ctext_size;
        r = ntp_extension_append_empty_field(packet, NTP_EXTENSION_FIELD_NTS_AEEF, auth_size, (void **) &p);
        if (r < 0)
                return log_warning_errno(r, "NTS: Failed to append NTP_EXTENSION_FIELD_NTS_AEEF: %m");

        *p = htobe16(nonce_size);
        p++;
        *p = htobe16(ctext_size);

        b = (uint8_t *) (p + 1);
        memcpy(b, m->nonce, nonce_size);
        ctext = b + nonce_size;

        r = gnutls_aead_cipher_encrypt(m->c2s_hd, m->nonce, nonce_size, ntpmsg, assoc_size, 0, NULL, 0, ctext, &ctext_size);
        if (r < 0)
                return log_warning_errno(r, "NTS: Failed to invoke gnutls_aead_cipher_encrypt: %s", gnutls_strerror(r));
#endif

        return 0;
}

static int ntp_extension_parse_aeef(Manager *m, struct ntp_msg *ntpmsg, void *data, size_t auth_size) {
#if HAVE_GNUTLS
        size_t nonce_size, ctext_size, tag_size, plaintext_size, cookie_size;
        uint8_t plaintext[NTP_EXTENSION_MESSAGE_SIZE_MAX] = {};
        uint8_t *nonce, *ciphertext, *cookie;
        gnutls_cipher_algorithm_t algorithm;
        gnutls_aead_cipher_hd_t hd;
        gnutls_datum_t dkey;
        uint16_t *p = data;
        size_t i;
        int r;

        assert(m);
        assert(ntpmsg);
        assert(data);
        assert(auth_size > 0);

        if (!m->s2c_hd) {
                algorithm = aead_ciphers_to_gnu_tls_cipher_algorithm(m->aead_algorithm);
                if (algorithm < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTSUP), "NTS: GnuTLS Unsupported cipher: %m");

                dkey = (gnutls_datum_t) {
                        .data = (void *) m->s2c_key,
                        .size = m->s2c_key_size,
                };

                r = gnutls_aead_cipher_init(&hd, algorithm, &dkey);
                if (r < 0)
                        return log_warning_errno(r, "NTS: GnuTLS failed to init cipher: %s", gnutls_strerror(r));

                m->s2c_hd = hd;
        }

        nonce_size = be16toh(*p);
        p++;
        ctext_size = be16toh(*p++);

        nonce = (uint8_t *) p;
        ciphertext = nonce + nonce_size;

        r = aead_ciphers_to_gnu_tls_cipher_algorithm(m->aead_algorithm);
        if (r < 0)
                return log_debug_errno(r, "NTS: Failed to decrypt AEEF message from server: %s", gnutls_strerror(r));

        tag_size = gnutls_cipher_get_tag_size(r);
        plaintext_size = ctext_size - tag_size;

        r = gnutls_aead_cipher_decrypt(m->s2c_hd,
                                       nonce, nonce_size, ntpmsg, auth_size, 0,
                                       ciphertext, ctext_size, plaintext, &plaintext_size);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTS: Failed to decrypt AEEF message from server: %m");

        log_debug("NTS: Successfully decrypted AEEF message received from server");

        r = ntp_extension_read_cookie_from_auth_field(plaintext, plaintext_size, (void *) &cookie, &cookie_size);
        if (r < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTS: Failed to extract cookie from AEEF message received from server: %m");

        if (cookie_size > NTS_KE_COOKIE_SIZE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTS: Cookie size '%zu' exceeds maximum: %m", cookie_size);

        i = random_u64() % m->n_cookies;
        if (cookie_size != m->cookies[i].size)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTS: Invalid cookie size '%zu' extracted from AEEF message received from server: %m", cookie_size);

        memcpy(m->cookies[i].cookie, cookie, cookie_size);

        log_debug("NTS: Extracted cookie of size '%zu' from AEEF message", cookie_size);
#endif

        return 0;
}

int ntp_extension_parse_extension_field(Manager *m, struct ntp_msg *ntpmsg, size_t size) {
        NTPExtensionPacket packet = {
                .data = ntpmsg->extensions,
                .size = size - NTP_HEADER_SIZE,
        };
        size_t data_size, total_size, k;
        uint16_t type;
        void *data;
        int r;

        assert(m);
        assert(ntpmsg);
        assert(size > NTP_HEADER_SIZE);

        log_debug("NTS: Received response message size '%zu' from server", size);

        for (k = NTP_HEADER_SIZE; ntp_extension_read_field(&packet, &type, &total_size, &data, &data_size); k += total_size) {
                switch (type) {
                case NTP_EXTENSION_FIELD_NTS_UNIQUE_IDENTIFIER:
                        if (data_size != NTS_UID_SIZE)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTS: Invalid UID size from server: %zu", data_size);

                        if (memcmp(m->uid, data, sizeof(m->uid)) != 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTS: Failed verify UID received from server: %m");
                        else
                                log_debug("NTS: Successfully verified UID received from server");
                        break;
                case NTP_EXTENSION_FIELD_NTS_COOKIE:
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "NTS: Received unencrypted cookie from server. Rejecting...: %m");
                case NTP_EXTENSION_FIELD_NTS_AEEF:
                        log_debug("NTS: Received AEEF message from server");

                        r = ntp_extension_parse_aeef(m, ntpmsg, data, k);
                        if (r < 0)
                                return r;
                        break;
                default:
                        break;
                }
        }

        return 0;
}

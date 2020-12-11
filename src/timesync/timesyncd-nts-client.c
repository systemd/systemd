/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "aes_siv.h"
#include "timesyncd-ntske-client.h"
#include "timesyncd-nts-client.h"
#include "timesyncd-ntp-extension.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(AES_SIV_CTX*, AES_SIV_CTX_free);

int ntp_extension_build_request_packet(Manager *m, struct ntp_msg *ntpmsg, size_t *size) {
        _cleanup_(ntp_extension_packet_freep) NTPExtensionPacket *packet = NULL;
        size_t i;
        void *d;
        int r;

        assert_return(m, -EINVAL);
        assert_return(ntpmsg, -EINVAL);

        r = ntp_extension_packet_new(0, ntpmsg->extensions, &packet);
        if (r < 0)
                return r;

        /* UID */
        r = ntp_extension_append_field(packet, NTP_EXTENSION_FIELD_NTS_UNIQUE_IDENTIFIER, &m->uid, sizeof(m->uid));
        if (r < 0)
                return r;

        i = random() % m->n_cookies;
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
        _cleanup_(AES_SIV_CTX_freep) AES_SIV_CTX *ctx = NULL;
        size_t auth_size, ctext_size, ad_size, nonce_size;
        uint8_t *b, *ctext;
        uint16_t *p;
        int r;

        assert(m);
        assert(ntpmsg);
        assert(packet);

        ctx = AES_SIV_CTX_new();
        if (!ctx)
                return log_oom();

        ad_size = packet->size + NTP_HEADER_SIZE;
        nonce_size = sizeof(m->nonce);

        auth_size = NTP_EXTENSION_AUTH_HEADER_SIZE + nonce_size + CMAC_SIZE;
        r = ntp_extension_append_empty_field(packet, NTP_EXTENSION_FIELD_NTS_AEEF, auth_size, (void **) &p);
        if (r < 0)
                return log_warning_errno(r, "NTS: Failed to append NTP_EXTENSION_FIELD_NTS_AEEF: %m");

        *p = htobe16(nonce_size);
        p++;
        *p = htobe16(CMAC_SIZE);

        b = (uint8_t *) (p + 1);
        memcpy(b, m->nonce, nonce_size);
        ctext = b + nonce_size;

        ctext_size = NTP_EXTENSION_MESSAGE_SIZE_MAX - packet->size;
        return AES_SIV_Encrypt(ctx,
                               ctext, &ctext_size,
                               (unsigned char *) m->c2s_key, m->c2s_key_size,
                               m->nonce, nonce_size,
                               NULL, 0,
                               (unsigned char *) ntpmsg, ad_size);
}

int ntp_extension_parse_extention_field(Manager *m, struct ntp_msg *ntpmsg, size_t ntp_size) {
        _cleanup_(AES_SIV_CTX_freep) AES_SIV_CTX *ctx = NULL;
        NTPExtensionPacket packet = {
                .data = ntpmsg->extensions,
                .size = ntp_size - NTP_HEADER_SIZE,
        };
        size_t data_size, total_size, k;
        uint16_t type;
        void *data;
        int r;

        assert(m);
        assert(ntpmsg);
        assert(ntp_size > 0);

        ctx = AES_SIV_CTX_new();
        if (!ctx)
                return log_oom();

        log_debug("NTS: Received responce message size '%d' from server", (int) ntp_size);

        for (k = NTP_HEADER_SIZE; ntp_extension_read_field(&packet, &type, &total_size, &data, &data_size); k += total_size) {
                switch(type) {
                case NTP_EXTENSION_FIELD_NTS_UNIQUE_IDENTIFIER:
                        if (data_size != NTS_UID_SIZE)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTS: Invalid UID size from server: %d", (int) data_size);

                        if (memcmp(m->uid, data, sizeof(m->uid)) != 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTS: Failed verify UID received from server: %m");
                        else
                                log_debug("NTS: Successfully verified UID received from server");
                        break;
                case NTP_EXTENSION_FIELD_NTS_COOKIE:
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "NTS: Received unencrypted cookie from server. Rejecting ...: %m");
                        break;
                case NTP_EXTENSION_FIELD_NTS_AEEF: {
                        size_t nonce_size, ctext_size, ad_size, plaintext_size;
                        uint8_t *nonce, *ciphertext,  *plaintext;
                        uint16_t *p = data;

                        log_debug("NTS: Received AEEF message from server");

                        ad_size = ntp_size - k;
                        nonce_size = be16toh(*p);
                        p++;
                        ctext_size = be16toh(*p);

                        nonce = (uint8_t *) ++p;
                        ciphertext = nonce + nonce_size;
                        plaintext = ciphertext + CMAC_SIZE;

                        plaintext_size = NTP_EXTENSION_MESSAGE_SIZE_MAX;
                        r = AES_SIV_Decrypt(ctx,
                                            (unsigned char *) plaintext, &plaintext_size,
                                            (unsigned char *) m->s2c_key, m->s2c_key_size,
                                            nonce, nonce_size,
                                            ciphertext,  ctext_size,
                                            (unsigned char *) ntpmsg, ad_size);
                        if (!r) {
                                log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                "NTS: Failed to decrypt AEEF message from server: %m");
                        }
                }
                        break;
                default:
                        break;
                }
        }

       return 0;
}

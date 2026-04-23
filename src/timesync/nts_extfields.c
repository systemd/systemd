/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "memory-util.h"
#include "nts_crypto.h"
#include "nts_definitions.h"
#include "nts_extfields.h"
#include "random-util.h"
#include "unaligned.h"

#ifndef ENCRYPTED_PLACEHOLDERS
#define ENCRYPTED_PLACEHOLDERS 0
#endif

typedef struct {
        uint8_t *data;
        uint8_t *data_end;
} slice;

static size_t capacity(const slice *p) {
        return p->data_end - p->data;
}

static int write_ntp_ext_field(slice *buf, uint16_t type, void *contents, uint16_t len, uint16_t size) {
        assert(buf);

        /* enforce minimum size */
        if (size < len+4) size = len+4;
        /* pad to a dword boundary */
        uint16_t padded_len = (size+3) & ~3;
        int padding = padded_len - (len+4);

        if (capacity(buf) < padded_len)
                return 0;

        if (contents)
                memmove(buf->data+4, contents, len);
        else
                memzero(buf->data+4, len);

        unaligned_write_be16(buf->data, type);
        unaligned_write_be16(buf->data+2, padded_len);

        buf->data += padded_len;
        memzero(buf->data - padding, padding);
        return padded_len;
}

int NTS_add_extension_fields(
                uint8_t dest[static 1280],
                const NTS_Query *nts,
                NTS_Identifier *identifier) {

        int r;

        assert(dest);
        assert(nts);
        assert(identifier);

        slice buf = { dest, dest + 1280 };

        /* skip beyond regular ntp portion */
        buf.data += 48;

        /* generate unique identifier */
        if (crypto_random_bytes(*identifier, sizeof(NTS_Identifier)) != 0)
                return -EINVAL;

        r = write_ntp_ext_field(&buf, NTS_EF_UniqueIdentifier, *identifier, sizeof(NTS_Identifier), 16);
        if (r == 0)
                return -ENOMEM;

        /* write cookie field */
        r = write_ntp_ext_field(&buf, NTS_EF_Cookie, nts->cookie.data, nts->cookie.length, 16);
        if (r == 0)
                return -ENOMEM;

        /* write unencrypted extra cookiefields */
        int placeholders = nts->extra_cookies;
        for ( ; placeholders > ENCRYPTED_PLACEHOLDERS; placeholders--) {
                r = write_ntp_ext_field(&buf, NTS_EF_CookiePlaceholder, NULL, nts->cookie.length, 16);
                if (r == 0)
                        return -ENOMEM;
        }

        /* --- cobble together the extension fields extension field --- */

        /* this represents "N_REQ" in the RFC */
        uint8_t const req_nonce_len = nts->cipher.nonce_size;
        uint8_t const nonce_len = req_nonce_len; /* RFC8915 permits < req_nonce_len, but many servers wont like it */

#if ENCRYPTED_PLACEHOLDERS
        uint8_t EF[1024] = { 0, nonce_len, 0, 0, };
#else
        uint8_t EF[64] = { 0, nonce_len, 0, 0, }; /* 64 bytes are plenty */
#endif
        void *const EF_ciphertext_len = EF+2;
        uint8_t *const EF_nonce = EF+4;
        uint8_t *const EF_payload = EF_nonce + nonce_len;

        assert((nonce_len & 3) == 0);
        assert((req_nonce_len & 3) == 0 && req_nonce_len <= 16);

        /* re-use the remaining buffer as a temporary scratch area for plaintext;
           since we are encrypting this and writing it to the buffer, it will be guaranteed
           to be overwritten */
        slice ptxt = buf;

#if defined(OPENSSL_WORKAROUND)
        /* bug in OpenSSL: https://github.com/openssl/openssl/issues/26580,
           which means that a ciphertext HAS TO BE PRESENT */
        if (placeholders == 0) {
                r = write_ntp_ext_field(&ptxt, NTS_EF_NoOpField, NULL, 0, 0);
                if (r == 0)
                        return -ENOMEM;
        }
#endif
        while (placeholders-- > 0) {
                r = write_ntp_ext_field(&ptxt, NTS_EF_CookiePlaceholder, NULL, nts->cookie.length, 0);
                if (r == 0)
                        return -ENOMEM;
        }

        /* generate the nonce */
        if (crypto_random_bytes(EF_nonce, nonce_len) != 0)
                return -EINVAL;

        AssociatedData info[] = {
                { dest, buf.data - dest },  /* aad */
                { EF_nonce,  nonce_len },   /* nonce */
                { },
        };

        int ptxt_len = ptxt.data - buf.data;
        assert((int)sizeof(EF) - (EF_payload - EF) >= ptxt_len + nts->cipher.block_size);

        int EF_capacity = sizeof(EF) - (EF_payload - EF);
        int ctxt_len = NTS_encrypt(EF_payload, EF_capacity, buf.data, ptxt_len, info, &nts->cipher, nts->c2s_key);

        assert(ctxt_len <= EF_capacity); /* failing this would be a serious error, try to run to the exit */
        if (ctxt_len < 0)
                return -EINVAL;

        /* add padding if we used a too-short nonce */
        int ef_len = 4 + ctxt_len + nonce_len + (nonce_len < req_nonce_len)*(req_nonce_len - nonce_len);

        /* set the ciphertext length */
        unaligned_write_be16(EF_ciphertext_len, ctxt_len);

        r = write_ntp_ext_field(&buf, NTS_EF_AuthEncExtFields, EF, ef_len, 28);
        if (r == 0)
                return -ENOMEM;

        return buf.data - dest;
}

/* caller checks memory bounds */
static void decode_hdr(uint16_t *ret_a, uint16_t *ret_b, const uint8_t bytes[static 4]) {
        *ret_a = unaligned_read_be16(bytes);
        *ret_b = unaligned_read_be16(bytes+2);
}

int NTS_parse_extension_fields(
                uint8_t src[static 1280],
                size_t src_len,
                const NTS_Query *nts,
                NTS_Receipt *fields) {

        assert(src);
        assert(src_len >= 48 && src_len <= 1280);
        assert(nts);
        assert(fields);

        slice buf = { src + 48, src + src_len };
        bool processed = false;

        while (capacity(&buf) >= 4) {
                uint16_t type, len;
                decode_hdr(&type, &len, buf.data);
                if (len < 4 || capacity(&buf) < len)
                        return -ENOMEM;

                switch (type) {
                case NTS_EF_UniqueIdentifier:
                        /* the length indicator contains the size of the header (4 bytes); the identifier
                         * itself is expected to be 32 bytes */
                        if (len - 4 != 32)
                                return -EINVAL;

                        fields->identifier = (NTS_Identifier*)(buf.data + 4);
                        processed = true;
                        break;
                case NTS_EF_AuthEncExtFields: {
                        uint16_t nonce_len, ciph_len;
                        decode_hdr(&nonce_len, &ciph_len, buf.data + 4);
                        /* check that the advertised nonce / cipher lengths + header don't exceed the outer length,
                         * which would be a malicious packet; the sizes don't need to match exactly since there may
                         * also be padding here */
                        if (nonce_len + ciph_len + 8 > len)
                                return -EINVAL;

                        uint8_t *nonce = buf.data + 8;
                        uint8_t *content = nonce + nonce_len;

                        AssociatedData info[] = {
                                { src, buf.data - src }, /* aad */
                                { nonce, nonce_len },    /* nonce */
                                { },
                        };

                        uint8_t *plaintext = content;
                        int plain_len = NTS_decrypt(plaintext, ciph_len, content, ciph_len, info, &nts->cipher, nts->s2c_key);

                        assert(plain_len < ciph_len); /* failing this would be a serious error, try to run to the exit */
                        if (plain_len < 0)
                                return -EINVAL;

                        slice plain = { plaintext, plaintext + plain_len };
                        unsigned cookies = 0;
                        zero(fields->new_cookie);

                        while (capacity(&plain) >= 4) {
                                uint16_t inner_type, inner_len;
                                decode_hdr(&inner_type, &inner_len, plain.data);
                                /* check that our buffer has enough room and the advertised length is valid */
                                if (capacity(&plain) < inner_len || inner_len < 4)
                                        return -ENOMEM;

                                /* only care about cookies */
                                switch (inner_type) {
                                case NTS_EF_Cookie:
                                        if (cookies < ELEMENTSOF(fields->new_cookie)) {
                                                fields->new_cookie[cookies].data = plain.data + 4;
                                                fields->new_cookie[cookies].length = inner_len - 4;
                                        }
                                        cookies++;
                                        break;

                                default:
                                        /* ignore any other field */;
                                }

                                plain.data += inner_len;
                        }

                        /* ignore any further fields after this,
                         * since they are not authenticated */
                        return processed ? plain.data - src : -EINVAL;
                }

                default:
                        /* ignore unknown fields */
                        ;
                }

                buf.data += len;
        }

        return -EINVAL;
}

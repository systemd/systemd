/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <endian.h>
#include <sys/random.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "memory-util.h"
#include "nts_crypto.h"
#include "nts_extfields.h"

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

        type = htobe16(type);
        memcpy(buf->data, &type, 2);
        len = htobe16(padded_len);
        memcpy(buf->data+2, &len, 2);

        buf->data += padded_len;
        memzero(buf->data - padding, padding);
        return padded_len;
}

enum extfields {
        UniqueIdentifier  = 0x0104,
        Cookie            = 0x0204,
        CookiePlaceholder = 0x0304,
        AuthEncExtFields  = 0x0404,
        NoOpField         = 0x0200,
};

#define CHECK(expr) { if (expr); else goto exit; }

int NTS_add_extension_fields(
                uint8_t dest[static 1280],
                const struct NTS_Query *nts,
                uint8_t (*uniq_id)[32]) {

        assert(dest);
        assert(nts);

        slice buf = { dest, dest + 1280 };

        /* skip beyond regular ntp portion */
        buf.data += 48;

        /* generate unique identifier */
        uint8_t rand_buf[32], *rand = *(uniq_id? uniq_id : &rand_buf);
        CHECK(getrandom(rand, sizeof(rand_buf), 0) == sizeof(rand_buf));
        CHECK(write_ntp_ext_field(&buf, UniqueIdentifier, rand, sizeof(rand_buf), 16));

        /* write cookie field */
        CHECK(write_ntp_ext_field(&buf, Cookie, nts->cookie.data, nts->cookie.length, 16));

        /* write unencrypted extra cookiefields */
        int placeholders = nts->extra_cookies;
        for ( ; placeholders > ENCRYPTED_PLACEHOLDERS; placeholders--) {
                CHECK(write_ntp_ext_field(&buf, CookiePlaceholder, NULL, nts->cookie.length, 16));
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
        if (placeholders == 0)
                CHECK(write_ntp_ext_field(&ptxt, NoOpField, NULL, 0, 0));
#endif
        while (placeholders-- > 0) {
                CHECK(write_ntp_ext_field(&ptxt, CookiePlaceholder, NULL, nts->cookie.length, 0));
        }

        /* generate the nonce */
        CHECK(getrandom(EF_nonce, nonce_len, 0) == nonce_len);

        AssociatedData info[] = {
                { dest, buf.data - dest },  /* aad */
                { EF_nonce,  nonce_len },   /* nonce */
                { },
        };

        int ptxt_len = ptxt.data - buf.data;
        assert((int)sizeof(EF) - (EF_payload - EF) >= ptxt_len + nts->cipher.block_size);

        int EF_capacity = sizeof(EF) - (EF_payload - EF);
        int ctxt_len = NTS_encrypt(EF_payload, EF_capacity, buf.data, ptxt_len, info, &nts->cipher, nts->c2s_key);
        CHECK(ctxt_len >= 0);
        assert(ctxt_len <= EF_capacity); /* failing this would be a serious error */

        /* add padding if we used a too-short nonce */
        int ef_len = 4 + ctxt_len + nonce_len + (nonce_len < req_nonce_len)*(req_nonce_len - nonce_len);

        /* set the ciphertext length */
        uint16_t encoded_len = htobe16(ctxt_len);
        memcpy(EF_ciphertext_len, &encoded_len, 2);

        CHECK(write_ntp_ext_field(&buf, AuthEncExtFields, EF, ef_len, 28));

        return buf.data - dest;
exit:
        return 0;
}

/* caller checks memory bounds */
static void decode_hdr(uint16_t *restrict a, uint16_t *restrict b, uint8_t *bytes) {
        memcpy(a, bytes, 2), memcpy(b, bytes+2, 2);
        *a = be16toh(*a), *b = be16toh(*b);
}

int NTS_parse_extension_fields(
                uint8_t src[static 1280],
                size_t src_len,
                const struct NTS_Query *nts,
                struct NTS_Receipt *fields) {

        assert(src);
        assert(src_len >= 48 && src_len <= 1280);
        assert(nts);
        assert(fields);

        slice buf = { src + 48, src + src_len };
        int processed = 0;

        while (capacity(&buf) >= 4) {
                uint16_t type, len;
                decode_hdr(&type, &len, buf.data);
                CHECK(len >= 4);
                CHECK(capacity(&buf) >= len);

                switch (type) {
                case UniqueIdentifier:
                        CHECK(len - 4 == 32);
                        fields->identifier = (uint8_t (*)[32])(buf.data + 4);
                        ++processed;
                        break;
                case AuthEncExtFields: {
                        uint16_t nonce_len, ciph_len;
                        decode_hdr(&nonce_len, &ciph_len, buf.data + 4);
                        CHECK(nonce_len + ciph_len + 8 <= len);
                        uint8_t *nonce = buf.data + 8;
                        uint8_t *content = nonce + nonce_len;

                        AssociatedData info[] = {
                                { src, buf.data - src }, /* aad */
                                { nonce, nonce_len },    /* nonce */
                                { },
                        };

                        uint8_t *plaintext = content;
                        int plain_len = NTS_decrypt(plaintext, ciph_len, content, ciph_len, info, &nts->cipher, nts->s2c_key);
                        assert(plain_len < ciph_len);
                        CHECK(plain_len >= 0);

                        slice plain = { plaintext, plaintext + plain_len };
                        unsigned cookies = 0;
                        zero(fields->new_cookie);

                        while (capacity(&plain) >= 4) {
                                uint16_t inner_type, inner_len;
                                decode_hdr(&inner_type, &inner_len, plain.data);
                                CHECK(capacity(&plain) >= inner_len);
                                CHECK(inner_len >= 4);

                                /* only care about cookies */
                                switch (inner_type) {
                                case Cookie:
                                        if(cookies < ELEMENTSOF(fields->new_cookie)) {
                                                fields->new_cookie[cookies].data = plain.data + 4;
                                                fields->new_cookie[cookies].length = inner_len - 4;
                                        }
                                        cookies++;
                                default:
                                        /* ignore any other field */;
                                }

                                plain.data += inner_len;
                        }

                        /* ignore any further fields after this,
                         * since they are not authenticated */
                        return processed;
                }

                default:
                        /* ignore unknown fields */
                        ;
                }

                buf.data += len;
        }

exit:
        return 0;
}

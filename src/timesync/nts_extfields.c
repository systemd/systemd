/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "iovec-util.h"
#include "memory-util.h"
#include "nts_crypto.h"
#include "nts_definitions.h"
#include "nts_extfields.h"
#include "random-util.h"
#include "unaligned.h"

#ifndef ENCRYPTED_PLACEHOLDERS
#define ENCRYPTED_PLACEHOLDERS 0
#endif

/* Per RFC7822, extension fields have to be at least 16 bytes each; but the final one has to be at least 28; however, per RFC8915, this
 * requirement does not hold for the encrypted and authenticated extension fields */

#define NORMAL_EF_MIN_SIZE 16
#define FINAL_EF_MIN_SIZE 28
#define ENCRYPTED_EF_MIN_SIZE 0

/* write an NTP extension field with minimum length min_size.
 * the pointer in the contents argument is allowed to be NULL, in that case an all-zero field of the given size is emitted */

static int write_ntp_ext_field(struct iovec *buf, uint16_t type, struct iovec contents, size_t min_size) {
        assert(buf);

        /* enforce minimum size */
        const size_t req_size = contents.iov_len+4;
        size_t size = MAX(min_size, req_size);

        /* pad to a dword boundary */
        size_t padded_len = ALIGN4(size);
        size_t padding = padded_len - req_size;

        if (buf->iov_len < padded_len)
                return -ENOBUFS;

        uint8_t *data = (uint8_t*) buf->iov_base;
        iovec_inc(buf, padded_len);

        assert(padded_len <= UINT16_MAX);
        unaligned_write_be16(data, type);
        unaligned_write_be16(data+2, padded_len);
        if (contents.iov_base)
                memmove(data+4, contents.iov_base, contents.iov_len);
        else
                memzero(data+4, contents.iov_len);

        memzero(data+req_size, padding);
        return 0;
}

ssize_t NTS_add_extension_fields(
                uint8_t dest[static NTS_MAX_PACKET_SIZE],
                const NTS_Query *nts,
                NTS_Identifier *identifier) {

        int r;

        assert(dest);
        assert(nts);
        assert(identifier);

        struct iovec buf = { dest, NTS_MAX_PACKET_SIZE };

        /* skip beyond regular ntp portion */
        iovec_inc(&buf, 48);

        /* generate unique identifier */
        r = crypto_random_bytes(identifier->bytes, sizeof(NTS_Identifier));
        if (r < 0)
                return r;

        r = write_ntp_ext_field(&buf, NTS_EF_UniqueIdentifier, IOVEC_MAKE(identifier->bytes, sizeof(NTS_Identifier)), NORMAL_EF_MIN_SIZE);
        if (r < 0)
                return r;

        /* write cookie field */
        r = write_ntp_ext_field(&buf, NTS_EF_Cookie, nts->cookie, NORMAL_EF_MIN_SIZE);
        if (r < 0)
                return r;

        /* write unencrypted extra cookiefields */
        int placeholders = nts->extra_cookies;
        for ( ; placeholders > ENCRYPTED_PLACEHOLDERS; placeholders--) {
                r = write_ntp_ext_field(&buf, NTS_EF_CookiePlaceholder, IOVEC_MAKE(NULL, nts->cookie.iov_len), NORMAL_EF_MIN_SIZE);
                if (r < 0)
                        return r;
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
        struct iovec ptxt = buf;

#if defined(OPENSSL_WORKAROUND)
        /* bug in OpenSSL: https://github.com/openssl/openssl/issues/26580,
           which means that a ciphertext HAS TO BE PRESENT */
        if (placeholders == 0) {
                r = write_ntp_ext_field(&ptxt, NTS_EF_NoOpField, IOVEC_MAKE(NULL, 0), ENCRYPTED_EF_MIN_SIZE);
                if (r < 0)
                        return r;
        }
#endif
        while (placeholders-- > 0) {
                r = write_ntp_ext_field(&ptxt, NTS_EF_CookiePlaceholder, IOVEC_MAKE(NULL, nts->cookie.iov_len), ENCRYPTED_EF_MIN_SIZE);
                if (r < 0)
                        return r;
        }

        /* generate the nonce */
        r = crypto_random_bytes(EF_nonce, nonce_len);
        if (r < 0)
                return r;

        AssociatedData info[] = {
                { dest,     (uint8_t*)buf.iov_base - dest },  /* aad */
                { EF_nonce, nonce_len },                      /* nonce */
                { },
        };

        size_t ptxt_len = (uint8_t*)ptxt.iov_base - (uint8_t*)buf.iov_base;
        size_t EF_capacity = sizeof(EF) - (EF_payload - EF);

        assert(EF_capacity >= ptxt_len + nts->cipher.block_size);

        ssize_t ctxt_len = NTS_encrypt(
                        &IOVEC_MAKE(EF_payload, EF_capacity),
                        &IOVEC_MAKE(buf.iov_base, ptxt_len),
                        info, &nts->cipher, nts->c2s_key);
        if (ctxt_len < 0)
                return ctxt_len;

        assert((size_t) ctxt_len <= EF_capacity); /* failing this would be a serious error */

        /* add padding if we used a too-short nonce */
        size_t ef_len = 4 + ctxt_len + nonce_len + (nonce_len < req_nonce_len)*(req_nonce_len - nonce_len);

        /* set the ciphertext length */
        unaligned_write_be16(EF_ciphertext_len, ctxt_len);

        r = write_ntp_ext_field(&buf, NTS_EF_AuthEncExtFields, IOVEC_MAKE(EF, ef_len), FINAL_EF_MIN_SIZE);
        if (r < 0)
                return r;

        return (uint8_t*)buf.iov_base - dest;
}

/* caller checks memory bounds */
static void decode_hdr(uint16_t *ret_a, uint16_t *ret_b, const struct iovec data, size_t offset) {
        assert(ret_a);
        assert(ret_b);
        assert(data.iov_len >= 4 + offset);

        uint8_t *bytes = (uint8_t*) data.iov_base + offset;
        *ret_a = unaligned_read_be16(bytes);
        *ret_b = unaligned_read_be16(bytes+2);
}

ssize_t NTS_parse_extension_fields(
                uint8_t src[static NTS_MAX_PACKET_SIZE],
                size_t src_len,
                const NTS_Query *nts,
                NTS_Receipt *fields) {

        assert(src);
        assert(src_len >= 48 && src_len <= NTS_MAX_PACKET_SIZE);
        assert(nts);
        assert(fields);

        struct iovec buf = { src + 48, src_len - 48 };
        bool processed = false;

        while (buf.iov_len >= 4) {
                uint16_t type, len;
                decode_hdr(&type, &len, buf, /* offset= */ 0);
                if (len < 4 || buf.iov_len < len)
                        return -EBADMSG;

                switch (type) {
                case NTS_EF_UniqueIdentifier:
                        /* the length indicator contains the size of the header (4 bytes); the identifier
                         * itself is expected to be 32 bytes */
                        if (len - 4 != sizeof(NTS_Identifier))
                                return -EBADMSG;

                        memcpy(&fields->identifier, (uint8_t*)buf.iov_base + 4, sizeof(NTS_Identifier));
                        processed = true;
                        break;
                case NTS_EF_AuthEncExtFields: {
                        uint16_t nonce_len, ciph_len;
                        decode_hdr(&nonce_len, &ciph_len, buf, /* offset= */ 4);
                        /* check that the advertised nonce / cipher lengths + header don't exceed the outer length,
                         * which would be a malicious packet; the sizes don't need to match exactly since there may
                         * also be padding here */
                        if (nonce_len + ciph_len + 8 > len)
                                return -EBADMSG;

                        uint8_t *nonce = (uint8_t*)buf.iov_base + 8;
                        uint8_t *content = nonce + nonce_len;

                        AssociatedData info[] = {
                                { src, (uint8_t*)buf.iov_base - src }, /* aad */
                                { nonce, nonce_len },                  /* nonce */
                                { },
                        };

                        uint8_t *plaintext = content;
                        ssize_t plain_len = NTS_decrypt(
                                        &IOVEC_MAKE(plaintext, ciph_len),
                                        &IOVEC_MAKE(content, ciph_len),
                                        info, &nts->cipher, nts->s2c_key);
                        if (plain_len < 0)
                                return plain_len;

                        assert(plain_len < ciph_len); /* failing this would be a serious error */

                        struct iovec plain = { plaintext, plain_len };
                        unsigned cookies = 0;
                        zero(fields->new_cookie);

                        while (plain.iov_len >= 4) {
                                uint16_t inner_type, inner_len;
                                decode_hdr(&inner_type, &inner_len, plain, /* offset= */ 0);
                                /* check that our buffer has enough room and the advertised length is valid */
                                if (plain.iov_len < inner_len || inner_len < 4)
                                        return -EBADMSG;

                                /* only care about cookies */
                                switch (inner_type) {
                                case NTS_EF_Cookie:
                                        if (cookies < ELEMENTSOF(fields->new_cookie)) {
                                                fields->new_cookie[cookies].iov_base = (uint8_t*)plain.iov_base + 4;
                                                fields->new_cookie[cookies].iov_len = inner_len - 4;
                                        }
                                        cookies++;
                                        break;

                                default:
                                        /* ignore any other field */;
                                }

                                iovec_inc(&plain, inner_len);
                        }

                        /* ignore any further fields after this,
                         * since they are not authenticated */
                        return processed ? (uint8_t*)plain.iov_base - src : -EBADMSG;
                }

                default:
                        /* ignore unknown fields */
                        ;
                }

                iovec_inc(&buf, len);
        }

        return -EBADMSG;
}

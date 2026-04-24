/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "iovec-util.h"
#include "nts.h"
#include "timesyncd-forward.h"
#include "unaligned.h"
#include "utf8.h"

/* should we emit the NTS record that forces chrony to be 'compliant'?
 * for info see: https://chrony-project.org/doc/spec/nts-compliant-128gcm.html
 */
#define CHRONY_WORKAROUND

/* does not check bounds */
static void push_u16(struct iovec *data, uint16_t value) {
        unaligned_write_be16(data->iov_base, value);
        iovec_inc_many(data, 1, 2);
}

/* does not check bounds */
static uint16_t take_u16(struct iovec *data) {
        uint16_t result = unaligned_read_be16(data->iov_base);
        iovec_inc_many(data, 1, 2);
        return result;
}

typedef struct NTS_Record {
        uint16_t type;
        struct iovec body;
} NTS_Record;

static int32_t NTS_decode_u16(NTS_Record *record) {
        assert(record);

        if (record->body.iov_len < 2)
                return -NTS_INSUFFICIENT_DATA;

        return take_u16(&record->body);
}

static int NTS_decode_record(struct iovec *message, NTS_Record *record) {
        assert(message);
        assert(record);

        if (message->iov_len < 4)
                /* not enough bytes to decode a header */
                return -NTS_INSUFFICIENT_DATA;

        bool is_critical = ((uint8_t*)message->iov_base)[0] >> 7;

        uint16_t rec_type = take_u16(message);
        uint16_t body_size = take_u16(message);

        if (body_size > message->iov_len)
                /* not enough data in the slice to decode this header */
                return -NTS_INSUFFICIENT_DATA;

        record->type = rec_type & 0x7FFF;
        record->body.iov_base = message->iov_base;
        record->body.iov_len = body_size;
        iovec_inc_many(message, 1, body_size);

        switch (record->type) {
        case NTS_REC_Error:
        case NTS_REC_Warning:
        case NTS_REC_NTPv4Port:
                if (body_size != 2)
                        goto error;
                break;
        case NTS_REC_EndOfMessage:
                if (body_size != 0)
                        goto error;
                break;
        case NTS_REC_AEADAlgorithm:
        case NTS_REC_NextProto:
                if (body_size % 2 != 0)
                        goto error;
                break;
        default:
                if (is_critical)
                        return -NTS_UNKNOWN_CRIT_RECORD;
                break;
        case NTS_REC_NTPv4Server:
        case NTS_REC_NTPv4Cookie:
                break;
        }

        return 0;

error:
        /* there was an inconsistency in the record */
        return -NTS_BAD_RESPONSE;
}

static int NTS_encode_record_u16(
                struct iovec *message,
                bool critical,
                NTS_RecordType type,
                const uint16_t *data, size_t num_words) {

        assert(message);
        assert(num_words == 0 || data);

        if (num_words >= 0x8000 || message->iov_len < 4 + num_words*2)
                /* not enough space */
                return -NTS_INSUFFICIENT_DATA;

        if (critical)
                type |= 0x8000;

        push_u16(message, type);
        push_u16(message, num_words * 2);

        for (size_t i = 0; i < num_words; i++)
                push_u16(message, data[i]);

        return 0;
}

int NTS_encode_request(
                uint8_t *buffer,
                size_t buf_size,
                const NTS_AEADAlgorithmType *preferred_crypto) {

        assert(buffer);

        struct iovec request = { buffer, buf_size };

        const uint16_t proto[] = { NTS_PROTO_NTPv4 };
        const uint16_t aead_default[] = {
                NTS_AEAD_AES_SIV_CMAC_256,
                NTS_AEAD_AES_SIV_CMAC_512
        }, *aead = aead_default;

        size_t aead_len = ELEMENTSOF(aead_default);
        if (preferred_crypto) {
                aead = preferred_crypto;
                for (aead_len = 0; preferred_crypto[aead_len] ; )
                        ++aead_len;
        }

        int result;
        result = NTS_encode_record_u16(&request, true, NTS_REC_NextProto, proto, ELEMENTSOF(proto));
        if (result < 0)
                return result;

        result = NTS_encode_record_u16(&request, true, NTS_REC_AEADAlgorithm, aead, aead_len);
        if (result < 0)
                return result;
#ifdef CHRONY_WORKAROUND
        result = NTS_encode_record_u16(&request, false, NTS_REC_Chrony_BugWorkaround, NULL, 0);
        if (result < 0)
                return result;
#endif
        result = NTS_encode_record_u16(&request, true, NTS_REC_EndOfMessage, NULL, 0);
        if (result < 0)
                return result;

        return (uint8_t*)request.iov_base - buffer;
}

int NTS_decode_response(uint8_t *buffer, size_t buf_size, NTS_Agreement *response) {
        assert(buffer);
        assert(response);

        struct iovec raw_response = { buffer, buf_size };
        NTS_Record rec;

        /* clear response */
        size_t cookie_nr = 0;
        bool is_ntp4 = false;
        char *ntp_server_terminator = NULL;

        /* make sure the result is only OK if we really succeed */
        *response = (NTS_Agreement) { .error = NTS_INTERNAL_CLIENT_ERROR };

        while (raw_response.iov_len > 0) {
                int val = NTS_decode_record(&raw_response, &rec);
                if (val < 0) {
                        response->error = -val;
                        if (response->error == NTS_INSUFFICIENT_DATA)
                                return -ENODATA;
                        else
                                return -EBADMSG;
                }

                switch (rec.type) {
                case NTS_REC_Error:
                        val = NTS_decode_u16(&rec);
                        if (val < 0)
                                goto unexpected_end;

                        response->error = val;
                        return -EBADMSG;

                case NTS_REC_Warning:
                        val = NTS_decode_u16(&rec);
                        if (val < 0)
                                goto unexpected_end;

                        response->error = NTS_UNEXPECTED_WARNING;
                        return -EBADMSG;

                case NTS_REC_EndOfMessage:
                        if (ntp_server_terminator)
                                /* this hack saves having to allocate a string that we are going to keep in-memory */
                                *ntp_server_terminator = '\0';

                        if (is_ntp4 && response->aead_id != 0) {
                                response->error = NTS_SUCCESS;
                                return 0;
                        } else {
                                response->error = NTS_BAD_RESPONSE;
                                return -EBADMSG;
                        }

                case NTS_REC_NextProto:
                        /* confirm that NTPv4 is on offer */
                        do {
                                val = NTS_decode_u16(&rec);
                                if (val < 0) {
                                        response->error = NTS_NO_PROTOCOL;
                                        return -EBADMSG;
                                }
                        } while (val != NTS_PROTO_NTPv4);
                        is_ntp4 = true;
                        break;

                case NTS_REC_AEADAlgorithm:
                        /* confirm that one of the supported AEAD algo's is offered */
                        val = NTS_decode_u16(&rec);
                        if (val < 0 || !NTS_get_param(val)) {
                                response->error = NTS_NO_AEAD;
                                return -EBADMSG;
                        }
                        response->aead_id = val;
                        break;

                case NTS_REC_NTPv4Cookie:
                        /* ignore any cookies in excess of eight */
                        if (cookie_nr < ELEMENTSOF(response->cookie)) {
                                NTS_Cookie *cookie = &response->cookie[cookie_nr++];
                                cookie->iov_base = rec.body.iov_base;
                                cookie->iov_len  = rec.body.iov_len;
                        }
                        break;

                case NTS_REC_NTPv4Server:
                        /* do limited sanity check */
                        if (rec.body.iov_len > 255) {
                                response->error = NTS_BAD_RESPONSE;
                                return -EBADMSG;
                        }

                        if (!ascii_is_valid_n((char *)rec.body.iov_base, rec.body.iov_len)) {
                                response->error = NTS_BAD_RESPONSE;
                                return -EBADMSG;
                        }

                        response->ntp_server  = (char *)rec.body.iov_base;
                        ntp_server_terminator = (char *)rec.body.iov_base + rec.body.iov_len;
                        break;

                case NTS_REC_NTPv4Port:
                        val = NTS_decode_u16(&rec);
                        if (val < 0)
                                goto unexpected_end;

                        response->ntp_port = val;
                        break;

                default:
                        /* ignore unknown non-critical fields */
                        ;
                }
        }

unexpected_end:
        response->error = NTS_INSUFFICIENT_DATA;
        return -ENODATA;
}

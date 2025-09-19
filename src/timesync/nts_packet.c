#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <endian.h>

#include "nts.h"

/* should we emit the NTS record that forces chrony to be 'compliant' */
#define CHRONY_WORKAROUND

enum NTS_RecordType {
        /* critical */
        NTS_EndOfMessage = 0,
        NTS_NextProto = 1,
        NTS_Error = 2,
        NTS_Warning = 3,
        /* may be critical */
        NTS_AEADAlgorithm = 4,
        /* never critical */
        NTS_NTPv4Cookie = 5,
        /* never critical by clients, may be critical by servers */
        NTS_NTPv4Server = 6,
        NTS_NTPv4Port = 7,
        /* https://chrony-project.org/doc/spec/nts-compliant-128gcm.html */
        NTS_Chrony_BugWorkaround = 1024,
};

enum NTS_ProtocolType {
        NTS_PROTO_NTPv4 = 0,
};

typedef struct {
        uint8_t *data;
        uint8_t *data_end;
} slice;

static size_t capacity(const slice *p) {
        return p->data_end - p->data;
}

/* does not check bounds */
static void push_u16(uint8_t **data, uint16_t value) {
        value = htobe16(value);
        memcpy(*data, &value, 2);
        *data += 2;
}

static uint16_t u16_from_bytes(uint8_t bytes[2]) {
        uint16_t value;
        memcpy(&value, bytes, 2);
        return be16toh(value);
}

struct NTS_Record {
        uint16_t type;
        slice body;
};

static int32_t NTS_decode_u16(struct NTS_Record *record) {
        assert(record);

        if (capacity(&record->body) < 2)
                return -NTS_INSUFFICIENT_DATA;

        uint16_t result = u16_from_bytes(record->body.data);
        record->body.data += 2;
        return result;
}

static int NTS_decode_record(slice *message, struct NTS_Record *record) {
        assert(message);
        assert(record);

        size_t bytes_remaining = capacity(message);
        if (bytes_remaining < 4)
                /* not enough bytes to decode a header */
                return -NTS_INSUFFICIENT_DATA;

        bool is_critical = message->data[0] >> 7;

        uint16_t body_size = u16_from_bytes(message->data + 2);
        if (body_size > bytes_remaining - 4)
                /* not enough data in the slice to decode this header */
                return -NTS_INSUFFICIENT_DATA;

        record->type = u16_from_bytes(message->data) & 0x7FFF;
        record->body.data = message->data += 4;
        record->body.data_end = message->data += body_size;

        switch (record->type) {
        case NTS_Error:
        case NTS_Warning:
        case NTS_NTPv4Port:
                if (body_size != 2) goto error;
                break;
        case NTS_EndOfMessage:
                if (body_size != 0) goto error;
                break;
        case NTS_AEADAlgorithm:
        case NTS_NextProto:
                if (body_size % 2 != 0) goto error;
                break;
        default:
                if (is_critical)
                        return -NTS_UNKNOWN_CRIT_RECORD;
                break;
        case NTS_NTPv4Server:
        case NTS_NTPv4Cookie:
                break;
        }

        return 0;

error:
        /* there was an inconsistency in the record */
        return -NTS_BAD_RESPONSE;
}

static int NTS_encode_record_u16(
                slice *message,
                bool critical,
                enum NTS_RecordType type,
                const uint16_t *data, size_t num_words) {

        assert(message);
        assert(num_words == 0 || data);

        size_t bytes_remaining = capacity(message);
        if (num_words >= 0x8000 || bytes_remaining < 4 + num_words*2)
                /* not enough space */
                return -NTS_INSUFFICIENT_DATA;

        if (critical)
                type |= 0x8000;

        push_u16(&message->data, type);
        push_u16(&message->data, num_words * 2);

        for (size_t i = 0; i < num_words; i++)
                push_u16(&message->data, data[i]);

        return 0;
}

int NTS_encode_request(
                uint8_t *buffer,
                size_t buf_size,
                const NTS_AEADAlgorithmType *preferred_crypto) {

        assert(buffer);

        slice request = { buffer, buffer + buf_size };

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
        result  = NTS_encode_record_u16(&request, true, NTS_NextProto, proto, ELEMENTSOF(proto));
        result += NTS_encode_record_u16(&request, true, NTS_AEADAlgorithm, aead, aead_len);
#ifdef CHRONY_WORKAROUND
        result += NTS_encode_record_u16(&request, false, NTS_Chrony_BugWorkaround, NULL, 0);
#endif
        result += NTS_encode_record_u16(&request, true, NTS_EndOfMessage, NULL, 0);

        return (result<0)? result : request.data - buffer;
}

int NTS_decode_response(uint8_t *buffer, size_t buf_size, struct NTS_Agreement *response) {
        assert(buffer);
        assert(response);

        slice raw_response = { buffer, buffer+buf_size };
        struct NTS_Record rec;

        /* clear response */
        size_t cookie_nr = 0;
        bool is_ntp4 = false;
        char *ntp_server_terminator = NULL;

        /* make sure the result is only OK if we really succeed */
        *response = (struct NTS_Agreement) { .error = NTS_INTERNAL_CLIENT_ERROR };

        #define CHECK(expr, err) {               \
                if (expr); else {                 \
                        response->error = (err); \
                        return -1;               \
                }                                \
        }

        while (raw_response.data < raw_response.data_end) {
                int val = NTS_decode_record(&raw_response, &rec);
                CHECK(val >= 0, -val);
                switch (rec.type) {
                case NTS_Error:
                        CHECK((val = NTS_decode_u16(&rec)) >= 0, NTS_BAD_RESPONSE);
                        response->error = val;
                        return -1;

                case NTS_Warning:
                        CHECK(NTS_decode_u16(&rec) >= 0, NTS_BAD_RESPONSE);
                        response->error = NTS_UNEXPECTED_WARNING;
                        return -1;

                case NTS_EndOfMessage:
                        if (ntp_server_terminator)
                                /* this hack saves having to allocate a string that we are going to keep in-memory */
                                *ntp_server_terminator = '\0';

                        if (is_ntp4 && response->aead_id != 0) {
                                response->error = NTS_SUCCESS;
                                return 0;
                        } else {
                                response->error = NTS_BAD_RESPONSE;
                                return -1;
                        }

                case NTS_NextProto:
                        /* confirm that NTPv4 is on offer */
                        do {
                                CHECK((val = NTS_decode_u16(&rec)) >= 0, NTS_NO_PROTOCOL);
                        } while (val != NTS_PROTO_NTPv4);
                        is_ntp4 = true;
                        break;

                case NTS_AEADAlgorithm:
                        /* confirm that one of the supported AEAD algo's is offered */
                        CHECK((val = NTS_decode_u16(&rec)) >= 0, NTS_NO_AEAD);
                        response->aead_id = val;
                        CHECK(NTS_get_param(response->aead_id), NTS_NO_AEAD);
                        break;

                case NTS_NTPv4Cookie:
                        /* ignore any cookies in excess of eight */
                        if (cookie_nr < 8) {
                                struct NTS_Cookie *cookie = &response->cookie[cookie_nr++];
                                cookie->data   = rec.body.data;
                                cookie->length = rec.body.data_end - rec.body.data;
                        }
                        break;

                case NTS_NTPv4Server:
                        /* do limited sanity CHECK */
                        CHECK(capacity(&rec.body) <= 255, NTS_BAD_RESPONSE);
                        for (const uint8_t* p = rec.body.data; p != rec.body.data_end; p++)
                                CHECK(isascii(*p) && isgraph(*p), NTS_BAD_RESPONSE);

                        response->ntp_server  = (char *)rec.body.data;
                        ntp_server_terminator = (char *)rec.body.data_end;
                        break;

                case NTS_NTPv4Port:
                        CHECK((val = NTS_decode_u16(&rec)) >= 0, NTS_BAD_RESPONSE);
                        response->ntp_port = val;
                        break;

                default:
                        /* ignore unknown non-critical fields */
                        ;
                }
        }

        response->error = NTS_INSUFFICIENT_DATA;
        return -1;
}
#undef CHECK

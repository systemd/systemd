/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "alloc-util.h"
#include "dns-domain.h"
#include "string-util.h"
#include "timesyncd-ntske-protocol.h"

/* rfc8915 The NTS Key Establishment Protocol
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C|         Record Type         |          Body Length          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * .                                                               .
 * .                           Record Body                         .
 * .                                                               .
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

int nts_ke_packet_new(size_t max_size, NTSKEPacket **ret) {
        _cleanup_(ntske_packet_freep) NTSKEPacket *p = NULL;

        assert(ret);

        if (max_size > NTS_KE_MESSAGE_SIZE_MAX)
                max_size = NTS_KE_MESSAGE_SIZE_MAX;

        p = new0(NTSKEPacket, 1);
        if (!p)
                return -ENOMEM;

        if (max_size) {
                p->data = malloc0(max_size);
                if (!p->data)
                        return -ENOMEM;

                p->size = max_size;
        }

        *ret = TAKE_PTR(p);
        return 0;
}

NTSKEPacket *ntske_packet_free(NTSKEPacket *p) {
        if (!p)
                return NULL;

        free(p->data);
        free(p->server);
        return mfree(p);
}

void ntske_packet_drop_payload(NTSKEPacket *p) {
        if (!p)
                return;

        p->data = mfree(p->data);
        p->size = 0;
        p->read = 0;
        p->offset = 0;
        p->payload = false;
}

int ntske_append_record(NTSKEPacket *packet, uint16_t type, const void *data, size_t data_size, bool critical) {
        NTSKERecord h = {
                .type = htobe16(critical * NTS_KE_RECORD_CRITICAL_BIT | type),
                .size = htobe16(data_size),
        };
        uint8_t *new_data;

        assert(packet);

        if (packet->size + sizeof(NTSKERecord) + data_size > NTS_KE_MESSAGE_SIZE_MAX)
                return -E2BIG;

        new_data = realloc(packet->data, sizeof(NTSKERecord) + data_size);
        if (!new_data)
                return -ENOMEM;

        packet->data = new_data;

        memcpy(packet->data + packet->size, &h, sizeof(NTSKERecord));
        packet->size += sizeof(NTSKERecord);

        if (data_size > 0) {
                memcpy(packet->data + packet->size, data, data_size);
                packet->size += data_size;
        }

        return 0;
}

int ntske_read_record(NTSKEPacket *packet, uint16_t *type, uint8_t **data, size_t *data_size, bool *critical)  {
        size_t size, record_size;
        NTSKERecord h;

        assert(packet);

        if (packet->size < packet->offset + sizeof(NTSKERecord) || !packet->payload)
                return 0;

        memcpy(&h, packet->data + packet->offset, sizeof(NTSKERecord));

        size = be16toh(h.size);
        record_size = sizeof(NTSKERecord) + size;

        if (type)
                *type = be16toh(h.type) & ~NTS_KE_RECORD_CRITICAL_BIT;

        if (data)
                *data = packet->data + packet->offset + sizeof(NTSKERecord);

        if (data_size)
                *data_size = size;

        if (critical)
                *critical = (be16toh(h.type) & NTS_KE_RECORD_CRITICAL_BIT);

        packet->offset += record_size;
        return 1;
}

int ntske_parse_packet(NTSKEPacket *packet) {
        size_t n_cookies = 0, n_allocated = 0;
        bool end = false, critical = false;
        uint16_t type;
        size_t data_size;
        uint8_t *data;
        int r;

        for(; !end && ntske_read_record(packet, &type, &data, &data_size, &critical);) {
                uint16_t *p = (uint16_t *) data;

                switch (type & ~NTS_KE_RECORD_CRITICAL_BIT) {
                case NTS_KE_RECORD_END_OF_MESSAGE:
                        end = true;
                        break;
                case NTS_KE_RECORD_NEXT_PROTOCOL:
                        if (!critical || data_size != 2 || be16toh(*p) != NTS_KE_NEXT_PROTOCOL_NTPV4)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: Next protocol field has wrong size or type, ignoring packet");

                        packet->next_protocol = be16toh(*p);
                        break;
                case NTS_KE_RECORD_ERROR:
                        if (data_size != 2)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: Error field has wrong size, ignoring packet");

                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "NTSKE: Error message received %d, ignoring packet", be16toh(*p));

                        break;
                case NTS_KE_RECORD_WARNING:
                        break;
                case NTS_KE_RECORD_AEAD_ALGORITHM:
                        if (data_size != 2 || be16toh(*p) != AEAD_AES_SIV_CMAC_256)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: AEAD algorithm field has wrong size or type, ignoring packet");

                        packet->aead_algorithm = AEAD_AES_SIV_CMAC_256;
                        break;
                case NTS_KE_RECORD_COOKIE: {
                        NTSCookie cookie;

                        if (data_size > NTS_KE_COOKIE_SIZE_MAX || packet->n_cookies >= NTS_KE_COOKIES_MAX)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: Cookie field has wrong size or exceeds max allowed values, ignoring packet");

                        cookie.size = data_size;
                        memcpy(&cookie.cookie, data, data_size);
                        if (!GREEDY_REALLOC(packet->cookies, n_allocated, n_cookies + 1))
                                return log_oom();

                        packet->cookies[n_cookies++] = cookie;
                        packet->n_cookies = n_cookies;
                }
                        break;
                case NTS_KE_RECORD_NTPV4_SERVER_NEGOTIATION: {
                        _cleanup_free_ char *d = NULL;

                        if (data_size == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: NTP4 server negotation field has wrong size, ignoring packet");

                        d = memdup_suffix0(data, data_size);
                        if (!d)
                                return -ENOMEM;

                        r = dns_name_is_valid_or_address(d);
                        if (r < 0)
                                return log_debug_errno(r, "NTSKE: Failed to check validity of NTP server name or address '%s': %m", d);
                        if (r == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: Invalid NTP server name or address '%s', ignoring : %m", d);

                        packet->server = TAKE_PTR(d);                }
                        break;
                case NTS_KE_RECORD_NTPV4_PORT_NEGOTIATION: {
                        if (data_size > 0 && data_size != sizeof(uint16_t)) {
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "NTSKE: NTP4 port negotation field has wrong size, ignoring packet");
                        }  else
                                packet->port = be32toh(*p);
                }
                        break;
                default:
                        break;
                }
        }

        ntske_packet_rewind(packet);

        if (packet->aead_algorithm == AEAD_NO_CIPHER)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTSKE: Missing AEAD algorithm field, ignoring packet");

        if (packet->n_cookies == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "NTSKE: Missing Cookie field, ignoring packet");

        log_debug("NTSKE: Received Next Protocol='%d', AEAD Algorithm='%d', Server='%s', N Cookies='%d' of size='%d' each",
                  packet->next_protocol, packet->aead_algorithm, strna(packet->server), (int) n_cookies, (int) packet->cookies[n_cookies-1].size);

        return 0;
}

int ntske_build_request_packet(NTSKEPacket **ret) {
        _cleanup_free_ NTSKEPacket *packet = NULL;
        uint16_t d;
        int r;

        r = nts_ke_packet_new(0, &packet);
        if (r < 0)
                return r;

        d = htobe16(NTS_KE_NEXT_PROTOCOL_NTPV4);
        r = ntske_append_record(packet, NTS_KE_RECORD_NEXT_PROTOCOL, &d, sizeof(uint16_t), true);
        if (r < 0)
                return r;

        d = htobe16(AEAD_AES_SIV_CMAC_256);
        r = ntske_append_record(packet, NTS_KE_RECORD_AEAD_ALGORITHM, &d, sizeof(uint16_t), true);
        if (r < 0)
                return r;

        r = ntske_append_record(packet, NTS_KE_RECORD_END_OF_MESSAGE, NULL, 0, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(packet);
        return 0;
}

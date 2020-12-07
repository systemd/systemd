/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "alloc-util.h"
#include "memory-util.h"
#include "random-util.h"

#include "timesyncd-ntp-extension.h"
#include "timesyncd-ntp-message.h"
#include "timesyncd-ntske-protocol.h"

/* rfc5905 7.5. NTP Extension Field Format
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Field Type           |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  .                                                               .
 *  .                            Value                              .
 *  .                                                               .
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Padding (as needed)                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
*/
int ntp_extension_packet_new(size_t max_size, uint8_t *data, NTPExtensionPacket **ret) {
        _cleanup_(ntp_extension_packet_freep) NTPExtensionPacket *p = NULL;

        assert(ret);
        assert(max_size <= NTP_EXTENSION_MESSAGE_SIZE_MAX);

        if (max_size > NTP_EXTENSION_MESSAGE_SIZE_MAX)
                max_size = NTP_EXTENSION_MESSAGE_SIZE_MAX;

        p = new0(NTPExtensionPacket, 1);
        if (!p)
                return -ENOMEM;

        p->data = data;

        *ret = TAKE_PTR(p);
        return 0;
}

NTPExtensionPacket *ntp_extension_packet_free(NTPExtensionPacket *p) {
        if (!p)
                return NULL;
        return mfree(p);
}

int ntp_extension_append_field(NTPExtensionPacket *packet, uint16_t type, const void *data, size_t data_size) {
        NTPExtensionField p = {
                .type = htobe16(type),
                .size = htobe16(data_size + sizeof(NTPExtensionField)),
        };

        assert_return(packet, -EINVAL);

        if (packet->size + NTS_HEADER_SIZE + data_size > NTP_EXTENSION_MESSAGE_SIZE_MAX)
                return -E2BIG;

        memcpy(packet->data + packet->size, &p, sizeof(NTPExtensionField));
        packet->size += sizeof(NTPExtensionField);

        if (data_size > 0) {
                if (data)
                        memcpy(packet->data + packet->size, data, data_size);
                else
                        memzero(packet->data + packet->size, data_size);

                packet->size += data_size;
        }

        return 0;
}

int ntp_extension_append_empty_field(NTPExtensionPacket *packet, uint16_t type, size_t data_size, void **body) {
        NTPExtensionField *h;

        assert_return(packet, -EINVAL);

        if (packet->size + NTS_HEADER_SIZE + data_size > NTP_EXTENSION_MESSAGE_SIZE_MAX)
                return -E2BIG;

        h = (NTPExtensionField *) (packet->data + packet->size);
        h->type = htobe16(type);
        h->size = htobe16(data_size + NTS_HEADER_SIZE);

        packet->size += sizeof(NTPExtensionField) + data_size;
        *body = h + 1;

        return 0;
}

int ntp_extension_read_field(NTPExtensionPacket *packet, uint16_t *type, size_t *total_size, void **data, size_t *data_size)  {
        NTPExtensionField *h;
        uint16_t t;
        size_t s;

        assert_return(packet, -EINVAL);
        assert_return(packet->size > 0, -EINVAL);

        if (packet->offset >= packet->size)
                return 0;

        h = (NTPExtensionField *) (packet->data + packet->offset);
        t = be16toh(h->type);
        s = be16toh(h->size);

        /* packet ends */
        if (t == 0 || s == 0)
                return 0;

        if (type)
                *type = t;

        if (total_size)
                *total_size = s;

        if (data)
                *data = h + 1;

        if (data_size)
                *data_size = s - sizeof(NTPExtensionField);


        packet->offset += s;

        return 1;
}

int ntp_extension_read_cookie_from_auth_field(uint8_t *message, size_t size, void **cookie, size_t *cookie_size)  {
        NTPExtensionField *h;
        uint16_t t;
        size_t s;

        assert_return(message, -EINVAL);
        assert_return(size > 0, -EINVAL);

        h = (NTPExtensionField *) (message);
        t = be16toh(h->type);
        s = be16toh(h->size);

        if (t != NTP_EXTENSION_FIELD_NTS_COOKIE || s == 0)
                return -EBADMSG;

        if (cookie)
                *cookie = h + 1;

        if (cookie_size)
                *cookie_size = s - sizeof(NTPExtensionField);

        return 0;
}

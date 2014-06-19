/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/in.h>
#include <errno.h>
#include <string.h>

#include "sparse-endian.h"
#include "util.h"

#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"

#define DHCP6_OPTION_HDR_LEN                    4
#define DHCP6_OPTION_IA_NA_LEN                  12
#define DHCP6_OPTION_IA_TA_LEN                  4
#define DHCP6_OPTION_IAADDR_LEN                 24

static int option_append_hdr(uint8_t **buf, size_t *buflen, uint16_t optcode,
                             size_t optlen) {
        assert_return(buf, -EINVAL);
        assert_return(*buf, -EINVAL);
        assert_return(buflen, -EINVAL);

        if (optlen > 0xffff || *buflen < optlen + DHCP6_OPTION_HDR_LEN)
                return -ENOBUFS;

        (*buf)[0] = optcode >> 8;
        (*buf)[1] = optcode & 0xff;
        (*buf)[2] = optlen >> 8;
        (*buf)[3] = optlen & 0xff;

        *buf += DHCP6_OPTION_HDR_LEN;
        *buflen -= DHCP6_OPTION_HDR_LEN;

        return 0;
}

int dhcp6_option_append(uint8_t **buf, size_t *buflen, uint16_t code,
                        size_t optlen, const void *optval) {
        int r;

        assert_return(optval, -EINVAL);

        r = option_append_hdr(buf, buflen, code, optlen);
        if (r < 0)
                return r;

        memcpy(*buf, optval, optlen);

        *buf += optlen;
        *buflen -= optlen;

        return 0;
}

int dhcp6_option_append_ia(uint8_t **buf, size_t *buflen, DHCP6IA *ia) {
        uint16_t len;
        uint8_t *ia_hdr;
        size_t ia_buflen, ia_addrlen = 0;
        DHCP6Address *addr;
        int r;

        assert_return(buf && *buf && buflen && ia, -EINVAL);

        switch (ia->type) {
        case DHCP6_OPTION_IA_NA:
                len = DHCP6_OPTION_IA_NA_LEN;
                break;

        case DHCP6_OPTION_IA_TA:
                len = DHCP6_OPTION_IA_TA_LEN;
                break;

        default:
                return -EINVAL;
        }

        if (*buflen < len)
                return -ENOBUFS;

        ia_hdr = *buf;
        ia_buflen = *buflen;

        *buf += DHCP6_OPTION_HDR_LEN;
        *buflen -= DHCP6_OPTION_HDR_LEN;

        memcpy(*buf, &ia->id, len);

        *buf += len;
        *buflen -= len;

        LIST_FOREACH(addresses, addr, ia->addresses) {
                r = option_append_hdr(buf, buflen, DHCP6_OPTION_IAADDR,
                                      DHCP6_OPTION_IAADDR_LEN);
                if (r < 0)
                        return r;

                memcpy(*buf, &addr->address, DHCP6_OPTION_IAADDR_LEN);

                *buf += DHCP6_OPTION_IAADDR_LEN;
                *buflen -= DHCP6_OPTION_IAADDR_LEN;

                ia_addrlen += DHCP6_OPTION_HDR_LEN + DHCP6_OPTION_IAADDR_LEN;
        }

        r = option_append_hdr(&ia_hdr, &ia_buflen, ia->type, len + ia_addrlen);
        if (r < 0)
                return r;

        return 0;
}

int dhcp6_option_parse(uint8_t **buf, size_t *buflen, uint16_t *optcode,
                       size_t *optlen, uint8_t **optvalue) {
        assert_return(buf && buflen && optcode && optlen && optvalue, -EINVAL);

        if (*buflen == 0)
                return -ENOMSG;

        *optcode = (*buf)[0] << 8 | (*buf)[1];
        *optlen = (*buf)[2] << 8 | (*buf)[3];

        if (*optlen > *buflen - 4)
                return -ENOBUFS;

        *optvalue = &(*buf)[4];
        *buflen -= (*optlen + 4);
        (*buf) += (*optlen + 4);

        return 0;
}

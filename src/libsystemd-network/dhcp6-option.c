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

        assert_return(optval || optlen == 0, -EINVAL);

        r = option_append_hdr(buf, buflen, code, optlen);
        if (r < 0)
                return r;

        if (optval)
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


static int option_parse_hdr(uint8_t **buf, size_t *buflen, uint16_t *opt,
                            size_t *optlen) {
        uint16_t len;

        assert_return(buf, -EINVAL);
        assert_return(opt, -EINVAL);
        assert_return(optlen, -EINVAL);

        if (*buflen < 4)
                return -ENOMSG;

        len = (*buf)[2] << 8 | (*buf)[3];

        if (len > *buflen)
                return -ENOMSG;

        *opt = (*buf)[0] << 8 | (*buf)[1];
        *optlen = len;

        *buf += 4;
        *buflen -= 4;

        return 0;
}

int dhcp6_option_parse(uint8_t **buf, size_t *buflen, uint16_t *optcode,
                       size_t *optlen, uint8_t **optvalue) {
        int r;

        assert_return(buf && buflen && optcode && optlen && optvalue, -EINVAL);

        r = option_parse_hdr(buf, buflen, optcode, optlen);
        if (r < 0)
                return r;

        if (*optlen > *buflen)
                return -ENOBUFS;

        *optvalue = *buf;
        *buflen -= *optlen;
        *buf += *optlen;

        return 0;
}

int dhcp6_option_parse_ia(uint8_t **buf, size_t *buflen, uint16_t iatype,
                          DHCP6IA *ia) {
        int r;
        uint16_t opt, status;
        size_t optlen;
        size_t iaaddr_offset;
        DHCP6Address *addr;
        uint32_t lt_t1, lt_t2, lt_valid, lt_pref, lt_min = ~0;

        assert_return(ia, -EINVAL);
        assert_return(!ia->addresses, -EINVAL);

        switch (iatype) {
        case DHCP6_OPTION_IA_NA:

                if (*buflen < DHCP6_OPTION_IA_NA_LEN + DHCP6_OPTION_HDR_LEN +
                    DHCP6_OPTION_IAADDR_LEN) {
                        r = -ENOBUFS;
                        goto error;
                }

                iaaddr_offset = DHCP6_OPTION_IA_NA_LEN;
                memcpy(&ia->id, *buf, iaaddr_offset);

                lt_t1 = be32toh(ia->lifetime_t1);
                lt_t2 = be32toh(ia->lifetime_t2);

                if (lt_t1 && lt_t2 && lt_t1 > lt_t2) {
                        log_dhcp6_client(client, "IA T1 %ds > T2 %ds",
                                         lt_t1, lt_t2);
                        r = -EINVAL;
                        goto error;
                }

                break;

        case DHCP6_OPTION_IA_TA:
                if (*buflen < DHCP6_OPTION_IA_TA_LEN + DHCP6_OPTION_HDR_LEN +
                    DHCP6_OPTION_IAADDR_LEN) {
                        r = -ENOBUFS;
                        goto error;
                }

                iaaddr_offset = DHCP6_OPTION_IA_TA_LEN;
                memcpy(&ia->id, *buf, iaaddr_offset);

                ia->lifetime_t1 = 0;
                ia->lifetime_t2 = 0;

                break;

        default:
                r = -ENOMSG;
                goto error;
        }

        ia->type = iatype;

        *buflen -= iaaddr_offset;
        *buf += iaaddr_offset;

        while ((r = option_parse_hdr(buf, buflen, &opt, &optlen)) >= 0) {

                switch (opt) {
                case DHCP6_OPTION_IAADDR:

                        addr = new0(DHCP6Address, 1);
                        if (!addr) {
                                r = -ENOMEM;
                                goto error;
                        }

                        LIST_INIT(addresses, addr);

                        memcpy(&addr->address, *buf, DHCP6_OPTION_IAADDR_LEN);

                        lt_valid = be32toh(addr->lifetime_valid);
                        lt_pref = be32toh(addr->lifetime_valid);

                        if (!lt_valid || lt_pref > lt_valid) {
                                log_dhcp6_client(client, "IA preferred %ds > valid %ds",
                                                 lt_pref, lt_valid);
                                free(addr);
                        } else {
                                LIST_PREPEND(addresses, ia->addresses, addr);
                                if (lt_valid < lt_min)
                                        lt_min = lt_valid;
                        }

                        break;

                case DHCP6_OPTION_STATUS_CODE:
                        if (optlen < sizeof(status))
                                break;

                        status = (*buf)[0] << 8 | (*buf)[1];
                        if (status) {
                                log_dhcp6_client(client, "IA status %d",
                                                 status);
                                r = -EINVAL;
                                goto error;
                        }

                        break;

                default:
                        log_dhcp6_client(client, "Unknown IA option %d", opt);
                        break;
                }

                *buflen -= optlen;
                *buf += optlen;
        }

        if (r == -ENOMSG)
                r = 0;

        if (!ia->lifetime_t1 && !ia->lifetime_t2) {
                lt_t1 = lt_min / 2;
                lt_t2 = lt_min / 10 * 8;
                ia->lifetime_t1 = htobe32(lt_t1);
                ia->lifetime_t2 = htobe32(lt_t2);

                log_dhcp6_client(client, "Computed IA T1 %ds and T2 %ds as both were zero",
                                 lt_t1, lt_t2);
        }

        if (*buflen)
                r = -ENOMSG;

error:
        *buf += *buflen;
        *buflen = 0;

        return r;
}

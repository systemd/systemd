#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2015 Tom Gundersen <teg@jklmen>

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

#include "sd-id128.h"

#include "macro.h"
#include "sparse-endian.h"
#include "unaligned.h"

typedef enum DUIDType {
        DUID_TYPE_RAW       = 0,
        DUID_TYPE_LLT       = 1,
        DUID_TYPE_EN        = 2,
        DUID_TYPE_LL        = 3,
        DUID_TYPE_UUID      = 4,
        _DUID_TYPE_MAX,
        _DUID_TYPE_INVALID  = -1,
} DUIDType;

/* RFC 3315 section 9.1:
 *      A DUID can be no more than 128 octets long (not including the type code).
 */
#define MAX_DUID_LEN 128

struct duid {
        be16_t type;
        union {
                struct {
                        /* DHCP6_DUID_LLT */
                        uint16_t htype;
                        uint32_t time;
                        uint8_t haddr[0];
                } _packed_ llt;
                struct {
                        /* DHCP6_DUID_EN */
                        uint32_t pen;
                        uint8_t id[8];
                } _packed_ en;
                struct {
                        /* DHCP6_DUID_LL */
                        int16_t htype;
                        uint8_t haddr[0];
                } _packed_ ll;
                struct {
                        /* DHCP6_DUID_UUID */
                        sd_id128_t uuid;
                } _packed_ uuid;
                struct {
                        uint8_t data[MAX_DUID_LEN];
                } _packed_ raw;
        };
} _packed_;

int dhcp_identifier_set_duid_en(struct duid *duid, size_t *len);
int dhcp_identifier_set_iaid(int ifindex, uint8_t *mac, size_t mac_len, void *_id);

static inline int dhcp_validate_duid_len(uint16_t duid_type, size_t duid_len) {
        struct duid d;

        assert_return(duid_len > 0 && duid_len <= MAX_DUID_LEN, -EINVAL);

        switch (duid_type) {
        case DUID_TYPE_LLT:
                if (duid_len <= sizeof(d.llt))
                        return -EINVAL;
                break;
        case DUID_TYPE_EN:
                if (duid_len != sizeof(d.en))
                        return -EINVAL;
                break;
        case DUID_TYPE_LL:
                if (duid_len <= sizeof(d.ll))
                        return -EINVAL;
                break;
        case DUID_TYPE_UUID:
                if (duid_len != sizeof(d.uuid))
                        return -EINVAL;
                break;
        default:
                /* accept unknown type in order to be forward compatible */
                break;
        }
        return 0;
}

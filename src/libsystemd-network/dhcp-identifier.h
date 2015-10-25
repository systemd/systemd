/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

/* RFC 3315 section 9.1:
 *      A DUID can be no more than 128 octets long (not including the type code).
 */
#define MAX_DUID_LEN 128

struct duid {
        uint16_t type;
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

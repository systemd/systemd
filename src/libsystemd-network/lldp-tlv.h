/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

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

#pragma once

#include <net/ethernet.h>

#include "util.h"
#include "lldp.h"
#include "list.h"

#include "sd-lldp.h"

#define LLDP_OUI_LEN 3

#define LLDP_MAC_NEAREST_BRIDGE          (uint8_t[]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }
#define LLDP_MAC_NEAREST_NON_TPMR_BRIDGE (uint8_t[]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }
#define LLDP_MAC_NEAREST_CUSTOMER_BRIDGE (uint8_t[]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }

struct sd_lldp_section {
        uint16_t type;
        uint16_t length;
        uint8_t *oui;
        uint8_t subtype;

        uint8_t *read_pos;
        uint8_t *data;

        LIST_FIELDS(sd_lldp_section, section);
};

struct sd_lldp_packet {
        unsigned n_ref;

        uint16_t type;
        uint16_t length;
        usec_t ts;

        uint8_t *container_pos;
        uint8_t pdu[ETHER_MAX_LEN];

        void *userdata;

        struct ether_addr mac;
        sd_lldp_section *container;

        LIST_HEAD(sd_lldp_section, sections);
};


DEFINE_TRIVIAL_CLEANUP_FUNC(sd_lldp_packet*, sd_lldp_packet_unref);
#define _cleanup_lldp_packet_unref_ _cleanup_(sd_lldp_packet_unrefp)

int sd_lldp_packet_parse_pdu(sd_lldp_packet *t, uint16_t size);

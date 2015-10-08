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

typedef struct sd_lldp_packet tlv_packet;
typedef struct sd_lldp_section tlv_section;

#define LLDP_OUI_LEN 3

struct sd_lldp_section {
        uint16_t type;
        uint16_t length;
        uint8_t *oui;
        uint8_t subtype;

        uint8_t *read_pos;
        uint8_t *data;

        LIST_FIELDS(tlv_section, section);
};

#define LLDP_MAC_NEAREST_BRIDGE          (uint8_t[]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }
#define LLDP_MAC_NEAREST_NON_TPMR_BRIDGE (uint8_t[]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }
#define LLDP_MAC_NEAREST_CUSTOMER_BRIDGE (uint8_t[]) { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }

int tlv_section_new(tlv_section **ret);
void tlv_section_free(tlv_section *ret);

struct sd_lldp_packet {
        unsigned n_ref;

        uint16_t type;
        uint16_t length;
        usec_t ts;

        uint8_t *container_pos;
        uint8_t pdu[ETHER_MAX_LEN];

        void *userdata;

        struct ether_addr mac;
        tlv_section *container;

        LIST_HEAD(tlv_section, sections);
};

int tlv_packet_new(tlv_packet **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_lldp_packet*, sd_lldp_packet_unref);
#define _cleanup_lldp_packet_unref_ _cleanup_(sd_lldp_packet_unrefp)

int lldp_tlv_packet_open_container(tlv_packet *m, uint16_t type);
int lldp_tlv_packet_close_container(tlv_packet *m);

int tlv_packet_append_bytes(tlv_packet *m, const void *data, size_t data_length);
int tlv_packet_append_u8(tlv_packet *m, uint8_t data);
int tlv_packet_append_u16(tlv_packet *m, uint16_t data);
int tlv_packet_append_u32(tlv_packet *m, uint32_t data);
int tlv_packet_append_string(tlv_packet *m, char *data, uint16_t size);

int lldp_tlv_packet_enter_container(tlv_packet *m, uint16_t type);
int lldp_tlv_packet_enter_container_oui(tlv_packet *m, const uint8_t *oui, uint8_t subtype);
int lldp_tlv_packet_exit_container(tlv_packet *m);

int tlv_packet_read_bytes(tlv_packet *m, uint8_t **data, uint16_t *data_length);
int tlv_packet_read_string(tlv_packet *m, char **data, uint16_t *data_length);
int tlv_packet_read_u8(tlv_packet *m, uint8_t *data);
int tlv_packet_read_u16(tlv_packet *m, uint16_t *data);
int tlv_packet_read_u32(tlv_packet *m, uint32_t *data);

int tlv_packet_parse_pdu(tlv_packet *t, uint16_t size);

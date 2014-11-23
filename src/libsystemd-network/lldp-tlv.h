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

typedef struct tlv_packet tlv_packet;
typedef struct tlv_section tlv_section;

struct tlv_section {
        uint16_t type;
        uint16_t length;

        uint8_t *read_pos;
        uint8_t *data;

        LIST_FIELDS(tlv_section, section);
};

int tlv_section_new(tlv_section **ret);
void tlv_section_free(tlv_section *ret);

struct tlv_packet {
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
void tlv_packet_free(tlv_packet *m);

DEFINE_TRIVIAL_CLEANUP_FUNC(tlv_packet*, tlv_packet_free);
#define _cleanup_tlv_packet_free_ _cleanup_(tlv_packet_freep)

int lldp_tlv_packet_open_container(tlv_packet *m, uint16_t type);
int lldp_tlv_packet_close_container(tlv_packet *m);

int tlv_packet_append_bytes(tlv_packet *m, const void *data, size_t data_length);
int tlv_packet_append_u8(tlv_packet *m, uint8_t data);
int tlv_packet_append_u16(tlv_packet *m, uint16_t data);
int tlv_packet_append_u32(tlv_packet *m, uint32_t data);
int tlv_packet_append_string(tlv_packet *m, char *data, uint16_t size);

int lldp_tlv_packet_enter_container(tlv_packet *m, uint16_t type);
int lldp_tlv_packet_exit_container(tlv_packet *m);

int tlv_packet_read_bytes(tlv_packet *m, uint8_t **data, uint16_t *data_length);
int tlv_packet_read_string(tlv_packet *m, char **data, uint16_t *data_length);
int tlv_packet_read_u8(tlv_packet *m, uint8_t *data);
int tlv_packet_read_u16(tlv_packet *m, uint16_t *data);
int tlv_packet_read_u32(tlv_packet *m, uint32_t *data);

int tlv_packet_parse_pdu(tlv_packet *t, uint16_t size);

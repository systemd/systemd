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

#include "sd-event.h"

enum {
        SD_LLDP_EVENT_UPDATE_INFO       = 0,
};

enum {
        SD_LLDP_DESTINATION_TYPE_NEAREST_BRIDGE,
        SD_LLDP_DESTINATION_TYPE_NEAREST_NON_TPMR_BRIDGE,
        SD_LLDP_DESTINATION_TYPE_NEAREST_CUSTOMER_BRIDGE,
};

typedef struct sd_lldp sd_lldp;
typedef struct sd_lldp_packet sd_lldp_packet;
typedef struct sd_lldp_section sd_lldp_section;

typedef void (*sd_lldp_cb_t)(sd_lldp *lldp, int event, void *userdata);

int sd_lldp_new(int ifindex, const char *ifname, const struct ether_addr *mac, sd_lldp **ret);
void sd_lldp_free(sd_lldp *lldp);

int sd_lldp_start(sd_lldp *lldp);
int sd_lldp_stop(sd_lldp *lldp);

int sd_lldp_attach_event(sd_lldp *lldp, sd_event *event, int priority);
int sd_lldp_detach_event(sd_lldp *lldp);

int sd_lldp_set_callback(sd_lldp *lldp, sd_lldp_cb_t cb, void *userdata);
int sd_lldp_save(sd_lldp *lldp, const char *file);

int sd_lldp_packet_new(sd_lldp_packet **ret);

sd_lldp_packet *sd_lldp_packet_ref(sd_lldp_packet *m);
sd_lldp_packet *sd_lldp_packet_unref(sd_lldp_packet *m);

int sd_lldp_section_new(sd_lldp_section **ret);
void sd_lldp_section_free(sd_lldp_section *ret);

int sd_lldp_packet_read_chassis_id(sd_lldp_packet *m, uint8_t *type, uint8_t **data, uint16_t *length);
int sd_lldp_packet_read_port_id(sd_lldp_packet *m, uint8_t *type, uint8_t **data, uint16_t *length);
int sd_lldp_packet_read_ttl(sd_lldp_packet *m, uint16_t *ttl);
int sd_lldp_packet_read_system_name(sd_lldp_packet *m, char **data, uint16_t *length);
int sd_lldp_packet_read_system_description(sd_lldp_packet *m, char **data, uint16_t *length);
int sd_lldp_packet_read_system_capability(sd_lldp_packet *m, uint16_t *data);
int sd_lldp_packet_read_port_description(sd_lldp_packet *m, char **data, uint16_t *length);

/* IEEE 802.1 organizationally specific TLVs */
int sd_lldp_packet_read_port_vlan_id(sd_lldp_packet *m, uint16_t *id);
int sd_lldp_packet_read_port_protocol_vlan_id(sd_lldp_packet *m, uint8_t *flags, uint16_t *id);
int sd_lldp_packet_read_vlan_name(sd_lldp_packet *m, uint16_t *vlan_id, char **name, uint16_t *length);
int sd_lldp_packet_read_management_vid(sd_lldp_packet *m, uint16_t *id);
int sd_lldp_packet_read_link_aggregation(sd_lldp_packet *m, uint8_t *status, uint32_t *id);

int sd_lldp_packet_get_destination_type(sd_lldp_packet *m, int *dest);

int sd_lldp_get_packets(sd_lldp *lldp, sd_lldp_packet ***tlvs);

int sd_lldp_packet_open_container(sd_lldp_packet *m, uint16_t type);
int sd_lldp_packet_close_container(sd_lldp_packet *m);

int sd_lldp_packet_append_bytes(sd_lldp_packet *m, const void *data, size_t data_length);
int sd_lldp_packet_append_u8(sd_lldp_packet *m, uint8_t data);
int sd_lldp_packet_append_u16(sd_lldp_packet *m, uint16_t data);
int sd_lldp_packet_append_u32(sd_lldp_packet *m, uint32_t data);
int sd_lldp_packet_append_string(sd_lldp_packet *m, char *data, uint16_t size);

int sd_lldp_packet_enter_container(sd_lldp_packet *m, uint16_t type);
int sd_lldp_packet_enter_container_oui(sd_lldp_packet *m, const uint8_t *oui, uint8_t subtype);
int sd_lldp_packet_exit_container(sd_lldp_packet *m);

int sd_lldp_packet_read_bytes(sd_lldp_packet *m, uint8_t **data, uint16_t *data_length);
int sd_lldp_packet_read_string(sd_lldp_packet *m, char **data, uint16_t *data_length);
int sd_lldp_packet_read_u8(sd_lldp_packet *m, uint8_t *data);
int sd_lldp_packet_read_u16(sd_lldp_packet *m, uint16_t *data);
int sd_lldp_packet_read_u32(sd_lldp_packet *m, uint32_t *data);

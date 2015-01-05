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

#include "log.h"
#include "list.h"
#include "refcnt.h"
#include "lldp-tlv.h"
#include "prioq.h"

typedef struct lldp_neighbour_port lldp_neighbour_port;
typedef struct lldp_chassis lldp_chassis;
typedef struct lldp_chassis_id lldp_chassis_id;
typedef struct lldp_agent_statistics lldp_agent_statistics;

struct lldp_neighbour_port {
        uint8_t type;
        uint8_t *data;

        uint16_t length;
        usec_t until;

        unsigned prioq_idx;

        lldp_chassis *c;
        tlv_packet *packet;

        LIST_FIELDS(lldp_neighbour_port, port);
};

int lldp_neighbour_port_new(lldp_chassis *c, tlv_packet *tlv, lldp_neighbour_port **ret);
void lldp_neighbour_port_free(lldp_neighbour_port *p);
void lldp_neighbour_port_remove_and_free(lldp_neighbour_port *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(lldp_neighbour_port *, lldp_neighbour_port_free);
#define _cleanup_lldp_neighbour_port_free_ _cleanup_(lldp_neighbour_port_freep)

struct lldp_chassis_id {
        uint8_t type;
        uint16_t length;

        uint8_t *data;
};

struct lldp_chassis {
        RefCount n_ref;

        lldp_chassis_id chassis_id;

        Prioq *by_expiry;
        Hashmap *neighbour_mib;

        LIST_HEAD(lldp_neighbour_port, ports);
};

int lldp_chassis_new(tlv_packet *tlv,
                     Prioq *by_expiry,
                     Hashmap *neighbour_mib,
                     lldp_chassis **ret);

void lldp_chassis_free(lldp_chassis *c);

DEFINE_TRIVIAL_CLEANUP_FUNC(lldp_chassis *, lldp_chassis_free);
#define _cleanup_lldp_chassis_free_ _cleanup_(lldp_chassis_freep)

int lldp_mib_update_objects(lldp_chassis *c, tlv_packet *tlv);
int lldp_mib_add_objects(Prioq *by_expiry, Hashmap *neighbour_mib, tlv_packet *tlv);
int lldp_mib_remove_objects(lldp_chassis *c, tlv_packet *tlv);

int lldp_read_chassis_id(tlv_packet *tlv, uint8_t *type, uint16_t *length, uint8_t **data);
int lldp_read_port_id(tlv_packet *tlv, uint8_t *type, uint16_t *length, uint8_t **data);
int lldp_read_ttl(tlv_packet *tlv, uint16_t *ttl);
int lldp_read_system_name(tlv_packet *tlv, uint16_t *length, char **data);
int lldp_read_system_description(tlv_packet *tlv, uint16_t *length, char **data);
int lldp_read_system_capability(tlv_packet *tlv, uint16_t *data);
int lldp_read_port_description(tlv_packet *tlv, uint16_t *length, char **data);

int lldp_handle_packet(tlv_packet *m, uint16_t length);
#define log_lldp(fmt, ...) log_internal(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, "LLDP: " fmt, ##__VA_ARGS__)

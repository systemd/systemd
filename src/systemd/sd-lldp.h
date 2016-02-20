#ifndef foosdlldphfoo
#define foosdlldphfoo

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

#include <inttypes.h>
#include <net/ethernet.h>

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_lldp sd_lldp;
typedef struct sd_lldp_neighbor sd_lldp_neighbor;

typedef void (*sd_lldp_callback_t)(sd_lldp *lldp, void *userdata);

int sd_lldp_new(sd_lldp **ret, int ifindex);
sd_lldp* sd_lldp_unref(sd_lldp *lldp);

int sd_lldp_start(sd_lldp *lldp);
int sd_lldp_stop(sd_lldp *lldp);

int sd_lldp_attach_event(sd_lldp *lldp, sd_event *event, int64_t priority);
int sd_lldp_detach_event(sd_lldp *lldp);

int sd_lldp_set_callback(sd_lldp *lldp, sd_lldp_callback_t cb, void *userdata);

/* Controls how much and what to store in the neighbors database */
int sd_lldp_set_neighbors_max(sd_lldp *lldp, uint64_t n);
int sd_lldp_match_capabilities(sd_lldp *lldp, uint16_t mask);

int sd_lldp_get_neighbors(sd_lldp *lldp, sd_lldp_neighbor ***neighbors);

int sd_lldp_neighbor_from_raw(sd_lldp_neighbor **ret, const void *raw, size_t raw_size);
sd_lldp_neighbor *sd_lldp_neighbor_ref(sd_lldp_neighbor *n);
sd_lldp_neighbor *sd_lldp_neighbor_unref(sd_lldp_neighbor *n);

/* Access to LLDP frame metadata */
int sd_lldp_neighbor_get_source_address(sd_lldp_neighbor *n, struct ether_addr* address);
int sd_lldp_neighbor_get_destination_address(sd_lldp_neighbor *n, struct ether_addr* address);
int sd_lldp_neighbor_get_raw(sd_lldp_neighbor *n, const void **ret, size_t *size);

/* High-level, direct, parsed out field access. These fields exist at most once, hence may be queried directly. */
int sd_lldp_neighbor_get_chassis_id(sd_lldp_neighbor *n, uint8_t *type, const void **ret, size_t *size);
int sd_lldp_neighbor_get_chassis_id_as_string(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_port_id(sd_lldp_neighbor *n, uint8_t *type, const void **ret, size_t *size);
int sd_lldp_neighbor_get_port_id_as_string(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_ttl(sd_lldp_neighbor *n, uint16_t *ret);
int sd_lldp_neighbor_get_system_name(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_system_description(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_port_description(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_system_capabilities(sd_lldp_neighbor *n, uint16_t *ret);
int sd_lldp_neighbor_get_enabled_capabilities(sd_lldp_neighbor *n, uint16_t *ret);

/* Low-level, iterative TLV access. This is for evertyhing else, it iteratively goes through all available TLVs
 * (including the ones covered with the calls above), and allows multiple TLVs for the same fields. */
int sd_lldp_neighbor_tlv_rewind(sd_lldp_neighbor *n);
int sd_lldp_neighbor_tlv_next(sd_lldp_neighbor *n);
int sd_lldp_neighbor_tlv_get_type(sd_lldp_neighbor *n, uint8_t *type);
int sd_lldp_neighbor_tlv_is_type(sd_lldp_neighbor *n, uint8_t type);
int sd_lldp_neighbor_tlv_get_oui(sd_lldp_neighbor *n, uint8_t oui[3], uint8_t *subtype);
int sd_lldp_neighbor_tlv_is_oui(sd_lldp_neighbor *n, const uint8_t oui[3], uint8_t subtype);
int sd_lldp_neighbor_tlv_get_raw(sd_lldp_neighbor *n, const void **ret, size_t *size);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_lldp, sd_lldp_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_lldp_neighbor, sd_lldp_neighbor_unref);

_SD_END_DECLARATIONS;

#endif

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdlldprxhfoo
#define foosdlldprxhfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <sys/types.h>

#include "sd-event.h"
#include "sd-lldp.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_lldp_rx sd_lldp_rx;
typedef struct sd_lldp_neighbor sd_lldp_neighbor;

__extension__ typedef enum sd_lldp_rx_event_t {
        SD_LLDP_RX_EVENT_ADDED,
        SD_LLDP_RX_EVENT_REMOVED,
        SD_LLDP_RX_EVENT_UPDATED,
        SD_LLDP_RX_EVENT_REFRESHED,
        _SD_LLDP_RX_EVENT_MAX,
        _SD_LLDP_RX_EVENT_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(LLDP_RX_EVENT)
} sd_lldp_rx_event_t;

typedef void (*sd_lldp_rx_callback_t)(sd_lldp_rx *lldp_rx, sd_lldp_rx_event_t event, sd_lldp_neighbor *n, void *userdata);

int sd_lldp_rx_new(sd_lldp_rx **ret);
sd_lldp_rx *sd_lldp_rx_ref(sd_lldp_rx *lldp_rx);
sd_lldp_rx *sd_lldp_rx_unref(sd_lldp_rx *lldp_rx);

int sd_lldp_rx_start(sd_lldp_rx *lldp_rx);
int sd_lldp_rx_stop(sd_lldp_rx *lldp_rx);
int sd_lldp_rx_is_running(sd_lldp_rx *lldp_rx);

int sd_lldp_rx_attach_event(sd_lldp_rx *lldp_rx, sd_event *event, int64_t priority);
int sd_lldp_rx_detach_event(sd_lldp_rx *lldp_rx);
sd_event *sd_lldp_rx_get_event(sd_lldp_rx *lldp_rx);

int sd_lldp_rx_set_callback(sd_lldp_rx *lldp_rx, sd_lldp_rx_callback_t cb, void *userdata);
int sd_lldp_rx_set_ifindex(sd_lldp_rx *lldp_rx, int ifindex);
int sd_lldp_rx_set_ifname(sd_lldp_rx *lldp_rx, const char *ifname);
int sd_lldp_rx_get_ifname(sd_lldp_rx *lldp_rx, const char **ret);

/* Controls how much and what to store in the neighbors database */
int sd_lldp_rx_set_neighbors_max(sd_lldp_rx *lldp_rx, uint64_t n);
int sd_lldp_rx_match_capabilities(sd_lldp_rx *lldp_rx, uint16_t mask);
int sd_lldp_rx_set_filter_address(sd_lldp_rx *lldp_rx, const struct ether_addr *address);

int sd_lldp_rx_get_neighbors(sd_lldp_rx *lldp_rx, sd_lldp_neighbor ***neighbors);

int sd_lldp_neighbor_from_raw(sd_lldp_neighbor **ret, const void *raw, size_t raw_size);
sd_lldp_neighbor *sd_lldp_neighbor_ref(sd_lldp_neighbor *n);
sd_lldp_neighbor *sd_lldp_neighbor_unref(sd_lldp_neighbor *n);

/* Access to LLDP frame metadata */
int sd_lldp_neighbor_get_source_address(sd_lldp_neighbor *n, struct ether_addr* address);
int sd_lldp_neighbor_get_destination_address(sd_lldp_neighbor *n, struct ether_addr* address);
int sd_lldp_neighbor_get_timestamp(sd_lldp_neighbor *n, clockid_t clock, uint64_t *ret);
int sd_lldp_neighbor_get_raw(sd_lldp_neighbor *n, const void **ret, size_t *size);

/* High-level, direct, parsed out field access. These fields exist at most once, hence may be queried directly. */
int sd_lldp_neighbor_get_chassis_id(sd_lldp_neighbor *n, uint8_t *type, const void **ret, size_t *size);
int sd_lldp_neighbor_get_chassis_id_as_string(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_port_id(sd_lldp_neighbor *n, uint8_t *type, const void **ret, size_t *size);
int sd_lldp_neighbor_get_port_id_as_string(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_ttl(sd_lldp_neighbor *n, uint16_t *ret_sec);
int sd_lldp_neighbor_get_system_name(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_system_description(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_port_description(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_mud_url(sd_lldp_neighbor *n, const char **ret);
int sd_lldp_neighbor_get_system_capabilities(sd_lldp_neighbor *n, uint16_t *ret);
int sd_lldp_neighbor_get_enabled_capabilities(sd_lldp_neighbor *n, uint16_t *ret);

/* Low-level, iterative TLV access. This is for everything else, it iteratively goes through all available TLVs
 * (including the ones covered with the calls above), and allows multiple TLVs for the same fields. */
int sd_lldp_neighbor_tlv_rewind(sd_lldp_neighbor *n);
int sd_lldp_neighbor_tlv_next(sd_lldp_neighbor *n);
int sd_lldp_neighbor_tlv_get_type(sd_lldp_neighbor *n, uint8_t *type);
int sd_lldp_neighbor_tlv_is_type(sd_lldp_neighbor *n, uint8_t type);
int sd_lldp_neighbor_tlv_get_oui(sd_lldp_neighbor *n, uint8_t oui[_SD_ARRAY_STATIC 3], uint8_t *subtype);
int sd_lldp_neighbor_tlv_is_oui(sd_lldp_neighbor *n, const uint8_t oui[_SD_ARRAY_STATIC 3], uint8_t subtype);
int sd_lldp_neighbor_tlv_get_raw(sd_lldp_neighbor *n, const void **ret, size_t *size);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_lldp_rx, sd_lldp_rx_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_lldp_neighbor, sd_lldp_neighbor_unref);

_SD_END_DECLARATIONS;

#endif

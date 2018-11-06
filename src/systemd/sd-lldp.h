/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosdlldphfoo
#define foosdlldphfoo

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
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <net/ethernet.h>
#include <sys/types.h>

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* IEEE 802.3AB Clause 9: TLV Types */
enum {
        SD_LLDP_TYPE_END                 = 0,
        SD_LLDP_TYPE_CHASSIS_ID          = 1,
        SD_LLDP_TYPE_PORT_ID             = 2,
        SD_LLDP_TYPE_TTL                 = 3,
        SD_LLDP_TYPE_PORT_DESCRIPTION    = 4,
        SD_LLDP_TYPE_SYSTEM_NAME         = 5,
        SD_LLDP_TYPE_SYSTEM_DESCRIPTION  = 6,
        SD_LLDP_TYPE_SYSTEM_CAPABILITIES = 7,
        SD_LLDP_TYPE_MGMT_ADDRESS        = 8,
        SD_LLDP_TYPE_PRIVATE             = 127,
};

/* IEEE 802.3AB Clause 9.5.2: Chassis subtypes */
enum {
        SD_LLDP_CHASSIS_SUBTYPE_RESERVED            = 0,
        SD_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT   = 1,
        SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS     = 2,
        SD_LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT      = 3,
        SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS         = 4,
        SD_LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS     = 5,
        SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME      = 6,
        SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED    = 7,
};

/* IEEE 802.3AB Clause 9.5.3: Port subtype */
enum {
        SD_LLDP_PORT_SUBTYPE_RESERVED         = 0,
        SD_LLDP_PORT_SUBTYPE_INTERFACE_ALIAS  = 1,
        SD_LLDP_PORT_SUBTYPE_PORT_COMPONENT   = 2,
        SD_LLDP_PORT_SUBTYPE_MAC_ADDRESS      = 3,
        SD_LLDP_PORT_SUBTYPE_NETWORK_ADDRESS  = 4,
        SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME   = 5,
        SD_LLDP_PORT_SUBTYPE_AGENT_CIRCUIT_ID = 6,
        SD_LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED = 7,
};

enum {
        SD_LLDP_SYSTEM_CAPABILITIES_OTHER    = 1 << 0,
        SD_LLDP_SYSTEM_CAPABILITIES_REPEATER = 1 << 1,
        SD_LLDP_SYSTEM_CAPABILITIES_BRIDGE   = 1 << 2,
        SD_LLDP_SYSTEM_CAPABILITIES_WLAN_AP  = 1 << 3,
        SD_LLDP_SYSTEM_CAPABILITIES_ROUTER   = 1 << 4,
        SD_LLDP_SYSTEM_CAPABILITIES_PHONE    = 1 << 5,
        SD_LLDP_SYSTEM_CAPABILITIES_DOCSIS   = 1 << 6,
        SD_LLDP_SYSTEM_CAPABILITIES_STATION  = 1 << 7,
        SD_LLDP_SYSTEM_CAPABILITIES_CVLAN    = 1 << 8,
        SD_LLDP_SYSTEM_CAPABILITIES_SVLAN    = 1 << 9,
        SD_LLDP_SYSTEM_CAPABILITIES_TPMR     = 1 << 10,
};

#define SD_LLDP_SYSTEM_CAPABILITIES_ALL ((uint16_t) -1)

#define SD_LLDP_SYSTEM_CAPABILITIES_ALL_ROUTERS                         \
        ((uint16_t)                                                     \
         (SD_LLDP_SYSTEM_CAPABILITIES_REPEATER|                         \
          SD_LLDP_SYSTEM_CAPABILITIES_BRIDGE|                           \
          SD_LLDP_SYSTEM_CAPABILITIES_WLAN_AP|                          \
          SD_LLDP_SYSTEM_CAPABILITIES_ROUTER|                           \
          SD_LLDP_SYSTEM_CAPABILITIES_DOCSIS|                           \
          SD_LLDP_SYSTEM_CAPABILITIES_CVLAN|                            \
          SD_LLDP_SYSTEM_CAPABILITIES_SVLAN|                            \
          SD_LLDP_SYSTEM_CAPABILITIES_TPMR))

#define SD_LLDP_OUI_802_1 (uint8_t[]) { 0x00, 0x80, 0xc2 }
#define SD_LLDP_OUI_802_3 (uint8_t[]) { 0x00, 0x12, 0x0f }

enum {
        SD_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID          = 1,
        SD_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID = 2,
        SD_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME             = 3,
        SD_LLDP_OUI_802_1_SUBTYPE_PROTOCOL_IDENTITY     = 4,
        SD_LLDP_OUI_802_1_SUBTYPE_VID_USAGE_DIGEST      = 5,
        SD_LLDP_OUI_802_1_SUBTYPE_MANAGEMENT_VID        = 6,
        SD_LLDP_OUI_802_1_SUBTYPE_LINK_AGGREGATION      = 7,
};

typedef struct sd_lldp sd_lldp;
typedef struct sd_lldp_neighbor sd_lldp_neighbor;

typedef enum sd_lldp_event {
        SD_LLDP_EVENT_ADDED,
        SD_LLDP_EVENT_REMOVED,
        SD_LLDP_EVENT_UPDATED,
        SD_LLDP_EVENT_REFRESHED,
        _SD_LLDP_EVENT_MAX,
        _SD_LLDP_EVENT_INVALID = -1,
} sd_lldp_event;

typedef void (*sd_lldp_callback_t)(sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata);

int sd_lldp_new(sd_lldp **ret);
sd_lldp* sd_lldp_ref(sd_lldp *lldp);
sd_lldp* sd_lldp_unref(sd_lldp *lldp);

int sd_lldp_start(sd_lldp *lldp);
int sd_lldp_stop(sd_lldp *lldp);

int sd_lldp_attach_event(sd_lldp *lldp, sd_event *event, int64_t priority);
int sd_lldp_detach_event(sd_lldp *lldp);
sd_event *sd_lldp_get_event(sd_lldp *lldp);

int sd_lldp_set_callback(sd_lldp *lldp, sd_lldp_callback_t cb, void *userdata);
int sd_lldp_set_ifindex(sd_lldp *lldp, int ifindex);

/* Controls how much and what to store in the neighbors database */
int sd_lldp_set_neighbors_max(sd_lldp *lldp, uint64_t n);
int sd_lldp_match_capabilities(sd_lldp *lldp, uint16_t mask);
int sd_lldp_set_filter_address(sd_lldp *lldp, const struct ether_addr *address);

int sd_lldp_get_neighbors(sd_lldp *lldp, sd_lldp_neighbor ***neighbors);

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

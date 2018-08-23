/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <endian.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-dhcp-client.h"
#include "sd-dhcp-server.h"
#include "sd-dhcp6-client.h"
#include "sd-ipv4ll.h"
#include "sd-lldp.h"
#include "sd-ndisc.h"
#include "sd-radv.h"
#include "sd-netlink.h"

#include "list.h"
#include "set.h"

typedef enum LinkState {
        LINK_STATE_PENDING,
        LINK_STATE_ENSLAVING,
        LINK_STATE_SETTING_ADDRESSES,
        LINK_STATE_SETTING_ROUTES,
        LINK_STATE_CONFIGURED,
        LINK_STATE_UNMANAGED,
        LINK_STATE_FAILED,
        LINK_STATE_LINGER,
        _LINK_STATE_MAX,
        _LINK_STATE_INVALID = -1
} LinkState;

typedef enum LinkOperationalState {
        LINK_OPERSTATE_OFF,
        LINK_OPERSTATE_NO_CARRIER,
        LINK_OPERSTATE_DORMANT,
        LINK_OPERSTATE_CARRIER,
        LINK_OPERSTATE_DEGRADED,
        LINK_OPERSTATE_ROUTABLE,
        _LINK_OPERSTATE_MAX,
        _LINK_OPERSTATE_INVALID = -1
} LinkOperationalState;

typedef struct Manager Manager;
typedef struct Network Network;
typedef struct Address Address;
typedef struct DUID DUID;

typedef struct Link {
        Manager *manager;

        int n_ref;

        int ifindex;
        char *ifname;
        char *kind;
        unsigned short iftype;
        char *state_file;
        struct ether_addr mac;
        struct in6_addr ipv6ll_address;
        uint32_t mtu;
        sd_device *sd_device;

        unsigned flags;
        uint8_t kernel_operstate;

        Network *network;

        LinkState state;
        LinkOperationalState operstate;

        unsigned address_messages;
        unsigned address_label_messages;
        unsigned route_messages;
        unsigned routing_policy_rule_messages;
        unsigned routing_policy_rule_remove_messages;
        unsigned enslaving;

        Set *addresses;
        Set *addresses_foreign;
        Set *routes;
        Set *routes_foreign;

        sd_dhcp_client *dhcp_client;
        sd_dhcp_lease *dhcp_lease;
        char *lease_file;
        uint32_t original_mtu;
        unsigned dhcp4_messages;
        bool dhcp4_configured;
        bool dhcp6_configured;

        unsigned ndisc_messages;
        bool ndisc_configured;

        sd_ipv4ll *ipv4ll;
        bool ipv4ll_address:1;
        bool ipv4ll_route:1;

        bool static_routes_configured;
        bool routing_policy_rules_configured;
        bool setting_mtu;

        LIST_HEAD(Address, pool_addresses);

        sd_dhcp_server *dhcp_server;

        sd_ndisc *ndisc;
        Set *ndisc_rdnss;
        Set *ndisc_dnssl;

        sd_radv *radv;

        sd_dhcp6_client *dhcp6_client;
        bool rtnl_extended_attrs;

        /* This is about LLDP reception */
        sd_lldp *lldp;
        char *lldp_file;

        /* This is about LLDP transmission */
        unsigned lldp_tx_fast; /* The LLDP txFast counter (See 802.1ab-2009, section 9.2.5.18) */
        sd_event_source *lldp_emit_event_source;

        Hashmap *bound_by_links;
        Hashmap *bound_to_links;
} Link;

DUID *link_get_duid(Link *link);
int get_product_uuid_handler(sd_bus_message *m, void *userdata, sd_bus_error *ret_error);

Link *link_unref(Link *link);
Link *link_ref(Link *link);
int link_get(Manager *m, int ifindex, Link **ret);
int link_add(Manager *manager, sd_netlink_message *message, Link **ret);
void link_drop(Link *link);

int link_up(Link *link);
int link_down(Link *link);

int link_address_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata);
int link_route_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata);

void link_enter_failed(Link *link);
int link_initialized(Link *link, sd_device *device);

void link_check_ready(Link *link);

void link_update_operstate(Link *link);
int link_update(Link *link, sd_netlink_message *message);

void link_dirty(Link *link);
void link_clean(Link *link);
int link_save(Link *link);

int link_carrier_reset(Link *link);
bool link_has_carrier(Link *link);

int link_ipv6ll_gained(Link *link, const struct in6_addr *address);

int link_set_mtu(Link *link, uint32_t mtu);

int ipv4ll_configure(Link *link);
int dhcp4_configure(Link *link);
int dhcp4_set_client_identifier(Link *link);
int dhcp4_set_promote_secondaries(Link *link);
int dhcp6_configure(Link *link);
int dhcp6_request_address(Link *link, int ir);

const char* link_state_to_string(LinkState s) _const_;
LinkState link_state_from_string(const char *s) _pure_;

const char* link_operstate_to_string(LinkOperationalState s) _const_;
LinkOperationalState link_operstate_from_string(const char *s) _pure_;

extern const sd_bus_vtable link_vtable[];

int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
int link_send_changed(Link *link, const char *property, ...) _sentinel_;

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_unref);

/* Macros which append INTERFACE= to the message */

#define log_link_full(link, level, error, ...)                          \
        ({                                                              \
                const Link *_l = (link);                                \
                _l ? log_object_internal(level, error, __FILE__, __LINE__, __func__, "INTERFACE=", _l->ifname, NULL, NULL, ##__VA_ARGS__) : \
                        log_internal(level, error, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        })                                                              \

#define log_link_debug(link, ...)   log_link_full(link, LOG_DEBUG, 0, ##__VA_ARGS__)
#define log_link_info(link, ...)    log_link_full(link, LOG_INFO, 0, ##__VA_ARGS__)
#define log_link_notice(link, ...)  log_link_full(link, LOG_NOTICE, 0, ##__VA_ARGS__)
#define log_link_warning(link, ...) log_link_full(link, LOG_WARNING, 0, ##__VA_ARGS__)
#define log_link_error(link, ...)   log_link_full(link, LOG_ERR, 0, ##__VA_ARGS__)

#define log_link_debug_errno(link, error, ...)   log_link_full(link, LOG_DEBUG, error, ##__VA_ARGS__)
#define log_link_info_errno(link, error, ...)    log_link_full(link, LOG_INFO, error, ##__VA_ARGS__)
#define log_link_notice_errno(link, error, ...)  log_link_full(link, LOG_NOTICE, error, ##__VA_ARGS__)
#define log_link_warning_errno(link, error, ...) log_link_full(link, LOG_WARNING, error, ##__VA_ARGS__)
#define log_link_error_errno(link, error, ...)   log_link_full(link, LOG_ERR, error, ##__VA_ARGS__)

#define LOG_LINK_MESSAGE(link, fmt, ...) "MESSAGE=%s: " fmt, (link)->ifname, ##__VA_ARGS__
#define LOG_LINK_INTERFACE(link) "INTERFACE=%s", (link)->ifname

#define ADDRESS_FMT_VAL(address)                   \
        be32toh((address).s_addr) >> 24,           \
        (be32toh((address).s_addr) >> 16) & 0xFFu, \
        (be32toh((address).s_addr) >> 8) & 0xFFu,  \
        be32toh((address).s_addr) & 0xFFu

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"
#include "sd-netlink.h"

#include "condition.h"
#include "conf-parser.h"
#include "cpu-set-util.h"
#include "ethtool-util.h"
#include "hashmap.h"
#include "list.h"
#include "net-condition.h"
#include "netif-naming-scheme.h"

typedef struct LinkConfigContext LinkConfigContext;
typedef struct LinkConfig LinkConfig;
typedef struct UdevEvent UdevEvent;

typedef enum MACAddressPolicy {
        MAC_ADDRESS_POLICY_PERSISTENT,
        MAC_ADDRESS_POLICY_RANDOM,
        MAC_ADDRESS_POLICY_NONE,
        _MAC_ADDRESS_POLICY_MAX,
        _MAC_ADDRESS_POLICY_INVALID = -EINVAL,
} MACAddressPolicy;

typedef struct Link {
        UdevEvent *event;
        LinkConfig *config;

        /* from sd_device */
        const char *ifname;
        int ifindex;
        sd_device_action_t action;

        /* from rtnl */
        char *kind;
        const char *driver;
        uint16_t iftype;
        uint32_t flags;
        struct hw_addr_data hw_addr;
        struct hw_addr_data permanent_hw_addr;
        unsigned name_assign_type;
        unsigned addr_assign_type;

        /* generated name */
        const char *new_name;
} Link;

struct LinkConfig {
        char *filename;
        char **dropins;

        NetMatch match;
        LIST_HEAD(Condition, conditions);

        char *description;
        char **properties;
        char **import_properties;
        char **unset_properties;
        struct hw_addr_data hw_addr;
        MACAddressPolicy mac_address_policy;
        NamePolicy *name_policy;
        NamePolicy *alternative_names_policy;
        char *name;
        char **alternative_names;
        char *alias;
        uint32_t txqueues;
        uint32_t rxqueues;
        uint32_t txqueuelen;
        uint32_t mtu;
        uint32_t gso_max_segments;
        size_t gso_max_size;
        uint64_t speed;
        Duplex duplex;
        int autonegotiation;
        uint32_t advertise[N_ADVERTISE];
        uint32_t wol;
        char *wol_password_file;
        uint8_t *wol_password;
        NetDevPort port;
        int features[_NET_DEV_FEAT_MAX];
        netdev_channels channels;
        netdev_ring_param ring;
        int rx_flow_control;
        int tx_flow_control;
        int autoneg_flow_control;
        netdev_coalesce_param coalesce;
        uint8_t mdi;
        CPUSet *rps_cpu_mask;

        uint32_t sr_iov_num_vfs;
        OrderedHashmap *sr_iov_by_section;

        LIST_FIELDS(LinkConfig, configs);
};

int link_config_ctx_new(LinkConfigContext **ret);
LinkConfigContext* link_config_ctx_free(LinkConfigContext *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(LinkConfigContext*, link_config_ctx_free);

int link_load_one(LinkConfigContext *ctx, const char *filename);
int link_config_load(LinkConfigContext *ctx);
bool link_config_should_reload(LinkConfigContext *ctx);

int link_new(LinkConfigContext *ctx, UdevEvent *event, Link **ret);
Link* link_free(Link *link);
DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_free);

int link_get_config(LinkConfigContext *ctx, Link *link);
int link_apply_config(LinkConfigContext *ctx, Link *link);

const char* mac_address_policy_to_string(MACAddressPolicy p) _const_;
MACAddressPolicy mac_address_policy_from_string(const char *p) _pure_;

/* gperf lookup function */
const struct ConfigPerfItem* link_config_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_udev_property);
CONFIG_PARSER_PROTOTYPE(config_parse_udev_property_name);
CONFIG_PARSER_PROTOTYPE(config_parse_ifalias);
CONFIG_PARSER_PROTOTYPE(config_parse_rx_tx_queues);
CONFIG_PARSER_PROTOTYPE(config_parse_txqueuelen);
CONFIG_PARSER_PROTOTYPE(config_parse_wol_password);
CONFIG_PARSER_PROTOTYPE(config_parse_mac_address_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_name_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_alternative_names_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_rps_cpu_mask);

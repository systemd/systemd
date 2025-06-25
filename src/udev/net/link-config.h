/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "ether-addr-util.h"
#include "ethtool-util.h"
#include "forward.h"
#include "list.h"
#include "net-condition.h"

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

        /* udev property */
        char **properties;
        char **import_properties;
        char **unset_properties;

        /* rtnl setlink */
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

        /* ethtool link settings */
        uint64_t speed;
        Duplex duplex;
        int autonegotiation;
        uint32_t advertise[N_ADVERTISE];
        NetDevPort port;
        uint8_t mdi;

        /* ethtool WoL */
        uint32_t wol;
        char *wol_password_file;
        uint8_t *wol_password;

        /* ethtool features */
        int features[_NET_DEV_FEAT_MAX];

        /* ethtool channels */
        netdev_channels channels;

        /* ethtool ring parameters */
        netdev_ring_param ring;

        /* ethtool pause parameters */
        int rx_flow_control;
        int tx_flow_control;
        int autoneg_flow_control;

        /* ethtool coalesce settings */
        netdev_coalesce_param coalesce;

        /* ethtool energy efficient ethernet settings */
        int eee_enabled;
        int eee_tx_lpi_enabled;
        usec_t eee_tx_lpi_timer_usec;
        uint32_t eee_advertise[N_ADVERTISE];

        /* Rx RPS CPU mask */
        CPUSet *rps_cpu_mask;

        /* SR-IOV */
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

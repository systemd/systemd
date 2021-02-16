/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "condition.h"
#include "conf-parser.h"
#include "ethtool-util.h"
#include "list.h"
#include "net-condition.h"

typedef struct link_config_ctx link_config_ctx;
typedef struct link_config link_config;

typedef enum MACAddressPolicy {
        MAC_ADDRESS_POLICY_PERSISTENT,
        MAC_ADDRESS_POLICY_RANDOM,
        MAC_ADDRESS_POLICY_NONE,
        _MAC_ADDRESS_POLICY_MAX,
        _MAC_ADDRESS_POLICY_INVALID = -EINVAL,
} MACAddressPolicy;

typedef enum NamePolicy {
        NAMEPOLICY_KERNEL,
        NAMEPOLICY_KEEP,
        NAMEPOLICY_DATABASE,
        NAMEPOLICY_ONBOARD,
        NAMEPOLICY_SLOT,
        NAMEPOLICY_PATH,
        NAMEPOLICY_MAC,
        _NAMEPOLICY_MAX,
        _NAMEPOLICY_INVALID = -EINVAL,
} NamePolicy;

struct link_config {
        char *filename;

        NetMatch match;
        LIST_HEAD(Condition, conditions);

        char *description;
        struct ether_addr *mac;
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
        WakeOnLan wol;
        NetDevPort port;
        int features[_NET_DEV_FEAT_MAX];
        netdev_channels channels;
        netdev_ring_param ring;
        int rx_flow_control;
        int tx_flow_control;
        int autoneg_flow_control;

        LIST_FIELDS(link_config, links);
};

int link_config_ctx_new(link_config_ctx **ret);
link_config_ctx* link_config_ctx_free(link_config_ctx *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(link_config_ctx*, link_config_ctx_free);

int link_load_one(link_config_ctx *ctx, const char *filename);
int link_config_load(link_config_ctx *ctx);
bool link_config_should_reload(link_config_ctx *ctx);

int link_config_get(link_config_ctx *ctx, sd_device *device, link_config **ret);
int link_config_apply(link_config_ctx *ctx, const link_config *config, sd_device *device, const char **ret_name);
int link_get_driver(link_config_ctx *ctx, sd_device *device, char **ret);

const char *name_policy_to_string(NamePolicy p) _const_;
NamePolicy name_policy_from_string(const char *p) _pure_;

const char *alternative_names_policy_to_string(NamePolicy p) _const_;
NamePolicy alternative_names_policy_from_string(const char *p) _pure_;

const char *mac_address_policy_to_string(MACAddressPolicy p) _const_;
MACAddressPolicy mac_address_policy_from_string(const char *p) _pure_;

/* gperf lookup function */
const struct ConfigPerfItem* link_config_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_ifalias);
CONFIG_PARSER_PROTOTYPE(config_parse_rx_tx_queues);
CONFIG_PARSER_PROTOTYPE(config_parse_txqueuelen);
CONFIG_PARSER_PROTOTYPE(config_parse_mac_address_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_name_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_alternative_names_policy);

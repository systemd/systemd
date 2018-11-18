/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-device.h"

#include "condition.h"
#include "conf-parser.h"
#include "ethtool-util.h"
#include "list.h"
#include "set.h"

typedef struct link_config_ctx link_config_ctx;
typedef struct link_config link_config;

typedef enum MACPolicy {
        MACPOLICY_PERSISTENT,
        MACPOLICY_RANDOM,
        MACPOLICY_NONE,
        _MACPOLICY_MAX,
        _MACPOLICY_INVALID = -1
} MACPolicy;

typedef enum NamePolicy {
        NAMEPOLICY_KERNEL,
        NAMEPOLICY_DATABASE,
        NAMEPOLICY_ONBOARD,
        NAMEPOLICY_SLOT,
        NAMEPOLICY_PATH,
        NAMEPOLICY_MAC,
        _NAMEPOLICY_MAX,
        _NAMEPOLICY_INVALID = -1
} NamePolicy;

struct link_config {
        char *filename;

        Set *match_mac;
        char **match_path;
        char **match_driver;
        char **match_type;
        char **match_name;
        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel_cmdline;
        Condition *match_kernel_version;
        Condition *match_arch;

        char *description;
        struct ether_addr *mac;
        MACPolicy mac_policy;
        NamePolicy *name_policy;
        char *name;
        char *alias;
        uint32_t mtu;
        size_t speed;
        Duplex duplex;
        int autonegotiation;
        uint32_t advertise[2];
        WakeOnLan wol;
        NetDevPort port;
        int features[_NET_DEV_FEAT_MAX];
        netdev_channels channels;

        LIST_FIELDS(link_config, links);
};

int link_config_ctx_new(link_config_ctx **ret);
void link_config_ctx_free(link_config_ctx *ctx);

int link_config_load(link_config_ctx *ctx);
bool link_config_should_reload(link_config_ctx *ctx);

int link_config_get(link_config_ctx *ctx, sd_device *device, struct link_config **ret);
int link_config_apply(link_config_ctx *ctx, struct link_config *config, sd_device *device, const char **name);
int link_get_driver(link_config_ctx *ctx, sd_device *device, char **ret);

const char *name_policy_to_string(NamePolicy p) _const_;
NamePolicy name_policy_from_string(const char *p) _pure_;

const char *mac_policy_to_string(MACPolicy p) _const_;
MACPolicy mac_policy_from_string(const char *p) _pure_;

/* gperf lookup function */
const struct ConfigPerfItem* link_config_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_mac_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_name_policy);

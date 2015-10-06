/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#include "ethtool-util.h"
#include "condition.h"
#include "list.h"
#include "libudev.h"

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

        struct ether_addr *match_mac;
        char **match_path;
        char **match_driver;
        char **match_type;
        char **match_name;
        Condition *match_host;
        Condition *match_virt;
        Condition *match_kernel;
        Condition *match_arch;

        char *description;
        struct ether_addr *mac;
        MACPolicy mac_policy;
        NamePolicy *name_policy;
        char *name;
        char *alias;
        size_t mtu;
        size_t speed;
        Duplex duplex;
        WakeOnLan wol;

        LIST_FIELDS(link_config, links);
};

int link_config_ctx_new(link_config_ctx **ret);
void link_config_ctx_free(link_config_ctx *ctx);

int link_config_load(link_config_ctx *ctx);
bool link_config_should_reload(link_config_ctx *ctx);

int link_config_get(link_config_ctx *ctx, struct udev_device *device, struct link_config **ret);
int link_config_apply(link_config_ctx *ctx, struct link_config *config, struct udev_device *device, const char **name);

int link_get_driver(link_config_ctx *ctx, struct udev_device *device, char **ret);

const char *name_policy_to_string(NamePolicy p) _const_;
NamePolicy name_policy_from_string(const char *p) _pure_;

const char *mac_policy_to_string(MACPolicy p) _const_;
MACPolicy mac_policy_from_string(const char *p) _pure_;

/* gperf lookup function */
const struct ConfigPerfItem* link_config_gperf_lookup(const char *key, unsigned length);

int config_parse_mac_policy(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_name_policy(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

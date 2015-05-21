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

#include <netinet/ether.h>
#include <linux/netdevice.h>


#include "missing.h"
#include "link-config.h"
#include "ethtool-util.h"

#include "libudev-private.h"
#include "sd-rtnl.h"
#include "util.h"
#include "log.h"
#include "strv.h"
#include "path-util.h"
#include "conf-parser.h"
#include "conf-files.h"
#include "rtnl-util.h"
#include "network-internal.h"
#include "random-util.h"

struct link_config_ctx {
        LIST_HEAD(link_config, links);

        int ethtool_fd;

        bool enable_name_policy;

        sd_rtnl *rtnl;

        usec_t link_dirs_ts_usec;
};

static const char* const link_dirs[] = {
        "/etc/systemd/network",
        "/run/systemd/network",
        "/usr/lib/systemd/network",
#ifdef HAVE_SPLIT_USR
        "/lib/systemd/network",
#endif
        NULL};

static void link_config_free(link_config *link) {
        if (!link)
                return;

        free(link->filename);

        free(link->match_mac);
        strv_free(link->match_path);
        strv_free(link->match_driver);
        strv_free(link->match_type);
        free(link->match_name);
        free(link->match_host);
        free(link->match_virt);
        free(link->match_kernel);
        free(link->match_arch);

        free(link->description);
        free(link->mac);
        free(link->name_policy);
        free(link->name);
        free(link->alias);

        free(link);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(link_config*, link_config_free);

static void link_configs_free(link_config_ctx *ctx) {
        link_config *link, *link_next;

        if (!ctx)
                return;

        LIST_FOREACH_SAFE(links, link, link_next, ctx->links)
                link_config_free(link);
}

void link_config_ctx_free(link_config_ctx *ctx) {
        if (!ctx)
                return;

        safe_close(ctx->ethtool_fd);

        sd_rtnl_unref(ctx->rtnl);

        link_configs_free(ctx);

        free(ctx);

        return;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(link_config_ctx*, link_config_ctx_free);

int link_config_ctx_new(link_config_ctx **ret) {
        _cleanup_(link_config_ctx_freep) link_config_ctx *ctx = NULL;

        if (!ret)
                return -EINVAL;

        ctx = new0(link_config_ctx, 1);
        if (!ctx)
                return -ENOMEM;

        LIST_HEAD_INIT(ctx->links);

        ctx->ethtool_fd = -1;

        ctx->enable_name_policy = true;

        *ret = ctx;
        ctx = NULL;

        return 0;
}

static int load_link(link_config_ctx *ctx, const char *filename) {
        _cleanup_(link_config_freep) link_config *link = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        assert(ctx);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }

        if (null_or_empty_fd(fileno(file))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        link = new0(link_config, 1);
        if (!link)
                return log_oom();

        link->mac_policy = _MACPOLICY_INVALID;
        link->wol = _WOL_INVALID;
        link->duplex = _DUP_INVALID;

        r = config_parse(NULL, filename, file,
                         "Match\0Link\0Ethernet\0",
                         config_item_perf_lookup, link_config_gperf_lookup,
                         false, false, true, link);
        if (r < 0)
                return r;
        else
                log_debug("Parsed configuration file %s", filename);

        if (link->mtu > UINT_MAX || link->speed > UINT_MAX)
                return -ERANGE;

        link->filename = strdup(filename);

        LIST_PREPEND(links, ctx->links, link);
        link = NULL;

        return 0;
}

static bool enable_name_policy(void) {
        _cleanup_free_ char *line = NULL;
        const char *word, *state;
        int r;
        size_t l;

        r = proc_cmdline(&line);
        if (r < 0) {
                log_warning_errno(r, "Failed to read /proc/cmdline, ignoring: %m");
                return true;
        }

        FOREACH_WORD_QUOTED(word, l, line, state)
                if (strneq(word, "net.ifnames=0", l))
                        return false;

        return true;
}

int link_config_load(link_config_ctx *ctx) {
        int r;
        _cleanup_strv_free_ char **files;
        char **f;

        link_configs_free(ctx);

        if (!enable_name_policy()) {
                ctx->enable_name_policy = false;
                log_info("Network interface NamePolicy= disabled on kernel command line, ignoring.");
        }

        /* update timestamp */
        paths_check_timestamp(link_dirs, &ctx->link_dirs_ts_usec, true);

        r = conf_files_list_strv(&files, ".link", NULL, link_dirs);
        if (r < 0)
                return log_error_errno(r, "failed to enumerate link files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = load_link(ctx, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}

bool link_config_should_reload(link_config_ctx *ctx) {
        return paths_check_timestamp(link_dirs, &ctx->link_dirs_ts_usec, false);
}

int link_config_get(link_config_ctx *ctx, struct udev_device *device,
                    link_config **ret) {
        link_config *link;

        LIST_FOREACH(links, link, ctx->links) {
                const char* attr_value;

                attr_value = udev_device_get_sysattr_value(device, "address");

                if (net_match_config(link->match_mac, link->match_path, link->match_driver,
                                     link->match_type, link->match_name, link->match_host,
                                     link->match_virt, link->match_kernel, link->match_arch,
                                     attr_value ? ether_aton(attr_value) : NULL,
                                     udev_device_get_property_value(device, "ID_PATH"),
                                     udev_device_get_driver(udev_device_get_parent(device)),
                                     udev_device_get_property_value(device, "ID_NET_DRIVER"),
                                     udev_device_get_devtype(device),
                                     udev_device_get_sysname(device))) {
                        if (link->match_name) {
                                unsigned char name_assign_type = NET_NAME_UNKNOWN;

                                attr_value = udev_device_get_sysattr_value(device, "name_assign_type");
                                if (attr_value)
                                        (void) safe_atou8(attr_value, &name_assign_type);

                                if (name_assign_type == NET_NAME_ENUM) {
                                        log_warning("Config file %s applies to device based on potentially unpredictable interface name '%s'",
                                                  link->filename, udev_device_get_sysname(device));
                                        *ret = link;

                                        return 0;
                                } else if (name_assign_type == NET_NAME_RENAMED) {
                                        log_warning("Config file %s matches device based on renamed interface name '%s', ignoring",
                                                  link->filename, udev_device_get_sysname(device));

                                        continue;
                                }
                        }

                        log_debug("Config file %s applies to device %s",
                                  link->filename,  udev_device_get_sysname(device));

                        *ret = link;

                        return 0;
                }
        }

        *ret = NULL;

        return -ENOENT;
}

static bool mac_is_random(struct udev_device *device) {
        const char *s;
        unsigned type;
        int r;

        /* if we can't get the assign type, assume it is not random */
        s = udev_device_get_sysattr_value(device, "addr_assign_type");
        if (!s)
                return false;

        r = safe_atou(s, &type);
        if (r < 0)
                return false;

        return type == NET_ADDR_RANDOM;
}

static bool should_rename(struct udev_device *device, bool respect_predictable) {
        const char *s;
        unsigned type;
        int r;

        /* if we can't get the assgin type, assume we should rename */
        s = udev_device_get_sysattr_value(device, "name_assign_type");
        if (!s)
                return true;

        r = safe_atou(s, &type);
        if (r < 0)
                return true;

        switch (type) {
        case NET_NAME_USER:
        case NET_NAME_RENAMED:
                /* these were already named by userspace, do not touch again */
                return false;
        case NET_NAME_PREDICTABLE:
                /* the kernel claims to have given a predictable name */
                if (respect_predictable)
                        return false;
                /* fall through */
        case NET_NAME_ENUM:
        default:
                /* the name is known to be bad, or of an unknown type */
                return true;
        }
}

static int get_mac(struct udev_device *device, bool want_random,
                   struct ether_addr *mac) {
        int r;

        if (want_random)
                random_bytes(mac->ether_addr_octet, ETH_ALEN);
        else {
                uint8_t result[8];

                r = net_get_unique_predictable_data(device, result);
                if (r < 0)
                        return r;

                assert_cc(ETH_ALEN <= sizeof(result));
                memcpy(mac->ether_addr_octet, result, ETH_ALEN);
        }

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;  /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;  /* set local assignment bit (IEEE802) */

        return 0;
}

int link_config_apply(link_config_ctx *ctx, link_config *config,
                      struct udev_device *device, const char **name) {
        const char *old_name;
        const char *new_name = NULL;
        struct ether_addr generated_mac;
        struct ether_addr *mac = NULL;
        bool respect_predictable = false;
        int r, ifindex;

        assert(ctx);
        assert(config);
        assert(device);
        assert(name);

        old_name = udev_device_get_sysname(device);
        if (!old_name)
                return -EINVAL;

        r = ethtool_set_speed(&ctx->ethtool_fd, old_name, config->speed / 1024, config->duplex);
        if (r < 0)
                log_warning_errno(r, "Could not set speed or duplex of %s to %zu Mbps (%s): %m",
                                  old_name, config->speed / 1024,
                                  duplex_to_string(config->duplex));

        r = ethtool_set_wol(&ctx->ethtool_fd, old_name, config->wol);
        if (r < 0)
                log_warning_errno(r, "Could not set WakeOnLan of %s to %s: %m",
                                  old_name, wol_to_string(config->wol));

        ifindex = udev_device_get_ifindex(device);
        if (ifindex <= 0) {
                log_warning("Could not find ifindex");
                return -ENODEV;
        }

        if (ctx->enable_name_policy && config->name_policy) {
                NamePolicy *policy;

                for (policy = config->name_policy;
                     !new_name && *policy != _NAMEPOLICY_INVALID; policy++) {
                        switch (*policy) {
                                case NAMEPOLICY_KERNEL:
                                        respect_predictable = true;
                                        break;
                                case NAMEPOLICY_DATABASE:
                                        new_name = udev_device_get_property_value(device, "ID_NET_NAME_FROM_DATABASE");
                                        break;
                                case NAMEPOLICY_ONBOARD:
                                        new_name = udev_device_get_property_value(device, "ID_NET_NAME_ONBOARD");
                                        break;
                                case NAMEPOLICY_SLOT:
                                        new_name = udev_device_get_property_value(device, "ID_NET_NAME_SLOT");
                                        break;
                                case NAMEPOLICY_PATH:
                                        new_name = udev_device_get_property_value(device, "ID_NET_NAME_PATH");
                                        break;
                                case NAMEPOLICY_MAC:
                                        new_name = udev_device_get_property_value(device, "ID_NET_NAME_MAC");
                                        break;
                                default:
                                        break;
                        }
                }
        }

        if (should_rename(device, respect_predictable)) {
                /* if not set by policy, fall back manually set name */
                if (!new_name)
                        new_name = config->name;
        } else
                new_name = NULL;

        switch (config->mac_policy) {
                case MACPOLICY_PERSISTENT:
                        if (mac_is_random(device)) {
                                r = get_mac(device, false, &generated_mac);
                                if (r == -ENOENT) {
                                        log_warning_errno(r, "Could not generate persistent MAC address for %s: %m", old_name);
                                        break;
                                } else if (r < 0)
                                        return r;
                                mac = &generated_mac;
                        }
                        break;
                case MACPOLICY_RANDOM:
                        if (!mac_is_random(device)) {
                                r = get_mac(device, true, &generated_mac);
                                if (r == -ENOENT) {
                                        log_warning_errno(r, "Could not generate random MAC address for %s: %m", old_name);
                                        break;
                                } else if (r < 0)
                                        return r;
                                mac = &generated_mac;
                        }
                        break;
                default:
                        mac = config->mac;
        }

        r = rtnl_set_link_properties(&ctx->rtnl, ifindex, config->alias, mac, config->mtu);
        if (r < 0)
                return log_warning_errno(r, "Could not set Alias, MACAddress or MTU on %s: %m", old_name);

        *name = new_name;

        return 0;
}

int link_get_driver(link_config_ctx *ctx, struct udev_device *device, char **ret) {
        const char *name;
        char *driver = NULL;
        int r;

        name = udev_device_get_sysname(device);
        if (!name)
                return -EINVAL;

        r = ethtool_get_driver(&ctx->ethtool_fd, name, &driver);
        if (r < 0)
                return r;

        *ret = driver;
        return 0;
}

static const char* const mac_policy_table[_MACPOLICY_MAX] = {
        [MACPOLICY_PERSISTENT] = "persistent",
        [MACPOLICY_RANDOM] = "random"
};

DEFINE_STRING_TABLE_LOOKUP(mac_policy, MACPolicy);
DEFINE_CONFIG_PARSE_ENUM(config_parse_mac_policy, mac_policy, MACPolicy,
                         "Failed to parse MAC address policy");

static const char* const name_policy_table[_NAMEPOLICY_MAX] = {
        [NAMEPOLICY_KERNEL] = "kernel",
        [NAMEPOLICY_DATABASE] = "database",
        [NAMEPOLICY_ONBOARD] = "onboard",
        [NAMEPOLICY_SLOT] = "slot",
        [NAMEPOLICY_PATH] = "path",
        [NAMEPOLICY_MAC] = "mac"
};

DEFINE_STRING_TABLE_LOOKUP(name_policy, NamePolicy);
DEFINE_CONFIG_PARSE_ENUMV(config_parse_name_policy, name_policy, NamePolicy,
                          _NAMEPOLICY_INVALID,
                          "Failed to parse interface name policy");

/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/ether.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "device-util.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "link-config.h"
#include "log.h"
#include "missing.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "random-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

struct link_config_ctx {
        LIST_HEAD(link_config, links);

        int ethtool_fd;

        bool enable_name_policy;

        sd_netlink *rtnl;

        usec_t link_dirs_ts_usec;
};

static const char* const link_dirs[] = {
        "/etc/systemd/network",
        "/run/systemd/network",
        "/usr/lib/systemd/network",
#if HAVE_SPLIT_USR
        "/lib/systemd/network",
#endif
        NULL};

static void link_config_free(link_config *link) {
        if (!link)
                return;

        free(link->filename);

        set_free_free(link->match_mac);
        strv_free(link->match_path);
        strv_free(link->match_driver);
        strv_free(link->match_type);
        free(link->match_name);
        free(link->match_host);
        free(link->match_virt);
        free(link->match_kernel_cmdline);
        free(link->match_kernel_version);
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

        sd_netlink_unref(ctx->rtnl);

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

        *ret = TAKE_PTR(ctx);

        return 0;
}

static int load_link(link_config_ctx *ctx, const char *filename) {
        _cleanup_(link_config_freep) link_config *link = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int i;
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
        link->port = _NET_DEV_PORT_INVALID;
        link->autonegotiation = -1;

        for (i = 0; i < (int)ELEMENTSOF(link->features); i++)
                link->features[i] = -1;

        r = config_parse(NULL, filename, file,
                         "Match\0Link\0Ethernet\0",
                         config_item_perf_lookup, link_config_gperf_lookup,
                         CONFIG_PARSE_WARN, link);
        if (r < 0)
                return r;
        else
                log_debug("Parsed configuration file %s", filename);

        if (link->speed > UINT_MAX)
                return -ERANGE;

        link->filename = strdup(filename);
        if (!link->filename)
                return log_oom();

        LIST_PREPEND(links, ctx->links, link);
        link = NULL;

        return 0;
}

static bool enable_name_policy(void) {
        bool b;

        return proc_cmdline_get_bool("net.ifnames", &b) <= 0 || b;
}

int link_config_load(link_config_ctx *ctx) {
        _cleanup_strv_free_ char **files;
        char **f;
        int r;

        link_configs_free(ctx);

        if (!enable_name_policy()) {
                ctx->enable_name_policy = false;
                log_info("Network interface NamePolicy= disabled on kernel command line, ignoring.");
        }

        /* update timestamp */
        paths_check_timestamp(link_dirs, &ctx->link_dirs_ts_usec, true);

        r = conf_files_list_strv(&files, ".link", NULL, 0, link_dirs);
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

int link_config_get(link_config_ctx *ctx, sd_device *device, link_config **ret) {
        link_config *link;

        assert(ctx);
        assert(device);
        assert(ret);

        LIST_FOREACH(links, link, ctx->links) {
                const char *address = NULL, *id_path = NULL, *parent_driver = NULL, *id_net_driver = NULL, *devtype = NULL, *sysname = NULL;
                sd_device *parent;

                (void) sd_device_get_sysattr_value(device, "address", &address);
                (void) sd_device_get_property_value(device, "ID_PATH", &id_path);
                if (sd_device_get_parent(device, &parent) >= 0)
                        (void) sd_device_get_driver(parent, &parent_driver);
                (void) sd_device_get_property_value(device, "ID_NET_DRIVER", &id_net_driver);
                (void) sd_device_get_devtype(device, &devtype);
                (void) sd_device_get_sysname(device, &sysname);

                if (net_match_config(link->match_mac, link->match_path, link->match_driver,
                                     link->match_type, link->match_name, link->match_host,
                                     link->match_virt, link->match_kernel_cmdline,
                                     link->match_kernel_version, link->match_arch,
                                     address ? ether_aton(address) : NULL,
                                     id_path,
                                     parent_driver,
                                     id_net_driver,
                                     devtype,
                                     sysname)) {
                        if (link->match_name) {
                                unsigned char name_assign_type = NET_NAME_UNKNOWN;
                                const char *attr_value;

                                if (sd_device_get_sysattr_value(device, "name_assign_type", &attr_value) >= 0)
                                        (void) safe_atou8(attr_value, &name_assign_type);

                                if (name_assign_type == NET_NAME_ENUM) {
                                        log_warning("Config file %s applies to device based on potentially unpredictable interface name '%s'",
                                                  link->filename, sysname);
                                        *ret = link;

                                        return 0;
                                } else if (name_assign_type == NET_NAME_RENAMED) {
                                        log_warning("Config file %s matches device based on renamed interface name '%s', ignoring",
                                                  link->filename, sysname);

                                        continue;
                                }
                        }

                        log_debug("Config file %s applies to device %s",
                                  link->filename, sysname);

                        *ret = link;

                        return 0;
                }
        }

        *ret = NULL;

        return -ENOENT;
}

static bool mac_is_random(sd_device *device) {
        const char *s;
        unsigned type;
        int r;

        /* if we can't get the assign type, assume it is not random */
        if (sd_device_get_sysattr_value(device, "addr_assign_type", &s) < 0)
                return false;

        r = safe_atou(s, &type);
        if (r < 0)
                return false;

        return type == NET_ADDR_RANDOM;
}

static bool should_rename(sd_device *device, bool respect_predictable) {
        const char *s;
        unsigned type;
        int r;

        /* if we can't get the assgin type, assume we should rename */
        if (sd_device_get_sysattr_value(device, "name_assign_type", &s) < 0)
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
                _fallthrough_;
        case NET_NAME_ENUM:
        default:
                /* the name is known to be bad, or of an unknown type */
                return true;
        }
}

static int get_mac(sd_device *device, bool want_random,
                   struct ether_addr *mac) {
        int r;

        if (want_random)
                random_bytes(mac->ether_addr_octet, ETH_ALEN);
        else {
                uint64_t result;

                r = net_get_unique_predictable_data(device, &result);
                if (r < 0)
                        return r;

                assert_cc(ETH_ALEN <= sizeof(result));
                memcpy(mac->ether_addr_octet, &result, ETH_ALEN);
        }

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;  /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;  /* set local assignment bit (IEEE802) */

        return 0;
}

int link_config_apply(link_config_ctx *ctx, link_config *config,
                      sd_device *device, const char **name) {
        bool respect_predictable = false;
        struct ether_addr generated_mac;
        struct ether_addr *mac = NULL;
        const char *new_name = NULL;
        const char *old_name;
        unsigned speed;
        int r, ifindex;

        assert(ctx);
        assert(config);
        assert(device);
        assert(name);

        r = sd_device_get_sysname(device, &old_name);
        if (r < 0)
                return r;

        r = ethtool_set_glinksettings(&ctx->ethtool_fd, old_name, config);
        if (r < 0) {

                if (config->port != _NET_DEV_PORT_INVALID)
                        log_warning_errno(r,  "Could not set port (%s) of %s: %m", port_to_string(config->port), old_name);

                if (config->advertise)
                        log_warning_errno(r, "Could not set advertise mode to 0x%X: %m", config->advertise);

                if (config->speed) {

                        speed = DIV_ROUND_UP(config->speed, 1000000);
                        if (r == -EOPNOTSUPP) {
                                r = ethtool_set_speed(&ctx->ethtool_fd, old_name, speed, config->duplex);
                                if (r < 0)
                                        log_warning_errno(r, "Could not set speed of %s to %u Mbps: %m", old_name, speed);
                        }
                }

                if (config->duplex !=_DUP_INVALID)
                        log_warning_errno(r, "Could not set duplex of %s to (%s): %m", old_name, duplex_to_string(config->duplex));
        }

        r = ethtool_set_wol(&ctx->ethtool_fd, old_name, config->wol);
        if (r < 0)
                log_warning_errno(r, "Could not set WakeOnLan of %s to %s: %m",
                                  old_name, wol_to_string(config->wol));

        r = ethtool_set_features(&ctx->ethtool_fd, old_name, config->features);
        if (r < 0)
                log_warning_errno(r, "Could not set offload features of %s: %m", old_name);

        if (config->channels.rx_count_set || config->channels.tx_count_set || config->channels.other_count_set || config->channels.combined_count_set) {
                r = ethtool_set_channels(&ctx->ethtool_fd, old_name, &config->channels);
                if (r < 0)
                        log_warning_errno(r, "Could not set channels of %s: %m", old_name);
        }

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0)
                return log_device_warning_errno(device, r, "Could not find ifindex: %m");
        if (ifindex <= 0)
                return log_device_warning_errno(device, EINVAL, "Invalid ifindex '%d'", ifindex);

        if (ctx->enable_name_policy && config->name_policy) {
                NamePolicy *policy;

                for (policy = config->name_policy;
                     !new_name && *policy != _NAMEPOLICY_INVALID; policy++) {
                        switch (*policy) {
                                case NAMEPOLICY_KERNEL:
                                        respect_predictable = true;
                                        break;
                                case NAMEPOLICY_DATABASE:
                                        (void) sd_device_get_property_value(device, "ID_NET_NAME_FROM_DATABASE", &new_name);
                                        break;
                                case NAMEPOLICY_ONBOARD:
                                        (void) sd_device_get_property_value(device, "ID_NET_NAME_ONBOARD", &new_name);
                                        break;
                                case NAMEPOLICY_SLOT:
                                        (void) sd_device_get_property_value(device, "ID_NET_NAME_SLOT", &new_name);
                                        break;
                                case NAMEPOLICY_PATH:
                                        (void) sd_device_get_property_value(device, "ID_NET_NAME_PATH", &new_name);
                                        break;
                                case NAMEPOLICY_MAC:
                                        (void) sd_device_get_property_value(device, "ID_NET_NAME_MAC", &new_name);
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
                case MACPOLICY_NONE:
                default:
                        mac = config->mac;
        }

        r = rtnl_set_link_properties(&ctx->rtnl, ifindex, config->alias, mac, config->mtu);
        if (r < 0)
                return log_warning_errno(r, "Could not set Alias=, MACAddress= or MTU= on %s: %m", old_name);

        *name = new_name;

        return 0;
}

int link_get_driver(link_config_ctx *ctx, sd_device *device, char **ret) {
        const char *name;
        char *driver = NULL;
        int r;

        r = sd_device_get_sysname(device, &name);
        if (r < 0)
                return r;

        r = ethtool_get_driver(&ctx->ethtool_fd, name, &driver);
        if (r < 0)
                return r;

        *ret = driver;
        return 0;
}

static const char* const mac_policy_table[_MACPOLICY_MAX] = {
        [MACPOLICY_PERSISTENT] = "persistent",
        [MACPOLICY_RANDOM] = "random",
        [MACPOLICY_NONE] = "none"
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

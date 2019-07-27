/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/netdevice.h>
#include <netinet/ether.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "def.h"
#include "device-util.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "link-config.h"
#include "log.h"
#include "memory-util.h"
#include "naming-scheme.h"
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

struct link_config_ctx {
        LIST_HEAD(link_config, links);

        int ethtool_fd;

        bool enable_name_policy;

        sd_netlink *rtnl;

        usec_t network_dirs_ts_usec;
};

static void link_config_free(link_config *link) {
        if (!link)
                return;

        free(link->filename);

        set_free_free(link->match_mac);
        strv_free(link->match_path);
        strv_free(link->match_driver);
        strv_free(link->match_type);
        strv_free(link->match_name);
        strv_free(link->match_property);
        condition_free_list(link->conditions);

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

int link_load_one(link_config_ctx *ctx, const char *filename) {
        _cleanup_(link_config_freep) link_config *link = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        _cleanup_free_ char *name = NULL;
        size_t i;
        int r;

        assert(ctx);
        assert(filename);

        file = fopen(filename, "re");
        if (!file)
                return errno == ENOENT ? 0 : -errno;

        if (null_or_empty_fd(fileno(file))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        name = strdup(filename);
        if (!name)
                return -ENOMEM;

        link = new(link_config, 1);
        if (!link)
                return -ENOMEM;

        *link = (link_config) {
                .filename = TAKE_PTR(name),
                .mac_address_policy = _MAC_ADDRESS_POLICY_INVALID,
                .wol = _WOL_INVALID,
                .duplex = _DUP_INVALID,
                .port = _NET_DEV_PORT_INVALID,
                .autonegotiation = -1,
        };

        for (i = 0; i < ELEMENTSOF(link->features); i++)
                link->features[i] = -1;

        r = config_parse(NULL, filename, file,
                         "Match\0Link\0",
                         config_item_perf_lookup, link_config_gperf_lookup,
                         CONFIG_PARSE_WARN, link);
        if (r < 0)
                return r;

        if (link->speed > UINT_MAX)
                return -ERANGE;

        if (set_isempty(link->match_mac) && strv_isempty(link->match_path) &&
            strv_isempty(link->match_driver) && strv_isempty(link->match_type) &&
            strv_isempty(link->match_name) && strv_isempty(link->match_property) && !link->conditions)
                log_warning("%s: No valid settings found in the [Match] section. "
                            "The file will match all interfaces. "
                            "If that is intended, please add OriginalName=* in the [Match] section.",
                            filename);

        if (!condition_test_list(link->conditions, NULL, NULL, NULL)) {
                log_debug("%s: Conditions do not match the system environment, skipping.", filename);
                return 0;
        }

        log_debug("Parsed configuration file %s", filename);

        LIST_PREPEND(links, ctx->links, TAKE_PTR(link));
        return 0;
}

static bool enable_name_policy(void) {
        bool b;

        return proc_cmdline_get_bool("net.ifnames", &b) <= 0 || b;
}

static int link_unsigned_attribute(sd_device *device, const char *attr, unsigned *type) {
        const char *s;
        int r;

        r = sd_device_get_sysattr_value(device, attr, &s);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to query %s: %m", attr);

        r = safe_atou(s, type);
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to parse %s \"%s\": %m", attr, s);

        log_device_debug(device, "Device has %s=%u", attr, *type);
        return 0;
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
        paths_check_timestamp(NETWORK_DIRS, &ctx->network_dirs_ts_usec, true);

        r = conf_files_list_strv(&files, ".link", NULL, 0, NETWORK_DIRS);
        if (r < 0)
                return log_error_errno(r, "failed to enumerate link files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = link_load_one(ctx, *f);
                if (r < 0)
                        log_error_errno(r, "Failed to load %s, ignoring: %m", *f);
        }

        return 0;
}

bool link_config_should_reload(link_config_ctx *ctx) {
        return paths_check_timestamp(NETWORK_DIRS, &ctx->network_dirs_ts_usec, false);
}

int link_config_get(link_config_ctx *ctx, sd_device *device, link_config **ret) {
        link_config *link;

        assert(ctx);
        assert(device);
        assert(ret);

        LIST_FOREACH(links, link, ctx->links) {
                if (net_match_config(link->match_mac, link->match_path, link->match_driver,
                                     link->match_type, link->match_name, link->match_property,
                                     device, NULL, NULL)) {
                        if (link->match_name && !strv_contains(link->match_name, "*")) {
                                unsigned name_assign_type = NET_NAME_UNKNOWN;

                                (void) link_unsigned_attribute(device, "name_assign_type", &name_assign_type);

                                if (name_assign_type == NET_NAME_ENUM) {
                                        log_device_warning(device, "Config file %s applies to device based on potentially unpredictable interface name",
                                                           link->filename);
                                        *ret = link;

                                        return 0;
                                } else if (name_assign_type == NET_NAME_RENAMED) {
                                        log_device_warning(device, "Config file %s matches device based on renamed interface name, ignoring",
                                                           link->filename);

                                        continue;
                                }
                        }

                        log_device_debug(device, "Config file %s is applied", link->filename);

                        *ret = link;
                        return 0;
                }
        }

        *ret = NULL;
        return -ENOENT;
}

static int get_mac(sd_device *device, MACAddressPolicy policy, struct ether_addr *mac) {
        unsigned addr_type;
        bool want_random = policy == MAC_ADDRESS_POLICY_RANDOM;
        int r;

        assert(IN_SET(policy, MAC_ADDRESS_POLICY_RANDOM, MAC_ADDRESS_POLICY_PERSISTENT));

        r = link_unsigned_attribute(device, "addr_assign_type", &addr_type);
        if (r < 0)
                return r;
        switch (addr_type) {
        case NET_ADDR_SET:
                return log_device_debug(device, "MAC on the device already set by userspace");
        case NET_ADDR_STOLEN:
                return log_device_debug(device, "MAC on the device already set based on another device");
        case NET_ADDR_RANDOM:
        case NET_ADDR_PERM:
                break;
        default:
                return log_device_warning(device, "Unknown addr_assign_type %u, ignoring", addr_type);
        }

        if (want_random == (addr_type == NET_ADDR_RANDOM))
                return log_device_debug(device, "MAC on the device already matches policy *%s*",
                                        mac_address_policy_to_string(policy));

        if (want_random) {
                log_device_debug(device, "Using random bytes to generate MAC");
                random_bytes(mac->ether_addr_octet, ETH_ALEN);
        } else {
                uint64_t result;

                r = net_get_unique_predictable_data(device,
                                                    naming_scheme_has(NAMING_STABLE_VIRTUAL_MACS),
                                                    &result);
                if (r < 0)
                        return log_device_warning_errno(device, r, "Could not generate persistent MAC: %m");

                log_device_debug(device, "Using generated persistent MAC address");
                assert_cc(ETH_ALEN <= sizeof(result));
                memcpy(mac->ether_addr_octet, &result, ETH_ALEN);
        }

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;  /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;  /* set local assignment bit (IEEE802) */
        return 1;
}

int link_config_apply(link_config_ctx *ctx, link_config *config,
                      sd_device *device, const char **name) {
        struct ether_addr generated_mac;
        struct ether_addr *mac = NULL;
        const char *new_name = NULL;
        const char *old_name;
        unsigned speed, name_type = NET_NAME_UNKNOWN;
        NamePolicy policy;
        int r, ifindex;

        assert(ctx);
        assert(config);
        assert(device);
        assert(name);

        r = sd_device_get_sysname(device, &old_name);
        if (r < 0)
                return r;

        r = ethtool_set_glinksettings(&ctx->ethtool_fd, old_name,
                                      config->autonegotiation, config->advertise,
                                      config->speed, config->duplex, config->port);
        if (r < 0) {

                if (config->port != _NET_DEV_PORT_INVALID)
                        log_warning_errno(r, "Could not set port (%s) of %s: %m", port_to_string(config->port), old_name);

                if (!eqzero(config->advertise))
                        log_warning_errno(r, "Could not set advertise mode: %m"); /* TODO: include modes in the log message. */

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

        (void) link_unsigned_attribute(device, "name_assign_type", &name_type);

        if (IN_SET(name_type, NET_NAME_USER, NET_NAME_RENAMED)
            && !naming_scheme_has(NAMING_ALLOW_RERENAMES)) {
                log_device_debug(device, "Device already has a name given by userspace, not renaming.");
                goto no_rename;
        }

        if (ctx->enable_name_policy && config->name_policy)
                for (NamePolicy *p = config->name_policy; !new_name && *p != _NAMEPOLICY_INVALID; p++) {
                        policy = *p;

                        switch (policy) {
                        case NAMEPOLICY_KERNEL:
                                if (name_type != NET_NAME_PREDICTABLE)
                                        continue;

                                /* The kernel claims to have given a predictable name, keep it. */
                                log_device_debug(device, "Policy *%s*: keeping predictable kernel name",
                                                 name_policy_to_string(policy));
                                goto no_rename;
                        case NAMEPOLICY_KEEP:
                                if (!IN_SET(name_type, NET_NAME_USER, NET_NAME_RENAMED))
                                        continue;

                                log_device_debug(device, "Policy *%s*: keeping existing userspace name",
                                                 name_policy_to_string(policy));
                                goto no_rename;
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
                                assert_not_reached("invalid policy");
                        }
                }

        if (new_name)
                log_device_debug(device, "Policy *%s* yields \"%s\".", name_policy_to_string(policy), new_name);
        else if (config->name) {
                new_name = config->name;
                log_device_debug(device, "Policies didn't yield a name, using specified Name=%s.", new_name);
        } else
                log_device_debug(device, "Policies didn't yield a name and Name= is not given, not renaming.");
 no_rename:

        if (IN_SET(config->mac_address_policy, MAC_ADDRESS_POLICY_PERSISTENT, MAC_ADDRESS_POLICY_RANDOM)) {
                if (get_mac(device, config->mac_address_policy, &generated_mac) > 0)
                        mac = &generated_mac;
        } else
                mac = config->mac;

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

static const char* const mac_address_policy_table[_MAC_ADDRESS_POLICY_MAX] = {
        [MAC_ADDRESS_POLICY_PERSISTENT] = "persistent",
        [MAC_ADDRESS_POLICY_RANDOM] = "random",
        [MAC_ADDRESS_POLICY_NONE] = "none",
};

DEFINE_STRING_TABLE_LOOKUP(mac_address_policy, MACAddressPolicy);
DEFINE_CONFIG_PARSE_ENUM(config_parse_mac_address_policy, mac_address_policy, MACAddressPolicy,
                         "Failed to parse MAC address policy");

static const char* const name_policy_table[_NAMEPOLICY_MAX] = {
        [NAMEPOLICY_KERNEL] = "kernel",
        [NAMEPOLICY_KEEP] = "keep",
        [NAMEPOLICY_DATABASE] = "database",
        [NAMEPOLICY_ONBOARD] = "onboard",
        [NAMEPOLICY_SLOT] = "slot",
        [NAMEPOLICY_PATH] = "path",
        [NAMEPOLICY_MAC] = "mac",
};

DEFINE_STRING_TABLE_LOOKUP(name_policy, NamePolicy);
DEFINE_CONFIG_PARSE_ENUMV(config_parse_name_policy, name_policy, NamePolicy,
                          _NAMEPOLICY_INVALID,
                          "Failed to parse interface name policy");

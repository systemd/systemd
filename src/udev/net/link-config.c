/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netdevice.h>
#include <netinet/ether.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "def.h"
#include "device-private.h"
#include "device-util.h"
#include "ethtool-util.h"
#include "fd-util.h"
#include "link-config.h"
#include "log.h"
#include "memory-util.h"
#include "net-condition.h"
#include "netif-naming-scheme.h"
#include "netlink-util.h"
#include "network-util.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "random-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

struct link_config_ctx {
        LIST_HEAD(link_config, links);

        int ethtool_fd;

        bool enable_name_policy;

        sd_netlink *rtnl;

        usec_t network_dirs_ts_usec;
};

static link_config* link_config_free(link_config *link) {
        if (!link)
                return NULL;

        free(link->filename);

        net_match_clear(&link->match);
        condition_free_list(link->conditions);

        free(link->description);
        free(link->mac);
        free(link->name_policy);
        free(link->name);
        strv_free(link->alternative_names);
        free(link->alternative_names_policy);
        free(link->alias);

        return mfree(link);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(link_config*, link_config_free);

static void link_configs_free(link_config_ctx *ctx) {
        link_config *link, *link_next;

        if (!ctx)
                return;

        LIST_FOREACH_SAFE(links, link, link_next, ctx->links)
                link_config_free(link);
}

link_config_ctx* link_config_ctx_free(link_config_ctx *ctx) {
        if (!ctx)
                return NULL;

        safe_close(ctx->ethtool_fd);
        sd_netlink_unref(ctx->rtnl);
        link_configs_free(ctx);
        return mfree(ctx);
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
        _cleanup_free_ char *name = NULL;
        const char *dropin_dirname;
        size_t i;
        int r;

        assert(ctx);
        assert(filename);

        r = null_or_empty_path(filename);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;
        if (r > 0) {
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
                .rx_flow_control = -1,
                .tx_flow_control = -1,
                .autoneg_flow_control = -1,
                .txqueuelen = UINT32_MAX,
        };

        for (i = 0; i < ELEMENTSOF(link->features); i++)
                link->features[i] = -1;

        dropin_dirname = strjoina(basename(filename), ".d");
        r = config_parse_many(
                        STRV_MAKE_CONST(filename),
                        (const char* const*) CONF_PATHS_STRV("systemd/network"),
                        dropin_dirname,
                        "Match\0Link\0",
                        config_item_perf_lookup, link_config_gperf_lookup,
                        CONFIG_PARSE_WARN, link, NULL);
        if (r < 0)
                return r;

        if (net_match_is_empty(&link->match) && !link->conditions) {
                log_warning("%s: No valid settings found in the [Match] section, ignoring file. "
                            "To match all interfaces, add OriginalName=* in the [Match] section.",
                            filename);
                return 0;
        }

        if (!condition_test_list(link->conditions, environ, NULL, NULL, NULL)) {
                log_debug("%s: Conditions do not match the system environment, skipping.", filename);
                return 0;
        }

        if (IN_SET(link->mac_address_policy, MAC_ADDRESS_POLICY_PERSISTENT, MAC_ADDRESS_POLICY_RANDOM) && link->mac) {
                log_warning("%s: MACAddress= in [Link] section will be ignored when MACAddressPolicy= "
                            "is set to \"persistent\" or \"random\".",
                            filename);
                link->mac = mfree(link->mac);
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
        _cleanup_strv_free_ char **files = NULL;
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
        unsigned name_assign_type = NET_NAME_UNKNOWN;
        struct ether_addr permanent_mac = {};
        unsigned short iftype = 0;
        link_config *link;
        const char *name;
        int ifindex, r;

        assert(ctx);
        assert(device);
        assert(ret);

        r = sd_device_get_sysname(device, &name);
        if (r < 0)
                return r;

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0)
                return r;

        r = rtnl_get_link_iftype(&ctx->rtnl, ifindex, &iftype);
        if (r < 0)
                return r;

        r = ethtool_get_permanent_macaddr(&ctx->ethtool_fd, name, &permanent_mac);
        if (r < 0)
                log_device_debug_errno(device, r, "Failed to get permanent MAC address, ignoring: %m");

        (void) link_unsigned_attribute(device, "name_assign_type", &name_assign_type);

        LIST_FOREACH(links, link, ctx->links) {
                if (net_match_config(&link->match, device, NULL, &permanent_mac, NULL, iftype, NULL, NULL, 0, NULL, NULL)) {
                        if (link->match.ifname && !strv_contains(link->match.ifname, "*") && name_assign_type == NET_NAME_ENUM)
                                log_device_warning(device, "Config file %s is applied to device based on potentially unpredictable interface name.",
                                                   link->filename);
                        else
                                log_device_debug(device, "Config file %s is applied", link->filename);

                        *ret = link;
                        return 0;
                }
        }

        return -ENOENT;
}

static int link_config_apply_ethtool_settings(int *ethtool_fd, const link_config *config, sd_device *device) {
        const char *name;
        int r;

        assert(ethtool_fd);
        assert(config);
        assert(device);

        r = sd_device_get_sysname(device, &name);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get sysname: %m");

        r = ethtool_set_glinksettings(ethtool_fd, name,
                                      config->autonegotiation, config->advertise,
                                      config->speed, config->duplex, config->port);
        if (r < 0) {
                if (config->port != _NET_DEV_PORT_INVALID)
                        log_device_warning_errno(device, r, "Could not set port '%s', ignoring: %m", port_to_string(config->port));

                if (!eqzero(config->advertise))
                        log_device_warning_errno(device, r, "Could not set advertise mode, ignoring: %m"); /* TODO: include modes in the log message. */

                if (config->speed) {
                        unsigned speed = DIV_ROUND_UP(config->speed, 1000000);
                        if (r == -EOPNOTSUPP) {
                                r = ethtool_set_speed(ethtool_fd, name, speed, config->duplex);
                                if (r < 0)
                                        log_device_warning_errno(device, r, "Could not set speed to %uMbps, ignoring: %m", speed);
                        }
                }

                if (config->duplex != _DUP_INVALID)
                        log_device_warning_errno(device, r, "Could not set duplex to %s, ignoring: %m", duplex_to_string(config->duplex));
        }

        r = ethtool_set_wol(ethtool_fd, name, config->wol);
        if (r < 0)
                log_device_warning_errno(device, r, "Could not set WakeOnLan to %s, ignoring: %m", wol_to_string(config->wol));

        r = ethtool_set_features(ethtool_fd, name, config->features);
        if (r < 0)
                log_device_warning_errno(device, r, "Could not set offload features, ignoring: %m");

        if (config->channels.rx_count_set || config->channels.tx_count_set || config->channels.other_count_set || config->channels.combined_count_set) {
                r = ethtool_set_channels(ethtool_fd, name, &config->channels);
                if (r < 0)
                        log_device_warning_errno(device, r, "Could not set channels, ignoring: %m");
        }

        if (config->ring.rx_pending_set || config->ring.rx_mini_pending_set || config->ring.rx_jumbo_pending_set || config->ring.tx_pending_set) {
                r = ethtool_set_nic_buffer_size(ethtool_fd, name, &config->ring);
                if (r < 0)
                        log_device_warning_errno(device, r, "Could not set ring buffer, ignoring: %m");
        }

        if (config->rx_flow_control >= 0 || config->tx_flow_control >= 0 || config->autoneg_flow_control >= 0) {
                r = ethtool_set_flow_control(ethtool_fd, name, config->rx_flow_control, config->tx_flow_control, config->autoneg_flow_control);
                if (r < 0)
                        log_device_warning_errno(device, r, "Could not set flow control, ignoring: %m");
        }

        return 0;
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
                log_device_warning(device, "Unknown addr_assign_type %u, ignoring", addr_type);
                return 0;
        }

        if (want_random == (addr_type == NET_ADDR_RANDOM))
                return log_device_debug(device, "MAC on the device already matches policy *%s*",
                                        mac_address_policy_to_string(policy));

        if (want_random) {
                log_device_debug(device, "Using random bytes to generate MAC");

                /* We require genuine randomness here, since we want to make sure we won't collide with other
                 * systems booting up at the very same time. We do allow RDRAND however, since this is not
                 * cryptographic key material. */
                r = genuine_random_bytes(mac->ether_addr_octet, ETH_ALEN, RANDOM_ALLOW_RDRAND);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to acquire random data to generate MAC: %m");
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

static int link_config_apply_rtnl_settings(sd_netlink **rtnl, const link_config *config, sd_device *device) {
        struct ether_addr generated_mac, *mac = NULL;
        int ifindex, r;

        assert(rtnl);
        assert(config);
        assert(device);

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0)
                return log_device_error_errno(device, r, "Could not find ifindex: %m");

        if (IN_SET(config->mac_address_policy, MAC_ADDRESS_POLICY_PERSISTENT, MAC_ADDRESS_POLICY_RANDOM)) {
                if (get_mac(device, config->mac_address_policy, &generated_mac) > 0)
                        mac = &generated_mac;
        } else
                mac = config->mac;

        r = rtnl_set_link_properties(rtnl, ifindex, config->alias, mac,
                                     config->txqueues, config->rxqueues, config->txqueuelen,
                                     config->mtu, config->gso_max_size, config->gso_max_segments);
        if (r < 0)
                log_device_warning_errno(device, r,
                                         "Could not set Alias=, MACAddress=, "
                                         "TransmitQueues=, ReceiveQueues=, TransmitQueueLength=, MTU=, "
                                         "GenericSegmentOffloadMaxBytes= or GenericSegmentOffloadMaxSegments=, "
                                         "ignoring: %m");

        return 0;
}

static int link_config_generate_new_name(const link_config_ctx *ctx, const link_config *config, sd_device *device, const char **ret_name) {
        unsigned name_type = NET_NAME_UNKNOWN;
        int r;

        assert(ctx);
        assert(config);
        assert(device);
        assert(ret_name);

        (void) link_unsigned_attribute(device, "name_assign_type", &name_type);

        if (IN_SET(name_type, NET_NAME_USER, NET_NAME_RENAMED)
            && !naming_scheme_has(NAMING_ALLOW_RERENAMES)) {
                log_device_debug(device, "Device already has a name given by userspace, not renaming.");
                goto no_rename;
        }

        if (ctx->enable_name_policy && config->name_policy)
                for (NamePolicy *p = config->name_policy; *p != _NAMEPOLICY_INVALID; p++) {
                        const char *new_name = NULL;
                        NamePolicy policy = *p;

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
                        if (ifname_valid(new_name)) {
                                log_device_debug(device, "Policy *%s* yields \"%s\".", name_policy_to_string(policy), new_name);
                                *ret_name = new_name;
                                return 0;
                        }
                }

        if (config->name) {
                log_device_debug(device, "Policies didn't yield a name, using specified Name=%s.", config->name);
                *ret_name = config->name;
                return 0;
        }

        log_device_debug(device, "Policies didn't yield a name and Name= is not given, not renaming.");
no_rename:
        r = sd_device_get_sysname(device, ret_name);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get sysname: %m");

        return 0;
}

static int link_config_apply_alternative_names(sd_netlink **rtnl, const link_config *config, sd_device *device, const char *new_name) {
        _cleanup_strv_free_ char **altnames = NULL, **current_altnames = NULL;
        const char *current_name;
        int ifindex, r;

        assert(rtnl);
        assert(config);
        assert(device);

        r = sd_device_get_sysname(device, &current_name);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get sysname: %m");

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0)
                return log_device_error_errno(device, r, "Could not find ifindex: %m");

        if (config->alternative_names) {
                altnames = strv_copy(config->alternative_names);
                if (!altnames)
                        return log_oom();
        }

        if (config->alternative_names_policy)
                for (NamePolicy *p = config->alternative_names_policy; *p != _NAMEPOLICY_INVALID; p++) {
                        const char *n = NULL;

                        switch (*p) {
                        case NAMEPOLICY_DATABASE:
                                (void) sd_device_get_property_value(device, "ID_NET_NAME_FROM_DATABASE", &n);
                                break;
                        case NAMEPOLICY_ONBOARD:
                                (void) sd_device_get_property_value(device, "ID_NET_NAME_ONBOARD", &n);
                                break;
                        case NAMEPOLICY_SLOT:
                                (void) sd_device_get_property_value(device, "ID_NET_NAME_SLOT", &n);
                                break;
                        case NAMEPOLICY_PATH:
                                (void) sd_device_get_property_value(device, "ID_NET_NAME_PATH", &n);
                                break;
                        case NAMEPOLICY_MAC:
                                (void) sd_device_get_property_value(device, "ID_NET_NAME_MAC", &n);
                                break;
                        default:
                                assert_not_reached("invalid policy");
                        }
                        if (!isempty(n)) {
                                r = strv_extend(&altnames, n);
                                if (r < 0)
                                        return log_oom();
                        }
                }

        if (new_name)
                strv_remove(altnames, new_name);
        strv_remove(altnames, current_name);

        r = rtnl_get_link_alternative_names(rtnl, ifindex, &current_altnames);
        if (r < 0)
                log_device_debug_errno(device, r, "Failed to get alternative names, ignoring: %m");

        char **p;
        STRV_FOREACH(p, current_altnames)
                strv_remove(altnames, *p);

        strv_uniq(altnames);
        strv_sort(altnames);
        r = rtnl_set_link_alternative_names(rtnl, ifindex, altnames);
        if (r < 0)
                log_device_full_errno(device, r == -EOPNOTSUPP ? LOG_DEBUG : LOG_WARNING, r,
                                      "Could not set AlternativeName= or apply AlternativeNamesPolicy=, ignoring: %m");

        return 0;
}

int link_config_apply(link_config_ctx *ctx, const link_config *config, sd_device *device, const char **ret_name) {
        const char *new_name;
        sd_device_action_t a;
        int r;

        assert(ctx);
        assert(config);
        assert(device);
        assert(ret_name);

        r = sd_device_get_action(device, &a);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get ACTION= property: %m");

        if (!IN_SET(a, SD_DEVICE_ADD, SD_DEVICE_BIND, SD_DEVICE_MOVE)) {
                log_device_debug(device, "Skipping to apply .link settings on '%s' uevent.", device_action_to_string(a));

                r = sd_device_get_sysname(device, ret_name);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to get sysname: %m");

                return 0;
        }

        r = link_config_apply_ethtool_settings(&ctx->ethtool_fd, config, device);
        if (r < 0)
                return r;

        r = link_config_apply_rtnl_settings(&ctx->rtnl, config, device);
        if (r < 0)
                return r;

        if (a == SD_DEVICE_MOVE) {
                log_device_debug(device, "Skipping to apply Name= and NamePolicy= on '%s' uevent.", device_action_to_string(a));

                r = sd_device_get_sysname(device, &new_name);
                if (r < 0)
                        return log_device_error_errno(device, r, "Failed to get sysname: %m");
        } else {
                r = link_config_generate_new_name(ctx, config, device, &new_name);
                if (r < 0)
                        return r;
        }

        r = link_config_apply_alternative_names(&ctx->rtnl, config, device, new_name);
        if (r < 0)
                return r;

        *ret_name = new_name;
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

int config_parse_ifalias(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!isempty(rvalue)) {
                *s = mfree(*s);
                return 0;
        }

        if (!ascii_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Interface alias is not ASCII clean, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (strlen(rvalue) >= IFALIASZ) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Interface alias is too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        return free_and_strdup_warn(s, rvalue);
}

int config_parse_rx_tx_queues(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t k, *v = data;
        int r;

        if (isempty(rvalue)) {
                *v = 0;
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s=, ignoring assignment: %s.", lvalue, rvalue);
                return 0;
        }
        if (k == 0 || k > 4096) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid %s=, ignoring assignment: %s.", lvalue, rvalue);
                return 0;
        }

        *v = k;
        return 0;
}

int config_parse_txqueuelen(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t k, *v = data;
        int r;

        if (isempty(rvalue)) {
                *v = UINT32_MAX;
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s=, ignoring assignment: %s.", lvalue, rvalue);
                return 0;
        }
        if (k == UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid %s=, ignoring assignment: %s.", lvalue, rvalue);
                return 0;
        }

        *v = k;
        return 0;
}

static const char* const mac_address_policy_table[_MAC_ADDRESS_POLICY_MAX] = {
        [MAC_ADDRESS_POLICY_PERSISTENT] = "persistent",
        [MAC_ADDRESS_POLICY_RANDOM] = "random",
        [MAC_ADDRESS_POLICY_NONE] = "none",
};

DEFINE_STRING_TABLE_LOOKUP(mac_address_policy, MACAddressPolicy);
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(
        config_parse_mac_address_policy,
        mac_address_policy,
        MACAddressPolicy,
        MAC_ADDRESS_POLICY_NONE,
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

static const char* const alternative_names_policy_table[_NAMEPOLICY_MAX] = {
        [NAMEPOLICY_DATABASE] = "database",
        [NAMEPOLICY_ONBOARD] = "onboard",
        [NAMEPOLICY_SLOT] = "slot",
        [NAMEPOLICY_PATH] = "path",
        [NAMEPOLICY_MAC] = "mac",
};

DEFINE_STRING_TABLE_LOOKUP(alternative_names_policy, NamePolicy);
DEFINE_CONFIG_PARSE_ENUMV(config_parse_alternative_names_policy, alternative_names_policy, NamePolicy,
                          _NAMEPOLICY_INVALID,
                          "Failed to parse alternative names policy");

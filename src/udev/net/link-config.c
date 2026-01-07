/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netdevice.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "arphrd-util.h"
#include "capability-util.h"
#include "condition.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "creds-util.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "ethtool-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "link-config.h"
#include "log-link.h"
#include "memory-util.h"
#include "net-condition.h"
#include "netif-naming-scheme.h"
#include "netif-sriov.h"
#include "netif-util.h"
#include "netlink-util.h"
#include "network-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "random-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "specifier.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"
#include "utf8.h"

static const Specifier link_specifier_table[] = {
        COMMON_SYSTEM_SPECIFIERS,
        COMMON_TMP_SPECIFIERS,
        {}
};

struct LinkConfigContext {
        LIST_HEAD(LinkConfig, configs);
        int ethtool_fd;
        Hashmap *stats_by_path;
};

static LinkConfig* link_config_free(LinkConfig *config) {
        if (!config)
                return NULL;

        free(config->filename);
        strv_free(config->dropins);

        net_match_clear(&config->match);
        condition_free_list(config->conditions);

        free(config->description);
        strv_free(config->properties);
        strv_free(config->import_properties);
        strv_free(config->unset_properties);
        free(config->name_policy);
        free(config->name);
        strv_free(config->alternative_names);
        free(config->alternative_names_policy);
        free(config->alias);
        free(config->wol_password_file);
        erase_and_free(config->wol_password);
        cpu_set_done(&config->rps_cpu_mask);

        ordered_hashmap_free(config->sr_iov_by_section);

        return mfree(config);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(LinkConfig*, link_config_free);

static void link_configs_free(LinkConfigContext *ctx) {
        if (!ctx)
                return;

        ctx->stats_by_path = hashmap_free(ctx->stats_by_path);

        LIST_FOREACH(configs, config, ctx->configs)
                link_config_free(config);
}

LinkConfigContext *link_config_ctx_free(LinkConfigContext *ctx) {
        if (!ctx)
                return NULL;

        safe_close(ctx->ethtool_fd);
        link_configs_free(ctx);
        return mfree(ctx);
}

int link_config_ctx_new(LinkConfigContext **ret) {
        _cleanup_(link_config_ctx_freep) LinkConfigContext *ctx = NULL;

        if (!ret)
                return -EINVAL;

        ctx = new(LinkConfigContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (LinkConfigContext) {
                .ethtool_fd = -EBADF,
        };

        *ret = TAKE_PTR(ctx);

        return 0;
}

static int link_parse_wol_password(LinkConfig *config, const char *str) {
        _cleanup_(erase_and_freep) uint8_t *p = NULL;
        int r;

        assert(config);
        assert(str);

        assert_cc(sizeof(struct ether_addr) == SOPASS_MAX);

        p = new(uint8_t, SOPASS_MAX);
        if (!p)
                return -ENOMEM;

        /* Reuse parse_ether_addr(), as their formats are equivalent. */
        r = parse_ether_addr(str, (struct ether_addr*) p);
        if (r < 0)
                return r;

        erase_and_free(config->wol_password);
        config->wol_password = TAKE_PTR(p);
        return 0;
}

static int link_read_wol_password_from_file(LinkConfig *config) {
        _cleanup_(erase_and_freep) char *password = NULL;
        int r;

        assert(config);

        if (!config->wol_password_file)
                return 0;

        r = read_full_file_full(
                        AT_FDCWD, config->wol_password_file, UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE | READ_FULL_FILE_WARN_WORLD_READABLE | READ_FULL_FILE_CONNECT_SOCKET,
                        NULL, &password, NULL);
        if (r < 0)
                return r;

        return link_parse_wol_password(config, password);
}

static int link_read_wol_password_from_cred(LinkConfig *config) {
        _cleanup_free_ char *base = NULL, *cred_name = NULL;
        _cleanup_(erase_and_freep) char *password = NULL;
        int r;

        assert(config);
        assert(config->filename);

        if (config->wol == UINT32_MAX)
                return 0; /* WakeOnLan= is not specified. */
        if (!FLAGS_SET(config->wol, WAKE_MAGICSECURE))
                return 0; /* secureon is not specified in WakeOnLan=. */
        if (config->wol_password)
                return 0; /* WakeOnLanPassword= is specified. */
        if (config->wol_password_file)
                return 0; /* a file name is specified in WakeOnLanPassword=, but failed to read it. */

        r = path_extract_filename(config->filename, &base);
        if (r < 0)
                return r;

        cred_name = strjoin(base, ".wol.password");
        if (!cred_name)
                return -ENOMEM;

        r = read_credential(cred_name, (void**) &password, NULL);
        if (r == -ENOENT)
                r = read_credential("wol.password", (void**) &password, NULL);
        if (r < 0)
                return r;

        return link_parse_wol_password(config, password);
}

static int link_adjust_wol_options(LinkConfig *config) {
        int r;

        assert(config);

        r = link_read_wol_password_from_file(config);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_warning_errno(r, "Failed to read WakeOnLan password from %s, ignoring: %m", config->wol_password_file);

        r = link_read_wol_password_from_cred(config);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_warning_errno(r, "Failed to read WakeOnLan password from credential, ignoring: %m");

        if (config->wol != UINT32_MAX && config->wol_password)
                /* Enable WAKE_MAGICSECURE flag when WakeOnLanPassword=. Note that when
                 * WakeOnLanPassword= is set without WakeOnLan=, then ethtool_set_wol() enables
                 * WAKE_MAGICSECURE flag and other flags are not changed. */
                config->wol |= WAKE_MAGICSECURE;

        return 0;
}

int link_load_one(LinkConfigContext *ctx, const char *filename) {
        _cleanup_(link_config_freep) LinkConfig *config = NULL;
        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        _cleanup_free_ char *name = NULL, *file_basename = NULL;
        const char *dropin_dirname;
        int r;

        assert(ctx);
        assert(filename);

        r = null_or_empty_path(filename);
        if (r < 0)
                return log_warning_errno(r, "Failed to check if \"%s\" is empty: %m", filename);
        if (r > 0) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        name = strdup(filename);
        if (!name)
                return log_oom();

        config = new(LinkConfig, 1);
        if (!config)
                return log_oom();

        *config = (LinkConfig) {
                .filename = TAKE_PTR(name),
                .mac_address_policy = MAC_ADDRESS_POLICY_NONE,
                .wol = UINT32_MAX, /* UINT32_MAX means do not change WOL setting. */
                .duplex = _DUP_INVALID,
                .port = _NET_DEV_PORT_INVALID,
                .autonegotiation = -1,
                .rx_flow_control = -1,
                .tx_flow_control = -1,
                .autoneg_flow_control = -1,
                .txqueuelen = UINT32_MAX,
                .coalesce.use_adaptive_rx_coalesce = -1,
                .coalesce.use_adaptive_tx_coalesce = -1,
                .mdi = ETH_TP_MDI_INVALID,
                .sr_iov_num_vfs = UINT32_MAX,
                .eee_enabled = -1,
                .eee_tx_lpi_enabled = -1,
                .eee_tx_lpi_timer_usec = USEC_INFINITY,
                .irq_affinity_policy = _IRQ_AFFINITY_POLICY_INVALID,
        };

        FOREACH_ELEMENT(feature, config->features)
                *feature = -1;

        r = path_extract_filename(filename, &file_basename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract file name of '%s': %m", filename);

        dropin_dirname = strjoina(file_basename, ".d");
        r = config_parse_many(
                        STRV_MAKE_CONST(filename),
                        NETWORK_DIRS,
                        dropin_dirname,
                        /* root= */ NULL,
                        "Match\0"
                        "Link\0"
                        "SR-IOV\0"
                        "EnergyEfficientEthernet\0",
                        config_item_perf_lookup, link_config_gperf_lookup,
                        CONFIG_PARSE_WARN, config, &stats_by_path,
                        &config->dropins);
        if (r < 0)
                return r; /* config_parse_many() logs internally. */

        if (ctx->stats_by_path) {
                r = hashmap_move(ctx->stats_by_path, stats_by_path);
                if (r < 0)
                        log_warning_errno(r, "Failed to save stats of '%s' and its drop-in configs, ignoring: %m", filename);
        } else
                ctx->stats_by_path = TAKE_PTR(stats_by_path);

        if (net_match_is_empty(&config->match) && !config->conditions) {
                log_warning("%s: No valid settings found in the [Match] section, ignoring file. "
                            "To match all interfaces, add OriginalName=* in the [Match] section.",
                            filename);
                return 0;
        }

        if (!condition_test_list(config->conditions, environ, NULL, NULL, NULL)) {
                log_debug("%s: Conditions do not match the system environment, skipping.", filename);
                return 0;
        }

        if (IN_SET(config->mac_address_policy, MAC_ADDRESS_POLICY_PERSISTENT, MAC_ADDRESS_POLICY_RANDOM) &&
            config->hw_addr.length > 0)
                log_warning("%s: MACAddress= in [Link] section will be ignored when MACAddressPolicy= "
                            "is set to \"persistent\" or \"random\".",
                            filename);

        r = link_adjust_wol_options(config);
        if (r < 0)
                return r; /* link_adjust_wol_options() logs internally. */

        r = sr_iov_drop_invalid_sections(config->sr_iov_num_vfs, config->sr_iov_by_section);
        if (r < 0)
                return r; /* sr_iov_drop_invalid_sections() logs internally. */

        log_debug("Parsed configuration file \"%s\"", filename);

        LIST_PREPEND(configs, ctx->configs, TAKE_PTR(config));
        return 0;
}

int link_config_load(LinkConfigContext *ctx) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(ctx);

        link_configs_free(ctx);

        r = conf_files_list_strv(&files, ".link", NULL, 0, NETWORK_DIRS);
        if (r < 0)
                return log_error_errno(r, "failed to enumerate link files: %m");

        STRV_FOREACH_BACKWARDS(f, files)
                (void) link_load_one(ctx, *f);

        return 0;
}

bool link_config_should_reload(LinkConfigContext *ctx) {
        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        int r;

        assert(ctx);

        r = config_get_stats_by_path(".link", NULL, 0, NETWORK_DIRS, /* check_dropins= */ true, &stats_by_path);
        if (r < 0) {
                log_warning_errno(r, "Failed to get stats of .link files, ignoring: %m");
                return true;
        }

        return !stats_by_path_equal(ctx->stats_by_path, stats_by_path);
}

Link* link_free(Link *link) {
        if (!link)
                return NULL;

        udev_event_unref(link->event);
        free(link->kind);
        return mfree(link);
}

int link_new(LinkConfigContext *ctx, UdevEvent *event, Link **ret) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_(link_freep) Link *link = NULL;
        int r;

        assert(ctx);
        assert(event);
        assert(ret);

        link = new(Link, 1);
        if (!link)
                return -ENOMEM;

        *link = (Link) {
                .event = udev_event_ref(event),
        };

        r = device_get_ifname(dev, &link->ifname);
        if (r < 0)
                return r;

        r = sd_device_get_ifindex(dev, &link->ifindex);
        if (r < 0)
                return r;

        r = sd_device_get_action(dev, &link->action);
        if (r < 0)
                return r;

        r = device_get_sysattr_unsigned(dev, "name_assign_type", &link->name_assign_type);
        if (r < 0)
                log_link_debug_errno(link, r, "Failed to get \"name_assign_type\" attribute, ignoring: %m");
        else
                log_link_debug(link, "Device has name_assign_type attribute: %u", link->name_assign_type);

        r = device_get_sysattr_unsigned(dev, "addr_assign_type", &link->addr_assign_type);
        if (r < 0)
                log_link_debug_errno(link, r, "Failed to get \"addr_assign_type\" attribute, ignoring: %m");
        else
                log_link_debug(link, "Device has addr_assign_type attribute: %u", link->addr_assign_type);

        r = rtnl_get_link_info(&event->rtnl, link->ifindex, &link->iftype, &link->flags,
                               &link->kind, &link->hw_addr, &link->permanent_hw_addr);
        if (r < 0)
                return r;

        if (link->hw_addr.length > 0 && link->permanent_hw_addr.length == 0) {
                r = ethtool_get_permanent_hw_addr(&ctx->ethtool_fd, link->ifname, &link->permanent_hw_addr);
                if (r < 0)
                        log_link_debug_errno(link, r, "Failed to get permanent hardware address, ignoring: %m");
        }

        r = sd_device_get_property_value(dev, "ID_NET_DRIVER", &link->driver);
        if (r < 0 && r != -ENOENT)
                log_link_debug_errno(link, r, "Failed to get driver, ignoring: %m");

        *ret = TAKE_PTR(link);
        return 0;
}

int link_get_config(LinkConfigContext *ctx, Link *link) {
        int r;

        assert(ctx);
        assert(link);

        /* Do not configure loopback interfaces by .link files. */
        if (link->flags & IFF_LOOPBACK)
                return -ENOENT;

        LIST_FOREACH(configs, config, ctx->configs) {
                r = net_match_config(
                                &config->match,
                                link->event->dev,
                                &link->hw_addr,
                                &link->permanent_hw_addr,
                                link->driver,
                                link->iftype,
                                link->kind,
                                link->ifname,
                                /* alternative_names= */ NULL,
                                /* wlan_iftype= */ 0,
                                /* ssid= */ NULL,
                                /* bssid= */ NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (config->match.ifname && !strv_contains(config->match.ifname, "*") && link->name_assign_type == NET_NAME_ENUM)
                        log_link_warning(link, "Config file %s is applied to device based on potentially unpredictable interface name.",
                                         config->filename);
                else
                        log_link_debug(link, "Config file %s is applied", config->filename);

                link->config = config;
                return 0;
        }

        return -ENOENT;
}

static int link_apply_ethtool_settings(Link *link, int *ethtool_fd) {
        LinkConfig *config = ASSERT_PTR(ASSERT_PTR(link)->config);
        const char *name = ASSERT_PTR(link->ifname);
        int r;

        assert(link->event);
        assert(ethtool_fd);

        if (link->event->event_mode != EVENT_UDEV_WORKER) {
                log_link_debug(link, "Running in test mode, skipping application of ethtool settings.");
                return 0;
        }

        r = ethtool_set_link_settings(ethtool_fd, name,
                                      config->autonegotiation, config->advertise,
                                      config->speed, config->duplex, config->port, config->mdi);
        if (r < 0) {
                if (config->autonegotiation >= 0)
                        log_link_warning_errno(link, r, "Could not %s auto negotiation, ignoring: %m",
                                               enable_disable(config->autonegotiation));

                if (!eqzero(config->advertise))
                        log_link_warning_errno(link, r, "Could not set advertise mode, ignoring: %m");

                if (config->speed > 0)
                        log_link_warning_errno(link, r, "Could not set speed to %"PRIu64"Mbps, ignoring: %m",
                                               DIV_ROUND_UP(config->speed, 1000000));

                if (config->duplex >= 0)
                        log_link_warning_errno(link, r, "Could not set duplex to %s, ignoring: %m",
                                               duplex_to_string(config->duplex));

                if (config->port >= 0)
                        log_link_warning_errno(link, r, "Could not set port to '%s', ignoring: %m",
                                               port_to_string(config->port));

                if (config->mdi != ETH_TP_MDI_INVALID)
                        log_link_warning_errno(link, r, "Could not set MDI-X to '%s', ignoring: %m",
                                               mdi_to_string(config->mdi));
        }

        r = ethtool_set_wol(ethtool_fd, name, config->wol, config->wol_password);
        if (r < 0) {
                _cleanup_free_ char *str = NULL;

                (void) wol_options_to_string_alloc(config->wol, &str);
                log_link_warning_errno(link, r, "Could not set WakeOnLan%s%s, ignoring: %m",
                                       isempty(str) ? "" : " to ", strempty(str));
        }

        r = ethtool_set_features(ethtool_fd, name, config->features);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set offload features, ignoring: %m");

        r = ethtool_set_channels(ethtool_fd, name, &config->channels);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set channels, ignoring: %m");

        r = ethtool_set_nic_buffer_size(ethtool_fd, name, &config->ring);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set ring buffer, ignoring: %m");

        r = ethtool_set_flow_control(ethtool_fd, name, config->rx_flow_control, config->tx_flow_control, config->autoneg_flow_control);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set flow control, ignoring: %m");

        r = ethtool_set_nic_coalesce_settings(ethtool_fd, name, &config->coalesce);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set coalesce settings, ignoring: %m");

        r = ethtool_set_eee_settings(ethtool_fd, name, config->eee_enabled, config->eee_tx_lpi_enabled, config->eee_tx_lpi_timer_usec, config->eee_advertise[0]);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set energy efficient ethernet settings, ignoring: %m");

        return 0;
}

static bool hw_addr_is_valid(Link *link, const struct hw_addr_data *hw_addr) {
        assert(link);
        assert(hw_addr);

        switch (link->iftype) {
        case ARPHRD_ETHER:
                /* Refuse all zero and all 0xFF. */
                assert(hw_addr->length == ETH_ALEN);
                return !ether_addr_is_null(&hw_addr->ether) && !ether_addr_is_broadcast(&hw_addr->ether);

        case ARPHRD_INFINIBAND:
                /* The last 8 bytes cannot be zero. */
                assert(hw_addr->length == INFINIBAND_ALEN);
                return !memeqzero(hw_addr->bytes + INFINIBAND_ALEN - 8, 8);

        default:
                assert_not_reached();
        }
}

static int link_generate_new_hw_addr(Link *link, struct hw_addr_data *ret) {
        struct hw_addr_data hw_addr = HW_ADDR_NULL;
        bool is_static = false;
        uint8_t *p;
        size_t len;
        int r;

        assert(link);
        assert(link->config);
        assert(link->event);
        assert(link->event->dev);
        assert(ret);

        if (link->hw_addr.length == 0)
                goto finalize;

        if (link->config->mac_address_policy == MAC_ADDRESS_POLICY_NONE) {
                log_link_debug(link, "Using static MAC address.");
                hw_addr = link->config->hw_addr;
                is_static = true;
                goto finalize;
        }

        if (!IN_SET(link->iftype, ARPHRD_ETHER, ARPHRD_INFINIBAND))
                goto finalize;

        switch (link->addr_assign_type) {
        case NET_ADDR_SET:
                log_link_debug(link, "MAC address on the device already set by userspace.");
                goto finalize;
        case NET_ADDR_STOLEN:
                log_link_debug(link, "MAC address on the device already set based on another device.");
                goto finalize;
        case NET_ADDR_RANDOM:
        case NET_ADDR_PERM:
                break;
        default:
                log_link_warning(link, "Unknown addr_assign_type %u, ignoring", link->addr_assign_type);
                goto finalize;
        }

        if ((link->config->mac_address_policy == MAC_ADDRESS_POLICY_RANDOM) == (link->addr_assign_type == NET_ADDR_RANDOM)) {
                log_link_debug(link, "MAC address on the device already matches policy \"%s\".",
                               mac_address_policy_to_string(link->config->mac_address_policy));
                goto finalize;
        }

        hw_addr = (struct hw_addr_data) {
                .length = arphrd_to_hw_addr_len(link->iftype),
        };

        switch (link->iftype) {
        case ARPHRD_ETHER:
                p = hw_addr.bytes;
                len = hw_addr.length;
                break;
        case ARPHRD_INFINIBAND:
                p = hw_addr.bytes + INFINIBAND_ALEN - 8;
                len = 8;
                break;
        default:
                assert_not_reached();
        }

        if (link->config->mac_address_policy == MAC_ADDRESS_POLICY_RANDOM)
                /* We require genuine randomness here, since we want to make sure we won't collide with other
                 * systems booting up at the very same time. */
                for (;;) {
                        random_bytes(p, len);
                        if (hw_addr_is_valid(link, &hw_addr))
                                break;
                }

        else {
                uint64_t result;

                r = net_get_unique_predictable_data(link->event->dev,
                                                    naming_scheme_has(NAMING_STABLE_VIRTUAL_MACS),
                                                    &result);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not generate persistent MAC address: %m");

                assert(len <= sizeof(result));
                memcpy(p, &result, len);
                if (!hw_addr_is_valid(link, &hw_addr))
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(EINVAL),
                                                      "Could not generate valid persistent MAC address.");
        }

finalize:

        r = net_verify_hardware_address(link->ifname, is_static, link->iftype, &link->hw_addr, &hw_addr);
        if (r < 0)
                return r;

        if (hw_addr_equal(&link->hw_addr, &hw_addr)) {
                *ret = HW_ADDR_NULL;
                return 0;
        }

        if (hw_addr.length > 0)
                log_link_debug(link, "Applying %s MAC address: %s",
                               link->config->mac_address_policy == MAC_ADDRESS_POLICY_NONE ? "static" :
                               mac_address_policy_to_string(link->config->mac_address_policy),
                               HW_ADDR_TO_STR(&hw_addr));

        *ret = hw_addr;
        return 0;
}

static int link_apply_rtnl_settings(Link *link) {
        struct hw_addr_data hw_addr = {};
        LinkConfig *config = ASSERT_PTR(ASSERT_PTR(link)->config);
        int r;

        assert(link->event);

        if (link->event->event_mode != EVENT_UDEV_WORKER) {
                log_link_debug(link, "Running in test mode, skipping application of rtnl settings.");
                return 0;
        }

        (void) link_generate_new_hw_addr(link, &hw_addr);

        r = rtnl_set_link_properties(&link->event->rtnl, link->ifindex, config->alias, &hw_addr,
                                     config->txqueues, config->rxqueues, config->txqueuelen,
                                     config->mtu, config->gso_max_size, config->gso_max_segments);
        if (r < 0)
                log_link_warning_errno(link, r,
                                       "Could not set Alias=, MACAddress=/MACAddressPolicy=, "
                                       "TransmitQueues=, ReceiveQueues=, TransmitQueueLength=, MTUBytes=, "
                                       "GenericSegmentOffloadMaxBytes= or GenericSegmentOffloadMaxSegments=, "
                                       "ignoring: %m");

        return 0;
}

static bool enable_name_policy(void) {
        static int cached = -1;
        bool b;
        int r;

        if (cached >= 0)
                return cached;

        r = proc_cmdline_get_bool("net.ifnames", /* flags= */ 0, &b);
        if (r < 0)
                log_warning_errno(r, "Failed to parse net.ifnames= kernel command line option, ignoring: %m");
        if (r <= 0)
                return (cached = true);

        if (!b)
                log_info("Network interface NamePolicy= disabled on kernel command line.");

        return (cached = b);
}

static int link_generate_new_name(Link *link) {
        LinkConfig *config = ASSERT_PTR(ASSERT_PTR(link)->config);;
        sd_device *device = ASSERT_PTR(ASSERT_PTR(link->event)->dev);

        if (link->action != SD_DEVICE_ADD) {
                log_link_debug(link, "Not applying Name= and NamePolicy= on '%s' uevent.",
                               device_action_to_string(link->action));
                goto no_rename;
        }

        if (IN_SET(link->name_assign_type, NET_NAME_USER, NET_NAME_RENAMED) &&
            !naming_scheme_has(NAMING_ALLOW_RERENAMES)) {
                log_link_debug(link, "Device already has a name given by userspace, not renaming.");
                goto no_rename;
        }

        if (enable_name_policy() && config->name_policy)
                for (NamePolicy *policy = config->name_policy; *policy != _NAMEPOLICY_INVALID; policy++) {
                        const char *new_name = NULL;

                        switch (*policy) {
                        case NAMEPOLICY_KERNEL:
                                if (link->name_assign_type != NET_NAME_PREDICTABLE)
                                        continue;

                                /* The kernel claims to have given a predictable name, keep it. */
                                log_link_debug(link, "Policy *%s*: keeping predictable kernel name",
                                               name_policy_to_string(*policy));
                                goto no_rename;
                        case NAMEPOLICY_KEEP:
                                if (!IN_SET(link->name_assign_type, NET_NAME_USER, NET_NAME_RENAMED))
                                        continue;

                                log_link_debug(link, "Policy *%s*: keeping existing userspace name",
                                               name_policy_to_string(*policy));
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
                                assert_not_reached();
                        }
                        if (ifname_valid(new_name)) {
                                log_link_debug(link, "Policy *%s* yields \"%s\".", name_policy_to_string(*policy), new_name);
                                link->new_name = new_name;
                                return 0;
                        }
                }

        if (link->config->name) {
                log_link_debug(link, "Policies didn't yield a name, using specified Name=%s.", link->config->name);
                link->new_name = link->config->name;
                return 0;
        }

        log_link_debug(link, "Policies didn't yield a name and Name= is not given, not renaming.");
no_rename:
        if (!naming_scheme_has(NAMING_USE_INTERFACE_PROPERTY))
                return sd_device_get_sysname(device, &link->new_name);

        link->new_name = link->ifname;
        return 0;
}

static int link_generate_alternative_names(Link *link) {
        _cleanup_strv_free_ char **altnames = NULL;
        LinkConfig *config = ASSERT_PTR(ASSERT_PTR(link)->config);
        sd_device *device = ASSERT_PTR(ASSERT_PTR(link->event)->dev);
        int r;

        assert(!ASSERT_PTR(link->event)->altnames);

        if (link->action != SD_DEVICE_ADD) {
                log_link_debug(link, "Not applying AlternativeNames= and AlternativeNamesPolicy= on '%s' uevent.",
                               device_action_to_string(link->action));
                return 0;
        }

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
                                assert_not_reached();
                        }
                        if (ifname_valid_full(n, IFNAME_VALID_ALTERNATIVE)) {
                                r = strv_extend(&altnames, n);
                                if (r < 0)
                                        return log_oom();
                        }
                }

        link->event->altnames = TAKE_PTR(altnames);
        return 0;
}

static int sr_iov_configure(Link *link, sd_netlink **rtnl, SRIOV *sr_iov, SRIOVAttribute attr) {
        int r;

        assert(link);
        assert(rtnl);
        assert(link->ifindex > 0);

        if (!sr_iov_has_config(sr_iov, attr))
                return 0;

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        r = sd_rtnl_message_new_link(*rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sr_iov_set_netlink_message(sr_iov, attr, req);
        if (r < 0)
                return r;

        return sd_netlink_call(*rtnl, req, 0, NULL);
}

static int link_apply_sr_iov_config(Link *link) {
        SRIOV *sr_iov;
        uint32_t n;
        int r;

        assert(link);
        assert(link->config);
        assert(ASSERT_PTR(link->event)->dev);

        if (link->event->event_mode != EVENT_UDEV_WORKER) {
                log_link_debug(link, "Running in test mode, skipping application of SR-IOV settings.");
                return 0;
        }

        r = sr_iov_set_num_vfs(link->event->dev, link->config->sr_iov_num_vfs, link->config->sr_iov_by_section);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to set the number of SR-IOV virtual functions, ignoring: %m");

        if (ordered_hashmap_isempty(link->config->sr_iov_by_section))
                return 0;

        r = sr_iov_get_num_vfs(link->event->dev, &n);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to get the number of SR-IOV virtual functions, ignoring all [SR-IOV] sections: %m");
                return 0;
        }
        if (n == 0) {
                log_link_warning(link, "No SR-IOV virtual functions exist, ignoring all [SR-IOV] sections.");
                return 0;
        }

        ORDERED_HASHMAP_FOREACH(sr_iov, link->config->sr_iov_by_section) {
                if (sr_iov->vf >= n) {
                        log_link_warning(link, "SR-IOV virtual function %"PRIu32" does not exist, ignoring [SR-IOV] section for the virtual function.", sr_iov->vf);
                        continue;
                }

                for (SRIOVAttribute attr = 0; attr < _SR_IOV_ATTRIBUTE_MAX; attr++) {
                        r = sr_iov_configure(link, &link->event->rtnl, sr_iov, attr);
                        if (r < 0)
                                log_link_warning_errno(link, r,
                                                       "Failed to set up %s for SR-IOV virtual function %"PRIu32", ignoring: %m",
                                                       sr_iov_attribute_to_string(attr), sr_iov->vf);
                }
        }

        return 0;
}

/* CPU topology information for IRQ affinity spread algorithm. */
typedef struct CPUTopology {
        unsigned cpu;
        int numa_node;
        int package_id;
        int die_id; /* L3 cache domain / chiplet */
        int core_id;
        bool is_first_thread; /* First hyperthread of a physical core */
} CPUTopology;

/* Die (L3 cache domain) information for spread algorithm */
typedef struct DieInfo {
        int die_id;
        unsigned *cpus; /* CPUs in this die (first HT only, sorted by core) */
        size_t cpu_count;
        size_t next_idx; /* For round-robin within die */
} DieInfo;

static int cpu_topology_read_int(unsigned cpu, const char *attr, int *ret) {
        char path[STRLEN("/sys/devices/system/cpu/cpu/topology/") + DECIMAL_STR_MAX(unsigned) + 64];
        _cleanup_free_ char *content = NULL;
        int r;

        xsprintf(path, "/sys/devices/system/cpu/cpu%u/topology/%s", cpu, attr);
        r = read_one_line_file(path, &content);
        if (r < 0)
                return r;

        return safe_atoi(content, ret);
}

static int cpu_topology_get_numa_node(unsigned cpu, int *ret) {
        _cleanup_closedir_ DIR *dir = NULL;
        int r;

        dir = opendir("/sys/devices/system/node");
        if (!dir) {
                if (errno == ENOENT) {
                        *ret = 0;
                        return 0;
                }
                return -errno;
        }

        FOREACH_DIRENT(de, dir, return -errno) {
                _cleanup_free_ char *cpulist = NULL;
                _cleanup_(cpu_set_done) CPUSet cpus = {};
                char path[STRLEN("/sys/devices/system/node//cpulist") + DECIMAL_STR_MAX(int)];
                const char *n;
                int node;

                if (de->d_type != DT_DIR)
                        continue;

                n = startswith(de->d_name, "node");
                if (!n)
                        continue;

                r = safe_atoi(n, &node);
                if (r < 0)
                        continue;

                xsprintf(path, "/sys/devices/system/node/%s/cpulist", de->d_name);
                r = read_one_line_file(path, &cpulist);
                if (r < 0)
                        continue;

                r = parse_cpu_set(cpulist, &cpus);
                if (r < 0)
                        continue;

                if (CPU_ISSET_S(cpu, cpus.allocated, cpus.set)) {
                        *ret = node;
                        return 0;
                }
        }

        /* CPU not found in any NUMA node, assume node 0 */
        *ret = 0;

        return 0;
}

/* Get L3 cache shared_cpu_list for a CPU (for die grouping).
 * Returns a string that uniquely identifies the L3 cache domain. */
static int cpu_topology_get_l3_shared_list(unsigned cpu, char **ret) {
        char path[STRLEN("/sys/devices/system/cpu/cpu/cache/index3/shared_cpu_list") +
                  DECIMAL_STR_MAX(unsigned) + 1];
        _cleanup_free_ char *content = NULL;
        int r;

        xsprintf(path, "/sys/devices/system/cpu/cpu%u/cache/index3/shared_cpu_list", cpu);
        r = read_one_line_file(path, &content);
        if (r < 0)
                return r;

        delete_trailing_chars(content, "\n");

        *ret = TAKE_PTR(content);

        return 0;
}

/* Check if this CPU is the first thread of its physical core */
static int cpu_topology_is_first_thread(unsigned cpu, bool *ret) {
        char path[STRLEN("/sys/devices/system/cpu/cpu/topology/thread_siblings_list") +
                  DECIMAL_STR_MAX(unsigned) + 1];
        _cleanup_free_ char *content = NULL;
        unsigned first_sibling;
        int r;

        xsprintf(path, "/sys/devices/system/cpu/cpu%u/topology/thread_siblings_list", cpu);
        r = read_one_line_file(path, &content);
        if (r < 0) {
                /* Can't determine, assume it's first thread */
                *ret = true;
                return 0;
        }

        /* Parse the first CPU number from the sibling list (e.g., "0,158" -> 0) */
        r = safe_atou(content, &first_sibling);
        if (r < 0) {
                /* Try parsing as range "0-1" or list "0,1" */
                char *dash = strchr(content, '-');
                char *comma = strchr(content, ',');
                char *end = dash ? dash : comma;
                if (end)
                        *end = '\0';
                r = safe_atou(content, &first_sibling);
                if (r < 0) {
                        *ret = true;
                        return 0;
                }
        }

        *ret = (cpu == first_sibling);
        return 0;
}

static int cpu_topology_compare(const CPUTopology *a, const CPUTopology *b) {
        int r;

        /* Sort by die first (for L3 cache grouping), then core, then CPU number */
        r = CMP(a->die_id, b->die_id);
        if (r != 0)
                return r;

        r = CMP(a->core_id, b->core_id);
        if (r != 0)
                return r;

        return CMP(a->cpu, b->cpu);
}

/* Comparison function for sorting CPUs by CPU number (for die ID assignment) */
static int cpu_number_compare(const CPUTopology *a, const CPUTopology *b) {
        return CMP(a->cpu, b->cpu);
}

/* Assign logical die IDs based on L3 cache sharing topology.
 *
 * For IRQ spreading, the goal is to distribute interrupts across CPUs that
 * don't share cache, minimizing cache line contention when processing packets.
 * The L3 cache boundary is the key locality domain: CPUs sharing an L3 can
 * exchange data cheaply, while cross-L3 communication is expensive.
 *
 * We use L3 shared_cpu_list rather than the kernel's physical die_id because:
 * - On AMD EPYC, multiple CCXs on the same physical die have separate L3 caches
 * - On Intel with Sub-NUMA Clustering, one die may have multiple L3 domains
 * - L3 sharing reflects actual data locality, not physical packaging */
static int assign_sequential_die_ids(CPUTopology *cpus, size_t count) {
        _cleanup_strv_free_ char **l3_groups = NULL;
        int r;

        /* First, sort CPUs by CPU number for consistent discovery order */
        typesafe_qsort(cpus, count, cpu_number_compare);

        /* Assign die IDs based on order of L3 shared_cpu_list discovery */
        for (size_t i = 0; i < count; i++) {
                _cleanup_free_ char *l3_list = NULL;
                size_t die_id = 0;
                bool found = false;

                r = cpu_topology_get_l3_shared_list(cpus[i].cpu, &l3_list);
                if (r < 0) {
                        /* No L3 info, fall back to package ID */
                        cpus[i].die_id = cpus[i].package_id;
                        continue;
                }

                /* Check if we've seen this L3 group before */
                STRV_FOREACH(g, l3_groups) {
                        if (streq(*g, l3_list)) {
                                cpus[i].die_id = die_id;
                                found = true;
                                break;
                        }
                        die_id++;
                }

                if (!found) {
                        /* New L3 group, assign next sequential die ID */
                        cpus[i].die_id = strv_length(l3_groups);
                        r = strv_extend(&l3_groups, l3_list);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int discover_cpu_topology(CPUTopology **ret, size_t *ret_count) {
        _cleanup_free_ CPUTopology *cpus = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        size_t count = 0;
        int r;

        dir = opendir("/sys/devices/system/cpu");
        if (!dir)
                return -errno;

        FOREACH_DIRENT(de, dir, return -errno) {
                char online_path[STRLEN("/sys/devices/system/cpu/cpu/online") + DECIMAL_STR_MAX(unsigned) + 1];
                char topo_path[STRLEN("/sys/devices/system/cpu/cpu/topology") + DECIMAL_STR_MAX(unsigned) + 1];
                const char *n;
                unsigned cpu;

                n = startswith(de->d_name, "cpu");
                if (!n)
                        continue;

                r = safe_atou(n, &cpu);
                if (r < 0)
                        continue;

                /* Check if CPU is online */
                xsprintf(online_path, "/sys/devices/system/cpu/cpu%u/online", cpu);
                if (access(online_path, F_OK) >= 0) {
                        _cleanup_free_ char *online = NULL;
                        r = read_one_line_file(online_path, &online);
                        if (r >= 0 && streq(online, "0"))
                                continue; /* CPU is offline */
                }

                /* Check if topology directory exists (filters out cpu0 on some systems) */
                xsprintf(topo_path, "/sys/devices/system/cpu/cpu%u/topology", cpu);
                if (access(topo_path, F_OK) < 0)
                        continue;

                if (!GREEDY_REALLOC(cpus, count + 1))
                        return -ENOMEM;

                cpus[count].cpu = cpu;

                r = cpu_topology_get_numa_node(cpu, &cpus[count].numa_node);
                if (r < 0)
                        cpus[count].numa_node = 0;

                r = cpu_topology_read_int(cpu, "physical_package_id", &cpus[count].package_id);
                if (r < 0)
                        cpus[count].package_id = 0;

                /* die_id will be assigned later by assign_sequential_die_ids() */
                cpus[count].die_id = 0;

                r = cpu_topology_read_int(cpu, "core_id", &cpus[count].core_id);
                if (r < 0)
                        cpus[count].core_id = cpu;

                r = cpu_topology_is_first_thread(cpu, &cpus[count].is_first_thread);
                if (r < 0)
                        cpus[count].is_first_thread = true;

                count++;
        }

        if (count == 0)
                return -ENOENT;

        /* Assign sequential die IDs based on L3 discovery order */
        r = assign_sequential_die_ids(cpus, count);
        if (r < 0)
                return r;

        /* Sort CPUs by topology for consistent ordering */
        typesafe_qsort(cpus, count, cpu_topology_compare);

        *ret = TAKE_PTR(cpus);
        *ret_count = count;

        return 0;
}

/* Reorder indices so consecutive elements are maximally spread apart.
 *
 * Uses recursive divide-and-conquer: split in half, permute each half,
 * then interleave. This ensures elements originally far apart become adjacent.
 *
 * Example trace for [0,1,2,3,4,5,6,7]:
 *   split into [0,1,2,3] and [4,5,6,7]
 *   recurse left:  [0,1,2,3] -> [0,2,1,3]
 *   recurse right: [4,5,6,7] -> [4,6,5,7]
 *   interleave -> [0,4,2,6,1,5,3,7]
 *
 * The first N elements of the output are roughly evenly distributed across the
 * original range, for any N. This is useful when assigning IRQs to CPUs: if a
 * NIC has fewer IRQs than CPUs, the assigned CPUs will still be spread across
 * the CPUs rather than all at the beginning. */
static void equidist_permute(size_t *indices, size_t count) {
        _cleanup_free_ size_t *temp = NULL;
        _cleanup_free_ size_t *left = NULL;
        _cleanup_free_ size_t *right = NULL;
        size_t left_count, right_count;
        size_t li = 0, ri = 0, ti = 0;

        if (count <= 1)
                return;

        temp = new(size_t, count);
        if (!temp)
                return;

        memcpy(temp, indices, count * sizeof(size_t));

        left_count = (count + 1) / 2;
        right_count = count - left_count;

        /* Recursively permute each half */
        left = new(size_t, left_count);
        right = new(size_t, right_count);
        if (!left || !right)
                return;

        for (size_t i = 0; i < left_count; i++)
                left[i] = temp[i];
        for (size_t i = 0; i < right_count; i++)
                right[i] = temp[left_count + i];

        equidist_permute(left, left_count);
        equidist_permute(right, right_count);

        /* Interleave: left[0], right[0], left[1], right[1], ... */
        for (size_t i = 0; i < count; i++) {
                if (i % 2 == 0 && li < left_count)
                        indices[ti++] = left[li++];
                else if (ri < right_count)
                        indices[ti++] = right[ri++];
                else if (li < left_count)
                        indices[ti++] = left[li++];
        }
}

static void die_info_free(DieInfo *dies, size_t count) {
        if (!dies)
                return;
        for (size_t i = 0; i < count; i++)
                free(dies[i].cpus);
        free(dies);
}

/* Build die information from topology, grouping CPUs by L3/die and filtering to first HT only */
static int build_die_info(const CPUTopology *topology, size_t topology_count, DieInfo **ret, size_t *ret_count) {
        DieInfo *dies = NULL;
        size_t die_count = 0, die_allocated = 0;
        int r;

        for (size_t i = 0; i < topology_count; i++) {
                DieInfo *die = NULL;
                unsigned *new_cpus;

                /* Only consider first hyperthreads for initial spread */
                if (!topology[i].is_first_thread)
                        continue;

                /* Find or create die entry */
                for (size_t j = 0; j < die_count; j++) {
                        if (dies[j].die_id == topology[i].die_id) {
                                die = &dies[j];
                                break;
                        }
                }

                if (!die) {
                        if (!GREEDY_REALLOC(dies, die_allocated + 1)) {
                                r = -ENOMEM;
                                goto fail;
                        }
                        die = &dies[die_count++];
                        *die = (DieInfo) { .die_id = topology[i].die_id };
                        die_allocated++;
                }

                new_cpus = reallocarray(die->cpus, die->cpu_count + 1, sizeof(unsigned));
                if (!new_cpus) {
                        r = -ENOMEM;
                        goto fail;
                }
                die->cpus = new_cpus;
                die->cpus[die->cpu_count++] = topology[i].cpu;
        }

        /* Sort dies by die_id for determinism, then apply equidist to CPUs within each die */
        for (size_t i = 0; i < die_count; i++) {
                _cleanup_free_ unsigned *reordered = NULL;
                _cleanup_free_ size_t *indices = new(size_t, dies[i].cpu_count);
                if (!indices) {
                        r = -ENOMEM;
                        goto fail;
                }

                for (size_t j = 0; j < dies[i].cpu_count; j++)
                        indices[j] = j;

                equidist_permute(indices, dies[i].cpu_count);

                /* Reorder CPUs according to equidist permutation */
                reordered = new(unsigned, dies[i].cpu_count);
                if (!reordered) {
                        r = -ENOMEM;
                        goto fail;
                }

                for (size_t j = 0; j < dies[i].cpu_count; j++)
                        reordered[j] = dies[i].cpus[indices[j]];

                memcpy(dies[i].cpus, reordered, dies[i].cpu_count * sizeof(unsigned));
        }

        *ret = dies;
        *ret_count = die_count;

        return 0;

fail:
        die_info_free(dies, die_count);
        return r;
}

/* Select CPUs for IRQ affinity spreading with optimal topology distribution.
 *
 * Algorithm:
 * 1. Group CPUs by die (L3 cache domain), using only first hyperthreads
 * 2. Apply equidistant permutation to both die order and CPUs within each die,
 *    so consecutive selections are maximally spread (e.g., [0,1,2,3] -> [0,2,1,3])
 * 3. Round-robin across dies, picking one CPU per die per round
 * 4. If more IRQs than physical cores, wrap around and reuse the same CPUs
 *
 * Ensures each IRQ gets a dedicated physical core before any core handles
 * multiple IRQs. Two IRQs on one physical core time-share but benefit from warm
 * cache, whereas spreading across SMT siblings causes resource contention with
 * no cache benefit.
 * Maximizes physical distance between consecutively assigned IRQs, improving
 * cache distribution even when only a few IRQs are assigned. */
static int select_spread_cpus(
                const CPUTopology *topology,
                size_t topology_count,
                size_t n_irqs,
                unsigned **ret,
                size_t *ret_count) {
        _cleanup_free_ unsigned *selected = NULL;
        _cleanup_free_ size_t *die_order = NULL;
        DieInfo *dies = NULL;
        size_t die_count = 0;
        size_t selected_count = 0;
        int r;

        assert(topology);
        assert(topology_count > 0);
        assert(ret);
        assert(ret_count);

        selected = new(unsigned, n_irqs);
        if (!selected)
                return -ENOMEM;

        /* Build die information with first HT CPUs only */
        r = build_die_info(topology, topology_count, &dies, &die_count);
        if (r < 0)
                return r;

        if (die_count == 0) {
                die_info_free(dies, die_count);
                return -ENOENT;
        }

        /* Create equidistant die ordering */
        die_order = new(size_t, die_count);
        if (!die_order) {
                die_info_free(dies, die_count);
                return -ENOMEM;
        }

        for (size_t i = 0; i < die_count; i++)
                die_order[i] = i;

        equidist_permute(die_order, die_count);

        /* Round-robin across dies, picking one CPU from each die at a time */
        size_t dies_exhausted = 0;
        while (selected_count < n_irqs) {
                bool made_progress = false;

                for (size_t i = 0; i < die_count && selected_count < n_irqs; i++) {
                        DieInfo *die = &dies[die_order[i]];

                        if (die->next_idx >= die->cpu_count)
                                continue;

                        selected[selected_count++] = die->cpus[die->next_idx++];
                        made_progress = true;

                        if (die->next_idx >= die->cpu_count)
                                dies_exhausted++;
                }

                if (!made_progress) {
                        /* All first HTs exhausted, wrap around for remaining IRQs */
                        if (dies_exhausted >= die_count) {
                                /* Reset all dies for round-robin wrap */
                                for (size_t i = 0; i < die_count; i++)
                                        dies[i].next_idx = 0;
                                dies_exhausted = 0;
                        } else
                                break;
                }
        }

        die_info_free(dies, die_count);

        *ret = TAKE_PTR(selected);
        *ret_count = selected_count;

        return 0;
}

static int set_irq_affinity(Link *link, const char *irq, unsigned cpu) {
        _cleanup_free_ char *affinity_path = NULL, *mask_str = NULL;
        unsigned int n_groups = cpu / 32;
        unsigned int current_group;
        char *p;
        int r;

        affinity_path = strjoin("/proc/irq/", irq, "/smp_affinity");
        if (!affinity_path)
                return log_oom();

        /* Convert CPU number to hex bitmask.
         * For CPU N, set bit N (1 << N). CPUs are split by comma-separated
         * 32-bits groups. To assign CPU 32, we should write 1,00000000 */

        mask_str = new0(char, (n_groups + 1) * 9); /* 8 hex digits + comma per group */
        if (!mask_str)
                return log_oom();

        p = mask_str;
        current_group = n_groups;
        do {
                if (current_group == n_groups)
                        p += sprintf(p, "%x", 1U << (cpu % 32));
                else
                        p += sprintf(p, ",00000000");
        } while (current_group--);

        r = write_string_file(affinity_path, mask_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set IRQ %s affinity to CPU %u: %m", irq, cpu);

        log_link_debug(link, "Set IRQ %s affinity to CPU %u.", irq, cpu);

        return 0;
}

static int link_apply_irq_affinity_spread(Link *link, const char *msi_irqs_path) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ CPUTopology *topology = NULL;
        _cleanup_free_ char **irqs = NULL;
        _cleanup_free_ unsigned *spread_cpus = NULL;
        size_t topology_count = 0, irq_count = 0, spread_count = 0;
        int r;

        dir = opendir(msi_irqs_path);
        if (!dir)
                return log_link_error_errno(link, errno, "Failed to open %s: %m", msi_irqs_path);

        FOREACH_DIRENT(de, dir, return log_link_error_errno(link, errno, "Failed to read directory %s: %m", msi_irqs_path)) {
                r = strv_extend(&irqs, de->d_name);
                if (r < 0)
                        return log_oom();
                irq_count++;
        }

        if (irq_count == 0) {
                log_link_debug(link, "No IRQs found, skipping spread.");
                return 0;
        }

        strv_sort(irqs);

        r = discover_cpu_topology(&topology, &topology_count);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to discover CPU topology: %m");

        log_link_debug(link, "Discovered %zu CPUs, spreading %zu IRQs.", topology_count, irq_count);

        /* Select CPUs using maximum distance algorithm */
        r = select_spread_cpus(topology, topology_count, irq_count, &spread_cpus, &spread_count);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to select spread CPUs: %m");

        for (size_t i = 0; i < irq_count; i++) {
                r = set_irq_affinity(link, irqs[i], spread_cpus[i]);
                if (r < 0)
                        continue; /* Non-fatal, try next IRQ */
        }

        log_link_info(link, "Applied IRQ affinity policy 'spread' across %zu CPUs for %zu IRQs.",
                      MIN(topology_count, irq_count), irq_count);

        return 0;
}

static int link_apply_irq_affinity_single(Link *link, const char *msi_irqs_path) {
        _cleanup_closedir_ DIR *dir = NULL;
        int r;

        dir = opendir(msi_irqs_path);
        if (!dir)
                return log_link_error_errno(link, errno, "Failed to open %s: %m", msi_irqs_path);

        FOREACH_DIRENT(de, dir, return log_link_error_errno(link, errno, "Failed to read directory %s: %m", msi_irqs_path)) {
                r = set_irq_affinity(link, de->d_name, 0);
                if (r < 0)
                        continue; /* Non-fatal, try next IRQ */
        }

        log_link_info(link, "Applied IRQ affinity policy 'single' (pinning to CPU 0).");

        return 0;
}

static int link_apply_irq_affinity(Link *link) {
        _cleanup_free_ char *msi_irqs_path = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        const char *syspath;
        int r;

        assert(link);
        assert(link->config);
        assert(ASSERT_PTR(link->event)->dev);

        if (link->event->event_mode != EVENT_UDEV_WORKER) {
                log_link_debug(link, "Running in test mode, skipping application of IRQ affinity settings.");
                return 0;
        }

        if (link->config->irq_affinity_policy < 0)
                return 0;

        r = have_effective_cap(CAP_SYS_NICE);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to check for CAP_SYS_NICE capability: %m");
        if (r == 0)
                return log_link_warning_errno(link, SYNTHETIC_ERRNO(EPERM),
                                              "Skipping IRQ affinity, as we don't have privileges.");

        r = sd_device_get_syspath(link->event->dev, &syspath);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get syspath: %m");

        msi_irqs_path = path_join(syspath, "device/msi_irqs");
        if (!msi_irqs_path)
                return log_oom();

        if (access(msi_irqs_path, F_OK) < 0) {
                if (errno == ENOENT) {
                        log_link_debug(link, "No MSI IRQs found at %s, skipping IRQ affinity configuration.", msi_irqs_path);
                        return 0;
                }
                return log_link_warning_errno(link, errno, "Failed to access %s: %m", msi_irqs_path);
        }

        switch (link->config->irq_affinity_policy) {
        case IRQ_AFFINITY_POLICY_SINGLE:
                return link_apply_irq_affinity_single(link, msi_irqs_path);
        case IRQ_AFFINITY_POLICY_SPREAD:
                return link_apply_irq_affinity_spread(link, msi_irqs_path);
        default:
                assert_not_reached();
        }

        return 0;
}

static int link_apply_rps_cpu_mask(Link *link) {
        _cleanup_free_ char *mask_str = NULL;
        LinkConfig *config;
        int r;

        config = ASSERT_PTR(ASSERT_PTR(link)->config);
        assert(ASSERT_PTR(link->event)->dev);

        if (link->event->event_mode != EVENT_UDEV_WORKER) {
                log_link_debug(link, "Running in test mode, skipping application of RPS setting.");
                return 0;
        }

        /* Skip if the config is not specified. */
        if (!config->rps_cpu_mask.set)
                return 0;

        mask_str = cpu_set_to_mask_string(&config->rps_cpu_mask);
        if (!mask_str)
                return log_oom();

        log_link_debug(link, "Applying RPS CPU mask: %s", mask_str);

        /* Currently, this will set CPU mask to all rx queue of matched device. */
        FOREACH_DEVICE_SYSATTR(link->event->dev, attr) {
                const char *c;

                c = path_startswith(attr, "queues/");
                if (!c)
                        continue;

                c = startswith(c, "rx-");
                if (!c)
                        continue;

                c += strcspn(c, "/");

                if (!path_equal(c, "/rps_cpus"))
                        continue;

                r = sd_device_set_sysattr_value(link->event->dev, attr, mask_str);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to write %s sysfs attribute, ignoring: %m", attr);
        }

        return 0;
}

static int link_apply_udev_properties(Link *link) {
        LinkConfig *config = ASSERT_PTR(ASSERT_PTR(link)->config);
        UdevEvent *event = ASSERT_PTR(link->event);

        /* 1. apply ImportProperty=. */
        STRV_FOREACH(p, config->import_properties)
                (void) udev_builtin_import_property(event, *p);

        /* 2. apply Property=. */
        STRV_FOREACH(p, config->properties) {
                _cleanup_free_ char *key = NULL;
                const char *eq;

                eq = strchr(*p, '=');
                if (!eq)
                        continue;

                key = strndup(*p, eq - *p);
                if (!key)
                        return log_oom();

                (void) udev_builtin_add_property(event, key, eq + 1);
        }

        /* 3. apply UnsetProperty=. */
        STRV_FOREACH(p, config->unset_properties)
                (void) udev_builtin_add_property(event, *p, NULL);

        /* 4. set the default properties. */
        (void) udev_builtin_add_property(event, "ID_NET_LINK_FILE", config->filename);

        _cleanup_free_ char *joined = NULL;
        STRV_FOREACH(d, config->dropins) {
                _cleanup_free_ char *escaped = NULL;

                escaped = xescape(*d, ":");
                if (!escaped)
                        return log_oom();

                if (!strextend_with_separator(&joined, ":", escaped))
                        return log_oom();
        }

        (void) udev_builtin_add_property(event, "ID_NET_LINK_FILE_DROPINS", joined);

        if (link->new_name)
                (void) udev_builtin_add_property(event, "ID_NET_NAME", link->new_name);

        return 0;
}

int link_apply_config(LinkConfigContext *ctx, Link *link) {
        int r;

        assert(ctx);
        assert(link);

        r = link_apply_ethtool_settings(link, &ctx->ethtool_fd);
        if (r < 0)
                return r;

        r = link_apply_rtnl_settings(link);
        if (r < 0)
                return r;

        r = link_generate_new_name(link);
        if (r < 0)
                return r;

        r = link_generate_alternative_names(link);
        if (r < 0)
                return r;

        r = link_apply_sr_iov_config(link);
        if (r < 0)
                return r;

        r = link_apply_rps_cpu_mask(link);
        if (r < 0)
                return r;

        r = link_apply_irq_affinity(link);
        if (r < 0)
                return r;

        return link_apply_udev_properties(link);
}

int config_parse_udev_property(
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

        char ***properties = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *properties = strv_free(*properties);
                return 0;
        }

        for (const char *p = rvalue;; ) {
                _cleanup_free_ char *word = NULL, *resolved = NULL, *key = NULL;
                const char *eq;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring assignment: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = specifier_printf(word, SIZE_MAX, link_specifier_table, NULL, NULL, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve specifiers in %s, ignoring assignment: %m", word);
                        continue;
                }

                if (!udev_property_assignment_is_valid(resolved)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid udev property, ignoring assignment: %s", word);
                        continue;
                }

                assert_se(eq = strchr(resolved, '='));
                key = strndup(resolved, eq - resolved);
                if (!key)
                        return log_oom();

                if (!device_property_can_set(key)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid udev property name '%s', ignoring assignment: %s", key, resolved);
                        continue;
                }

                r = strv_env_replace_consume(properties, TAKE_PTR(resolved));
                if (r < 0)
                        return log_error_errno(r, "Failed to update properties: %m");
        }
}

int config_parse_udev_property_name(
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

        char ***properties = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *properties = strv_free(*properties);
                return 0;
        }

        for (const char *p = rvalue;; ) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring assignment: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = specifier_printf(word, SIZE_MAX, link_specifier_table, NULL, NULL, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to resolve specifiers in %s, ignoring assignment: %m", word);
                        continue;
                }

                if (!udev_property_name_is_valid(resolved)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid udev property name, ignoring assignment: %s", resolved);
                        continue;
                }

                if (!device_property_can_set(resolved)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid udev property name, ignoring assignment: %s", resolved);
                        continue;
                }

                r = strv_consume(properties, TAKE_PTR(resolved));
                if (r < 0)
                        return log_error_errno(r, "Failed to update properties: %m");
        }
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

        char **s = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
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

int config_parse_wol_password(
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

        LinkConfig *config = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                config->wol_password = erase_and_free(config->wol_password);
                config->wol_password_file = mfree(config->wol_password_file);
                return 0;
        }

        if (path_is_absolute(rvalue) && path_is_safe(rvalue)) {
                config->wol_password = erase_and_free(config->wol_password);
                return free_and_strdup_warn(&config->wol_password_file, rvalue);
        }

        warn_file_is_world_accessible(filename, NULL, unit, line);

        r = link_parse_wol_password(config, rvalue);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s.", lvalue, rvalue);
                return 0;
        }

        config->wol_password_file = mfree(config->wol_password_file);
        return 0;
}

int config_parse_rps_cpu_mask(
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

        CPUSet *mask = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (streq(rvalue, "disable")) {
                _cleanup_(cpu_set_done) CPUSet c = {};

                r = cpu_set_realloc(&c, 1);
                if (r < 0)
                        return log_oom();

                return cpu_set_done_and_replace(*mask, c);
        }

        if (streq(rvalue, "all")) {
                _cleanup_(cpu_set_done) CPUSet c = {};

                r = cpu_set_add_all(&c);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to create CPU affinity mask representing \"all\" cpus, ignoring: %m");
                        return 0;
                }

                return cpu_set_done_and_replace(*mask, c);
        }

        return config_parse_cpu_set(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);
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
        MAC_ADDRESS_POLICY_NONE);

DEFINE_CONFIG_PARSE_ENUMV(config_parse_name_policy, name_policy, NamePolicy,
                          _NAMEPOLICY_INVALID);

DEFINE_CONFIG_PARSE_ENUMV(config_parse_alternative_names_policy, alternative_names_policy, NamePolicy,
                          _NAMEPOLICY_INVALID);

static const char* const irq_affinity_policy_table[_IRQ_AFFINITY_POLICY_MAX] = {
        [IRQ_AFFINITY_POLICY_SINGLE] = "single",
        [IRQ_AFFINITY_POLICY_SPREAD] = "spread",
};

DEFINE_STRING_TABLE_LOOKUP(irq_affinity_policy, IRQAffinityPolicy);
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(
        config_parse_irq_affinity_policy,
        irq_affinity_policy,
        IRQAffinityPolicy,
        _IRQ_AFFINITY_POLICY_INVALID);

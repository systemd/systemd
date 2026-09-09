/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "sd-device.h"
#include "sd-json.h"
#include "sd-netlink.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "json-util.h"
#include "log.h"
#include "metrics.h"
#include "netif-util.h"
#include "report-netstat.h"
#include "sort-util.h"
#include "utf8.h"

/* Reports the traffic counters and a few related properties of all network interfaces in our network
 * namespace. Everything is acquired with a single RTM_GETLINK dump, except for the link speed, which the
 * kernel does not expose via rtnetlink, and which we hence read from sysfs. Note that the "speed" sysfs
 * attribute is backed by the very same driver hook (ethtool's get_link_ksettings) as the ethtool ioctl and
 * ethtool-netlink APIs, hence is exactly as widely available as those. */

typedef enum NetstatMetric {
        /* Keep in the same order as the metric family table below */
        NETSTAT_CARRIER_CHANGES,
        NETSTAT_COLLISIONS,
        NETSTAT_MTU,
        NETSTAT_RECEIVE_BYTES,
        NETSTAT_RECEIVE_DROPPED,
        NETSTAT_RECEIVE_ERRORS,
        NETSTAT_RECEIVE_MULTICAST_PACKETS,
        NETSTAT_RECEIVE_PACKETS,
        NETSTAT_SPEED_BITS_PER_SECOND,
        NETSTAT_TRANSMIT_BYTES,
        NETSTAT_TRANSMIT_DROPPED,
        NETSTAT_TRANSMIT_ERRORS,
        NETSTAT_TRANSMIT_PACKETS,
        NETSTAT_TRANSMIT_QUEUE_LENGTH,
        _NETSTAT_METRIC_MAX,
} NetstatMetric;

typedef struct NetworkInterface {
        int ifindex;
        uint16_t iftype;
        const char *ifname;    /* owned by the netlink reply */
        const char *kind;      /* ditto */

        struct rtnl_link_stats64 stats;
        bool has_stats;

        uint32_t carrier_changes;
        bool has_carrier_changes;

        uint32_t mtu;
        bool has_mtu;

        uint32_t txqlen;
        bool has_txqlen;
} NetworkInterface;

static int network_interface_compare(const NetworkInterface *a, const NetworkInterface *b) {
        assert(a);
        assert(b);
        return CMP(a->ifindex, b->ifindex);
}

static int network_interface_parse(sd_netlink_message *m, NetworkInterface *ret) {
        int r;

        assert(m);
        assert(ret);

        NetworkInterface i = {};

        r = sd_rtnl_message_link_get_ifindex(m, &i.ifindex);
        if (r < 0)
                return log_debug_errno(r, "Failed to get interface index from netlink message: %m");

        r = sd_rtnl_message_link_get_type(m, &i.iftype);
        if (r < 0)
                return log_debug_errno(r, "Failed to get interface type from netlink message: %m");

        r = sd_netlink_message_read_string(m, IFLA_IFNAME, &i.ifname);
        if (r < 0)
                return log_debug_errno(r, "Failed to get interface name of interface %i: %m", i.ifindex);
        if (!utf8_is_valid(i.ifname)) /* we cannot insert non-UTF-8 into json, let's refuse early */
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN), "Interface name of interface %i is not valid UTF-8: %m", i.ifindex);

        i.has_stats = sd_netlink_message_read(m, IFLA_STATS64, sizeof(i.stats), &i.stats) >= 0;
        i.has_carrier_changes = sd_netlink_message_read_u32(m, IFLA_CARRIER_CHANGES, &i.carrier_changes) >= 0;
        i.has_mtu = sd_netlink_message_read_u32(m, IFLA_MTU, &i.mtu) >= 0;
        i.has_txqlen = sd_netlink_message_read_u32(m, IFLA_TXQLEN, &i.txqlen) >= 0;

        if (sd_netlink_message_enter_container(m, IFLA_LINKINFO) >= 0) {
                (void) sd_netlink_message_read_string(m, IFLA_INFO_KIND, &i.kind);
                (void) sd_netlink_message_exit_container(m);
        }

        *ret = i;
        return 0;
}

static int network_interface_get_device(const NetworkInterface *i, sd_device **ret) {
        int r;

        assert(i);
        assert(ret);

        /* Note that we look up the device by name instead of with sd_device_new_from_ifindex(), as the
         * latter would issue another netlink request to resolve the name. To protect against the interface
         * having been renamed in the meantime, we verify the index afterwards. A fresh sd_device object is
         * used each time, so that the sysattr cache never hands out stale readings. */
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_subsystem_sysname(&dev, "net", i->ifname);
        if (r < 0)
                return r;

        int ifindex;
        r = sd_device_get_ifindex(dev, &ifindex);
        if (r < 0)
                return r;
        if (ifindex != i->ifindex)
                return -ENXIO;

        *ret = TAKE_PTR(dev);
        return 0;
}

/* Returns the link speed in bits per second, or 0 if not known. */
static int network_interface_get_speed(sd_device *dev, uint64_t *ret) {
        int r;

        assert(dev);
        assert(ret);

        /* Reading this fails with EINVAL if the driver does not implement ethtool's get_link_ksettings
         * (loopback, Wi-Fi, many virtual devices…) or if the interface is not up. Drivers that do not know
         * the speed (for example because there is no carrier) report -1. */
        int mbps;
        r = device_get_sysattr_int(dev, "speed", &mbps);
        if (r < 0)
                return r;
        if (mbps <= 0)
                return -ENODATA;

        *ret = (uint64_t) mbps * UINT64_C(1000000);
        return 0;
}

static int network_interface_send(
                const MetricFamily mf[static _NETSTAT_METRIC_MAX],
                sd_varlink *link,
                const NetworkInterface *i) {

        int r;

        assert(mf);
        assert(link);
        assert(i);

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = network_interface_get_device(i, &dev);
        if (r < 0)
                log_debug_errno(r, "Failed to get device for network interface '%s', ignoring: %m", i->ifname);

        /* Same as the "Type" column of networkctl, i.e. the device type if there is one, the hardware
         * type otherwise */
        _cleanup_free_ char *type = NULL;
        if (dev) {
                r = net_get_type_string(dev, i->iftype, &type);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to determine type of network interface '%s', ignoring: %m", i->ifname);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
        r = sd_json_buildo(
                        &fields,
                        SD_JSON_BUILD_PAIR_UNSIGNED("ifindex", i->ifindex),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("type", type),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("kind", i->kind));
        if (r < 0)
                return log_error_errno(r, "Failed to build metric fields: %m");

        uint64_t speed = 0;
        if (dev) {
                r = network_interface_get_speed(dev, &speed);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Unable to get device speed, ignoring: %m");
        }

        const struct {
                NetstatMetric metric;
                bool valid;
                uint64_t value;
        } table[] = {
                { NETSTAT_CARRIER_CHANGES,           i->has_carrier_changes, i->carrier_changes      },
                { NETSTAT_COLLISIONS,                i->has_stats,           i->stats.collisions     },
                { NETSTAT_MTU,                       i->has_mtu,             i->mtu                  },
                { NETSTAT_RECEIVE_BYTES,             i->has_stats,           i->stats.rx_bytes       },
                { NETSTAT_RECEIVE_DROPPED,           i->has_stats,           i->stats.rx_dropped     },
                { NETSTAT_RECEIVE_ERRORS,            i->has_stats,           i->stats.rx_errors      },
                { NETSTAT_RECEIVE_MULTICAST_PACKETS, i->has_stats,           i->stats.multicast      },
                { NETSTAT_RECEIVE_PACKETS,           i->has_stats,           i->stats.rx_packets     },
                { NETSTAT_SPEED_BITS_PER_SECOND,     speed > 0,              speed                   },
                { NETSTAT_TRANSMIT_BYTES,            i->has_stats,           i->stats.tx_bytes       },
                { NETSTAT_TRANSMIT_DROPPED,          i->has_stats,           i->stats.tx_dropped     },
                { NETSTAT_TRANSMIT_ERRORS,           i->has_stats,           i->stats.tx_errors      },
                { NETSTAT_TRANSMIT_PACKETS,          i->has_stats,           i->stats.tx_packets     },
                { NETSTAT_TRANSMIT_QUEUE_LENGTH,     i->has_txqlen,          i->txqlen               },
        };
        assert_cc(ELEMENTSOF(table) == _NETSTAT_METRIC_MAX);

        FOREACH_ELEMENT(t, table) {
                if (!t->valid)
                        continue;

                r = metric_build_send_unsigned(mf + t->metric, link, i->ifname, t->value, fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netstat_generate(
                const MetricFamily mf[static _NETSTAT_METRIC_MAX],
                sd_varlink *link,
                void *userdata) {

        int r;

        assert(mf);
        assert(link);

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, /* ifindex= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate RTM_GETLINK message: %m");

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable dump mode on RTM_GETLINK message: %m");

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *reply = NULL;
        r = sd_netlink_call(rtnl, req, /* timeout= */ 0, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate network interfaces: %m");

        /* Collect all interfaces first, so that we can report them ordered by interface index, for stable
         * output. The strings we collect point into the reply, which hence must stay around. */
        _cleanup_free_ NetworkInterface *interfaces = NULL;
        size_t n_interfaces = 0;
        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                uint16_t type;

                r = sd_netlink_message_get_errno(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate network interfaces: %m");

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0)
                        return log_error_errno(r, "Failed to get netlink message type: %m");
                if (type != RTM_NEWLINK)
                        continue;

                NetworkInterface i;
                if (network_interface_parse(m, &i) < 0)
                        continue;

                if (!GREEDY_REALLOC(interfaces, n_interfaces + 1))
                        return log_oom();

                interfaces[n_interfaces++] = i;
        }

        typesafe_qsort(interfaces, n_interfaces, network_interface_compare);

        FOREACH_ARRAY(i, interfaces, n_interfaces) {
                r = network_interface_send(mf, link, i);
                if (r < 0)
                        return r;
        }

        return 0;
}

#define METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "io.systemd.NetworkStatistics."

static const MetricFamily netstat_metric_family_table[_NETSTAT_METRIC_MAX + 1] = {
        /* Keep metrics ordered alphabetically, and in sync with NetstatMetric. All are generated by the
         * same function, attached to the first of them. */
        [NETSTAT_CARRIER_CHANGES] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "CarrierChanges",
                "Per interface metric: number of times the carrier state changed "
                "(object=interface name, ifindex=interface index, type=interface type, kind=interface kind)",
                METRIC_FAMILY_TYPE_COUNTER,
                .generate = netstat_generate,
        },
        [NETSTAT_COLLISIONS] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "Collisions",
                "Per interface metric: number of collisions during packet transmission",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_MTU] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "MTU",
                "Per interface metric: maximum transmission unit in bytes",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        [NETSTAT_RECEIVE_BYTES] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "ReceiveBytes",
                "Per interface metric: number of bytes received",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_RECEIVE_DROPPED] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "ReceiveDropped",
                "Per interface metric: number of received packets dropped without error",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_RECEIVE_ERRORS] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "ReceiveErrors",
                "Per interface metric: number of receive errors",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_RECEIVE_MULTICAST_PACKETS] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "ReceiveMulticastPackets",
                "Per interface metric: number of multicast packets received",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_RECEIVE_PACKETS] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "ReceivePackets",
                "Per interface metric: number of packets received",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_SPEED_BITS_PER_SECOND] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "SpeedBitsPerSecond",
                "Per interface metric: link speed in bits per second, if known",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        [NETSTAT_TRANSMIT_BYTES] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "TransmitBytes",
                "Per interface metric: number of bytes transmitted",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_TRANSMIT_DROPPED] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "TransmitDropped",
                "Per interface metric: number of packets dropped on transmission without error",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_TRANSMIT_ERRORS] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "TransmitErrors",
                "Per interface metric: number of transmit errors",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_TRANSMIT_PACKETS] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "TransmitPackets",
                "Per interface metric: number of packets transmitted",
                METRIC_FAMILY_TYPE_COUNTER,
        },
        [NETSTAT_TRANSMIT_QUEUE_LENGTH] = {
                METRIC_IO_SYSTEMD_NETWORK_STATISTICS_PREFIX "TransmitQueueLength",
                "Per interface metric: transmit queue length in packets",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(netstat_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(netstat_metric_family_table, link, parameters, flags, userdata);
}

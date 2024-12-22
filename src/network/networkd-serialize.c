/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "json-util.h"
#include "memfd-util.h"
#include "networkd-address.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-serialize.h"

int manager_serialize(Manager *manager) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *array = NULL;
        int r;

        assert(manager);

        log_debug("Serializing...");

        Link *link;
        HASHMAP_FOREACH(link, manager->links_by_index) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;

                /* ignore unmanaged, failed, or removed interfaces. */
                if (!IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_INITIALIZED, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                r = sd_json_buildo(
                                &e,
                                SD_JSON_BUILD_PAIR_INTEGER("Index", link->ifindex));
                if (r < 0)
                        return r;

                r = addresses_append_json(link, /* serializing = */ true, &e);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&array, e);
                if (r < 0)
                        return r;
        }

        r = json_variant_set_field_non_null(&v, "Interfaces", array);
        if (r < 0)
                return r;

        r = nexthops_append_json(manager, /* ifindex = */ -1, &v);
        if (r < 0)
                return r;

        r = routes_append_json(manager, /* ifindex = */ -1, &v);
        if (r < 0)
                return r;

        if (!v) {
                log_debug("There is nothing to serialize.");
                return 0;
        }

        _cleanup_free_ char *dump = NULL;
        r = sd_json_variant_format(v, /* flags = */ 0, &dump);
        if (r < 0)
                return r;

        _cleanup_close_ int fd = -EBADF;
        fd = memfd_new_and_seal_string("serialization", dump);
        if (fd < 0)
                return fd;

        r = notify_push_fd(fd, "manager-serialization");
        if (r < 0)
                return log_debug_errno(r, "Failed to push serialization file descriptor: %m");

        log_debug("Serialization completed.");
        return 0;
}

int manager_set_serialization_fd(Manager *manager, int fd, const char *name) {
        assert(manager);
        assert(fd >= 0);
        assert(name);

        if (!startswith(name, "manager-serialization"))
                return -EINVAL;

        if (manager->serialization_fd >= 0)
                return -EEXIST;

        manager->serialization_fd = fd;
        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_network_config_source, NetworkConfigSource, network_config_source_from_string);

static int json_dispatch_address_family(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int r, *i = ASSERT_PTR(userdata);
        int64_t i64;

        assert_return(variant, -EINVAL);

        if (FLAGS_SET(flags, SD_JSON_RELAX) && sd_json_variant_is_null(variant)) {
                *i = AF_UNSPEC;
                return 0;
        }

        r = sd_json_dispatch_int64(name, variant, flags, &i64);
        if (r < 0)
                return r;

        if (!IN_SET(i64, AF_INET, AF_INET6) && !(FLAGS_SET(flags, SD_JSON_RELAX) && i64 == AF_UNSPEC))
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds for an address family.", strna(name));

        *i = (int) i64;
        return 0;
}

typedef struct AddressParam {
        int family;
        struct iovec address;
        struct iovec peer;
        uint8_t prefixlen;
        NetworkConfigSource source;
        struct iovec provider;
} AddressParam;

static void address_param_done(AddressParam *p) {
        assert(p);

        iovec_done(&p->address);
        iovec_done(&p->peer);
        iovec_done(&p->provider);
}

static int link_deserialize_address(Link *link, sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Family",         _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family,        offsetof(AddressParam, family),    SD_JSON_MANDATORY },
                { "Address",        SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(AddressParam, address),   SD_JSON_MANDATORY },
                { "Peer",           SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(AddressParam, peer),      0                 },
                { "PrefixLength",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(AddressParam, prefixlen), SD_JSON_MANDATORY },
                { "ConfigSource",   SD_JSON_VARIANT_STRING,        json_dispatch_network_config_source, offsetof(AddressParam, source),    SD_JSON_MANDATORY },
                { "ConfigProvider", SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(AddressParam, provider),  0                 },
                {},
        };

        int r;

        assert(link);
        assert(v);

        _cleanup_(address_param_done) AddressParam p = {};
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to dispatch address from json variant: %m");

        if (p.address.iov_len != FAMILY_ADDRESS_SIZE(p.family))
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EINVAL),
                                            "Dispatched address size (%zu) is incompatible with the family (%s).",
                                            p.address.iov_len, af_to_ipv4_ipv6(p.family));

        if (p.peer.iov_len != 0 && p.peer.iov_len != FAMILY_ADDRESS_SIZE(p.family))
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EINVAL),
                                            "Dispatched peer address size (%zu) is incompatible with the family (%s).",
                                            p.peer.iov_len, af_to_ipv4_ipv6(p.family));

        if (p.provider.iov_len != 0 && p.provider.iov_len != FAMILY_ADDRESS_SIZE(p.family))
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EINVAL),
                                            "Dispatched provider address size (%zu) is incompatible with the family (%s).",
                                            p.provider.iov_len, af_to_ipv4_ipv6(p.family));

        Address tmp = {
                .family = p.family,
                .prefixlen = p.prefixlen,
        };

        memcpy_safe(&tmp.in_addr, p.address.iov_base, p.address.iov_len);
        memcpy_safe(&tmp.in_addr_peer, p.peer.iov_base, p.peer.iov_len);

        Address *address;
        r = address_get(link, &tmp, &address);
        if (r < 0) {
                log_link_debug_errno(link, r, "Cannot find deserialized address %s: %m",
                                     IN_ADDR_PREFIX_TO_STRING(tmp.family, &tmp.in_addr, tmp.prefixlen));
                return 0; /* Already removed? */
        }

        if (address->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                return 0; /* Huh?? Already deserialized?? */

        address->source = p.source;
        memcpy_safe(&address->provider, p.provider.iov_base, p.provider.iov_len);

        log_address_debug(address, "Deserialized", link);
        return 0;
}

static int manager_deserialize_link(Manager *manager, sd_json_variant *v) {
        typedef struct LinkParam {
                int ifindex;
                sd_json_variant *addresses;
        } LinkParam;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Index",     _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(LinkParam, ifindex),   SD_JSON_MANDATORY | SD_JSON_REFUSE_NULL },
                { "Addresses", SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant_noref, offsetof(LinkParam, addresses), 0                                       },
                {},
        };

        int r, ret = 0;

        assert(manager);
        assert(v);

        LinkParam p = {};
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to dispatch interface from json variant: %m");

        Link *link;
        r = link_get_by_index(manager, p.ifindex, &link);
        if (r < 0) {
                log_debug_errno(r, "No interface with deserialized ifindex (%i) found: %m", p.ifindex);
                return 0; /* Already removed? */
        }

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, p.addresses)
                RET_GATHER(ret, link_deserialize_address(link, i));

        return ret;
}

typedef struct NextHopParam {
        uint32_t id;
        int family;
        NetworkConfigSource source;
        struct iovec provider;
} NextHopParam;

static void nexthop_param_done(NextHopParam *p) {
        assert(p);

        iovec_done(&p->provider);
}

static int manager_deserialize_nexthop(Manager *manager, sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ID",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,             offsetof(NextHopParam, id),        SD_JSON_MANDATORY },
                { "Family",         _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family,        offsetof(NextHopParam, family),    SD_JSON_MANDATORY },
                { "ConfigSource",   SD_JSON_VARIANT_STRING,        json_dispatch_network_config_source, offsetof(NextHopParam, source),    SD_JSON_MANDATORY },
                { "ConfigProvider", SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(NextHopParam, provider),  0                 },
                {},
        };

        int r;

        assert(manager);
        assert(v);

        _cleanup_(nexthop_param_done) NextHopParam p = {};
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to dispatch nexthop from json variant: %m");

        if (p.id == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Dispatched nexthop ID is zero.");

        if (p.provider.iov_len != 0 && p.provider.iov_len != FAMILY_ADDRESS_SIZE(p.family))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched provider address size (%zu) is incompatible with the family (%s).",
                                       p.provider.iov_len, af_to_ipv4_ipv6(p.family));

        NextHop *nexthop;
        r = nexthop_get_by_id(manager, p.id, &nexthop);
        if (r < 0) {
                log_debug_errno(r, "Cannot find deserialized nexthop (ID=%"PRIu32"): %m", p.id);
                return 0; /* Already removed? */
        }

        if (nexthop->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                return 0; /* Huh?? Already deserialized?? */

        nexthop->source = p.source;
        memcpy_safe(&nexthop->provider, p.provider.iov_base, p.provider.iov_len);

        log_nexthop_debug(nexthop, "Deserialized", manager);
        return 0;
}

typedef struct RouteParam {
        Route route;

        struct iovec dst;
        struct iovec src;
        struct iovec prefsrc;
        struct iovec gw;
        struct iovec metrics;
        struct iovec provider;
} RouteParam;

static void route_param_done(RouteParam *p) {
        assert(p);

        free(p->route.metric.metrics);

        iovec_done(&p->dst);
        iovec_done(&p->src);
        iovec_done(&p->prefsrc);
        iovec_done(&p->gw);
        iovec_done(&p->metrics);
        iovec_done(&p->provider);
}

static int manager_deserialize_route(Manager *manager, sd_json_variant *v) {
        static const sd_json_dispatch_field dispatch_table[] = {
                /* rtmsg header */
                { "Family",                        _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family,        offsetof(RouteParam, route.family),                             SD_JSON_MANDATORY                 },
                { "DestinationPrefixLength",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(RouteParam, route.dst_prefixlen),                      SD_JSON_MANDATORY                 },
                { "SourcePrefixLength",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(RouteParam, route.src_prefixlen),                      0                                 },
                { "TOS",                           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(RouteParam, route.tos),                                SD_JSON_MANDATORY                 },
                { "Protocol",                      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(RouteParam, route.protocol),                           SD_JSON_MANDATORY                 },
                { "Scope",                         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(RouteParam, route.scope),                              SD_JSON_MANDATORY                 },
                { "Type",                          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,              offsetof(RouteParam, route.type),                               SD_JSON_MANDATORY                 },
                { "Flags",                         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,             offsetof(RouteParam, route.flags),                              SD_JSON_MANDATORY                 },
                /* attributes */
                { "Destination",                   SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(RouteParam, dst),                                      SD_JSON_MANDATORY                 },
                { "Source",                        SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(RouteParam, src),                                      0                                 },
                { "Priority",                      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,             offsetof(RouteParam, route.priority),                           SD_JSON_MANDATORY                 },
                { "PreferredSource",               SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(RouteParam, prefsrc),                                  0                                 },
                { "Table",                         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,             offsetof(RouteParam, route.table),                              SD_JSON_MANDATORY                 },
                /* nexthops */
                { "Gateway",                       SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(RouteParam, gw),                                       0                                 },
                { "InterfaceIndex",                _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,               offsetof(RouteParam, route.nexthop.ifindex),                    SD_JSON_MANDATORY | SD_JSON_RELAX },
                { "NextHopID",                     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,             offsetof(RouteParam, route.nexthop_id),                         0                                 },
                /* metrics */
                { "Metrics",                       SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(RouteParam, metrics),                                  0                                 },
                { "TCPCongestionControlAlgorithm", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,       offsetof(RouteParam, route.metric.tcp_congestion_control_algo), 0                                 },
                /* config */
                { "ConfigSource",                  SD_JSON_VARIANT_STRING,        json_dispatch_network_config_source, offsetof(RouteParam, route.source),                             SD_JSON_MANDATORY                 },
                { "ConfigProvider",                SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec,      offsetof(RouteParam, provider),                                 0                                 },
                {},
        };

        int r;

        assert(manager);
        assert(v);

        _cleanup_(route_param_done) RouteParam p = {};
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to dispatch route from json variant: %m");

        if (p.dst.iov_len != FAMILY_ADDRESS_SIZE(p.route.family))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched destination address size (%zu) is incompatible with the family (%s).",
                                       p.dst.iov_len, af_to_ipv4_ipv6(p.route.family));

        if (p.src.iov_len != 0 && p.src.iov_len != FAMILY_ADDRESS_SIZE(p.route.family))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched source address size (%zu) is incompatible with the family (%s).",
                                       p.src.iov_len, af_to_ipv4_ipv6(p.route.family));

        if (p.prefsrc.iov_len != 0 && p.prefsrc.iov_len != FAMILY_ADDRESS_SIZE(p.route.family))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched preferred source address size (%zu) is incompatible with the family (%s).",
                                       p.prefsrc.iov_len, af_to_ipv4_ipv6(p.route.family));

        switch (p.gw.iov_len) {
        case 0:
                p.route.nexthop.family = AF_UNSPEC;
                break;
        case sizeof(struct in_addr):
                p.route.nexthop.family = AF_INET;
                break;
        case sizeof(struct in6_addr):
                p.route.nexthop.family = AF_INET6;
                break;
        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched gateway address size (%zu) is invalid.",
                                       p.prefsrc.iov_len);
        }

        if (p.metrics.iov_len % sizeof(uint32_t) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched route metric size (%zu) is invalid.",
                                       p.metrics.iov_len);

        if (p.provider.iov_len != 0 && p.provider.iov_len != FAMILY_ADDRESS_SIZE(p.route.family))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Dispatched provider address size (%zu) is incompatible with the family (%s).",
                                       p.provider.iov_len, af_to_ipv4_ipv6(p.route.family));

        memcpy_safe(&p.route.dst, p.dst.iov_base, p.dst.iov_len);
        memcpy_safe(&p.route.src, p.src.iov_base, p.src.iov_len);
        memcpy_safe(&p.route.prefsrc, p.prefsrc.iov_base, p.prefsrc.iov_len);
        memcpy_safe(&p.route.nexthop.gw, p.gw.iov_base, p.gw.iov_len);

        p.route.metric.n_metrics = p.metrics.iov_len / sizeof(uint32_t);
        p.route.metric.metrics = new(uint32_t, p.route.metric.n_metrics);
        if (!p.route.metric.metrics)
                return log_oom_debug();

        memcpy_safe(p.route.metric.metrics, p.metrics.iov_base, p.metrics.iov_len);

        Route *route;
        r = route_get(manager, &p.route, &route);
        if (r < 0) {
                log_route_debug(&p.route, "Cannot find deserialized", manager);
                return 0; /* Already removed? */
        }

        if (route->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                return 0; /* Huh?? Already deserialized?? */

        route->source = p.route.source;
        memcpy_safe(&route->provider, p.provider.iov_base, p.provider.iov_len);

        log_route_debug(route, "Deserialized", manager);
        return 0;
}

int manager_deserialize(Manager *manager) {
        int r, ret = 0;

        assert(manager);

        _cleanup_close_ int fd = TAKE_FD(manager->serialization_fd);
        if (fd < 0)
                return 0;

        log_debug("Deserializing...");

        _cleanup_fclose_ FILE *f = take_fdopen(&fd, "r");
        if (!f)
                return log_debug_errno(errno, "Failed to fdopen() serialization file descriptor: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned err_line, err_column;
        r = sd_json_parse_file(
                        f,
                        /* path = */ NULL,
                        /* flags = */ 0,
                        &v,
                        &err_line,
                        &err_column);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse json (line=%u, column=%u): %m", err_line, err_column);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, sd_json_variant_by_key(v, "Interfaces"))
                RET_GATHER(ret, manager_deserialize_link(manager, i));

        JSON_VARIANT_ARRAY_FOREACH(i, sd_json_variant_by_key(v, "NextHops"))
                RET_GATHER(ret, manager_deserialize_nexthop(manager, i));

        JSON_VARIANT_ARRAY_FOREACH(i, sd_json_variant_by_key(v, "Routes"))
                RET_GATHER(ret, manager_deserialize_route(manager, i));

        log_debug("Deserialization completed.");
        return ret;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#include "conf-parser.h"
#include "alloc-util.h"
#include "extract-word.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "parse-util.h"
#include "vxlan.h"

static const char* const df_table[_NETDEV_VXLAN_DF_MAX] = {
        [NETDEV_VXLAN_DF_NO] = "no",
        [NETDEV_VXLAN_DF_YES] = "yes",
        [NETDEV_VXLAN_DF_INHERIT] = "inherit",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(df, VxLanDF, NETDEV_VXLAN_DF_YES);
DEFINE_CONFIG_PARSE_ENUM(config_parse_df, df, VxLanDF, "Failed to parse VXLAN IPDoNotFragment= setting");

static int vxlan_get_local_address(VxLan *v, Link *link, int *ret_family, union in_addr_union *ret_address) {
        assert(v);

        if (v->local_type < 0) {
                if (ret_family)
                        *ret_family = v->local_family;
                if (ret_address)
                        *ret_address = v->local;
                return 0;
        }

        return link_get_local_address(link, v->local_type, v->local_family, ret_family, ret_address);
}

static int netdev_vxlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        union in_addr_union local;
        int local_family, r;
        VxLan *v;

        assert(netdev);
        assert(m);

        v = VXLAN(netdev);

        assert(v);

        if (v->vni <= VXLAN_VID_MAX) {
                r = sd_netlink_message_append_u32(m, IFLA_VXLAN_ID, v->vni);
                if (r < 0)
                        return r;
        }

        if (in_addr_is_set(v->group_family, &v->group)) {
                if (v->group_family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, IFLA_VXLAN_GROUP, &v->group.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, IFLA_VXLAN_GROUP6, &v->group.in6);
                if (r < 0)
                        return r;
        } else if (in_addr_is_set(v->remote_family, &v->remote)) {
                if (v->remote_family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, IFLA_VXLAN_GROUP, &v->remote.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, IFLA_VXLAN_GROUP6, &v->remote.in6);
                if (r < 0)
                        return r;
        }

        r = vxlan_get_local_address(v, link, &local_family, &local);
        if (r < 0)
                return r;

        if (in_addr_is_set(local_family, &local)) {
                if (local_family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, IFLA_VXLAN_LOCAL, &local.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, IFLA_VXLAN_LOCAL6, &local.in6);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u32(m, IFLA_VXLAN_LINK, link ? link->ifindex : 0);
        if (r < 0)
                return r;

        if (v->inherit) {
                r = sd_netlink_message_append_flag(m, IFLA_VXLAN_TTL_INHERIT);
                if (r < 0)
                        return r;
        } else {
                r = sd_netlink_message_append_u8(m, IFLA_VXLAN_TTL, v->ttl);
                if (r < 0)
                        return r;
        }

        if (v->tos != 0) {
                r = sd_netlink_message_append_u8(m, IFLA_VXLAN_TOS, v->tos);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_LEARNING, v->learning);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_RSC, v->route_short_circuit);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_PROXY, v->arp_proxy);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_L2MISS, v->l2miss);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_L3MISS, v->l3miss);
        if (r < 0)
                return r;

        if (v->fdb_ageing != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_VXLAN_AGEING, v->fdb_ageing / USEC_PER_SEC);
                if (r < 0)
                        return r;
        }

        if (v->max_fdb != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_VXLAN_LIMIT, v->max_fdb);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_UDP_CSUM, v->udpcsum);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_UDP_ZERO_CSUM6_TX, v->udp6zerocsumtx);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_UDP_ZERO_CSUM6_RX, v->udp6zerocsumrx);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_REMCSUM_TX, v->remote_csum_tx);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_VXLAN_REMCSUM_RX, v->remote_csum_rx);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_VXLAN_PORT, htobe16(v->dest_port));
        if (r < 0)
                return r;

        if (v->port_range.low != 0 || v->port_range.high != 0) {
                struct ifla_vxlan_port_range port_range;

                port_range.low = htobe16(v->port_range.low);
                port_range.high = htobe16(v->port_range.high);

                r = sd_netlink_message_append_data(m, IFLA_VXLAN_PORT_RANGE, &port_range, sizeof(port_range));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u32(m, IFLA_VXLAN_LABEL, htobe32(v->flow_label));
        if (r < 0)
                return r;

        if (v->group_policy) {
                r = sd_netlink_message_append_flag(m, IFLA_VXLAN_GBP);
                if (r < 0)
                        return r;
        }

        if (v->generic_protocol_extension) {
                r = sd_netlink_message_append_flag(m, IFLA_VXLAN_GPE);
                if (r < 0)
                        return r;
        }

        if (v->df != _NETDEV_VXLAN_DF_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_VXLAN_DF, v->df);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_vxlan_address(
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

        VxLan *v = ASSERT_PTR(userdata);
        union in_addr_union *addr = data, buffer;
        int *family, f, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(lvalue, "Local"))
                family = &v->local_family;
        else if (streq(lvalue, "Remote"))
                family = &v->remote_family;
        else if (streq(lvalue, "Group"))
                family = &v->group_family;
        else
                assert_not_reached();

        if (isempty(rvalue)) {
                *addr = IN_ADDR_NULL;
                *family = AF_UNSPEC;
                return 0;
        }

        if (streq(lvalue, "Local")) {
                NetDevLocalAddressType t;

                t = netdev_local_address_type_from_string(rvalue);
                if (t >= 0) {
                        v->local = IN_ADDR_NULL;
                        v->local_family = AF_UNSPEC;
                        v->local_type = t;
                        return 0;
                }
        }

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        r = in_addr_is_multicast(f, &buffer);

        if (streq(lvalue, "Group")) {
                if (r <= 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "%s= must be a multicast address, ignoring assignment: %s", lvalue, rvalue);
                        return 0;
                }
        } else {
                if (r > 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "%s= cannot be a multicast address, ignoring assignment: %s", lvalue, rvalue);
                        return 0;
                }
        }

        if (streq(lvalue, "Local"))
                v->local_type = _NETDEV_LOCAL_ADDRESS_TYPE_INVALID;
        *addr = buffer;
        *family = f;

        return 0;
}

int config_parse_port_range(
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

        VxLan *v = userdata;
        uint16_t low, high;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_ip_port_range(rvalue, &low, &high);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse VXLAN port range '%s'. Port should be greater than 0 and less than 65535.", rvalue);
                return 0;
        }

        v->port_range.low = low;
        v->port_range.high = high;

        return 0;
}

int config_parse_flow_label(
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

        VxLan *v = userdata;
        unsigned f;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou(rvalue, &f);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse VXLAN flow label '%s'.", rvalue);
                return 0;
        }

        if (f & ~VXLAN_FLOW_LABEL_MAX_MASK) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "VXLAN flow label '%s' not valid. Flow label range should be [0-1048575].", rvalue);
                return 0;
        }

        v->flow_label = f;

        return 0;
}

int config_parse_vxlan_ttl(
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

        VxLan *v = userdata;
        unsigned f;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "inherit"))
                v->inherit = true;
        else {
                r = safe_atou(rvalue, &f);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse VXLAN TTL '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }

                if (f > 255) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid VXLAN TTL '%s'. TTL must be <= 255. Ignoring assignment.", rvalue);
                        return 0;
                }

                v->ttl = f;
        }

        return 0;
}

static int netdev_vxlan_verify(NetDev *netdev, const char *filename) {
        VxLan *v = VXLAN(netdev);

        assert(netdev);
        assert(v);
        assert(filename);

        if (v->vni > VXLAN_VID_MAX)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: VXLAN without valid VNI (or VXLAN Segment ID) configured. Ignoring.",
                                                filename);

        if (v->ttl > 255)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: VXLAN TTL must be <= 255. Ignoring.",
                                                filename);

        if (!v->dest_port && v->generic_protocol_extension)
                v->dest_port = 4790;

        if (in_addr_is_set(v->group_family, &v->group) && in_addr_is_set(v->remote_family, &v->remote))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: VXLAN both 'Group=' and 'Remote=' cannot be specified. Ignoring.",
                                                filename);

        if (v->independent && v->local_type >= 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "The local address cannot be '%s' when Independent= is enabled, ignoring.",
                                              strna(netdev_local_address_type_to_string(v->local_type)));

        return 0;
}

static int netdev_vxlan_is_ready_to_create(NetDev *netdev, Link *link) {
        VxLan *v;

        assert(netdev);

        v = VXLAN(netdev);

        assert(v);

        if (v->independent)
                return true;

        return vxlan_get_local_address(v, link, NULL, NULL) >= 0;
}

static void vxlan_init(NetDev *netdev) {
        VxLan *v;

        assert(netdev);

        v = VXLAN(netdev);

        assert(v);

        v->local_type = _NETDEV_LOCAL_ADDRESS_TYPE_INVALID;
        v->vni = VXLAN_VID_MAX + 1;
        v->df = _NETDEV_VXLAN_DF_INVALID;
        v->learning = true;
        v->udpcsum = false;
        v->udp6zerocsumtx = false;
        v->udp6zerocsumrx = false;
}

const NetDevVTable vxlan_vtable = {
        .object_size = sizeof(VxLan),
        .init = vxlan_init,
        .sections = NETDEV_COMMON_SECTIONS "VXLAN\0",
        .fill_message_create = netdev_vxlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .is_ready_to_create = netdev_vxlan_is_ready_to_create,
        .config_verify = netdev_vxlan_verify,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};

/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <linux/l2tp.h>
#include <linux/genetlink.h>

#include "sd-netlink.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "l2tp-tunnel.h"
#include "missing.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static const char* const l2tp_l2spec_type_table[_NETDEV_L2TP_L2SPECTYPE_MAX] = {
        [NETDEV_L2TP_L2SPECTYPE_NONE]    = "none",
        [NETDEV_L2TP_L2SPECTYPE_DEFAULT] = "default",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(l2tp_l2spec_type, L2tpL2specType);

static const char* const l2tp_encap_type_table[_NETDEV_L2TP_ENCAPTYPE_MAX] = {
        [NETDEV_L2TP_ENCAPTYPE_UDP] = "udp",
        [NETDEV_L2TP_ENCAPTYPE_IP]  = "ip",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(l2tp_encap_type, L2tpEncapType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_l2tp_encap_type, l2tp_encap_type, L2tpEncapType, "Failed to parse L2TP Encapsulation Type");

static const char* const l2tp_local_address_type_table[_NETDEV_L2TP_LOCAL_ADDRESS_MAX] = {
         [NETDEV_L2TP_LOCAL_ADDRESS_AUTO]    = "auto",
         [NETDEV_L2TP_LOCAL_ADDRESS_STATIC]  = "static",
         [NETDEV_L2TP_LOCAL_ADDRESS_DYNAMIC] = "dynamic",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(l2tp_local_address_type, L2tpLocalAddressType);

static void l2tp_session_free(L2tpSession *s) {
        if (!s)
                return;

        if (s->tunnel && s->section)
                ordered_hashmap_remove(s->tunnel->sessions_by_section, s);

        network_config_section_free(s->section);

        free(s->name);

        free(s);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(L2tpSession, l2tp_session_free);

static int l2tp_session_new_static(L2tpTunnel *t, const char *filename, unsigned section_line, L2tpSession **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(l2tp_session_freep) L2tpSession *s = NULL;
        int r;

        assert(t);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        s = ordered_hashmap_get(t->sessions_by_section, n);
        if (s) {
                *ret = TAKE_PTR(s);
                return 0;
        }

        s = new(L2tpSession, 1);
        if (!s)
                return -ENOMEM;

        *s = (L2tpSession) {
                .l2tp_l2spec_type = NETDEV_L2TP_L2SPECTYPE_DEFAULT,
                .tunnel = t,
                .section = TAKE_PTR(n),
        };

        r = ordered_hashmap_ensure_allocated(&t->sessions_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = ordered_hashmap_put(t->sessions_by_section, s->section, s);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

static int netdev_l2tp_fill_message_tunnel(NetDev *netdev, union in_addr_union *local_address, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t encap_type;
        L2tpTunnel *t;
        int r;

        assert(netdev);
        assert(local_address);

        t = L2TP(netdev);

        assert(t);

        r = sd_genl_message_new(netdev->manager->genl, SD_GENL_L2TP, L2TP_CMD_TUNNEL_CREATE, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_CONN_ID, t->tunnel_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_CONN_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_CONN_ID, t->peer_tunnel_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PEER_CONN_ID attribute: %m");

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_PROTO_VERSION, 3);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PROTO_VERSION attribute: %m");

        switch(t->l2tp_encap_type) {
        case NETDEV_L2TP_ENCAPTYPE_IP:
                encap_type = L2TP_ENCAPTYPE_IP;
                break;
        case NETDEV_L2TP_ENCAPTYPE_UDP:
        default:
                encap_type = L2TP_ENCAPTYPE_UDP;
                break;
        }

        r = sd_netlink_message_append_u16(m, L2TP_ATTR_ENCAP_TYPE, encap_type);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_ENCAP_TYPE attribute: %m");

        if (t->family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, L2TP_ATTR_IP_SADDR, &local_address->in);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IP_SADDR attribute: %m");

                r = sd_netlink_message_append_in_addr(m, L2TP_ATTR_IP_DADDR, &t->remote.in);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IP_DADDR attribute: %m");
        } else {
                r = sd_netlink_message_append_in6_addr(m, L2TP_ATTR_IP6_SADDR, &local_address->in6);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IP6_SADDR attribute: %m");

                r = sd_netlink_message_append_in6_addr(m, L2TP_ATTR_IP6_DADDR, &t->remote.in6);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IP6_DADDR attribute: %m");
        }

        if (encap_type == L2TP_ENCAPTYPE_UDP) {
                r = sd_netlink_message_append_u16(m, L2TP_ATTR_UDP_SPORT, t->l2tp_udp_sport);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_UDP_SPORT, attribute: %m");

                r = sd_netlink_message_append_u16(m, L2TP_ATTR_UDP_DPORT, t->l2tp_udp_dport);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_UDP_DPORT attribute: %m");

                if (t->udp_csum) {
                        r = sd_netlink_message_append_u8(m, L2TP_ATTR_UDP_CSUM, t->udp_csum);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_UDP_CSUM attribute: %m");
                }

                if (t->udp6_csum_tx) {
                        r = sd_netlink_message_append_flag(m, L2TP_ATTR_UDP_ZERO_CSUM6_TX);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_UDP_ZERO_CSUM6_TX attribute: %m");
                }

                if (t->udp6_csum_rx) {
                        r = sd_netlink_message_append_flag(m, L2TP_ATTR_UDP_ZERO_CSUM6_RX);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_UDP_ZERO_CSUM6_RX attribute: %m");
                }
        }

        *ret = TAKE_PTR(m);

        return 0;
}

static int netdev_l2tp_fill_message_session(NetDev *netdev, L2tpSession *session, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t l2_spec_len;
        uint8_t l2_spec_type;
        int r;

        assert(netdev);
        assert(session);
        assert(session->tunnel);

        r = sd_genl_message_new(netdev->manager->genl, SD_GENL_L2TP, L2TP_CMD_SESSION_CREATE, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_CONN_ID, session->tunnel->tunnel_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_CONN_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_CONN_ID, session->tunnel->peer_tunnel_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PEER_CONN_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_SESSION_ID, session->session_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_SESSION_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_SESSION_ID, session->peer_session_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PEER_SESSION_ID attribute: %m");

        r = sd_netlink_message_append_u16(m, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PW_TYPE attribute: %m");

        switch (session->l2tp_l2spec_type) {
        case NETDEV_L2TP_L2SPECTYPE_NONE:
                l2_spec_type = L2TP_L2SPECTYPE_NONE;
                l2_spec_len = 0;
                break;
        case NETDEV_L2TP_L2SPECTYPE_DEFAULT:
        default:
                l2_spec_type = L2TP_L2SPECTYPE_DEFAULT;
                l2_spec_len = 4;
                break;
        }

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_L2SPEC_TYPE, l2_spec_type);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_L2SPEC_TYPE attribute: %m");

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_L2SPEC_LEN, l2_spec_len);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_L2SPEC_LEN attribute: %m");

        r = sd_netlink_message_append_string(m, L2TP_ATTR_IFNAME, session->name);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IFNAME attribute: %m");

        *ret = TAKE_PTR(m);

        return 0;
}

static int l2tp_acquire_local_address_one(L2tpTunnel *t, Address *a, union in_addr_union *ret) {
        if (a->family != t->family)
                return -EINVAL;

        if (in_addr_is_null(a->family, &a->in_addr_peer) <= 0)
                return -EINVAL;

        if (t->local_address_type == NETDEV_L2TP_LOCAL_ADDRESS_STATIC &&
            !FLAGS_SET(a->flags, IFA_F_PERMANENT))
                return -EINVAL;

        if (t->local_address_type == NETDEV_L2TP_LOCAL_ADDRESS_DYNAMIC &&
            FLAGS_SET(a->flags, IFA_F_PERMANENT))
                return -EINVAL;

        *ret = a->in_addr;
        return 0;
}

static int l2tp_acquire_local_address(L2tpTunnel *t, Link *link, union in_addr_union *ret) {
        Address *a;
        Iterator i;

        assert(t);
        assert(link);
        assert(ret);
        assert(IN_SET(t->family, AF_INET, AF_INET6));

        if (!in_addr_is_null(t->family, &t->local)) {
                /* local address is explicitly specified. */
                *ret = t->local;
                return 0;
        }

        SET_FOREACH(a, link->addresses, i)
                if (l2tp_acquire_local_address_one(t, a, ret) >= 0)
                        return 1;

        SET_FOREACH(a, link->addresses_foreign, i)
                if (l2tp_acquire_local_address_one(t, a, ret) >= 0)
                        return 1;

        return -ENODATA;
}

static void l2tp_session_destroy_callback(L2tpSession *session) {
        if (!session)
                return;

        netdev_unref(NETDEV(session->tunnel));
}

static int l2tp_create_session_handler(sd_netlink *rtnl, sd_netlink_message *m, L2tpSession *session) {
        NetDev *netdev;
        int r;

        assert(session);
        assert(session->tunnel);

        netdev = NETDEV(session->tunnel);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev, "L2TP session %s exists, using existing without changing its parameters",
                                session->name);
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "L2TP session %s could not be created: %m", session->name);
                return 1;
        }

        log_netdev_debug(netdev, "L2TP session %s created", session->name);
        return 1;
}

static int l2tp_create_session(NetDev *netdev, L2tpSession *session) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *n = NULL;
        int r;

        r = netdev_l2tp_fill_message_session(netdev, session, &n);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->genl, NULL, n, l2tp_create_session_handler,
                               l2tp_session_destroy_callback, session);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create L2TP session %s: %m", session->name);

        netdev_ref(netdev);
        return 0;
}

static int l2tp_create_tunnel_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        L2tpSession *session;
        L2tpTunnel *t;
        Iterator i;
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        t = L2TP(netdev);

        assert(t);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev, "netdev exists, using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "netdev could not be created: %m");
                netdev_drop(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "L2TP tunnel is created");

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section, i)
                (void) l2tp_create_session(netdev, session);

        return 1;
}

static int l2tp_create_tunnel(NetDev *netdev, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        union in_addr_union local_address;
        L2tpTunnel *t;
        int r;

        assert(netdev);

        t = L2TP(netdev);

        assert(t);

        r = l2tp_acquire_local_address(t, link, &local_address);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address.");

        if (r > 0 && DEBUG_LOGGING) {
                _cleanup_free_ char *str = NULL;

                (void) in_addr_to_string(t->family, &local_address, &str);
                log_netdev_debug(netdev, "Local address %s acquired.", strna(str));
        }

        r = netdev_l2tp_fill_message_tunnel(netdev, &local_address, &m);
        if (r < 0)
                return r;

        r = netlink_call_async(netdev->manager->genl, NULL, m, l2tp_create_tunnel_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create L2TP tunnel: %m");

        netdev_ref(netdev);

        return 0;
}

int config_parse_l2tp_tunnel_address(
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

        L2tpTunnel *t = userdata;
        union in_addr_union *addr = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(lvalue, "Local")) {
                L2tpLocalAddressType addr_type;

                if (isempty(rvalue))
                        addr_type = NETDEV_L2TP_LOCAL_ADDRESS_AUTO;
                else
                        addr_type = l2tp_local_address_type_from_string(rvalue);

                if (addr_type >= 0) {
                        if (in_addr_is_null(t->family, &t->remote) != 0)
                                /* If Remote= is not specified yet, then also clear family. */
                                t->family = AF_UNSPEC;

                        t->local = IN_ADDR_NULL;
                        t->local_address_type = addr_type;

                        return 0;
                }
        }

        if (t->family == AF_UNSPEC)
                r = in_addr_from_string_auto(rvalue, &t->family, addr);
        else
                r = in_addr_from_string(t->family, rvalue, addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid L2TP Tunnel address specified in %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        return 0;
}

int config_parse_l2tp_tunnel_id(
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

        uint32_t *id = data, k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse L2TP tunnel id. Ignoring assignment: %s", rvalue);
                return 0;
        }

        if (k == 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid L2TP tunnel id. Ignoring assignment: %s", rvalue);
                return 0;
        }

        *id = k;

        return 0;
}

int config_parse_l2tp_session_id(
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

        _cleanup_(l2tp_session_free_or_set_invalidp) L2tpSession *session = NULL;
        L2tpTunnel *t = userdata;
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = l2tp_session_new_static(t, filename, section_line, &session);
        if (r < 0)
                return r;

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse L2TP session id. Ignoring assignment: %s", rvalue);
                return 0;
        }

        if (k == 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid L2TP session id. Ignoring assignment: %s", rvalue);
                return 0;
        }

        if (streq(lvalue, "SessionId"))
                session->session_id = k;
        else
                session->peer_session_id = k;

        session = NULL;
        return 0;
}

int config_parse_l2tp_session_l2spec(
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

        _cleanup_(l2tp_session_free_or_set_invalidp) L2tpSession *session = NULL;
        L2tpTunnel *t = userdata;
        L2tpL2specType spec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = l2tp_session_new_static(t, filename, section_line, &session);
        if (r < 0)
                return r;

        spec = l2tp_l2spec_type_from_string(rvalue);
        if (spec < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Failed to parse layer2 specific header type. Ignoring assignment: %s", rvalue);
                return 0;
        }

        session->l2tp_l2spec_type = spec;

        session = NULL;
        return 0;
}

int config_parse_l2tp_session_name(
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

        _cleanup_(l2tp_session_free_or_set_invalidp) L2tpSession *session = NULL;
        L2tpTunnel *t = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = l2tp_session_new_static(t, filename, section_line, &session);
        if (r < 0)
                return r;

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Failed to parse L2TP tunnel session name. Ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup(&session->name, rvalue);
        if (r < 0)
                return log_oom();

        session = NULL;
        return 0;
}

static void l2tp_tunnel_init(NetDev *netdev) {
        L2tpTunnel *t;

        assert(netdev);

        t = L2TP(netdev);

        assert(t);

        t->l2tp_encap_type = NETDEV_L2TP_ENCAPTYPE_UDP;
        t->udp6_csum_rx = true;
        t->udp6_csum_tx = true;
}

static int l2tp_session_verify(L2tpSession *session) {
        NetDev *netdev;

        assert(session);
        assert(session->tunnel);

        netdev = NETDEV(session->tunnel);

        if (section_is_invalid(session->section))
                return -EINVAL;

        if (!session->name)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: L2TP session without name configured. "
                                              "Ignoring [L2TPSession] section from line %u",
                                              session->section->filename, session->section->line);

        if (session->session_id == 0 || session->peer_session_id == 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: L2TP session without session IDs configured. "
                                              "Ignoring [L2TPSession] section from line %u",
                                              session->section->filename, session->section->line);

        return 0;
}

static int netdev_l2tp_tunnel_verify(NetDev *netdev, const char *filename) {
        L2tpTunnel *t;
        L2tpSession *session;
        Iterator i;

        assert(netdev);
        assert(filename);

        t = L2TP(netdev);

        assert(t);

        if (!IN_SET(t->family, AF_INET, AF_INET6))
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: L2TP tunnel with invalid address family configured. Ignoring",
                                              filename);

        if (in_addr_is_null(t->family, &t->remote))
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: L2TP tunnel without a remote address configured. Ignoring",
                                              filename);

        if (t->tunnel_id == 0 || t->peer_tunnel_id == 0)
                return log_netdev_error_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s: L2TP tunnel without tunnel IDs configured. Ignoring",
                                              filename);

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section, i)
                if (l2tp_session_verify(session) < 0)
                        l2tp_session_free(session);

        return 0;
}

static void l2tp_tunnel_done(NetDev *netdev) {
        L2tpTunnel *t;

        assert(netdev);

        t = L2TP(netdev);

        assert(t);

        ordered_hashmap_free_with_destructor(t->sessions_by_section, l2tp_session_free);
}

const NetDevVTable l2tptnl_vtable = {
        .object_size = sizeof(L2tpTunnel),
        .init = l2tp_tunnel_init,
        .sections = "Match\0NetDev\0L2TP\0L2TPSession\0",
        .create_after_configured = l2tp_create_tunnel,
        .done = l2tp_tunnel_done,
        .create_type = NETDEV_CREATE_AFTER_CONFIGURED,
        .config_verify = netdev_l2tp_tunnel_verify,
};

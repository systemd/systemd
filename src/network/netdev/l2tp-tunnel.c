/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/l2tp.h>
#include <linux/genetlink.h>

#include "conf-parser.h"
#include "hashmap.h"
#include "l2tp-tunnel.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"

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
DEFINE_CONFIG_PARSE_ENUM(config_parse_l2tp_encap_type, l2tp_encap_type, L2tpEncapType);

static const char* const l2tp_local_address_type_table[_NETDEV_L2TP_LOCAL_ADDRESS_MAX] = {
         [NETDEV_L2TP_LOCAL_ADDRESS_AUTO]    = "auto",
         [NETDEV_L2TP_LOCAL_ADDRESS_STATIC]  = "static",
         [NETDEV_L2TP_LOCAL_ADDRESS_DYNAMIC] = "dynamic",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(l2tp_local_address_type, L2tpLocalAddressType);

static L2tpSession* l2tp_session_free(L2tpSession *s) {
        if (!s)
                return NULL;

        if (s->tunnel && s->section)
                ordered_hashmap_remove(s->tunnel->sessions_by_section, s->section);

        config_section_free(s->section);
        free(s->name);
        return mfree(s);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(L2tpSession, l2tp_session_free);

static int l2tp_session_new_static(L2tpTunnel *t, const char *filename, unsigned section_line, L2tpSession **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(l2tp_session_freep) L2tpSession *s = NULL;
        int r;

        assert(t);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
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

        r = ordered_hashmap_ensure_put(&t->sessions_by_section, &config_section_hash_ops, s->section, s);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

static int netdev_l2tp_create_message_tunnel(NetDev *netdev, union in_addr_union *local_address, sd_netlink_message **ret) {
        assert(local_address);
        assert(netdev);
        assert(netdev->manager);

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t encap_type;
        L2tpTunnel *t = L2TP(netdev);
        int r;

        r = sd_genl_message_new(netdev->manager->genl, L2TP_GENL_NAME, L2TP_CMD_TUNNEL_CREATE, &m);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_CONN_ID, t->tunnel_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_CONN_ID, t->peer_tunnel_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_PROTO_VERSION, 3);
        if (r < 0)
                return r;

        switch (t->l2tp_encap_type) {
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
                return r;

        if (t->family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, L2TP_ATTR_IP_SADDR, &local_address->in);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_in_addr(m, L2TP_ATTR_IP_DADDR, &t->remote.in);
                if (r < 0)
                        return r;
        } else {
                r = sd_netlink_message_append_in6_addr(m, L2TP_ATTR_IP6_SADDR, &local_address->in6);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_in6_addr(m, L2TP_ATTR_IP6_DADDR, &t->remote.in6);
                if (r < 0)
                        return r;
        }

        if (encap_type == L2TP_ENCAPTYPE_UDP) {
                r = sd_netlink_message_append_u16(m, L2TP_ATTR_UDP_SPORT, t->l2tp_udp_sport);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u16(m, L2TP_ATTR_UDP_DPORT, t->l2tp_udp_dport);
                if (r < 0)
                        return r;

                if (t->udp_csum) {
                        r = sd_netlink_message_append_u8(m, L2TP_ATTR_UDP_CSUM, t->udp_csum);
                        if (r < 0)
                                return r;
                }

                if (t->udp6_csum_tx) {
                        r = sd_netlink_message_append_flag(m, L2TP_ATTR_UDP_ZERO_CSUM6_TX);
                        if (r < 0)
                                return r;
                }

                if (t->udp6_csum_rx) {
                        r = sd_netlink_message_append_flag(m, L2TP_ATTR_UDP_ZERO_CSUM6_RX);
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(m);

        return 0;
}

static int netdev_l2tp_create_message_session(NetDev *netdev, L2tpSession *session, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t l2_spec_len;
        uint8_t l2_spec_type;
        int r;

        assert(netdev);
        assert(netdev->manager);
        assert(session);
        assert(session->tunnel);

        r = sd_genl_message_new(netdev->manager->genl, L2TP_GENL_NAME, L2TP_CMD_SESSION_CREATE, &m);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_CONN_ID, session->tunnel->tunnel_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_CONN_ID, session->tunnel->peer_tunnel_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_SESSION_ID, session->session_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_SESSION_ID, session->peer_session_id);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
        if (r < 0)
                return r;

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
                return r;

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_L2SPEC_LEN, l2_spec_len);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, L2TP_ATTR_IFNAME, session->name);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static int link_get_l2tp_local_address(Link *link, L2tpTunnel *t, union in_addr_union *ret) {
        Address *a;

        assert(link);
        assert(t);

        SET_FOREACH(a, link->addresses) {
                if (!address_is_ready(a))
                        continue;

                if (a->family != t->family)
                        continue;

                if (in_addr_is_set(a->family, &a->in_addr_peer))
                        continue;

                if (t->local_address_type == NETDEV_L2TP_LOCAL_ADDRESS_STATIC &&
                    !FLAGS_SET(a->flags, IFA_F_PERMANENT))
                        continue;

                if (t->local_address_type == NETDEV_L2TP_LOCAL_ADDRESS_DYNAMIC &&
                    FLAGS_SET(a->flags, IFA_F_PERMANENT))
                        continue;

                if (ret)
                        *ret = a->in_addr;
        }

        return -ENOENT;
}

static int l2tp_get_local_address(NetDev *netdev, union in_addr_union *ret) {
        Link *link = NULL;
        L2tpTunnel *t = L2TP(netdev);
        Address *a = NULL;
        int r;

        assert(netdev->manager);

        if (t->local_ifname) {
                r = link_get_by_name(netdev->manager, t->local_ifname, &link);
                if (r < 0)
                        return r;

                if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                        return -EBUSY;
        }

        if (netdev->manager->manage_foreign_routes) {
                /* First, check if the remote address is accessible. */
                if (link)
                        r = link_address_is_reachable(link, t->family, &t->remote, &t->local, &a);
                else
                        r = manager_address_is_reachable(netdev->manager, t->family, &t->remote, &t->local, &a);
                if (r < 0)
                        return r;
        }

        if (in_addr_is_set(t->family, &t->local)) {
                /* local address is explicitly specified. */

                if (!a) {
                        if (link)
                                r = link_get_address(link, t->family, &t->local, &a);
                        else
                                r = manager_get_address(netdev->manager, t->family, &t->local, &a);
                        if (r < 0)
                                return r;

                        if (!address_is_ready(a))
                                return -EBUSY;
                }

                if (ret)
                        *ret = a->in_addr;

                return 0;
        }

        if (a) {
                if (t->local_address_type == NETDEV_L2TP_LOCAL_ADDRESS_STATIC &&
                    !FLAGS_SET(a->flags, IFA_F_PERMANENT))
                        return -EINVAL;

                if (t->local_address_type == NETDEV_L2TP_LOCAL_ADDRESS_DYNAMIC &&
                    FLAGS_SET(a->flags, IFA_F_PERMANENT))
                        return -EINVAL;

                if (ret)
                        *ret = a->in_addr;

                return 0;
        }

        if (link)
                return link_get_l2tp_local_address(link, t, ret);

        HASHMAP_FOREACH(link, netdev->manager->links_by_index) {
                if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                        continue;

                if (link_get_l2tp_local_address(link, t, ret) >= 0)
                        return 0;
        }

        return -ENOENT;
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

        assert(netdev);

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        r = netdev_l2tp_create_message_session(netdev, session, &n);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, n, l2tp_create_session_handler,
                               l2tp_session_destroy_callback, session);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create L2TP session %s: %m", session->name);

        netdev_ref(netdev);
        return 0;
}

static int l2tp_create_tunnel_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        L2tpSession *session;
        L2tpTunnel *t = L2TP(netdev);
        int r;

        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev, "netdev exists, using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "netdev could not be created: %m");
                netdev_enter_failed(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "L2TP tunnel is created");

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section)
                (void) l2tp_create_session(netdev, session);

        return 1;
}

static int l2tp_create_tunnel(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        union in_addr_union local_address;
        L2tpTunnel *t = L2TP(netdev);
        int r;

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        r = l2tp_get_local_address(netdev, &local_address);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not find local address.");

        if (t->local_address_type >= 0 && DEBUG_LOGGING)
                log_netdev_debug(netdev, "Local address %s acquired.",
                                 IN_ADDR_TO_STRING(t->family, &local_address));

        r = netdev_l2tp_create_message_tunnel(netdev, &local_address, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create netlink message: %m");

        r = netlink_call_async(netdev->manager->genl, NULL, m, l2tp_create_tunnel_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create L2TP tunnel: %m");

        netdev_ref(netdev);

        return 0;
}

static int netdev_l2tp_is_ready_to_create(NetDev *netdev, Link *link) {
        return l2tp_get_local_address(netdev, NULL) >= 0;
}

int config_parse_l2tp_tunnel_local_address(
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

        _cleanup_free_ char *addr_or_type = NULL, *ifname = NULL;
        L2tpLocalAddressType type;
        L2tpTunnel *t = ASSERT_PTR(userdata);
        const char *p = ASSERT_PTR(rvalue);
        union in_addr_union a;
        int r, f;

        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                t->local_ifname = mfree(t->local_ifname);
                t->local_address_type = NETDEV_L2TP_LOCAL_ADDRESS_AUTO;
                t->local = IN_ADDR_NULL;

                if (!in_addr_is_set(t->family, &t->remote))
                        /* If Remote= is not specified yet, then also clear family. */
                        t->family = AF_UNSPEC;

                return 0;
        }

        r = extract_first_word(&p, &addr_or_type, "@", 0);
        if (r < 0)
                return log_oom();
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid L2TP Tunnel address specified in %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (!isempty(p)) {
                if (!ifname_valid_full(p, IFNAME_VALID_ALTERNATIVE)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid interface name specified in %s=, ignoring assignment: %s", lvalue, rvalue);
                        return 0;
                }

                ifname = strdup(p);
                if (!ifname)
                        return log_oom();
        }

        type = l2tp_local_address_type_from_string(addr_or_type);
        if (type >= 0) {
                free_and_replace(t->local_ifname, ifname);
                t->local_address_type = type;
                t->local = IN_ADDR_NULL;

                if (!in_addr_is_set(t->family, &t->remote))
                        /* If Remote= is not specified yet, then also clear family. */
                        t->family = AF_UNSPEC;

                return 0;
        }

        r = in_addr_from_string_auto(addr_or_type, &f, &a);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid L2TP Tunnel local address \"%s\" specified, ignoring assignment: %s", addr_or_type, rvalue);
                return 0;
        }

        if (in_addr_is_null(f, &a)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "L2TP Tunnel local address cannot be null, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (t->family != AF_UNSPEC && t->family != f) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Address family does not match the previous assignment, ignoring assignment: %s", rvalue);
                return 0;
        }

        t->family = f;
        t->local = a;
        free_and_replace(t->local_ifname, ifname);
        t->local_address_type = _NETDEV_L2TP_LOCAL_ADDRESS_INVALID;
        return 0;
}

int config_parse_l2tp_tunnel_remote_address(
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

        L2tpTunnel *t = ASSERT_PTR(userdata);
        union in_addr_union a;
        int r, f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                t->remote = IN_ADDR_NULL;

                if (!in_addr_is_set(t->family, &t->local))
                        /* If Local= is not specified yet, then also clear family. */
                        t->family = AF_UNSPEC;

                return 0;
        }

        r = in_addr_from_string_auto(rvalue, &f, &a);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid L2TP Tunnel remote address specified, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(f, &a)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "L2TP Tunnel remote address cannot be null, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (t->family != AF_UNSPEC && t->family != f) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Address family does not match the previous assignment, ignoring assignment: %s", rvalue);
                return 0;
        }

        t->family = f;
        t->remote = a;
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        uint32_t *id = ASSERT_PTR(data);

        return config_parse_uint32_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        1, UINT32_MAX, true,
                        id);
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

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        L2tpTunnel *t = ASSERT_PTR(userdata);
        _cleanup_(l2tp_session_free_or_set_invalidp) L2tpSession *session = NULL;
        int r;

        r = l2tp_session_new_static(t, filename, section_line, &session);
        if (r < 0)
                return log_oom();

        uint32_t *id = streq(lvalue, "SessionId") ? &session->session_id : &session->peer_session_id;

        r = config_parse_uint32_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        1, UINT32_MAX, true,
                        id);
        if (r <= 0)
                return r;
        TAKE_PTR(session);
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
                return log_oom();

        spec = l2tp_l2spec_type_from_string(rvalue);
        if (spec < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, spec,
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
                return log_oom();

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
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
        L2tpTunnel *t = L2TP(netdev);

        t->l2tp_encap_type = NETDEV_L2TP_ENCAPTYPE_UDP;
        t->udp6_csum_rx = true;
        t->udp6_csum_tx = true;
}

#define log_session(session, fmt, ...)                                  \
        ({                                                              \
                const L2tpSession *_session = (session);                \
                log_section_warning_errno(                              \
                                _session ? _session->section : NULL,    \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [L2TPSession] section.", \
                                ##__VA_ARGS__);                         \
        })

static int l2tp_session_verify(L2tpSession *session, Set **names) {
        int r;

        assert(session);
        assert(session->tunnel);
        assert(names);

        if (section_is_invalid(session->section))
                return -EINVAL;

        if (!session->name)
                return log_session(session, "L2TP session without name configured.");

        if (session->session_id == 0 || session->peer_session_id == 0)
                return log_session(session, "L2TP session without session IDs configured.");

        if (streq(session->name, NETDEV(session->tunnel)->ifname))
                return log_session(session, "L2TP session name %s cannot be the same as the netdev name.", session->name);

        r = set_ensure_put(names, &string_hash_ops, session->name);
        if (r < 0)
                return log_oom();
        if (r == 0)
                return log_session(session, "L2TP session name %s is duplicated.", session->name);

        return 0;
}

static int netdev_l2tp_tunnel_verify(NetDev *netdev, const char *filename) {
        assert(filename);

        L2tpTunnel *t = L2TP(netdev);
        L2tpSession *session;

        if (!IN_SET(t->family, AF_INET, AF_INET6))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: L2TP tunnel with invalid address family configured. Ignoring",
                                                filename);

        if (!in_addr_is_set(t->family, &t->remote))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: L2TP tunnel without a remote address configured. Ignoring",
                                                filename);

        if (t->tunnel_id == 0 || t->peer_tunnel_id == 0)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: L2TP tunnel without tunnel IDs configured. Ignoring",
                                                filename);

        _cleanup_set_free_ Set *names = NULL;
        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section)
                if (l2tp_session_verify(session, &names) < 0)
                        l2tp_session_free(session);

        return 0;
}

static int netdev_l2tp_tunnel_attach(NetDev *netdev) {
        L2tpTunnel *t = L2TP(netdev);
        L2tpSession *session;
        int r;

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section) {
                assert(session->name);

                r = netdev_attach_name(netdev, session->name);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void netdev_l2tp_tunnel_detach(NetDev *netdev) {
        L2tpTunnel *t = L2TP(netdev);
        L2tpSession *session;

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section)
                netdev_detach_name(netdev, session->name);
}

static int netdev_l2tp_tunnel_set_ifindex(NetDev *netdev, const char *name, int ifindex) {
        L2tpTunnel *t = L2TP(netdev);
        L2tpSession *session;
        bool found = false;

        assert(name);
        assert(ifindex > 0);

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section)
                if (streq(session->name, name)) {
                        if (session->ifindex == ifindex)
                                return 0; /* already set. */
                        if (session->ifindex > 0 && session->ifindex != ifindex)
                                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EEXIST),
                                                                "Could not set ifindex %i for session %s, already set to %i.",
                                                                ifindex, session->name, session->ifindex);

                        session->ifindex = ifindex;
                        log_netdev_debug(netdev, "Session %s gained ifindex %i.", session->name, session->ifindex);
                        found = true;
                        break;
                }

        if (!found)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "Received netlink message with unexpected interface name %s (ifindex=%i).",
                                                name, ifindex);

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section)
                if (session->ifindex <= 0)
                        return 0; /* This session is not ready yet. */

        return netdev_enter_ready(netdev);
}

static int netdev_l2tp_tunnel_get_ifindex(NetDev *netdev, const char *name) {
        L2tpTunnel *t = L2TP(netdev);
        L2tpSession *session;

        assert(name);

        ORDERED_HASHMAP_FOREACH(session, t->sessions_by_section)
                if (streq(session->name, name))
                        return session->ifindex;

        return -ENODEV;
}

static void l2tp_tunnel_done(NetDev *netdev) {
        L2tpTunnel *t = L2TP(netdev);

        ordered_hashmap_free_with_destructor(t->sessions_by_section, l2tp_session_free);
        free(t->local_ifname);
}

const NetDevVTable l2tptnl_vtable = {
        .object_size = sizeof(L2tpTunnel),
        .init = l2tp_tunnel_init,
        .sections = NETDEV_COMMON_SECTIONS "L2TP\0L2TPSession\0",
        .create = l2tp_create_tunnel,
        .done = l2tp_tunnel_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .is_ready_to_create = netdev_l2tp_is_ready_to_create,
        .config_verify = netdev_l2tp_tunnel_verify,
        .attach = netdev_l2tp_tunnel_attach,
        .detach = netdev_l2tp_tunnel_detach,
        .set_ifindex = netdev_l2tp_tunnel_set_ifindex,
        .get_ifindex = netdev_l2tp_tunnel_get_ifindex,
        .iftype = ARPHRD_ETHER,
        .skip_netdev_kind_check = true,
};

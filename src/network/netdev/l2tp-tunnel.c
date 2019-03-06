/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <linux/l2tp.h>
#include <linux/genetlink.h>

#include "sd-netlink.h"
#include "conf-parser.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"
#include "hashmap.h"
#include "socket-util.h"

#include "missing.h"
#include "networkd-manager.h"
#include "netdev/l2tp-tunnel.h"

static const char* const l2tp_l2spec_type_table[_NETDEV_L2TP_L2SPECTYPE_MAX] = {
        [NETDEV_L2TP_L2SPECTYPE_NONE] = "none",
        [NETDEV_L2TP_L2SPECTYPE_DEFAULT] = "default",
};

DEFINE_STRING_TABLE_LOOKUP(l2tp_l2spec_type, L2tpL2specType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_l2tp_l2spec_type, l2tp_l2spec_type, L2tpL2specType, "Failed to parse L2TP L2 spec type");

static const char* const l2tp_encap_type_table[_NETDEV_L2TP_ENCAPTYPE_MAX] = {
        [NETDEV_L2TP_ENCAPTYPE_UDP] = "udp",
        [NETDEV_L2TP_ENCAPTYPE_IP] = "ip",
};

DEFINE_STRING_TABLE_LOOKUP(l2tp_encap_type, L2tpEncapType);
DEFINE_CONFIG_PARSE_ENUM(config_parse_l2tp_encap_type, l2tp_encap_type, L2tpEncapType, "Failed to parse L2TP Encapsulation Type");

static int session_new(unsigned section_line, L2tpSession **ret) {
        _cleanup_free_ L2tpSession *session = NULL;

        session = new(L2tpSession, 1);
        if (!session)
                return -ENOMEM;

        *session = (L2tpSession) {
                   .section_line = section_line,
                   .pw_type = L2TP_PWTYPE_ETH,
                   .l2tp_l2spec_type = NETDEV_L2TP_L2SPECTYPE_DEFAULT,
                   .l2spec_len = 4,
                   .l2tp_encap_type = NETDEV_L2TP_ENCAPTYPE_UDP,
        };

        *ret = TAKE_PTR(session);

        return 0;
}

static int l2tp_tunnel_new_session(L2tpTunnel *t, unsigned section_line, L2tpSession **ret) {
        _cleanup_free_ L2tpSession *session = NULL;
        int r;

        assert(ret);

        if (t->l2tp_sessions) {
                session = hashmap_get(t->l2tp_sessions, INT_TO_PTR(section_line));
                if (session) {
                        *ret = TAKE_PTR(session);
                        return 0;
                }
        }

        r = session_new(section_line, &session);
        if (r < 0)
                return r;

        LIST_APPEND(sessions, t->sessions, session);
        t->n_sessiones++;

        r = hashmap_ensure_allocated(&t->l2tp_sessions, NULL);
        if (r < 0)
                return r;

        r = hashmap_put(t->l2tp_sessions, INT_TO_PTR(session->section_line), session);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(session);

        return 0;
}

static int netdev_l2tp_fill_message_tunnel(NetDev *netdev, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint16_t encap_type;
        L2tpTunnel *t;
        int r;

        assert(netdev);

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
                r = sd_netlink_message_append_in_addr(m, L2TP_ATTR_IP_SADDR, &t->local.in);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IP_SADDR attribute: %m");

                r = sd_netlink_message_append_in_addr(m, L2TP_ATTR_IP_DADDR, &t->remote.in);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IP_DADDR attribute: %m");
        } else {
                r = sd_netlink_message_append_in6_addr(m, L2TP_ATTR_IP6_SADDR, &t->local.in6);
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
        uint8_t l2_spec_type;
        L2tpTunnel *t;
        int r;

        assert(netdev);
        assert(session);

        t = L2TP(netdev);

        assert(t);

        r = sd_genl_message_new(netdev->manager->genl, SD_GENL_L2TP, L2TP_CMD_SESSION_CREATE, &m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Failed to create generic netlink message: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_CONN_ID, t->tunnel_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_CONN_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_CONN_ID, t->peer_tunnel_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PEER_CONN_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_SESSION_ID, session->session_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_SESSION_ID attribute: %m");

        r = sd_netlink_message_append_u32(m, L2TP_ATTR_PEER_SESSION_ID, session->peer_session_id);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PEER_SESSION_ID attribute: %m");

        r = sd_netlink_message_append_u16(m, L2TP_ATTR_PW_TYPE, session->pw_type);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_PW_TYPE attribute: %m");

        switch (t->l2tp_l2spec_type) {
        case NETDEV_L2TP_L2SPECTYPE_NONE:

                l2_spec_type = L2TP_L2SPECTYPE_DEFAULT;
                break;

        case NETDEV_L2TP_L2SPECTYPE_DEFAULT:
        default:

                l2_spec_type = L2TP_L2SPECTYPE_DEFAULT;
                break;
        }

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_L2SPEC_TYPE, l2_spec_type);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_L2SPEC_TYPE attribute: %m");

        if (session->l2tp_l2spec_type == NETDEV_L2TP_L2SPECTYPE_NONE)
                session->l2spec_len = 0;

        r = sd_netlink_message_append_u8(m, L2TP_ATTR_L2SPEC_LEN, session->l2spec_len);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_L2SPEC_LEN attribute: %m");

        r = sd_netlink_message_append_string(m, L2TP_ATTR_IFNAME, session->name);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append L2TP_ATTR_IFNAME attribute: %m");

        *ret = TAKE_PTR(m);

        return 0;
}

static int netdev_l2tp_tunnel_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        L2tpSession *session = NULL;
        uint32_t serial;
        L2tpTunnel *t;
        int r;

        assert(netdev);

        t = L2TP(netdev);

        assert(t);

        r = netdev_l2tp_fill_message_tunnel(netdev, &m);
        if (r < 0)
                return r;

        r = sd_netlink_send(netdev->manager->genl, m, &serial);
        if (r < 0 && r != -EEXIST)
                return log_netdev_error_errno(netdev, r, "Failed to create L2TP tunnel: %m");

        LIST_FOREACH(sessions, session, t->sessions) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *n = NULL;

                r = netdev_l2tp_fill_message_session(netdev, session, &n);
                if (r < 0)
                        return r;

                r = sd_netlink_send(netdev->manager->genl, n, &serial);
                if (r < 0 && r != -EEXIST)
                        return log_netdev_error_errno(netdev, r, "Failed to add L2TP session: %m");

        }

        return 0;
}

int config_parse_l2tp_tunnel_address(const char *unit,
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
        union in_addr_union *addr = data, buffer;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (t->family == AF_UNSPEC)
                r = in_addr_from_string_auto(rvalue, &t->family, addr);
        else
                r = in_addr_from_string(t->family, rvalue, addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Invalid L2TP Tunnel address specified in %s='%s', ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }

        *addr = buffer;

        return 0;
}

int config_parse_l2tp_tunnel_port(const char *unit,
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
        uint16_t port;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_ip_port(rvalue, &port);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse L2TP Tunnel's '%s' port '%s'.", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "UDPSourcePort"))
                t->l2tp_udp_sport = port;
        else
                t->l2tp_udp_dport = port;

        return 0;
}

static int netdev_l2tp_tunnel_verify(NetDev *netdev, const char *filename) {
        L2tpTunnel *t;

        assert(netdev);
        assert(filename);

        t = L2TP(netdev);

        assert(t);

        if (!IN_SET(t->family, AF_INET, AF_INET6)) {
                log_netdev_error(netdev,
                                 "L2TP Tunnel with invalid address family configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        if (in_addr_is_null(t->family, &t->local) || in_addr_is_null(t->family, &t->remote)) {
                log_netdev_error(netdev,
                                 "L2TP Tunnel without a local or remote address configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        return 0;
}

int config_parse_l2tp_session_id(const char *unit,
                                 const char *filename,
                                 unsigned line,
                                 const char *section,
                                 unsigned section_line,
                                 const char *lvalue,
                                 int ltype,
                                 const char *rvalue,
                                 void *data,
                                 void *userdata) {
        _cleanup_free_ L2tpSession *session = NULL;
        L2tpTunnel *t = userdata;
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = l2tp_tunnel_new_session(t, section_line, &session);
        if (r < 0)
                return r;

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse L2TP tunnel session id. Ignoring assignment: %s", rvalue);
                return 0;
        }

        if (streq(lvalue, "SessionId"))
                session->session_id = k;
        else
                session->peer_session_id = k;

        session = NULL;

        return 0;
}

int config_parse_l2tp_session_name(const char *unit,
                                   const char *filename,
                                   unsigned line,
                                   const char *section,
                                   unsigned section_line,
                                   const char *lvalue,
                                   int ltype,
                                   const char *rvalue,
                                   void *data,
                                   void *userdata) {
        _cleanup_free_ L2tpSession *session = NULL;
        L2tpTunnel *t = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = l2tp_tunnel_new_session(t, section_line, &session);
        if (r < 0)
                return r;

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse L2TP tunnel session name. Ignoring assignment: %s", rvalue);
                return 0;
        }

        session->name = strdup(rvalue);
        if (!session->name)
                return -ENOMEM;

        session = NULL;

        return 0;
}

static void l2tp_tunnel_init(NetDev *netdev) {
        L2tpTunnel *t;

        assert(netdev);

        t = L2TP(netdev);

        assert(t);

        LIST_HEAD_INIT(t->sessions);

        t->udp6_csum_rx = true;
        t->udp6_csum_tx = true;
}

static void l2tp_tunnel_done(NetDev *netdev) {
        L2tpSession *session, *session_next;
        L2tpTunnel *t;

        assert(netdev);

        t = L2TP(netdev);

        assert(t);

        LIST_FOREACH_SAFE(sessions, session, session_next, t->sessions)
                free(session);

        hashmap_free(t->l2tp_sessions);
}

const NetDevVTable l2tptnl_vtable = {
        .object_size = sizeof(L2tpTunnel),
        .init = l2tp_tunnel_init,
        .sections = "Match\0NetDev\0L2TP\0L2TPSession",
        .create = netdev_l2tp_tunnel_create,
        .done = l2tp_tunnel_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_l2tp_tunnel_verify,
};

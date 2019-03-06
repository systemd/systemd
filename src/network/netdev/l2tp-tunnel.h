/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "linux/l2tp.h"

#include "in-addr-util.h"
#include "netdev/netdev.h"

typedef enum L2tpL2specType {
        NETDEV_L2TP_L2SPECTYPE_NONE = L2TP_L2SPECTYPE_NONE,
        NETDEV_L2TP_L2SPECTYPE_DEFAULT = L2TP_L2SPECTYPE_DEFAULT,
        _NETDEV_L2TP_L2SPECTYPE_MAX,
        _NETDEV_L2TP_L2SPECTYPE_INVALID = -1,
} L2tpL2specType;

typedef enum L2tpEncapType {
        NETDEV_L2TP_ENCAPTYPE_UDP = L2TP_ENCAPTYPE_UDP,
        NETDEV_L2TP_ENCAPTYPE_IP = L2TP_ENCAPTYPE_IP,
        _NETDEV_L2TP_ENCAPTYPE_MAX,
        _NETDEV_L2TP_ENCAPTYPE_INVALID = -1,
} L2tpEncapType;

typedef struct L2tpSession {
        unsigned section_line;

        char *name;

        uint16_t l2spec_len;
        uint16_t pw_type;

        uint32_t session_id;
        uint32_t peer_session_id;

        L2tpL2specType l2tp_l2spec_type;
        L2tpEncapType l2tp_encap_type;

        LIST_FIELDS(struct L2tpSession, sessions);
} L2tpSession;

typedef struct L2tpTunnel {
        NetDev meta;

        uint16_t l2tp_udp_sport;
        uint16_t l2tp_udp_dport;

        uint32_t tunnel_id;
        uint32_t peer_tunnel_id;
        uint32_t n_sessiones;

        int family;

        bool udp_csum;
        bool udp6_csum_rx;
        bool udp6_csum_tx;

        union in_addr_union local;
        union in_addr_union remote;

        L2tpL2specType l2tp_l2spec_type;
        L2tpEncapType l2tp_encap_type;

        Hashmap *l2tp_sessions;
        LIST_HEAD(L2tpSession, sessions);
} L2tpTunnel;

int l2tpsession_new_static(Network *network, const char *filename, unsigned section, L2tpSession *session);
int l2tpsession_new(L2tpSession **ret);
void l2tpsession_free(L2tpSession *address);

DEFINE_NETDEV_CAST(L2TP, L2tpTunnel);
extern const NetDevVTable l2tptnl_vtable;

const char *l2tp_l2spec_type_to_string(L2tpL2specType d) _const_;
L2tpL2specType l2tp_l2spec_type_from_string(const char *d) _pure_;

const char *l2tp_encap_type_to_string(L2tpEncapType d) _const_;
L2tpEncapType l2tp_encap_type_from_string(const char *d) _pure_;

CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_l2spec_type);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_encap_type);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_tunnel_address);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_tunnel_port);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_session_id);
CONFIG_PARSER_PROTOTYPE(config_parse_l2tp_session_name);

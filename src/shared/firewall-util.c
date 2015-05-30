/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering
  Copyright 2015 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "util.h"
#include "firewall-util.h"

#define SYSTEMD_TABLE "systemd"
#define SYSTEMD_CHAIN_NAT_PRE_IPV4  "nat-pre-ipv4"
#define SYSTEMD_CHAIN_NAT_POST_IPV4 "nat-post-ipv4"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct mnl_socket*, mnl_socket_close);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct nft_table*, nft_table_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct nft_chain*, nft_chain_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct nft_rule*, nft_rule_free);

enum CallbackReturnType {
        CALLBACK_RETURN_UNDEF,
        CALLBACK_RETURN_HANDLE,
        _CALLBACK_RETURN_MAX,
};

struct fw_callback_data {
        enum CallbackReturnType type;
        uint64_t value;
        bool success;
};

static int events_cb(const struct nlmsghdr *nlh, void *data)
{
        int event = NFNL_MSG_TYPE(nlh->nlmsg_type);
        struct fw_callback_data *cb = data;
        int r;

        if (!cb || cb->type == CALLBACK_RETURN_UNDEF)
                return MNL_CB_OK;

        switch(event) {
        case NFT_MSG_NEWRULE: {
                _cleanup_(nft_rule_freep) struct nft_rule *rule = NULL;

                rule = nft_rule_alloc();
                if (!rule)
                        return -ENOMEM;

                r = nft_rule_nlmsg_parse(nlh, rule);
                if (r < 0)
                        return r;

                switch (cb->type) {
                case CALLBACK_RETURN_HANDLE:
                        cb->value = nft_rule_attr_get_u64(rule, NFT_RULE_ATTR_HANDLE);
                        cb->success = true;
                        return MNL_CB_STOP;

                default:
                        assert_not_reached("Invalid callback type");
                }
                break;
        }
        default:
                break;
        }

        return MNL_CB_OK;
}

static int socket_open_and_bind(struct mnl_socket **n) {

        _cleanup_(mnl_socket_closep) struct mnl_socket *nl = NULL;
        int r;

        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (!nl)
                return -errno;

        r = mnl_socket_bind(nl, 1 << (NFNLGRP_NFTABLES-1), MNL_SOCKET_AUTOPID);
        if (r < 0)
                return -errno;

        *n = nl;
        nl = NULL;
        return 0;
}

static int send_and_dispatch(
                struct mnl_socket *nl,
                const void *req,
                size_t req_size,
                enum CallbackReturnType callback_type,
                uint64_t *callback_value) {

        struct fw_callback_data cb = {};
        uint32_t portid;
        int r;

        r = mnl_socket_sendto(nl, req, req_size);
        if (r < 0)
                return -errno;

        portid = mnl_socket_get_portid(nl);
        cb.type = callback_type;

        for (;;) {
                char buf[MNL_SOCKET_BUFFER_SIZE];

                r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                if (r <= 0)
                        break;

                r = mnl_cb_run(buf, r, 0, portid, events_cb, &cb);
                if (r <= 0)
                        break;
        }

        if (r < 0)
                return -errno;

        if (callback_type == CALLBACK_RETURN_UNDEF)
                return 0;

        if (cb.success) {
                if (callback_value)
                        *callback_value = cb.value;

                return 0;
        }

        return -ENOENT;
}

static int table_cmd(struct mnl_socket *nl,
                     const char *name,
                     uint16_t family,
                     bool add) {

        _cleanup_(nft_table_freep) struct nft_table *t = NULL;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct mnl_nlmsg_batch *batch;
        struct nlmsghdr *nlh;
        uint32_t seq = 0;
        int r;

        t = nft_table_alloc();
        if (!t)
                return -ENOMEM;

        nft_table_attr_set_u32(t, NFT_TABLE_ATTR_FAMILY, family);
        nft_table_attr_set_str(t, NFT_TABLE_ATTR_NAME, name);

        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
        nft_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        nlh = nft_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                        add ? NFT_MSG_NEWTABLE : NFT_MSG_DELTABLE,
                                        family, NLM_F_ACK, seq++);
        nft_table_nlmsg_build_payload(nlh, t);
        mnl_nlmsg_batch_next(batch);

        nft_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        r = send_and_dispatch(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch), 0, NULL);
        if (r < 0)
                return r;

        mnl_nlmsg_batch_stop(batch);

        return 0;
}

static int chain_cmd(
                struct mnl_socket *nl,
                const char *name,
                const char *table,
                const char *type,
                int family,
                int hooknum,
                int prio,
                bool add) {

        _cleanup_(nft_chain_freep) struct nft_chain *c = NULL;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct mnl_nlmsg_batch *batch;
        struct nlmsghdr *nlh;
        uint32_t seq = 0;
        int r;

        c = nft_chain_alloc();
        if (!c)
                return -ENOMEM;

        nft_chain_attr_set(c, NFT_CHAIN_ATTR_TABLE, table);
        nft_chain_attr_set(c, NFT_CHAIN_ATTR_NAME, name);

        if (type)
                nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_TYPE, type);

        if (prio >= 0)
                nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_PRIO, prio);

        if (hooknum >= 0)
                nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_HOOKNUM, hooknum);

        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
        nft_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        nlh = nft_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                        add ? NFT_MSG_NEWCHAIN: NFT_MSG_DELCHAIN,
                                        family, NLM_F_ACK, seq++);
        nft_chain_nlmsg_build_payload(nlh, c);
        mnl_nlmsg_batch_next(batch);

        nft_batch_end(mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);

        r = send_and_dispatch(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch), 0, NULL);
        if (r < 0)
                return r;

        mnl_nlmsg_batch_stop(batch);

        return 0;
}

static void put_batch_headers(char *buf, uint16_t type, uint32_t seq) {

        struct nlmsghdr *nlh;
        struct nfgenmsg *nfg;

        nlh = mnl_nlmsg_put_header(buf);
        nlh->nlmsg_type = type;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = seq;

        nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
        nfg->nfgen_family = AF_INET;
        nfg->version = NFNETLINK_V0;
        nfg->res_id = NFNL_SUBSYS_NFTABLES;
}

static int add_payload(struct nft_rule *r, uint32_t base, uint32_t dreg, uint32_t offset, uint32_t len) {
        struct nft_rule_expr *expr;

        expr = nft_rule_expr_alloc("payload");
        if (!expr)
                return -ENOMEM;

        nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_BASE, base);
        nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_DREG, dreg);
        nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_OFFSET, offset);
        nft_rule_expr_set_u32(expr, NFT_EXPR_PAYLOAD_LEN, len);

        nft_rule_add_expr(r, expr);

        return 0;
}

static int add_bitwise(struct nft_rule *r, int reg, const void *mask, size_t len) {
        struct nft_rule_expr *expr;
        uint8_t *xor;

        expr = nft_rule_expr_alloc("bitwise");
        if (!expr)
                return -ENOMEM;

        xor = alloca0(len);

        nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_SREG, reg);
        nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_DREG, reg);
        nft_rule_expr_set_u32(expr, NFT_EXPR_BITWISE_LEN, len);
        nft_rule_expr_set(expr, NFT_EXPR_BITWISE_MASK, mask, len);
        nft_rule_expr_set(expr, NFT_EXPR_BITWISE_XOR, &xor, len);

        nft_rule_add_expr(r, expr);

        return 0;
}

static int add_cmp(struct nft_rule *r, uint32_t sreg, uint32_t op, const void *data, uint32_t data_len) {
        struct nft_rule_expr *expr;

        expr = nft_rule_expr_alloc("cmp");
        if (!expr)
                return -ENOMEM;

        nft_rule_expr_set_u32(expr, NFT_EXPR_CMP_SREG, sreg);
        nft_rule_expr_set_u32(expr, NFT_EXPR_CMP_OP, op);
        nft_rule_expr_set(expr, NFT_EXPR_CMP_DATA, data, data_len);

        nft_rule_add_expr(r, expr);

        return 0;
}

static int add_imm(struct nft_rule *r, uint32_t reg, const void *data, uint32_t data_len) {
        struct nft_rule_expr *expr;

        expr = nft_rule_expr_alloc("immediate");
        if (!expr)
                return -ENOMEM;

        nft_rule_expr_set_u32(expr, NFT_EXPR_IMM_DREG, reg);
        nft_rule_expr_set(expr, NFT_EXPR_IMM_DATA, data, data_len);

        nft_rule_add_expr(r, expr);

        return 0;
}

static int rule_cmd(
                struct mnl_socket *nl,
                struct nft_rule *rule,
                uint16_t cmd,
                uint16_t family,
                uint16_t type,
                enum CallbackReturnType callback_type,
                uint64_t *callback_value) {

        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct mnl_nlmsg_batch *batch;
        struct nlmsghdr *nlh;
        uint32_t seq = 0;
        int r;

        batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
        put_batch_headers(mnl_nlmsg_batch_current(batch), NFNL_MSG_BATCH_BEGIN, seq++);
        mnl_nlmsg_batch_next(batch);

        nlh = nft_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), cmd, family, type, seq++);
        nft_rule_nlmsg_build_payload(nlh, rule);
        mnl_nlmsg_batch_next(batch);

        put_batch_headers(mnl_nlmsg_batch_current(batch), NFNL_MSG_BATCH_END, seq++);
        mnl_nlmsg_batch_next(batch);

        r = send_and_dispatch(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch), callback_type, callback_value);
        mnl_nlmsg_batch_stop(batch);

        return r;
}

int fw_add_masquerade(
                int af,
                uint8_t protocol,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const char *out_interface,
                const union in_addr_union *destination,
                unsigned destination_prefixlen,
                uint64_t *handle) {

        _cleanup_(mnl_socket_closep) struct mnl_socket *nl = NULL;
        _cleanup_(nft_rule_freep) struct nft_rule *rule = NULL;
        struct nft_rule_expr *expr;
        int r;

        if (af != AF_INET)
                return -EOPNOTSUPP;

        if (protocol != 0 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
                return -EOPNOTSUPP;

        rule = nft_rule_alloc();
        if (!rule)
                return -ENOMEM;

        nft_rule_attr_set(rule, NFT_RULE_ATTR_TABLE, SYSTEMD_TABLE);
        nft_rule_attr_set(rule, NFT_RULE_ATTR_CHAIN, SYSTEMD_CHAIN_NAT_POST_IPV4);
        nft_rule_attr_set_u32(rule, NFT_RULE_ATTR_FAMILY, NFPROTO_IPV4);

        r = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                        offsetof(struct iphdr, protocol), sizeof(protocol));
        if (r < 0)
                return r;

        r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &protocol, sizeof(protocol));
        if (r < 0)
                return r;

        if (source) {
                struct in_addr smsk;

                in_addr_prefixlen_to_netmask(&smsk, source_prefixlen);

                r = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                                offsetof(struct iphdr, saddr), sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_bitwise(rule, NFT_REG_1, &smsk.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &source->in.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;
        }

        if (destination) {
                struct in_addr dmsk;

                in_addr_prefixlen_to_netmask(&dmsk, destination_prefixlen);

                r = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                                offsetof(struct iphdr, daddr), sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_bitwise(rule, NFT_REG_1, &dmsk.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &destination->in.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;
        }

        if (out_interface) {
                expr = nft_rule_expr_alloc("meta");
                if (!expr)
                        return -ENOMEM;

                nft_rule_expr_set_u32(expr, NFT_EXPR_META_KEY, NFT_META_OIFNAME);
                nft_rule_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);
                nft_rule_add_expr(rule, expr);

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, out_interface, strlen(out_interface) + 1);
                if (r < 0)
                        return r;
        }

        expr = nft_rule_expr_alloc("masq");
        if (!expr)
                return -ENOMEM;

        nft_rule_add_expr(rule, expr);

        r = socket_open_and_bind(&nl);
        if (r < 0)
                return r;

        r = table_cmd(nl, SYSTEMD_TABLE, NFPROTO_IPV4, true);
        if (r < 0)
                return r;

        r = chain_cmd(nl, SYSTEMD_CHAIN_NAT_POST_IPV4, SYSTEMD_TABLE, "nat", NFPROTO_IPV4, NF_INET_POST_ROUTING, 0, true);
        if (r < 0)
                return r;

        return rule_cmd(nl, rule, NFT_MSG_NEWRULE, NFPROTO_IPV4, NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, CALLBACK_RETURN_HANDLE, handle);
}

int fw_add_local_dnat(
                int af,
                uint8_t protocol,
                const char *in_interface,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const union in_addr_union *destination,
                unsigned destination_prefixlen,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                uint64_t *handle) {

        _cleanup_(mnl_socket_closep) struct mnl_socket *nl = NULL;
        _cleanup_(nft_rule_freep) struct nft_rule *rule = NULL;
        struct nft_rule_expr *expr;
        int r;

        if (af != AF_INET)
                return -EOPNOTSUPP;

        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
                return -EOPNOTSUPP;

        if (local_port <= 0)
                return -EINVAL;

        if (remote_port <= 0)
                return -EINVAL;

        rule = nft_rule_alloc();
        if (!rule)
                return -ENOMEM;

        nft_rule_attr_set(rule, NFT_RULE_ATTR_TABLE, SYSTEMD_TABLE);
        nft_rule_attr_set(rule, NFT_RULE_ATTR_CHAIN, SYSTEMD_CHAIN_NAT_PRE_IPV4);
        nft_rule_attr_set_u32(rule, NFT_RULE_ATTR_FAMILY, NFPROTO_IPV4);

        r = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                        offsetof(struct iphdr, protocol), sizeof(protocol));
        if (r < 0)
                return r;

        r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &protocol, sizeof(protocol));
        if (r < 0)
                return r;

        if (source) {
                struct in_addr smsk;

                in_addr_prefixlen_to_netmask(&smsk, source_prefixlen);

                r = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                                offsetof(struct iphdr, saddr), sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_bitwise(rule, NFT_REG_1, &smsk.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &source->in.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;
        }

        if (destination) {
                struct in_addr dmsk;

                in_addr_prefixlen_to_netmask(&dmsk, destination_prefixlen);

                r = add_payload(rule, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                                offsetof(struct iphdr, daddr), sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_bitwise(rule, NFT_REG_1, &dmsk.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &destination->in.s_addr, sizeof(struct in_addr));
                if (r < 0)
                        return r;
        }

        if (in_interface) {
                expr = nft_rule_expr_alloc("meta");
                if (!expr)
                        return -ENOMEM;

                nft_rule_expr_set_u32(expr, NFT_EXPR_META_KEY, NFT_META_IIFNAME);
                nft_rule_expr_set_u32(expr, NFT_EXPR_META_DREG, NFT_REG_1);
                nft_rule_add_expr(rule, expr);

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, in_interface, strlen(in_interface) + 1);
                if (r < 0)
                        return r;
        }

        if (local_port) {
                local_port = htobe16(local_port);
                r = add_payload(rule, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
                                offsetof(struct tcphdr, dest), sizeof(local_port));
                if (r < 0)
                        return r;

                r = add_cmp(rule, NFT_REG_1, NFT_CMP_EQ, &local_port, sizeof(local_port));
                if (r < 0)
                        return r;
        }

        expr = nft_rule_expr_alloc("nat");
        if (!expr)
                return -ENOMEM;

        nft_rule_expr_set_u32(expr, NFT_EXPR_NAT_TYPE, NFT_NAT_DNAT);
        nft_rule_expr_set_u32(expr, NFT_EXPR_NAT_FAMILY, af);

        if (remote) {
                nft_rule_expr_set_u32(expr, NFT_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
                nft_rule_expr_set_u32(expr, NFT_EXPR_NAT_REG_ADDR_MAX, NFT_REG_1);

                r = add_imm(rule, NFT_REG_1, &remote->in.s_addr, sizeof(remote->in.s_addr));
                if (r < 0)
                        return r;
        }

        if (remote_port) {
                remote_port = htobe16(remote_port);
                nft_rule_expr_set_u32(expr, NFT_EXPR_NAT_REG_PROTO_MIN, NFT_REG_2);
                nft_rule_expr_set_u32(expr, NFT_EXPR_NAT_REG_PROTO_MAX, NFT_REG_2);

                r = add_imm(rule, NFT_REG_2, &remote_port, sizeof(remote_port));
                if (r < 0)
                        return r;
        }

        nft_rule_add_expr(rule, expr);

        r = socket_open_and_bind(&nl);
        if (r < 0)
                return r;

        r = table_cmd(nl, SYSTEMD_TABLE, NFPROTO_IPV4, true);
        if (r < 0)
                return r;

        r = chain_cmd(nl, SYSTEMD_CHAIN_NAT_PRE_IPV4, SYSTEMD_TABLE, "nat", NFPROTO_IPV4, NF_INET_PRE_ROUTING, 0, true);
        if (r < 0)
                return r;

        return rule_cmd(nl, rule, NFT_MSG_NEWRULE, NFPROTO_IPV4, NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, CALLBACK_RETURN_HANDLE, handle);
}

static int fw_remove_rule(uint64_t handle, const char *chain) {

        _cleanup_(mnl_socket_closep) struct mnl_socket *nl = NULL;
        _cleanup_(nft_rule_freep) struct nft_rule *rule = NULL;
        int r;

        rule = nft_rule_alloc();
        if (!rule)
                return -ENOMEM;

        nft_rule_attr_set(rule, NFT_RULE_ATTR_TABLE, SYSTEMD_TABLE);
        nft_rule_attr_set(rule, NFT_RULE_ATTR_CHAIN, chain);
        nft_rule_attr_set_u64(rule, NFT_RULE_ATTR_HANDLE, handle);

        r = socket_open_and_bind(&nl);
        if (r < 0)
                return r;

        return rule_cmd(nl, rule, NFT_MSG_DELRULE, NFPROTO_IPV4, NLM_F_ACK, 0, NULL);
}

int fw_remove_masquerade(uint64_t handle) {
        return fw_remove_rule(handle, SYSTEMD_CHAIN_NAT_POST_IPV4);
}

int fw_remove_local_dnat(uint64_t handle) {
        return fw_remove_rule(handle, SYSTEMD_CHAIN_NAT_PRE_IPV4);
}
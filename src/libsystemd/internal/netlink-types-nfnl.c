/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include "netlink-types-internal.h"
#include "string-table.h"

static const NLType nfnl_nft_table_types[] = {
        [NFTA_TABLE_NAME]  = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_TABLE_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_table);

static const NLType nfnl_nft_chain_hook_types[] = {
        [NFTA_HOOK_HOOKNUM]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_HOOK_PRIORITY] = { .type = NETLINK_TYPE_U32 },
        [NFTA_HOOK_DEV]      = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ - 1 },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_chain_hook);

static const NLType nfnl_nft_chain_types[] = {
        [NFTA_CHAIN_TABLE] = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_CHAIN_NAME]  = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_CHAIN_HOOK]  = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_chain_hook_type_system },
        [NFTA_CHAIN_TYPE]  = { .type = NETLINK_TYPE_STRING, .size = 16 },
        [NFTA_CHAIN_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_chain);

static const NLType nfnl_nft_expr_meta_types[] = {
        [NFTA_META_DREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_META_KEY]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_META_SREG] = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_payload_types[] = {
        [NFTA_PAYLOAD_DREG]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_PAYLOAD_BASE]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_PAYLOAD_OFFSET] = { .type = NETLINK_TYPE_U32 },
        [NFTA_PAYLOAD_LEN]    = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_nat_types[] = {
        [NFTA_NAT_TYPE]          = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_FAMILY]        = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_ADDR_MIN]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_ADDR_MAX]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_PROTO_MIN] = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_REG_PROTO_MAX] = { .type = NETLINK_TYPE_U32 },
        [NFTA_NAT_FLAGS]         = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_data_types[] = {
        [NFTA_DATA_VALUE] = { .type = NETLINK_TYPE_BINARY },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_data);

static const NLType nfnl_nft_expr_bitwise_types[] = {
        [NFTA_BITWISE_SREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_BITWISE_DREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_BITWISE_LEN]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_BITWISE_MASK] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
        [NFTA_BITWISE_XOR]  = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
};

static const NLType nfnl_nft_expr_cmp_types[] = {
        [NFTA_CMP_SREG] = { .type = NETLINK_TYPE_U32 },
        [NFTA_CMP_OP]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_CMP_DATA] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
};

static const NLType nfnl_nft_expr_fib_types[] = {
        [NFTA_FIB_DREG]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_FIB_RESULT] = { .type = NETLINK_TYPE_U32 },
        [NFTA_FIB_FLAGS]  = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_lookup_types[] = {
        [NFTA_LOOKUP_SET]   = { .type = NETLINK_TYPE_STRING },
        [NFTA_LOOKUP_SREG]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_LOOKUP_DREG]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_LOOKUP_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

static const NLType nfnl_nft_expr_masq_types[] = {
        [NFTA_MASQ_FLAGS]         = { .type = NETLINK_TYPE_U32 },
        [NFTA_MASQ_REG_PROTO_MIN] = { .type = NETLINK_TYPE_U32 },
        [NFTA_MASQ_REG_PROTO_MAX] = { .type = NETLINK_TYPE_U32 },
};

static const NLTypeSystemUnionElement nfnl_expr_data_type_systems[] = {
        { .name = "bitwise", .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_bitwise), },
        { .name = "cmp",     .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_cmp),     },
        { .name = "fib",     .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_fib),     },
        { .name = "lookup",  .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_lookup),  },
        { .name = "masq",    .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_masq),    },
        { .name = "meta",    .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_meta),    },
        { .name = "nat",     .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_nat),     },
        { .name = "payload", .type_system = TYPE_SYSTEM_FROM_TYPE(nfnl_nft_expr_payload), },
};

DEFINE_TYPE_SYSTEM_UNION_MATCH_SIBLING(nfnl_expr_data, NFTA_EXPR_NAME);

static const NLType nfnl_nft_rule_expr_types[] = {
        [NFTA_EXPR_NAME] = { .type = NETLINK_TYPE_STRING, .size = 16 },
        [NFTA_EXPR_DATA] = { .type = NETLINK_TYPE_UNION, .type_system_union = &nfnl_expr_data_type_system_union },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_rule_expr);

static const NLType nfnl_nft_rule_types[] = {
        [NFTA_RULE_TABLE]       = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_RULE_CHAIN]       = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_RULE_EXPRESSIONS] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_rule_expr_type_system }
};

DEFINE_TYPE_SYSTEM(nfnl_nft_rule);

static const NLType nfnl_nft_set_types[] = {
        [NFTA_SET_TABLE]      = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_NAME]       = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_FLAGS]      = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_KEY_TYPE]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_KEY_LEN]    = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_DATA_TYPE]  = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_DATA_LEN]   = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_POLICY]     = { .type = NETLINK_TYPE_U32 },
        [NFTA_SET_ID]         = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_set);

static const NLType nfnl_nft_setelem_types[] = {
        [NFTA_SET_ELEM_KEY]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
        [NFTA_SET_ELEM_DATA]  = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_data_type_system },
        [NFTA_SET_ELEM_FLAGS] = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_setelem);

static const NLType nfnl_nft_setelem_list_types[] = {
        [NFTA_SET_ELEM_LIST_TABLE]    = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_ELEM_LIST_SET]      = { .type = NETLINK_TYPE_STRING, .size = NFT_TABLE_MAXNAMELEN - 1 },
        [NFTA_SET_ELEM_LIST_ELEMENTS] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_setelem_type_system },
};

DEFINE_TYPE_SYSTEM(nfnl_nft_setelem_list);

static const NLType nfnl_subsys_nft_types [] = {
        [NFT_MSG_DELTABLE]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_table_type_system,        .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWTABLE]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_table_type_system,        .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWCHAIN]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_chain_type_system,        .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWRULE]    = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_rule_type_system,         .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWSET]     = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_set_type_system,          .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_NEWSETELEM] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_setelem_list_type_system, .size = sizeof(struct nfgenmsg) },
        [NFT_MSG_DELSETELEM] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_nft_setelem_list_type_system, .size = sizeof(struct nfgenmsg) },
};

DEFINE_TYPE_SYSTEM(nfnl_subsys_nft);

static const NLType nfnl_msg_batch_types [] = {
        [NFNL_BATCH_GENID] = { .type = NETLINK_TYPE_U32 }
};

DEFINE_TYPE_SYSTEM(nfnl_msg_batch);

static const NLType nfnl_subsys_none_types[] = {
        [NFNL_MSG_BATCH_BEGIN] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_msg_batch_type_system, .size = sizeof(struct nfgenmsg) },
        [NFNL_MSG_BATCH_END]   = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_msg_batch_type_system, .size = sizeof(struct nfgenmsg) },
};

DEFINE_TYPE_SYSTEM(nfnl_subsys_none);

static const NLType nfnl_types[] = {
        [NFNL_SUBSYS_NONE]     = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_subsys_none_type_system },
        [NFNL_SUBSYS_NFTABLES] = { .type = NETLINK_TYPE_NESTED, .type_system = &nfnl_subsys_nft_type_system },
};

DEFINE_TYPE_SYSTEM(nfnl);

const NLType *nfnl_get_type(uint16_t nlmsg_type) {
        const NLTypeSystem *subsys;

        subsys = type_system_get_type_system(&nfnl_type_system, nlmsg_type >> 8);
        if (!subsys)
                return NULL;

        return type_system_get_type(subsys, nlmsg_type & ((1U << 8) - 1));
}

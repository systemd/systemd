/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include "netlink-types-internal.h"

static const NLAPolicy nfnl_nft_table_policies[] = {
        [NFTA_TABLE_NAME]  = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_TABLE_FLAGS] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(nfnl_nft_table);

static const NLAPolicy nfnl_nft_chain_hook_policies[] = {
        [NFTA_HOOK_HOOKNUM]  = BUILD_POLICY(U32),
        [NFTA_HOOK_PRIORITY] = BUILD_POLICY(U32),
        [NFTA_HOOK_DEV]      = BUILD_POLICY_WITH_SIZE(STRING, IFNAMSIZ - 1),
};

DEFINE_POLICY_SET(nfnl_nft_chain_hook);

static const NLAPolicy nfnl_nft_chain_policies[] = {
        [NFTA_CHAIN_TABLE] = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_CHAIN_NAME]  = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_CHAIN_HOOK]  = BUILD_POLICY_NESTED(nfnl_nft_chain_hook),
        [NFTA_CHAIN_TYPE]  = BUILD_POLICY_WITH_SIZE(STRING, 16),
        [NFTA_CHAIN_FLAGS] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(nfnl_nft_chain);

static const NLAPolicy nfnl_nft_expr_meta_policies[] = {
        [NFTA_META_DREG] = BUILD_POLICY(U32),
        [NFTA_META_KEY]  = BUILD_POLICY(U32),
        [NFTA_META_SREG] = BUILD_POLICY(U32),
};

static const NLAPolicy nfnl_nft_expr_payload_policies[] = {
        [NFTA_PAYLOAD_DREG]   = BUILD_POLICY(U32),
        [NFTA_PAYLOAD_BASE]   = BUILD_POLICY(U32),
        [NFTA_PAYLOAD_OFFSET] = BUILD_POLICY(U32),
        [NFTA_PAYLOAD_LEN]    = BUILD_POLICY(U32),
};

static const NLAPolicy nfnl_nft_expr_nat_policies[] = {
        [NFTA_NAT_TYPE]          = BUILD_POLICY(U32),
        [NFTA_NAT_FAMILY]        = BUILD_POLICY(U32),
        [NFTA_NAT_REG_ADDR_MIN]  = BUILD_POLICY(U32),
        [NFTA_NAT_REG_ADDR_MAX]  = BUILD_POLICY(U32),
        [NFTA_NAT_REG_PROTO_MIN] = BUILD_POLICY(U32),
        [NFTA_NAT_REG_PROTO_MAX] = BUILD_POLICY(U32),
        [NFTA_NAT_FLAGS]         = BUILD_POLICY(U32),
};

static const NLAPolicy nfnl_nft_data_policies[] = {
        [NFTA_DATA_VALUE] = { .type = NETLINK_TYPE_BINARY },
};

DEFINE_POLICY_SET(nfnl_nft_data);

static const NLAPolicy nfnl_nft_expr_bitwise_policies[] = {
        [NFTA_BITWISE_SREG] = BUILD_POLICY(U32),
        [NFTA_BITWISE_DREG] = BUILD_POLICY(U32),
        [NFTA_BITWISE_LEN]  = BUILD_POLICY(U32),
        [NFTA_BITWISE_MASK] = BUILD_POLICY_NESTED(nfnl_nft_data),
        [NFTA_BITWISE_XOR]  = BUILD_POLICY_NESTED(nfnl_nft_data),
};

static const NLAPolicy nfnl_nft_expr_cmp_policies[] = {
        [NFTA_CMP_SREG] = BUILD_POLICY(U32),
        [NFTA_CMP_OP]   = BUILD_POLICY(U32),
        [NFTA_CMP_DATA] = BUILD_POLICY_NESTED(nfnl_nft_data),
};

static const NLAPolicy nfnl_nft_expr_fib_policies[] = {
        [NFTA_FIB_DREG]   = BUILD_POLICY(U32),
        [NFTA_FIB_RESULT] = BUILD_POLICY(U32),
        [NFTA_FIB_FLAGS]  = BUILD_POLICY(U32),
};

static const NLAPolicy nfnl_nft_expr_lookup_policies[] = {
        [NFTA_LOOKUP_SET]   = { .type = NETLINK_TYPE_STRING },
        [NFTA_LOOKUP_SREG]  = BUILD_POLICY(U32),
        [NFTA_LOOKUP_DREG]  = BUILD_POLICY(U32),
        [NFTA_LOOKUP_FLAGS] = BUILD_POLICY(U32),
};

static const NLAPolicy nfnl_nft_expr_masq_policies[] = {
        [NFTA_MASQ_FLAGS]         = BUILD_POLICY(U32),
        [NFTA_MASQ_REG_PROTO_MIN] = BUILD_POLICY(U32),
        [NFTA_MASQ_REG_PROTO_MAX] = BUILD_POLICY(U32),
};

static const NLAPolicySetUnionElement nfnl_expr_data_policy_set_union_elements[] = {
        BUILD_UNION_ELEMENT_BY_STRING("bitwise", nfnl_nft_expr_bitwise),
        BUILD_UNION_ELEMENT_BY_STRING("cmp",     nfnl_nft_expr_cmp),
        BUILD_UNION_ELEMENT_BY_STRING("fib",     nfnl_nft_expr_fib),
        BUILD_UNION_ELEMENT_BY_STRING("lookup",  nfnl_nft_expr_lookup),
        BUILD_UNION_ELEMENT_BY_STRING("masq",    nfnl_nft_expr_masq),
        BUILD_UNION_ELEMENT_BY_STRING("meta",    nfnl_nft_expr_meta),
        BUILD_UNION_ELEMENT_BY_STRING("nat",     nfnl_nft_expr_nat),
        BUILD_UNION_ELEMENT_BY_STRING("payload", nfnl_nft_expr_payload),
};

DEFINE_POLICY_SET_UNION(nfnl_expr_data, NFTA_EXPR_NAME);

static const NLAPolicy nfnl_nft_rule_expr_policies[] = {
        [NFTA_EXPR_NAME] = BUILD_POLICY_WITH_SIZE(STRING, 16),
        [NFTA_EXPR_DATA] = BUILD_POLICY_NESTED_UNION_BY_STRING(nfnl_expr_data),
};

DEFINE_POLICY_SET(nfnl_nft_rule_expr);

static const NLAPolicy nfnl_nft_rule_policies[] = {
        [NFTA_RULE_TABLE]       = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_RULE_CHAIN]       = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_RULE_EXPRESSIONS] = BUILD_POLICY_NESTED(nfnl_nft_rule_expr),
};

DEFINE_POLICY_SET(nfnl_nft_rule);

static const NLAPolicy nfnl_nft_set_policies[] = {
        [NFTA_SET_TABLE]      = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_SET_NAME]       = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_SET_FLAGS]      = BUILD_POLICY(U32),
        [NFTA_SET_KEY_TYPE]   = BUILD_POLICY(U32),
        [NFTA_SET_KEY_LEN]    = BUILD_POLICY(U32),
        [NFTA_SET_DATA_TYPE]  = BUILD_POLICY(U32),
        [NFTA_SET_DATA_LEN]   = BUILD_POLICY(U32),
        [NFTA_SET_POLICY]     = BUILD_POLICY(U32),
        [NFTA_SET_ID]         = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(nfnl_nft_set);

static const NLAPolicy nfnl_nft_setelem_policies[] = {
        [NFTA_SET_ELEM_KEY]   = BUILD_POLICY_NESTED(nfnl_nft_data),
        [NFTA_SET_ELEM_DATA]  = BUILD_POLICY_NESTED(nfnl_nft_data),
        [NFTA_SET_ELEM_FLAGS] = BUILD_POLICY(U32),
};

DEFINE_POLICY_SET(nfnl_nft_setelem);

static const NLAPolicy nfnl_nft_setelem_list_policies[] = {
        [NFTA_SET_ELEM_LIST_TABLE]    = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_SET_ELEM_LIST_SET]      = BUILD_POLICY_WITH_SIZE(STRING, NFT_TABLE_MAXNAMELEN - 1),
        [NFTA_SET_ELEM_LIST_ELEMENTS] = BUILD_POLICY_NESTED(nfnl_nft_setelem),
};

DEFINE_POLICY_SET(nfnl_nft_setelem_list);

static const NLAPolicy nfnl_subsys_nft_policies[] = {
        [NFT_MSG_DELTABLE]   = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_table,        sizeof(struct nfgenmsg)),
        [NFT_MSG_NEWTABLE]   = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_table,        sizeof(struct nfgenmsg)),
        [NFT_MSG_NEWCHAIN]   = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_chain,        sizeof(struct nfgenmsg)),
        [NFT_MSG_NEWRULE]    = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_rule,         sizeof(struct nfgenmsg)),
        [NFT_MSG_NEWSET]     = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_set,          sizeof(struct nfgenmsg)),
        [NFT_MSG_NEWSETELEM] = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_setelem_list, sizeof(struct nfgenmsg)),
        [NFT_MSG_DELSETELEM] = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_nft_setelem_list, sizeof(struct nfgenmsg)),
};

DEFINE_POLICY_SET(nfnl_subsys_nft);

static const NLAPolicy nfnl_msg_batch_policies[] = {
        [NFNL_BATCH_GENID] = BUILD_POLICY(U32)
};

DEFINE_POLICY_SET(nfnl_msg_batch);

static const NLAPolicy nfnl_subsys_none_policies[] = {
        [NFNL_MSG_BATCH_BEGIN] = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_msg_batch, sizeof(struct nfgenmsg)),
        [NFNL_MSG_BATCH_END]   = BUILD_POLICY_NESTED_WITH_SIZE(nfnl_msg_batch, sizeof(struct nfgenmsg)),
};

DEFINE_POLICY_SET(nfnl_subsys_none);

static const NLAPolicy nfnl_policies[] = {
        [NFNL_SUBSYS_NONE]     = BUILD_POLICY_NESTED(nfnl_subsys_none),
        [NFNL_SUBSYS_NFTABLES] = BUILD_POLICY_NESTED(nfnl_subsys_nft),
};

DEFINE_POLICY_SET(nfnl);

const NLAPolicy *nfnl_get_policy(uint16_t nlmsg_type) {
        const NLAPolicySet *subsys;

        subsys = policy_set_get_policy_set(&nfnl_policy_set, NFNL_SUBSYS_ID(nlmsg_type));
        if (!subsys)
                return NULL;

        return policy_set_get_policy(subsys, NFNL_MSG_TYPE(nlmsg_type));
}

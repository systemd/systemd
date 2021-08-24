/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"
#include "netlink-types.h"

struct NLType {
        uint16_t type;
        size_t size;
        const NLTypeSystem *type_system;
        const NLTypeSystemUnion *type_system_union;
};

struct NLTypeSystem {
        uint16_t count;
        const NLType *types;
};

struct NLTypeSystemUnion {
        int num;
        NLMatchType match_type;
        uint16_t match_attribute;
        int (*lookup)(const char *);
        const NLTypeSystem *type_systems;
};

typedef enum NLUnionLinkInfoData {
        NL_UNION_LINK_INFO_DATA_BOND,
        NL_UNION_LINK_INFO_DATA_BRIDGE,
        NL_UNION_LINK_INFO_DATA_VLAN,
        NL_UNION_LINK_INFO_DATA_VETH,
        NL_UNION_LINK_INFO_DATA_DUMMY,
        NL_UNION_LINK_INFO_DATA_MACVLAN,
        NL_UNION_LINK_INFO_DATA_MACVTAP,
        NL_UNION_LINK_INFO_DATA_IPVLAN,
        NL_UNION_LINK_INFO_DATA_IPVTAP,
        NL_UNION_LINK_INFO_DATA_VXLAN,
        NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL,
        NL_UNION_LINK_INFO_DATA_ERSPAN,
        NL_UNION_LINK_INFO_DATA_IPGRETAP_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IP6GRE_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IP6GRETAP_TUNNEL,
        NL_UNION_LINK_INFO_DATA_SIT_TUNNEL,
        NL_UNION_LINK_INFO_DATA_VTI_TUNNEL,
        NL_UNION_LINK_INFO_DATA_VTI6_TUNNEL,
        NL_UNION_LINK_INFO_DATA_IP6TNL_TUNNEL,
        NL_UNION_LINK_INFO_DATA_VRF,
        NL_UNION_LINK_INFO_DATA_VCAN,
        NL_UNION_LINK_INFO_DATA_GENEVE,
        NL_UNION_LINK_INFO_DATA_VXCAN,
        NL_UNION_LINK_INFO_DATA_WIREGUARD,
        NL_UNION_LINK_INFO_DATA_NETDEVSIM,
        NL_UNION_LINK_INFO_DATA_CAN,
        NL_UNION_LINK_INFO_DATA_MACSEC,
        NL_UNION_LINK_INFO_DATA_NLMON,
        NL_UNION_LINK_INFO_DATA_XFRM,
        NL_UNION_LINK_INFO_DATA_IFB,
        NL_UNION_LINK_INFO_DATA_BAREUDP,
        NL_UNION_LINK_INFO_DATA_BATADV,
        _NL_UNION_LINK_INFO_DATA_MAX,
        _NL_UNION_LINK_INFO_DATA_INVALID = -EINVAL,
} NLUnionLinkInfoData;

const char *nl_union_link_info_data_to_string(NLUnionLinkInfoData p) _const_;
NLUnionLinkInfoData nl_union_link_info_data_from_string(const char *p) _pure_;

typedef enum NLUnionTCAOptionData {
        NL_UNION_TCA_OPTION_DATA_CAKE,
        NL_UNION_TCA_OPTION_DATA_CODEL,
        NL_UNION_TCA_OPTION_DATA_DRR,
        NL_UNION_TCA_OPTION_DATA_ETS,
        NL_UNION_TCA_OPTION_DATA_FQ,
        NL_UNION_TCA_OPTION_DATA_FQ_CODEL,
        NL_UNION_TCA_OPTION_DATA_FQ_PIE,
        NL_UNION_TCA_OPTION_DATA_GRED,
        NL_UNION_TCA_OPTION_DATA_HHF,
        NL_UNION_TCA_OPTION_DATA_HTB,
        NL_UNION_TCA_OPTION_DATA_PIE,
        NL_UNION_TCA_OPTION_DATA_QFQ,
        NL_UNION_TCA_OPTION_DATA_SFB,
        NL_UNION_TCA_OPTION_DATA_TBF,
        _NL_UNION_TCA_OPTION_DATA_MAX,
        _NL_UNION_TCA_OPTION_DATA_INVALID = -EINVAL,
} NLUnionTCAOptionData;

const char *nl_union_tca_option_data_to_string(NLUnionTCAOptionData p) _const_;
NLUnionTCAOptionData nl_union_tca_option_data_from_string(const char *p) _pure_;

typedef enum NLUnionNFTExprData {
        NL_UNION_NFT_EXPR_DATA_BITWISE,
        NL_UNION_NFT_EXPR_DATA_CMP,
        NL_UNION_NFT_EXPR_DATA_FIB,
        NL_UNION_NFT_EXPR_DATA_LOOKUP,
        NL_UNION_NFT_EXPR_DATA_PAYLOAD,
        NL_UNION_NFT_EXPR_DATA_MASQ,
        NL_UNION_NFT_EXPR_DATA_META,
        NL_UNION_NFT_EXPR_DATA_NAT,
        _NL_UNION_NFT_EXPR_DATA_MAX,
        _NL_UNION_NFT_EXPR_DATA_INVALID = -EINVAL,
} NLUnionNFTExprData;

const char *nl_union_nft_expr_data_to_string(NLUnionNFTExprData p) _const_;
NLUnionNFTExprData nl_union_nft_expr_data_from_string(const char *p) _pure_;

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/batman_adv.h>
#include <linux/devlink.h>
#include <linux/fou.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_macsec.h>
#include <linux/l2tp.h>
#include <linux/nl80211.h>
#include <linux/wireguard.h>

#include "netlink-genl.h"
#include "netlink-types-internal.h"

/***************** genl ctrl type systems *****************/
static const NLType genl_ctrl_mcast_group_types[] = {
        [CTRL_ATTR_MCAST_GRP_NAME]  = { .type = NETLINK_TYPE_STRING },
        [CTRL_ATTR_MCAST_GRP_ID]    = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(genl_ctrl_mcast_group);

static const NLType genl_ctrl_ops_types[] = {
        [CTRL_ATTR_OP_ID]           = { .type = NETLINK_TYPE_U32 },
        [CTRL_ATTR_OP_FLAGS]        = { .type = NETLINK_TYPE_U32 },
};

DEFINE_TYPE_SYSTEM(genl_ctrl_ops);

static const NLType genl_ctrl_types[] = {
        [CTRL_ATTR_FAMILY_ID]    = { .type = NETLINK_TYPE_U16 },
        [CTRL_ATTR_FAMILY_NAME]  = { .type = NETLINK_TYPE_STRING },
        [CTRL_ATTR_VERSION]      = { .type = NETLINK_TYPE_U32 },
        [CTRL_ATTR_HDRSIZE]      = { .type = NETLINK_TYPE_U32 },
        [CTRL_ATTR_MAXATTR]      = { .type = NETLINK_TYPE_U32 },
        [CTRL_ATTR_OPS]          = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_ctrl_ops_type_system },
        [CTRL_ATTR_MCAST_GROUPS] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_ctrl_mcast_group_type_system },
        /*
        [CTRL_ATTR_POLICY]       = { .type = NETLINK_TYPE_NESTED, },
        [CTRL_ATTR_OP_POLICY]    = { .type = NETLINK_TYPE_NESTED, }
        */
        [CTRL_ATTR_OP]           = { .type = NETLINK_TYPE_U32 },
};

/***************** genl batadv type systems *****************/
static const NLType genl_batadv_types[] = {
        [BATADV_ATTR_VERSION]                       = { .type = NETLINK_TYPE_STRING },
        [BATADV_ATTR_ALGO_NAME]                     = { .type = NETLINK_TYPE_STRING },
        [BATADV_ATTR_MESH_IFINDEX]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_MESH_IFNAME]                   = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ },
        [BATADV_ATTR_MESH_ADDRESS]                  = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_HARD_IFINDEX]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_HARD_IFNAME]                   = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ },
        [BATADV_ATTR_HARD_ADDRESS]                  = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_ORIG_ADDRESS]                  = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_TPMETER_RESULT]                = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_TPMETER_TEST_TIME]             = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_TPMETER_BYTES]                 = { .type = NETLINK_TYPE_U64 },
        [BATADV_ATTR_TPMETER_COOKIE]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_PAD]                           = { .type = NETLINK_TYPE_UNSPEC },
        [BATADV_ATTR_ACTIVE]                        = { .type = NETLINK_TYPE_FLAG },
        [BATADV_ATTR_TT_ADDRESS]                    = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_TT_TTVN]                       = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_TT_LAST_TTVN]                  = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_TT_CRC32]                      = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_TT_VID]                        = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_TT_FLAGS]                      = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_FLAG_BEST]                     = { .type = NETLINK_TYPE_FLAG },
        [BATADV_ATTR_LAST_SEEN_MSECS]               = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_NEIGH_ADDRESS]                 = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_TQ]                            = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_THROUGHPUT]                    = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_BANDWIDTH_UP]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_BANDWIDTH_DOWN]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_ROUTER]                        = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_BLA_OWN]                       = { .type = NETLINK_TYPE_FLAG },
        [BATADV_ATTR_BLA_ADDRESS]                   = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_BLA_VID]                       = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_BLA_BACKBONE]                  = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_BLA_CRC]                       = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_DAT_CACHE_IP4ADDRESS]          = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_DAT_CACHE_HWADDRESS]           = { .type = NETLINK_TYPE_ETHER_ADDR, .size = ETH_ALEN },
        [BATADV_ATTR_DAT_CACHE_VID]                 = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_MCAST_FLAGS]                   = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_MCAST_FLAGS_PRIV]              = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_VLANID]                        = { .type = NETLINK_TYPE_U16 },
        [BATADV_ATTR_AGGREGATED_OGMS_ENABLED]       = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_AP_ISOLATION_ENABLED]          = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_ISOLATION_MARK]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_ISOLATION_MASK]                = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_BONDING_ENABLED]               = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED] = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED] = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_FRAGMENTATION_ENABLED]         = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_GW_BANDWIDTH_DOWN]             = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_GW_BANDWIDTH_UP]               = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_GW_MODE]                       = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_GW_SEL_CLASS]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_HOP_PENALTY]                   = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_LOG_LEVEL]                     = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED]  = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_MULTICAST_FANOUT]              = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_NETWORK_CODING_ENABLED]        = { .type = NETLINK_TYPE_U8 },
        [BATADV_ATTR_ORIG_INTERVAL]                 = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_ELP_INTERVAL]                  = { .type = NETLINK_TYPE_U32 },
        [BATADV_ATTR_THROUGHPUT_OVERRIDE]           = { .type = NETLINK_TYPE_U32 },
};

/***************** genl devlink type systems *****************/
static const NLType genl_devlink_stats_types[] = {
        [DEVLINK_ATTR_STATS_RX_PACKETS] = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_STATS_RX_BYTES]   = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_STATS_RX_DROPPED] = { .type = NETLINK_TYPE_U64 },
};

DEFINE_TYPE_SYSTEM(genl_devlink_stats);

static const NLType genl_devlink_trap_metadata_types[] = {
        [DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT]   = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE] = { .type = NETLINK_TYPE_FLAG },
};

DEFINE_TYPE_SYSTEM(genl_devlink_trap_metadata);

static const NLType genl_devlink_port_function_types[] = {
        [DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR] = { .type = NETLINK_TYPE_ETHER_ADDR },
        [DEVLINK_PORT_FN_ATTR_STATE]         = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_PORT_FN_ATTR_OPSTATE]       = { .type = NETLINK_TYPE_U8 },
};

DEFINE_TYPE_SYSTEM(genl_devlink_port_function);

static const NLTypeSystem genl_devlink_type_system;
static const NLType genl_devlink_types[] = {
        [DEVLINK_ATTR_BUS_NAME]                        = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_DEV_NAME]                        = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_PORT_INDEX]                      = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_PORT_TYPE]                       = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_PORT_DESIRED_TYPE]               = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_PORT_NETDEV_IFINDEX]             = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_PORT_NETDEV_NAME]                = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_PORT_IBDEV_NAME]                 = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_PORT_SPLIT_COUNT]                = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_PORT_SPLIT_GROUP]                = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_SB_INDEX]                        = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_SB_SIZE]                         = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_SB_INGRESS_POOL_COUNT]           = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_SB_EGRESS_POOL_COUNT]            = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_SB_INGRESS_TC_COUNT]             = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_SB_EGRESS_TC_COUNT]              = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_SB_POOL_INDEX]                   = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_SB_POOL_TYPE]                    = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_SB_POOL_SIZE]                    = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE]          = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_SB_THRESHOLD]                    = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_SB_TC_INDEX]                     = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_SB_OCC_CUR]                      = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_SB_OCC_MAX]                      = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_ESWITCH_MODE]                    = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_ESWITCH_INLINE_MODE]             = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_DPIPE_TABLES]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_DPIPE_TABLE */
        [DEVLINK_ATTR_DPIPE_TABLE]                     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_DPIPE_TABLE_* */
        [DEVLINK_ATTR_DPIPE_TABLE_NAME]                = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_DPIPE_TABLE_SIZE]                = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_DPIPE_TABLE_MATCHES]             = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system },
        [DEVLINK_ATTR_DPIPE_TABLE_ACTIONS]             = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system },
        [DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED]    = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_DPIPE_ENTRIES]                   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_DPIPE_ENTRY */
        [DEVLINK_ATTR_DPIPE_ENTRY]                     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_DPIPE_ENTRY_* */
        [DEVLINK_ATTR_DPIPE_ENTRY_INDEX]               = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES]        = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_DPIPE_MATCH_VALUE */
        [DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES]       = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_DPIPE_ACTION_VALUE */
        [DEVLINK_ATTR_DPIPE_ENTRY_COUNTER]             = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_DPIPE_MATCH]                     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system },
        [DEVLINK_ATTR_DPIPE_MATCH_VALUE]               = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system },
        [DEVLINK_ATTR_DPIPE_MATCH_TYPE]                = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_ACTION]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system },
        [DEVLINK_ATTR_DPIPE_ACTION_VALUE]              = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system },
        [DEVLINK_ATTR_DPIPE_ACTION_TYPE]               = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_VALUE]                     = { .type = NETLINK_TYPE_BINARY },
        [DEVLINK_ATTR_DPIPE_VALUE_MASK]                = { .type = NETLINK_TYPE_BINARY },
        [DEVLINK_ATTR_DPIPE_VALUE_MAPPING]             = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_HEADERS]                   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_DPIPE_HEADER */
        [DEVLINK_ATTR_DPIPE_HEADER]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_DPIPE_HEADER_* */
        [DEVLINK_ATTR_DPIPE_HEADER_NAME]               = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_DPIPE_HEADER_ID]                 = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_HEADER_FIELDS]             = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_DPIPE_FIELD */
        [DEVLINK_ATTR_DPIPE_HEADER_GLOBAL]             = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_DPIPE_HEADER_INDEX]              = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_FIELD]                     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_DPIPE_FIELD_* */
        [DEVLINK_ATTR_DPIPE_FIELD_NAME]                = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_DPIPE_FIELD_ID]                  = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH]            = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE]        = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_ESWITCH_ENCAP_MODE]              = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_RESOURCE_LIST]                   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_RESOURCE */
        [DEVLINK_ATTR_RESOURCE]                        = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_RESOURCE_* */
        [DEVLINK_ATTR_RESOURCE_NAME]                   = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_RESOURCE_ID]                     = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RESOURCE_SIZE]                   = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RESOURCE_SIZE_NEW]               = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RESOURCE_SIZE_VALID]             = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_RESOURCE_SIZE_MIN]               = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RESOURCE_SIZE_MAX]               = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RESOURCE_SIZE_GRAN]              = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RESOURCE_UNIT]                   = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_RESOURCE_OCC]                    = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID]         = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS]      = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_PORT_FLAVOUR]                    = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_PORT_NUMBER]                     = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER]       = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_PARAM]                           = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_PARAM_* */
        [DEVLINK_ATTR_PARAM_NAME]                      = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_PARAM_GENERIC]                   = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_PARAM_TYPE]                      = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_PARAM_VALUES_LIST]               = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_PARAM_VALUE */
        [DEVLINK_ATTR_PARAM_VALUE]                     = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_PARAM_VALUE_* */
        [DEVLINK_ATTR_PARAM_VALUE_DATA]                = { .type = NETLINK_TYPE_BINARY }, /* u8, u16, u32, string, or flag */
        [DEVLINK_ATTR_PARAM_VALUE_CMODE]               = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_REGION_NAME]                     = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_REGION_SIZE]                     = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_REGION_SNAPSHOTS]                = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_REGION_SNAPSHOT */
        [DEVLINK_ATTR_REGION_SNAPSHOT]                 = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_REGION_SNAPSHOT_* */
        [DEVLINK_ATTR_REGION_SNAPSHOT_ID]              = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_REGION_CHUNKS]                   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_REGION_CHUNK */
        [DEVLINK_ATTR_REGION_CHUNK]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_REGION_CHUNK_* */
        [DEVLINK_ATTR_REGION_CHUNK_DATA]               = { .type = NETLINK_TYPE_BINARY }, /* see devlink_nl_cmd_region_read_chunk_fill() */
        [DEVLINK_ATTR_REGION_CHUNK_ADDR]               = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_REGION_CHUNK_LEN]                = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_INFO_DRIVER_NAME]                = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_INFO_SERIAL_NUMBER]              = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_INFO_VERSION_FIXED]              = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_INFO_VERSION_* */
        [DEVLINK_ATTR_INFO_VERSION_RUNNING]            = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_INFO_VERSION_* */
        [DEVLINK_ATTR_INFO_VERSION_STORED]             = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_INFO_VERSION_* */
        [DEVLINK_ATTR_INFO_VERSION_NAME]               = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_INFO_VERSION_VALUE]              = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_SB_POOL_CELL_SIZE]               = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_FMSG]                            = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_FMSG_* */
        [DEVLINK_ATTR_FMSG_OBJ_NEST_START]             = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_FMSG_PAIR_NEST_START]            = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_FMSG_ARR_NEST_START]             = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_FMSG_NEST_END]                   = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_FMSG_OBJ_NAME]                   = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE]             = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA]             = { .type = NETLINK_TYPE_BINARY }, /* see devlink_fmsg_item_fill_data() */
        [DEVLINK_ATTR_HEALTH_REPORTER]                 = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_HEALTH_REPORTER_* */
        [DEVLINK_ATTR_HEALTH_REPORTER_NAME]            = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_HEALTH_REPORTER_STATE]           = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT]       = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT]   = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS]         = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD] = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER]    = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME]          = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_FLASH_UPDATE_COMPONENT]          = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG]         = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE]        = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL]       = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_PORT_PCI_PF_NUMBER]              = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_PORT_PCI_VF_NUMBER]              = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_STATS]                           = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_stats_type_system },
        [DEVLINK_ATTR_TRAP_NAME]                       = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_TRAP_ACTION]                     = { .type = NETLINK_TYPE_U8 }, /* enum devlink_trap_action */
        [DEVLINK_ATTR_TRAP_TYPE]                       = { .type = NETLINK_TYPE_U8 }, /* enum devlink_trap_type */
        [DEVLINK_ATTR_TRAP_GENERIC]                    = { .type = NETLINK_TYPE_FLAG },
        [DEVLINK_ATTR_TRAP_METADATA]                   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_trap_metadata_type_system },
        [DEVLINK_ATTR_TRAP_GROUP_NAME]                 = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_RELOAD_FAILED]                   = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS]      = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_NETNS_FD]                        = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_NETNS_PID]                       = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_NETNS_ID]                        = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP]       = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_TRAP_POLICER_ID]                 = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_TRAP_POLICER_RATE]               = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_TRAP_POLICER_BURST]              = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_PORT_FUNCTION]                   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_port_function_type_system },
        [DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER]        = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_PORT_LANES]                      = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_PORT_SPLITTABLE]                 = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_PORT_EXTERNAL]                   = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_PORT_CONTROLLER_NUMBER]          = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT]     = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK]     = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_RELOAD_ACTION]                   = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED]        = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_RELOAD_LIMITS]                   = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_DEV_STATS]                       = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_{,REMOTE_}RELOAD_STATS */
        [DEVLINK_ATTR_RELOAD_STATS]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_RELOAD_ACTION_INFO */
        [DEVLINK_ATTR_RELOAD_STATS_ENTRY]              = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_RELOAD_STATS_LIMIT and _VALUE */
        [DEVLINK_ATTR_RELOAD_STATS_LIMIT]              = { .type = NETLINK_TYPE_U8 },
        [DEVLINK_ATTR_RELOAD_STATS_VALUE]              = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_REMOTE_RELOAD_STATS]             = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_RELOAD_ACTION_INFO */
        [DEVLINK_ATTR_RELOAD_ACTION_INFO]              = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* takes DEVLINK_ATTR_RELOAD_ACTION_STATS */
        [DEVLINK_ATTR_RELOAD_ACTION_STATS]             = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_devlink_type_system }, /* array of DEVLINK_ATTR_RELOAD_STATS_ENTRY */
        [DEVLINK_ATTR_PORT_PCI_SF_NUMBER]              = { .type = NETLINK_TYPE_U32 },
        [DEVLINK_ATTR_RATE_TYPE]                       = { .type = NETLINK_TYPE_U16 },
        [DEVLINK_ATTR_RATE_TX_SHARE]                   = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RATE_TX_MAX]                     = { .type = NETLINK_TYPE_U64 },
        [DEVLINK_ATTR_RATE_NODE_NAME]                  = { .type = NETLINK_TYPE_STRING },
        [DEVLINK_ATTR_RATE_PARENT_NODE_NAME]           = { .type = NETLINK_TYPE_STRING },
};

/***************** genl fou type systems *****************/
static const NLType genl_fou_types[] = {
        [FOU_ATTR_PORT]              = { .type = NETLINK_TYPE_U16 },
        [FOU_ATTR_AF]                = { .type = NETLINK_TYPE_U8 },
        [FOU_ATTR_IPPROTO]           = { .type = NETLINK_TYPE_U8 },
        [FOU_ATTR_TYPE]              = { .type = NETLINK_TYPE_U8 },
        [FOU_ATTR_REMCSUM_NOPARTIAL] = { .type = NETLINK_TYPE_FLAG },
        [FOU_ATTR_LOCAL_V4]          = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_PEER_V4]           = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_LOCAL_V6]          = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_PEER_V6]           = { .type = NETLINK_TYPE_IN_ADDR },
        [FOU_ATTR_PEER_PORT]         = { .type = NETLINK_TYPE_U16 },
        [FOU_ATTR_IFINDEX]           = { .type = NETLINK_TYPE_U32 },
};

/***************** genl l2tp type systems *****************/
static const NLType genl_l2tp_types[] = {
        [L2TP_ATTR_PW_TYPE]           = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_ENCAP_TYPE]        = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_OFFSET]            = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_DATA_SEQ]          = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_L2SPEC_TYPE]       = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_L2SPEC_LEN]        = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_PROTO_VERSION]     = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_IFNAME]            = { .type = NETLINK_TYPE_STRING },
        [L2TP_ATTR_CONN_ID]           = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_PEER_CONN_ID]      = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_SESSION_ID]        = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_PEER_SESSION_ID]   = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_UDP_CSUM]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_VLAN_ID]           = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_RECV_SEQ]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_SEND_SEQ]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_LNS_MODE]          = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_USING_IPSEC]       = { .type = NETLINK_TYPE_U8 },
        [L2TP_ATTR_FD]                = { .type = NETLINK_TYPE_U32 },
        [L2TP_ATTR_IP_SADDR]          = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_IP_DADDR]          = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_UDP_SPORT]         = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_UDP_DPORT]         = { .type = NETLINK_TYPE_U16 },
        [L2TP_ATTR_IP6_SADDR]         = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_IP6_DADDR]         = { .type = NETLINK_TYPE_IN_ADDR },
        [L2TP_ATTR_UDP_ZERO_CSUM6_TX] = { .type = NETLINK_TYPE_FLAG },
        [L2TP_ATTR_UDP_ZERO_CSUM6_RX] = { .type = NETLINK_TYPE_FLAG },
};

/***************** genl macsec type systems *****************/
static const NLType genl_macsec_rxsc_types[] = {
        [MACSEC_RXSC_ATTR_SCI] = { .type = NETLINK_TYPE_U64 },
};

DEFINE_TYPE_SYSTEM(genl_macsec_rxsc);

static const NLType genl_macsec_sa_types[] = {
        [MACSEC_SA_ATTR_AN]     = { .type = NETLINK_TYPE_U8 },
        [MACSEC_SA_ATTR_ACTIVE] = { .type = NETLINK_TYPE_U8 },
        [MACSEC_SA_ATTR_PN]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_SA_ATTR_KEYID]  = { .type = NETLINK_TYPE_BINARY, .size = MACSEC_KEYID_LEN },
        [MACSEC_SA_ATTR_KEY]    = { .type = NETLINK_TYPE_BINARY, .size = MACSEC_MAX_KEY_LEN },
};

DEFINE_TYPE_SYSTEM(genl_macsec_sa);

static const NLType genl_macsec_types[] = {
        [MACSEC_ATTR_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
        [MACSEC_ATTR_RXSC_CONFIG] = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_rxsc_type_system },
        [MACSEC_ATTR_SA_CONFIG]   = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_macsec_sa_type_system },
};

/***************** genl nl80211 type systems *****************/
static const NLType genl_nl80211_types[] = {
        [NL80211_ATTR_IFINDEX] = { .type = NETLINK_TYPE_U32 },
        [NL80211_ATTR_MAC]     = { .type = NETLINK_TYPE_ETHER_ADDR },
        [NL80211_ATTR_SSID]    = { .type = NETLINK_TYPE_STRING },
        [NL80211_ATTR_IFTYPE]  = { .type = NETLINK_TYPE_U32 },
};

/***************** genl wireguard type systems *****************/
static const NLType genl_wireguard_allowedip_types[] = {
        [WGALLOWEDIP_A_FAMILY]    = { .type = NETLINK_TYPE_U16 },
        [WGALLOWEDIP_A_IPADDR]    = { .type = NETLINK_TYPE_IN_ADDR },
        [WGALLOWEDIP_A_CIDR_MASK] = { .type = NETLINK_TYPE_U8 },
};

DEFINE_TYPE_SYSTEM(genl_wireguard_allowedip);

static const NLType genl_wireguard_peer_types[] = {
        [WGPEER_A_PUBLIC_KEY]                    = { .type = NETLINK_TYPE_BINARY, .size = WG_KEY_LEN },
        [WGPEER_A_FLAGS]                         = { .type = NETLINK_TYPE_U32 },
        [WGPEER_A_PRESHARED_KEY]                 = { .type = NETLINK_TYPE_BINARY, .size = WG_KEY_LEN },
        [WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL] = { .type = NETLINK_TYPE_U16 },
        [WGPEER_A_ENDPOINT]                      = { .type = NETLINK_TYPE_SOCKADDR },
        [WGPEER_A_ALLOWEDIPS]                    = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_allowedip_type_system },
};

DEFINE_TYPE_SYSTEM(genl_wireguard_peer);

static const NLType genl_wireguard_types[] = {
        [WGDEVICE_A_IFINDEX]     = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_IFNAME]      = { .type = NETLINK_TYPE_STRING, .size = IFNAMSIZ-1 },
        [WGDEVICE_A_FLAGS]       = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_PRIVATE_KEY] = { .type = NETLINK_TYPE_BINARY, .size = WG_KEY_LEN },
        [WGDEVICE_A_LISTEN_PORT] = { .type = NETLINK_TYPE_U16 },
        [WGDEVICE_A_FWMARK]      = { .type = NETLINK_TYPE_U32 },
        [WGDEVICE_A_PEERS]       = { .type = NETLINK_TYPE_NESTED, .type_system = &genl_wireguard_peer_type_system },
};

/***************** genl families *****************/
static const NLTypeSystemUnionElement genl_type_systems[] = {
        { .name = CTRL_GENL_NAME,    .type_system = TYPE_SYSTEM_FROM_TYPE(genl_ctrl),      },
        { .name = BATADV_NL_NAME,    .type_system = TYPE_SYSTEM_FROM_TYPE(genl_batadv),    },
        { .name = DEVLINK_GENL_NAME, .type_system = TYPE_SYSTEM_FROM_TYPE(genl_devlink),   },
        { .name = FOU_GENL_NAME,     .type_system = TYPE_SYSTEM_FROM_TYPE(genl_fou),       },
        { .name = L2TP_GENL_NAME,    .type_system = TYPE_SYSTEM_FROM_TYPE(genl_l2tp),      },
        { .name = MACSEC_GENL_NAME,  .type_system = TYPE_SYSTEM_FROM_TYPE(genl_macsec),    },
        { .name = NL80211_GENL_NAME, .type_system = TYPE_SYSTEM_FROM_TYPE(genl_nl80211),   },
        { .name = WG_GENL_NAME,      .type_system = TYPE_SYSTEM_FROM_TYPE(genl_wireguard), },
};

/* This is the root type system union, so match_attribute is not necessary. */
DEFINE_TYPE_SYSTEM_UNION_MATCH_SIBLING(genl, 0);

const NLTypeSystem *genl_get_type_system_by_name(const char *name) {
        return type_system_union_get_type_system_by_string(&genl_type_system_union, name);
}

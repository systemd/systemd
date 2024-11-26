/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "hash-funcs.h"
#include "list.h"
#include "log-link.h"
#include "netdev-util.h"
#include "networkd-link.h"
#include "time-util.h"

/* Special hardware address value to suppress generating persistent hardware address for the netdev. */
#define HW_ADDR_NONE ((struct hw_addr_data) { .length = 1, })

#define NETDEV_COMMON_SECTIONS "Match\0NetDev\0"
/* This is the list of known sections. We need to ignore them in the initial parsing phase. */
#define NETDEV_OTHER_SECTIONS                     \
        "-BareUDP\0"                              \
        "-BatmanAdvanced\0"                       \
        "-Bond\0"                                 \
        "-Bridge\0"                               \
        "-FooOverUDP\0"                           \
        "-GENEVE\0"                               \
        "-IPoIB\0"                                \
        "-IPVLAN\0"                               \
        "-IPVTAP\0"                               \
        "-L2TP\0"                                 \
        "-L2TPSession\0"                          \
        "-MACsec\0"                               \
        "-MACsecReceiveAssociation\0"             \
        "-MACsecReceiveChannel\0"                 \
        "-MACsecTransmitAssociation\0"            \
        "-MACVLAN\0"                              \
        "-MACVTAP\0"                              \
        "-Peer\0"                                 \
        "-Tap\0"                                  \
        "-Tun\0"                                  \
        "-Tunnel\0"                               \
        "-VLAN\0"                                 \
        "-VRF\0"                                  \
        "-VXCAN\0"                                \
        "-VXLAN\0"                                \
        "-WLAN\0"                                 \
        "-WireGuard\0"                            \
        "-WireGuardPeer\0"                        \
        "-Xfrm\0"

typedef enum NetDevKind {
        NETDEV_KIND_BAREUDP,
        NETDEV_KIND_BATADV,
        NETDEV_KIND_BOND,
        NETDEV_KIND_BRIDGE,
        NETDEV_KIND_DUMMY,
        NETDEV_KIND_ERSPAN,
        NETDEV_KIND_FOU,
        NETDEV_KIND_GENEVE,
        NETDEV_KIND_GRE,
        NETDEV_KIND_GRETAP,
        NETDEV_KIND_IFB,
        NETDEV_KIND_IP6GRE,
        NETDEV_KIND_IP6GRETAP,
        NETDEV_KIND_IP6TNL,
        NETDEV_KIND_IPIP,
        NETDEV_KIND_IPOIB,
        NETDEV_KIND_IPVLAN,
        NETDEV_KIND_IPVTAP,
        NETDEV_KIND_L2TP,
        NETDEV_KIND_MACSEC,
        NETDEV_KIND_MACVLAN,
        NETDEV_KIND_MACVTAP,
        NETDEV_KIND_NETDEVSIM,
        NETDEV_KIND_NLMON,
        NETDEV_KIND_SIT,
        NETDEV_KIND_TAP,
        NETDEV_KIND_TUN,
        NETDEV_KIND_VCAN,
        NETDEV_KIND_VETH,
        NETDEV_KIND_VLAN,
        NETDEV_KIND_VRF,
        NETDEV_KIND_VTI,
        NETDEV_KIND_VTI6,
        NETDEV_KIND_VXCAN,
        NETDEV_KIND_VXLAN,
        NETDEV_KIND_WIREGUARD,
        NETDEV_KIND_WLAN,
        NETDEV_KIND_XFRM,
        _NETDEV_KIND_MAX,
        _NETDEV_KIND_TUNNEL, /* Used by config_parse_stacked_netdev() */
        _NETDEV_KIND_INVALID = -EINVAL,
} NetDevKind;

typedef enum NetDevState {
        NETDEV_STATE_LOADING,
        NETDEV_STATE_FAILED,
        NETDEV_STATE_CREATING,
        NETDEV_STATE_READY,
        NETDEV_STATE_LINGER,
        _NETDEV_STATE_MAX,
        _NETDEV_STATE_INVALID = -EINVAL,
} NetDevState;

typedef enum NetDevCreateType {
        NETDEV_CREATE_INDEPENDENT,
        NETDEV_CREATE_STACKED,
        _NETDEV_CREATE_MAX,
        _NETDEV_CREATE_INVALID = -EINVAL,
} NetDevCreateType;

typedef struct Manager Manager;
typedef struct Condition Condition;

typedef struct NetDev {
        Manager *manager;

        unsigned n_ref;

        char *filename;
        char **dropins;
        Hashmap *stats_by_path;

        LIST_HEAD(Condition, conditions);

        NetDevState state;
        NetDevKind kind;
        char *description;
        char *ifname;
        struct hw_addr_data hw_addr;
        uint32_t mtu;
        int ifindex;
} NetDev;

typedef struct NetDevVTable {
        /* How much memory does an object of this unit type need */
        size_t object_size;

        /* Config file sections this netdev kind understands, separated
         * by NUL chars */
        const char *sections;

        /* This should reset all type-specific variables. This should
         * not allocate memory, and is called with zero-initialized
         * data. It should hence only initialize variables that need
         * to be set != 0. */
        void (*init)(NetDev *n);

        /* This is called when the interface is removed. */
        void (*drop)(NetDev *n);

        /* This should free all kind-specific variables. It should be
         * idempotent. */
        void (*done)(NetDev *n);

        /* fill in message to create netdev */
        int (*fill_message_create)(NetDev *netdev, Link *link, sd_netlink_message *message);

        /* specifies if netdev is independent, or a master device or a stacked device */
        NetDevCreateType create_type;

        /* This is used for stacked netdev. Return true when the underlying link is ready. */
        int (*is_ready_to_create)(NetDev *netdev, Link *link);

        /* create netdev, if not done via rtnl */
        int (*create)(NetDev *netdev);

        /* perform additional configuration after netdev has been createad */
        int (*post_create)(NetDev *netdev, Link *link);

        /* verify that compulsory configuration options were specified */
        int (*config_verify)(NetDev *netdev, const char *filename);

        /* attach/detach additional interfaces, e.g. veth peer or L2TP sessions. */
        int (*attach)(NetDev *netdev);
        void (*detach)(NetDev *netdev);

        /* set ifindex of the created interface. */
        int (*set_ifindex)(NetDev *netdev, const char *name, int ifindex);

        /* get ifindex of the netdev. */
        int (*get_ifindex)(NetDev *netdev, const char *name);

        /* provides if MAC address can be set. If this is not set, assumed to be yes. */
        bool (*can_set_mac)(NetDev *netdev, const struct hw_addr_data *hw_addr);

        /* provides if MTU can be set. If this is not set, assumed to be yes. */
        bool (*can_set_mtu)(NetDev *netdev, uint32_t mtu);

        /* provides if the netdev needs to be reconfigured when a specified type of address on the underlying
         * interface is updated. */
        bool (*needs_reconfigure)(NetDev *netdev, NetDevLocalAddressType type);

        /* expected iftype, e.g. ARPHRD_ETHER. */
        uint16_t iftype;

        /* Generate MAC address when MACAddress= is not specified. */
        bool generate_mac;

        /* When assigning ifindex to the netdev, skip to check if the netdev kind matches. */
        bool skip_netdev_kind_check;

        /* Provides if the netdev can be updated, that is, whether RTM_NEWLINK with existing ifindex is supported or not.
         * If this is true, the netdev does not support updating. */
        bool keep_existing;
} NetDevVTable;

extern const NetDevVTable * const netdev_vtable[_NETDEV_KIND_MAX];

#define NETDEV_VTABLE(n) ((n)->kind != _NETDEV_KIND_INVALID ? netdev_vtable[(n)->kind] : NULL)

/* For casting a netdev into the various netdev kinds */
#define DEFINE_NETDEV_CAST(UPPERCASE, MixedCase)                        \
        static inline MixedCase* UPPERCASE(NetDev *n) {                 \
                assert(n);                                              \
                assert(n->kind == NETDEV_KIND_##UPPERCASE);             \
                assert(n->state < _NETDEV_STATE_MAX);                   \
                                                                        \
                return (MixedCase*) n;                                  \
        }

/* For casting the various netdev kinds into a netdev */
#define NETDEV(n) (&(n)->meta)

int netdev_attach_name(NetDev *netdev, const char *name);
NetDev* netdev_detach_name(NetDev *netdev, const char *name);
void netdev_detach(NetDev *netdev);
int netdev_set_ifindex_internal(NetDev *netdev, int ifindex);

int netdev_load(Manager *manager);
int netdev_reload(Manager *manager);
int netdev_load_one(Manager *manager, const char *filename, NetDev **ret);
void netdev_drop(NetDev *netdev);
void netdev_enter_failed(NetDev *netdev);
int netdev_enter_ready(NetDev *netdev);

NetDev* netdev_unref(NetDev *netdev);
NetDev* netdev_ref(NetDev *netdev);
DEFINE_TRIVIAL_DESTRUCTOR(netdev_destroy_callback, NetDev, netdev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(NetDev*, netdev_unref);

bool netdev_is_managed(NetDev *netdev);
int netdev_get(Manager *manager, const char *name, NetDev **ret);
void link_assign_netdev(Link *link);
int netdev_set_ifindex(NetDev *netdev, sd_netlink_message *newlink);
int netdev_generate_hw_addr(NetDev *netdev, Link *link, const char *name,
                            const struct hw_addr_data *hw_addr, struct hw_addr_data *ret);

bool netdev_needs_reconfigure(NetDev *netdev, NetDevLocalAddressType type);
int link_request_stacked_netdev(Link *link, NetDev *netdev);

const char* netdev_kind_to_string(NetDevKind d) _const_;
NetDevKind netdev_kind_from_string(const char *d) _pure_;

static inline NetDevCreateType netdev_get_create_type(NetDev *netdev) {
        assert(netdev);
        assert(NETDEV_VTABLE(netdev));

        return NETDEV_VTABLE(netdev)->create_type;
}

CONFIG_PARSER_PROTOTYPE(config_parse_netdev_kind);
CONFIG_PARSER_PROTOTYPE(config_parse_netdev_hw_addr);

/* gperf */
const struct ConfigPerfItem* network_netdev_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

/* Macros which append INTERFACE= to the message */

#define log_netdev_full_errno_zerook(netdev, level, error, ...)         \
        ({                                                              \
                const NetDev *_n = (netdev);                            \
                log_interface_full_errno_zerook(_n ? _n->ifname : NULL, level, error, __VA_ARGS__); \
        })

#define log_netdev_full_errno(netdev, level, error, ...) \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_netdev_full_errno_zerook(netdev, level, _error, __VA_ARGS__); \
        })

#define log_netdev_full(netdev, level, ...) (void) log_netdev_full_errno_zerook(netdev, level, 0, __VA_ARGS__)

#define log_netdev_debug(netdev, ...)   log_netdev_full(netdev, LOG_DEBUG, __VA_ARGS__)
#define log_netdev_info(netdev, ...)    log_netdev_full(netdev, LOG_INFO, __VA_ARGS__)
#define log_netdev_notice(netdev, ...)  log_netdev_full(netdev, LOG_NOTICE, __VA_ARGS__)
#define log_netdev_warning(netdev, ...) log_netdev_full(netdev, LOG_WARNING,  __VA_ARGS__)
#define log_netdev_error(netdev, ...)   log_netdev_full(netdev, LOG_ERR, __VA_ARGS__)

#define log_netdev_debug_errno(netdev, error, ...)   log_netdev_full_errno(netdev, LOG_DEBUG, error, __VA_ARGS__)
#define log_netdev_info_errno(netdev, error, ...)    log_netdev_full_errno(netdev, LOG_INFO, error, __VA_ARGS__)
#define log_netdev_notice_errno(netdev, error, ...)  log_netdev_full_errno(netdev, LOG_NOTICE, error, __VA_ARGS__)
#define log_netdev_warning_errno(netdev, error, ...) log_netdev_full_errno(netdev, LOG_WARNING, error, __VA_ARGS__)
#define log_netdev_error_errno(netdev, error, ...)   log_netdev_full_errno(netdev, LOG_ERR, error, __VA_ARGS__)

#define LOG_NETDEV_MESSAGE(netdev, fmt, ...) "MESSAGE=%s: " fmt, (netdev)->ifname, ##__VA_ARGS__
#define LOG_NETDEV_INTERFACE(netdev) "INTERFACE=%s", (netdev)->ifname

/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-netlink.h"

#include "conf-parser.h"
#include "list.h"
#include "../networkd-link.h"
#include "time-util.h"

typedef struct netdev_join_callback netdev_join_callback;

struct netdev_join_callback {
        link_netlink_message_handler_t callback;
        Link *link;

        LIST_FIELDS(netdev_join_callback, callbacks);
};

typedef enum NetDevKind {
        NETDEV_KIND_BRIDGE,
        NETDEV_KIND_BOND,
        NETDEV_KIND_VLAN,
        NETDEV_KIND_MACVLAN,
        NETDEV_KIND_MACVTAP,
        NETDEV_KIND_IPVLAN,
        NETDEV_KIND_IPVTAP,
        NETDEV_KIND_VXLAN,
        NETDEV_KIND_IPIP,
        NETDEV_KIND_GRE,
        NETDEV_KIND_GRETAP,
        NETDEV_KIND_IP6GRE,
        NETDEV_KIND_IP6GRETAP,
        NETDEV_KIND_SIT,
        NETDEV_KIND_VETH,
        NETDEV_KIND_VTI,
        NETDEV_KIND_VTI6,
        NETDEV_KIND_IP6TNL,
        NETDEV_KIND_DUMMY,
        NETDEV_KIND_TUN,
        NETDEV_KIND_TAP,
        NETDEV_KIND_VRF,
        NETDEV_KIND_VCAN,
        NETDEV_KIND_GENEVE,
        NETDEV_KIND_VXCAN,
        NETDEV_KIND_WIREGUARD,
        NETDEV_KIND_NETDEVSIM,
        NETDEV_KIND_FOU,
        NETDEV_KIND_ERSPAN,
        NETDEV_KIND_L2TP,
        NETDEV_KIND_MACSEC,
        NETDEV_KIND_NLMON,
        NETDEV_KIND_XFRM,
        _NETDEV_KIND_MAX,
        _NETDEV_KIND_TUNNEL, /* Used by config_parse_stacked_netdev() */
        _NETDEV_KIND_INVALID = -1
} NetDevKind;

typedef enum NetDevState {
        NETDEV_STATE_LOADING,
        NETDEV_STATE_FAILED,
        NETDEV_STATE_CREATING,
        NETDEV_STATE_READY,
        NETDEV_STATE_LINGER,
        _NETDEV_STATE_MAX,
        _NETDEV_STATE_INVALID = -1,
} NetDevState;

typedef enum NetDevCreateType {
        NETDEV_CREATE_INDEPENDENT,
        NETDEV_CREATE_MASTER,
        NETDEV_CREATE_STACKED,
        NETDEV_CREATE_AFTER_CONFIGURED,
        _NETDEV_CREATE_MAX,
        _NETDEV_CREATE_INVALID = -1,
} NetDevCreateType;

typedef struct Manager Manager;
typedef struct Condition Condition;

typedef struct NetDev {
        Manager *manager;

        unsigned n_ref;

        char *filename;

        LIST_HEAD(Condition, conditions);

        NetDevState state;
        NetDevKind kind;
        char *description;
        char *ifname;
        struct ether_addr *mac;
        uint32_t mtu;
        int ifindex;

        LIST_HEAD(netdev_join_callback, callbacks);
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

        /* This should free all kind-specific variables. It should be
         * idempotent. */
        void (*done)(NetDev *n);

        /* fill in message to create netdev */
        int (*fill_message_create)(NetDev *netdev, Link *link, sd_netlink_message *message);

        /* specifies if netdev is independent, or a master device or a stacked device */
        NetDevCreateType create_type;

        /* create netdev, if not done via rtnl */
        int (*create)(NetDev *netdev);

        /* create netdev after link is fully configured */
        int (*create_after_configured)(NetDev *netdev, Link *link);

        /* perform additional configuration after netdev has been createad */
        int (*post_create)(NetDev *netdev, Link *link, sd_netlink_message *message);

        /* verify that compulsory configuration options were specified */
        int (*config_verify)(NetDev *netdev, const char *filename);

        /* Generate MAC address or not When MACAddress= is not specified. */
        bool generate_mac;
} NetDevVTable;

extern const NetDevVTable * const netdev_vtable[_NETDEV_KIND_MAX];

#define NETDEV_VTABLE(n) ((n)->kind != _NETDEV_KIND_INVALID ? netdev_vtable[(n)->kind] : NULL)

/* For casting a netdev into the various netdev kinds */
#define DEFINE_NETDEV_CAST(UPPERCASE, MixedCase)                            \
        static inline MixedCase* UPPERCASE(NetDev *n) {                     \
                if (_unlikely_(!n ||                                        \
                               n->kind != NETDEV_KIND_##UPPERCASE) ||       \
                               n->state == _NETDEV_STATE_INVALID)           \
                        return NULL;                                        \
                                                                            \
                return (MixedCase*) n;                                      \
        }

/* For casting the various netdev kinds into a netdev */
#define NETDEV(n) (&(n)->meta)

int netdev_load(Manager *manager);
int netdev_load_one(Manager *manager, const char *filename);
void netdev_drop(NetDev *netdev);

NetDev *netdev_unref(NetDev *netdev);
NetDev *netdev_ref(NetDev *netdev);
DEFINE_TRIVIAL_DESTRUCTOR(netdev_destroy_callback, NetDev, netdev_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(NetDev*, netdev_unref);

bool netdev_is_managed(NetDev *netdev);
int netdev_get(Manager *manager, const char *name, NetDev **ret);
int netdev_set_ifindex(NetDev *netdev, sd_netlink_message *newlink);
int netdev_get_mac(const char *ifname, struct ether_addr **ret);
int netdev_join(NetDev *netdev, Link *link, link_netlink_message_handler_t cb);
int netdev_join_after_configured(NetDev *netdev, Link *link, link_netlink_message_handler_t callback);

const char *netdev_kind_to_string(NetDevKind d) _const_;
NetDevKind netdev_kind_from_string(const char *d) _pure_;

static inline NetDevCreateType netdev_get_create_type(NetDev *netdev) {
        assert(netdev);
        assert(NETDEV_VTABLE(netdev));

        return NETDEV_VTABLE(netdev)->create_type;
}

CONFIG_PARSER_PROTOTYPE(config_parse_netdev_kind);

/* gperf */
const struct ConfigPerfItem* network_netdev_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

/* Macros which append INTERFACE= to the message */

#define log_netdev_full(netdev, level, error, ...)                      \
        ({                                                              \
                const NetDev *_n = (netdev);                            \
                _n ? log_object_internal(level, error, PROJECT_FILE, __LINE__, __func__, "INTERFACE=", _n->ifname, NULL, NULL, ##__VA_ARGS__) : \
                        log_internal(level, error, PROJECT_FILE, __LINE__, __func__, ##__VA_ARGS__); \
        })

#define log_netdev_debug(netdev, ...)       log_netdev_full(netdev, LOG_DEBUG, 0, ##__VA_ARGS__)
#define log_netdev_info(netdev, ...)        log_netdev_full(netdev, LOG_INFO, 0, ##__VA_ARGS__)
#define log_netdev_notice(netdev, ...)      log_netdev_full(netdev, LOG_NOTICE, 0, ##__VA_ARGS__)
#define log_netdev_warning(netdev, ...)     log_netdev_full(netdev, LOG_WARNING, 0, ## __VA_ARGS__)
#define log_netdev_error(netdev, ...)       log_netdev_full(netdev, LOG_ERR, 0, ##__VA_ARGS__)

#define log_netdev_debug_errno(netdev, error, ...)   log_netdev_full(netdev, LOG_DEBUG, error, ##__VA_ARGS__)
#define log_netdev_info_errno(netdev, error, ...)    log_netdev_full(netdev, LOG_INFO, error, ##__VA_ARGS__)
#define log_netdev_notice_errno(netdev, error, ...)  log_netdev_full(netdev, LOG_NOTICE, error, ##__VA_ARGS__)
#define log_netdev_warning_errno(netdev, error, ...) log_netdev_full(netdev, LOG_WARNING, error, ##__VA_ARGS__)
#define log_netdev_error_errno(netdev, error, ...)   log_netdev_full(netdev, LOG_ERR, error, ##__VA_ARGS__)

#define LOG_NETDEV_MESSAGE(netdev, fmt, ...) "MESSAGE=%s: " fmt, (netdev)->ifname, ##__VA_ARGS__
#define LOG_NETDEV_INTERFACE(netdev) "INTERFACE=%s", (netdev)->ifname

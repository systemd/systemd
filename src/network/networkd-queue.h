/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "alloc-util.h"
#include "hash-funcs.h"

typedef struct Link Link;
typedef struct NetDev NetDev;
typedef struct Manager Manager;
typedef struct Request Request;

typedef int (*request_process_func_t)(Request *req, Link *link, void *userdata);
typedef int (*request_netlink_handler_t)(sd_netlink *nl, sd_netlink_message *m, Request *req, Link *link, void *userdata);

typedef enum RequestType {
        REQUEST_TYPE_ACTIVATE_LINK,
        REQUEST_TYPE_ADDRESS,
        REQUEST_TYPE_ADDRESS_LABEL,
        REQUEST_TYPE_BRIDGE_FDB,
        REQUEST_TYPE_BRIDGE_MDB,
        REQUEST_TYPE_DHCP_SERVER,
        REQUEST_TYPE_DHCP4_CLIENT,
        REQUEST_TYPE_DHCP6_CLIENT,
        REQUEST_TYPE_IPV6_PROXY_NDP,
        REQUEST_TYPE_NDISC,
        REQUEST_TYPE_NEIGHBOR,
        REQUEST_TYPE_NETDEV_INDEPENDENT,
        REQUEST_TYPE_NETDEV_STACKED,
        REQUEST_TYPE_NEXTHOP,
        REQUEST_TYPE_RADV,
        REQUEST_TYPE_ROUTE,
        REQUEST_TYPE_ROUTING_POLICY_RULE,
        REQUEST_TYPE_SET_LINK_ADDRESS_GENERATION_MODE, /* Setting IPv6LL address generation mode. */
        REQUEST_TYPE_SET_LINK_BOND,                    /* Setting bond configs. */
        REQUEST_TYPE_SET_LINK_BRIDGE,                  /* Setting bridge configs. */
        REQUEST_TYPE_SET_LINK_BRIDGE_VLAN,             /* Setting bridge VLAN configs. */
        REQUEST_TYPE_DEL_LINK_BRIDGE_VLAN,             /* Removing bridge VLAN configs. */
        REQUEST_TYPE_SET_LINK_CAN,                     /* Setting CAN interface configs. */
        REQUEST_TYPE_SET_LINK_FLAGS,                   /* Setting IFF_NOARP or friends. */
        REQUEST_TYPE_SET_LINK_GROUP,                   /* Setting interface group. */
        REQUEST_TYPE_SET_LINK_IPOIB,                   /* Setting IPoIB configs. */
        REQUEST_TYPE_SET_LINK_MAC,                     /* Setting MAC address. */
        REQUEST_TYPE_SET_LINK_MASTER,                  /* Setting IFLA_MASTER. */
        REQUEST_TYPE_SET_LINK_MTU,                     /* Setting MTU. */
        REQUEST_TYPE_SRIOV,
        REQUEST_TYPE_TC_CLASS,
        REQUEST_TYPE_TC_QDISC,
        REQUEST_TYPE_UP_DOWN,
        _REQUEST_TYPE_MAX,
        _REQUEST_TYPE_INVALID = -EINVAL,
} RequestType;

struct Request {
        unsigned n_ref;

        Manager *manager; /* must be non-NULL */
        Link *link; /* can be NULL */

        RequestType type;

        /* Target object, e.g. Address, Route, NetDev, and so on. */
        void *userdata;
        /* freeing userdata when the request is completed or failed. */
        mfree_func_t free_func;

        /* hash and compare functions for userdata, used for dedup requests. */
        hash_func_t hash_func;
        compare_func_t compare_func;

        /* Checks the request dependencies, and then processes this request, e.g. call address_configure().
         * Return 1 when processed, 0 when its dependencies not resolved, and negative errno on failure. */
        request_process_func_t process;

        /* incremented when requested, decremented when request is completed or failed. */
        unsigned *counter;
        /* called in netlink handler, the 'counter' is decremented before this is called.
         * If this is specified, then the 'process' function must increment the reference of this
         * request, and pass this request to the netlink_call_async(), and set the destroy function
         * to the slot. */
        request_netlink_handler_t netlink_handler;

        bool waiting_reply;
};

Request *request_ref(Request *req);
Request *request_unref(Request *req);
DEFINE_TRIVIAL_CLEANUP_FUNC(Request*, request_unref);

void request_detach(Manager *manager, Request *req);

int netdev_queue_request(
                NetDev *netdev,
                request_process_func_t process,
                Request **ret);

int link_queue_request_full(
                Link *link,
                RequestType type,
                void *userdata,
                mfree_func_t free_func,
                hash_func_t hash_func,
                compare_func_t compare_func,
                request_process_func_t process,
                unsigned *counter,
                request_netlink_handler_t netlink_handler,
                Request **ret);

static inline int link_queue_request(
                Link *link,
                RequestType type,
                request_process_func_t process,
                Request **ret) {

        return link_queue_request_full(link, type, NULL, NULL, NULL, NULL,
                                       process, NULL, NULL, ret);
}

#define link_queue_request_safe(link, type, userdata, free_func, hash_func, compare_func, process, counter, netlink_handler, ret) \
        ({                                                              \
                typeof(userdata) (*_f)(typeof(userdata)) = (free_func); \
                void (*_h)(const typeof(*userdata)*, struct siphash*) = (hash_func); \
                int (*_c)(const typeof(*userdata)*, const typeof(*userdata)*) = (compare_func); \
                int (*_p)(Request*, Link*, typeof(userdata)) = (process); \
                int (*_n)(sd_netlink*, sd_netlink_message*, Request*, Link*, typeof(userdata)) = (netlink_handler); \
                                                                        \
                link_queue_request_full(link, type, userdata,           \
                                        (mfree_func_t) _f,              \
                                        (hash_func_t) _h,               \
                                        (compare_func_t) _c,            \
                                        (request_process_func_t) _p,    \
                                        counter,                        \
                                        (request_netlink_handler_t) _n, \
                                        ret);                           \
        })

int manager_process_requests(Manager *manager);
int request_call_netlink_async(sd_netlink *nl, sd_netlink_message *m, Request *req);

const char* request_type_to_string(RequestType t) _const_;

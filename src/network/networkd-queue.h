/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-netlink.h"

#include "networkd-link.h"

typedef struct Address Address;
typedef struct AddressLabel AddressLabel;
typedef struct BridgeFDB BridgeFDB;
typedef struct BridgeMDB BridgeMDB;
typedef struct Neighbor Neighbor;
typedef struct NetDev NetDev;
typedef struct NextHop NextHop;
typedef struct Route Route;
typedef struct RoutingPolicyRule RoutingPolicyRule;
typedef struct QDisc QDisc;
typedef struct TClass TClass;
typedef struct Request Request;

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
        REQUEST_TYPE_SET_LINK,
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
        bool consume_object;
        union {
                Address *address;
                AddressLabel *label;
                BridgeFDB *fdb;
                BridgeMDB *mdb;
                struct in6_addr *ipv6_proxy_ndp;
                Neighbor *neighbor;
                NextHop *nexthop;
                Route *route;
                RoutingPolicyRule *rule;
                void *set_link_operation_ptr;
                NetDev *netdev;
                QDisc *qdisc;
                TClass *tclass;
                void *object;
        };
        void *userdata;

        /* incremented when requested, decremented when request is completed or failed. */
        unsigned *counter;
        /* called in netlink handler, the 'counter' is decremented before this is called.
         * If this is specified, then the 'process' function must increment the reference of this
         * request, and pass this request to the netlink_call_async(), and set the destroy function
         * to the slot. */
        request_netlink_handler_t netlink_handler;
};

Request *request_ref(Request *req);
Request *request_unref(Request *req);
DEFINE_TRIVIAL_CLEANUP_FUNC(Request*, request_unref);

void request_detach(Manager *manager, Request *req);

int netdev_queue_request(
                NetDev *netdev,
                Request **ret);

int link_queue_request(
                Link *link,
                RequestType type,
                void *object,
                bool consume_object,
                unsigned *counter,
                request_netlink_handler_t netlink_handler,
                Request **ret);

int manager_process_requests(sd_event_source *s, void *userdata);
int request_call_netlink_async(sd_netlink *nl, sd_netlink_message *m, Request *req);

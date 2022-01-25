/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

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
typedef struct TrafficControl TrafficControl;

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
        REQUEST_TYPE_NEXTHOP,
        REQUEST_TYPE_RADV,
        REQUEST_TYPE_ROUTE,
        REQUEST_TYPE_ROUTING_POLICY_RULE,
        REQUEST_TYPE_SET_LINK,
        REQUEST_TYPE_STACKED_NETDEV,
        REQUEST_TYPE_TRAFFIC_CONTROL,
        REQUEST_TYPE_UP_DOWN,
        _REQUEST_TYPE_MAX,
        _REQUEST_TYPE_INVALID = -EINVAL,
} RequestType;

typedef struct Request {
        Link *link;
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
                TrafficControl *traffic_control;
                void *object;
        };
        void *userdata;
        unsigned *message_counter;
        link_netlink_message_handler_t netlink_handler;
} Request;

void request_drop(Request *req);

int link_queue_request(
                Link *link,
                RequestType type,
                void *object,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret);

int manager_process_requests(sd_event_source *s, void *userdata);

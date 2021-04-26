/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-link.h"

typedef struct Address Address;
typedef struct Manager Manager;
typedef struct Neighbor Neighbor;
typedef struct NextHop NextHop;
typedef struct Route Route;
typedef struct RoutingPolicyRule RoutingPolicyRule;

typedef int (*link_after_configure_handler_t)(Link*, void *);

typedef enum RequestType {
        REQUEST_TYPE_ADDRESS,
        REQUEST_TYPE_NEIGHBOR,
        REQUEST_TYPE_NEXTHOP,
        REQUEST_TYPE_ROUTE,
        REQUEST_TYPE_ROUTING_POLICY_RULE,
        _REQUEST_TYPE_MAX,
        _REQUEST_TYPE_INVALID = -EINVAL,
} RequestType;

typedef struct Request {
        Link *link;
        RequestType type;
        bool take_object;
        union {
                Address *address;
                Neighbor *neighbor;
                NextHop *nexthop;
                Route *route;
                RoutingPolicyRule *rule;
                void *object;
        };
        link_netlink_message_handler_t netlink_handler;
        link_after_configure_handler_t after_configure_handler;
} Request;

Request *request_free(Request *req);

int link_queue_request(
                Link *link,
                RequestType type,
                void *object,
                bool take_object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler);
static inline int link_request_address(
                Link *link,
                Address *address,
                bool take_object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler) {
        return link_queue_request(link, REQUEST_TYPE_ADDRESS, address, take_object, netlink_handler, after_configure_handler);
}
static inline int link_request_neighbor(
                Link *link,
                Neighbor *neighbor,
                bool take_object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler) {
        return link_queue_request(link, REQUEST_TYPE_NEIGHBOR, neighbor, take_object, netlink_handler, after_configure_handler);
}
static inline int link_request_nexthop(
                Link *link,
                NextHop *nexthop,
                bool take_object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler) {
        return link_queue_request(link, REQUEST_TYPE_NEXTHOP, nexthop, take_object, netlink_handler, after_configure_handler);
}
static inline int link_request_route(
                Link *link,
                Route *route,
                bool take_object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler) {
        return link_queue_request(link, REQUEST_TYPE_ROUTE, route, take_object, netlink_handler, after_configure_handler);
}
static inline int link_request_routing_policy_rule(
                Link *link,
                RoutingPolicyRule *rule,
                bool take_object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler) {
        return link_queue_request(link, REQUEST_TYPE_ROUTING_POLICY_RULE, rule, take_object, netlink_handler, after_configure_handler);
}

int manager_process_request_queue(Manager *manager);

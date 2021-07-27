/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address.h"
#include "networkd-address-label.h"
#include "networkd-bridge-fdb.h"
#include "networkd-bridge-mdb.h"
#include "networkd-dhcp-server.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-queue.h"
#include "networkd-setlink.h"

static void request_free_object(RequestType type, void *object) {
        switch(type) {
        case REQUEST_TYPE_ACTIVATE_LINK:
                break;
        case REQUEST_TYPE_ADDRESS:
                address_free(object);
                break;
        case REQUEST_TYPE_ADDRESS_LABEL:
                address_label_free(object);
                break;
        case REQUEST_TYPE_BRIDGE_FDB:
                bridge_fdb_free(object);
                break;
        case REQUEST_TYPE_BRIDGE_MDB:
                bridge_mdb_free(object);
                break;
        case REQUEST_TYPE_CREATE_STACKED_NETDEV:
                break;
        case REQUEST_TYPE_DHCP_SERVER:
                break;
        case REQUEST_TYPE_IPV6_PROXY_NDP:
                free(object);
                break;
        case REQUEST_TYPE_NEIGHBOR:
                neighbor_free(object);
                break;
        case REQUEST_TYPE_NEXTHOP:
                nexthop_free(object);
                break;
        case REQUEST_TYPE_ROUTE:
                route_free(object);
                break;
        case REQUEST_TYPE_ROUTING_POLICY_RULE:
                routing_policy_rule_free(object);
                break;
        case REQUEST_TYPE_SET_LINK:
        case REQUEST_TYPE_UP_DOWN:
                break;
        default:
                assert_not_reached();
        }
}

static Request *request_free(Request *req) {
        if (!req)
                return NULL;

        if (req->link && req->link->manager)
                /* To prevent from triggering assertions in hash functions, remove this request before
                 * freeing object below. */
                ordered_set_remove(req->link->manager->request_queue, req);
        if (req->on_free)
                /* on_free() may use object. So, let's call this earlier. */
                req->on_free(req);
        if (req->consume_object)
                request_free_object(req->type, req->object);
        link_unref(req->link);

        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Request*, request_free);

void request_drop(Request *req) {
        if (!req)
                return;

        if (req->message_counter)
                (*req->message_counter)--;

        request_free(req);
}

static void request_hash_func(const Request *req, struct siphash *state) {
        assert(req);
        assert(req->link);
        assert(state);

        siphash24_compress(&req->link->ifindex, sizeof(req->link->ifindex), state);
        siphash24_compress(&req->type, sizeof(req->type), state);

        switch(req->type) {
        case REQUEST_TYPE_ACTIVATE_LINK:
                break;
        case REQUEST_TYPE_ADDRESS:
                address_hash_func(req->address, state);
                break;
        case REQUEST_TYPE_ADDRESS_LABEL:
        case REQUEST_TYPE_BRIDGE_FDB:
        case REQUEST_TYPE_BRIDGE_MDB:
        case REQUEST_TYPE_CREATE_STACKED_NETDEV:
                /* TODO: Currently, these types do not have any specific hash and compare functions.
                 * Fortunately, all these objects are 'static', thus we can use the trivial functions. */
                trivial_hash_func(req->object, state);
                break;
        case REQUEST_TYPE_DHCP_SERVER:
                /* This type does not have object. */
                break;
        case REQUEST_TYPE_IPV6_PROXY_NDP:
                in6_addr_hash_func(req->ipv6_proxy_ndp, state);
                break;
        case REQUEST_TYPE_NEIGHBOR:
                neighbor_hash_func(req->neighbor, state);
                break;
        case REQUEST_TYPE_NEXTHOP:
                nexthop_hash_func(req->nexthop, state);
                break;
        case REQUEST_TYPE_ROUTE:
                route_hash_func(req->route, state);
                break;
        case REQUEST_TYPE_ROUTING_POLICY_RULE:
                routing_policy_rule_hash_func(req->rule, state);
                break;
        case REQUEST_TYPE_SET_LINK: {
                trivial_hash_func(req->set_link_operation_ptr, state);
                break;
        }
        case REQUEST_TYPE_UP_DOWN:
                break;
        default:
                assert_not_reached();
        }
}

static int request_compare_func(const struct Request *a, const struct Request *b) {
        int r;

        assert(a);
        assert(b);
        assert(a->link);
        assert(b->link);

        r = CMP(a->link->ifindex, b->link->ifindex);
        if (r != 0)
                return r;

        r = CMP(a->type, b->type);
        if (r != 0)
                return r;

        switch (a->type) {
        case REQUEST_TYPE_ACTIVATE_LINK:
                return 0;
        case REQUEST_TYPE_ADDRESS:
                return address_compare_func(a->address, b->address);
        case REQUEST_TYPE_ADDRESS_LABEL:
        case REQUEST_TYPE_BRIDGE_FDB:
        case REQUEST_TYPE_BRIDGE_MDB:
        case REQUEST_TYPE_CREATE_STACKED_NETDEV:
                return trivial_compare_func(a->object, b->object);
        case REQUEST_TYPE_DHCP_SERVER:
                return 0;
        case REQUEST_TYPE_IPV6_PROXY_NDP:
                return in6_addr_compare_func(a->ipv6_proxy_ndp, b->ipv6_proxy_ndp);
        case REQUEST_TYPE_NEIGHBOR:
                return neighbor_compare_func(a->neighbor, b->neighbor);
        case REQUEST_TYPE_NEXTHOP:
                return nexthop_compare_func(a->nexthop, b->nexthop);
        case REQUEST_TYPE_ROUTE:
                return route_compare_func(a->route, b->route);
        case REQUEST_TYPE_ROUTING_POLICY_RULE:
                return routing_policy_rule_compare_func(a->rule, b->rule);
        case REQUEST_TYPE_SET_LINK:
                return trivial_compare_func(a->set_link_operation_ptr, b->set_link_operation_ptr);
        case REQUEST_TYPE_UP_DOWN:
                return 0;
        default:
                assert_not_reached();
        }
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                request_hash_ops,
                Request,
                request_hash_func,
                request_compare_func,
                request_free);

int link_queue_request(
                Link *link,
                RequestType type,
                void *object,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        _cleanup_(request_freep) Request *req = NULL;
        Request *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(type >= 0 && type < _REQUEST_TYPE_MAX);
        assert(IN_SET(type,
                      REQUEST_TYPE_ACTIVATE_LINK,
                      REQUEST_TYPE_DHCP_SERVER,
                      REQUEST_TYPE_SET_LINK,
                      REQUEST_TYPE_UP_DOWN) ||
               object);
        assert(type == REQUEST_TYPE_DHCP_SERVER || netlink_handler);

        req = new(Request, 1);
        if (!req) {
                if (consume_object)
                        request_free_object(type, object);
                return -ENOMEM;
        }

        *req = (Request) {
                .link = link_ref(link),
                .type = type,
                .object = object,
                .consume_object = consume_object,
                .message_counter = message_counter,
                .netlink_handler = netlink_handler,
        };

        existing = ordered_set_get(link->manager->request_queue, req);
        if (existing) {
                /* To prevent from removing the existing request. */
                req->link = link_unref(req->link);

                if (ret)
                        *ret = existing;
                return 0;
        }

        r = ordered_set_ensure_put(&link->manager->request_queue, &request_hash_ops, req);
        if (r < 0)
                return r;

        if (req->message_counter)
                (*req->message_counter)++;

        if (ret)
                *ret = req;

        TAKE_PTR(req);
        return 1;
}

int manager_process_requests(sd_event_source *s, void *userdata) {
        Manager *manager = userdata;
        int r;

        assert(manager);

        for (;;) {
                bool processed = false;
                Request *req;

                ORDERED_SET_FOREACH(req, manager->request_queue) {
                        switch(req->type) {
                        case REQUEST_TYPE_ACTIVATE_LINK:
                                r = request_process_activation(req);
                                break;
                        case REQUEST_TYPE_ADDRESS:
                                r = request_process_address(req);
                                break;
                        case REQUEST_TYPE_ADDRESS_LABEL:
                                r = request_process_address_label(req);
                                break;
                        case REQUEST_TYPE_BRIDGE_FDB:
                                r = request_process_bridge_fdb(req);
                                break;
                        case REQUEST_TYPE_BRIDGE_MDB:
                                r = request_process_bridge_mdb(req);
                                break;
                        case REQUEST_TYPE_CREATE_STACKED_NETDEV:
                                r = request_process_create_stacked_netdev(req);
                                break;
                        case REQUEST_TYPE_DHCP_SERVER:
                                r = request_process_dhcp_server(req);
                                break;
                        case REQUEST_TYPE_IPV6_PROXY_NDP:
                                r = request_process_ipv6_proxy_ndp_address(req);
                                break;
                        case REQUEST_TYPE_NEIGHBOR:
                                r = request_process_neighbor(req);
                                break;
                        case REQUEST_TYPE_NEXTHOP:
                                r = request_process_nexthop(req);
                                break;
                        case REQUEST_TYPE_ROUTE:
                                r = request_process_route(req);
                                break;
                        case REQUEST_TYPE_ROUTING_POLICY_RULE:
                                r = request_process_routing_policy_rule(req);
                                break;
                        case REQUEST_TYPE_SET_LINK:
                                r = request_process_set_link(req);
                                break;
                        case REQUEST_TYPE_UP_DOWN:
                                r = request_process_link_up_or_down(req);
                                break;
                        default:
                                return -EINVAL;
                        }
                        if (r < 0)
                                link_enter_failed(req->link);
                        if (r > 0) {
                                ordered_set_remove(manager->request_queue, req);
                                request_free(req);
                                processed = true;
                        }
                }

                if (!processed)
                        break;
        }

        return 0;
}

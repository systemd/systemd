/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-queue.h"

Request *request_free(Request *req) {
        if (!req)
                return NULL;

        if (req->link)
                set_remove(req->link->manager->request_queue, req);
        link_unref(req->link);

        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Request*, request_free);

int link_queue_request(
                Link *link,
                RequestType type,
                const void *object,
                link_netlink_message_handler_t netlink_handler,
                link_after_configure_handler_t after_configure_handler) {

        _cleanup_(request_freep) Request *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(type >= 0 && type < _REQUEST_TYPE_MAX);
        assert(object);

        req = new(Request, 1);
        if (!req)
                return -ENOMEM;

        *req = (Request) {
                .link = link,
                .type = type,
                .object = object,
                .netlink_handler = netlink_handler,
                .after_configure_handler = after_configure_handler,
        };

        link_ref(link);

        r = set_ensure_put(&link->manager->request_queue, NULL, req);
        if (r < 0)
                return r;

        TAKE_PTR(req);
        return 0;
}

int manager_process_request_queue(Manager *manager) {
        Request *req;
        int r;

        SET_FOREACH(req, manager->request_queue) {
                switch(req->type) {
                case REQUEST_TYPE_ADDRESS:
                        r = request_process_address(req);
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
                default:
                        return -EINVAL;
                }
                if (r < 0)
                        link_enter_failed(req->link);
                if (r > 0)
                        set_remove(manager->request_queue, req);
        }

        return 0;
}

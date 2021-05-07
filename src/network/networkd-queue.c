/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-queue.h"

static void request_free_object(RequestType type, void *object) {
        switch(type) {
        case REQUEST_TYPE_NEIGHBOR:
                neighbor_free(object);
                break;
        case REQUEST_TYPE_ROUTING_POLICY_RULE:
                routing_policy_rule_free(object);
                break;
        default:
                assert_not_reached("invalid request type.");
        }
}

Request *request_free(Request *req) {
        if (!req)
                return NULL;

        if (req->on_free)
                req->on_free(req);
        if (req->consume_object)
                request_free_object(req->type, req->object);
        if (req->link && req->link->manager)
                ordered_set_remove(req->link->manager->request_queue, req);
        link_unref(req->link);

        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Request*, request_free);

void request_drop(Request *req) {
        if (req->message_counter)
                (*req->message_counter)--;

        request_free(req);
}

int link_queue_request(
                Link *link,
                RequestType type,
                void *object,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        _cleanup_(request_freep) Request *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(type >= 0 && type < _REQUEST_TYPE_MAX);
        assert(object);
        assert(netlink_handler);

        req = new(Request, 1);
        if (!req) {
                if (consume_object)
                        request_free_object(type, object);
                return -ENOMEM;
        }

        *req = (Request) {
                .link = link,
                .type = type,
                .object = object,
                .consume_object = consume_object,
                .message_counter = message_counter,
                .netlink_handler = netlink_handler,
        };

        link_ref(link);

        r = ordered_set_ensure_put(&link->manager->request_queue, NULL, req);
        if (r < 0)
                return r;

        if (req->message_counter)
                (*req->message_counter)++;

        if (ret)
                *ret = req;

        TAKE_PTR(req);
        return 0;
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
                        case REQUEST_TYPE_NEIGHBOR:
                                r = request_process_neighbor(req);
                                break;
                        case REQUEST_TYPE_ROUTING_POLICY_RULE:
                                r = request_process_routing_policy_rule(req);
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

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netdev.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "ordered-set.h"
#include "siphash24.h"
#include "string-table.h"

#define REPLY_CALLBACK_COUNT_THRESHOLD 128

static Request* request_detach_impl(Request *req) {
        assert(req);

        if (!req->manager)
                return NULL;

        ordered_set_remove(req->manager->request_queue, req);
        req->manager = NULL;
        return req;
}

void request_detach(Request *req) {
        request_unref(request_detach_impl(req));
}

static Request *request_free(Request *req) {
        if (!req)
                return NULL;

        /* To prevent from triggering assertions in the hash and compare functions, remove this request
         * from the set before freeing userdata below. */
        request_detach_impl(req);

        if (req->free_func)
                req->free_func(req->userdata);

        if (req->counter)
                (*req->counter)--;

        link_unref(req->link); /* link may be NULL, but link_unref() can handle it gracefully. */

        return mfree(req);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Request, request, request_free);

static void request_destroy_callback(Request *req) {
        assert(req);

        request_detach(req);
        request_unref(req);
}

static void request_hash_func(const Request *req, struct siphash *state) {
        assert(req);
        assert(state);

        siphash24_compress_typesafe(req->type, state);

        if (!IN_SET(req->type,
                    REQUEST_TYPE_NEXTHOP,
                    REQUEST_TYPE_ROUTE,
                    REQUEST_TYPE_ROUTING_POLICY_RULE)) {

                siphash24_compress_boolean(req->link, state);
                if (req->link)
                        siphash24_compress_typesafe(req->link->ifindex, state);
        }

        siphash24_compress_typesafe(req->hash_func, state);
        siphash24_compress_typesafe(req->compare_func, state);

        if (req->hash_func)
                req->hash_func(req->userdata, state);
}

static int request_compare_func(const struct Request *a, const struct Request *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->type, b->type);
        if (r != 0)
                return r;

        if (!IN_SET(a->type,
                    REQUEST_TYPE_NEXTHOP,
                    REQUEST_TYPE_ROUTE,
                    REQUEST_TYPE_ROUTING_POLICY_RULE)) {

                r = CMP(!!a->link, !!b->link);
                if (r != 0)
                        return r;

                if (a->link) {
                        r = CMP(a->link->ifindex, b->link->ifindex);
                        if (r != 0)
                                return r;
                }
        }

        r = CMP(PTR_TO_UINT64(a->hash_func), PTR_TO_UINT64(b->hash_func));
        if (r != 0)
                return r;

        r = CMP(PTR_TO_UINT64(a->compare_func), PTR_TO_UINT64(b->compare_func));
        if (r != 0)
                return r;

        if (a->compare_func)
                return a->compare_func(a->userdata, b->userdata);

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                request_hash_ops,
                Request,
                request_hash_func,
                request_compare_func,
                request_detach);

static int request_new(
                Manager *manager,
                Link *link,
                RequestType type,
                void *userdata,
                mfree_func_t free_func,
                hash_func_t hash_func,
                compare_func_t compare_func,
                request_process_func_t process,
                unsigned *counter,
                request_netlink_handler_t netlink_handler,
                Request **ret) {

        _cleanup_(request_unrefp) Request *req = NULL;
        Request *existing;
        int r;

        assert(manager);
        assert(process);

        /* Note, requests will be processed only when the manager is in MANAGER_RUNNING. If a new operation
         * is requested when the manager is in MANAGER_TERMINATING or MANAGER_RESTARTING, the request will be
         * successfully queued but will never be processed. Then, here why we refuse new requests when the
         * manager is in MANAGER_STOPPED? This is because we cannot call link_ref() in that case, as this may
         * be called during link_free(), that means the reference counter of the link is already 0 and
         * calling link_ref() below triggers assertion. */
        if (manager->state == MANAGER_STOPPED)
                return -EBUSY;

        req = new(Request, 1);
        if (!req)
                return -ENOMEM;

        *req = (Request) {
                .n_ref = 1,
                .link = link_ref(link), /* link may be NULL, but link_ref() handles it gracefully. */
                .type = type,
                .userdata = userdata,
                .hash_func = hash_func,
                .compare_func = compare_func,
                .process = process,
                .netlink_handler = netlink_handler,
        };

        existing = ordered_set_get(manager->request_queue, req);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        r = ordered_set_ensure_put(&manager->request_queue, &request_hash_ops, req);
        if (r < 0)
                return r;

        req->manager = manager;
        req->free_func = free_func;
        req->counter = counter;
        if (req->counter)
                (*req->counter)++;

        /* If this is called in the ORDERED_SET_FOREACH() loop of manager_process_requests(), we need to
         * exit from the loop, due to the limitation of the iteration on OrderedSet. */
        manager->request_queued = true;

        if (ret)
                *ret = req;

        TAKE_PTR(req);
        return 1;
}

int netdev_queue_request(
                NetDev *netdev,
                request_process_func_t process,
                Request **ret) {

        int r;

        assert(netdev);
        assert(netdev->manager);

        r = request_new(netdev->manager, NULL, REQUEST_TYPE_NETDEV_INDEPENDENT,
                        netdev, (mfree_func_t) netdev_unref,
                        trivial_hash_func, trivial_compare_func,
                        process, NULL, NULL, ret);
        if (r <= 0)
                return r;

        netdev_ref(netdev);
        return 1;
}

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
                Request **ret) {

        assert(link);

        return request_new(link->manager, link, type,
                           userdata, free_func, hash_func, compare_func,
                           process, counter, netlink_handler, ret);
}

int manager_queue_request_full(
                Manager *manager,
                RequestType type,
                void *userdata,
                mfree_func_t free_func,
                hash_func_t hash_func,
                compare_func_t compare_func,
                request_process_func_t process,
                unsigned *counter,
                request_netlink_handler_t netlink_handler,
                Request **ret) {

        return request_new(manager, NULL, type,
                           userdata, free_func, hash_func, compare_func,
                           process, counter, netlink_handler, ret);
}

int link_requeue_request(Link *link, Request *req, void *userdata, Request **ret) {
        assert(link);
        assert(req);

        return link_queue_request_full(
                        link,
                        req->type,
                        userdata,
                        req->free_func,
                        req->hash_func,
                        req->compare_func,
                        req->process,
                        req->counter,
                        req->netlink_handler,
                        ret);
}

int manager_process_requests(Manager *manager) {
        Request *req;
        int r;

        assert(manager);

        /* Process only when no remove request is queued. */
        if (!ordered_set_isempty(manager->remove_request_queue))
                return 0;

        manager->request_queued = false;

        ORDERED_SET_FOREACH(req, manager->request_queue) {
                if (req->waiting_reply)
                        continue; /* Already processed, and waiting for netlink reply. */

                /* Typically, requests send netlink message asynchronously. If there are many requests
                 * queued, then this event may make reply callback queue in sd-netlink full. */
                if (netlink_get_reply_callback_count(manager->rtnl) >= REPLY_CALLBACK_COUNT_THRESHOLD ||
                    netlink_get_reply_callback_count(manager->genl) >= REPLY_CALLBACK_COUNT_THRESHOLD ||
                    fw_ctx_get_reply_callback_count(manager->fw_ctx) >= REPLY_CALLBACK_COUNT_THRESHOLD)
                        break;

                /* Avoid the request and link freed by req->process() and request_detach(). */
                _unused_ _cleanup_(request_unrefp) Request *req_unref = request_ref(req);
                _cleanup_(link_unrefp) Link *link = link_ref(req->link);

                assert(req->process);
                r = req->process(req, link, req->userdata);
                if (r < 0) {
                        request_detach(req);

                        if (link) {
                                link_enter_failed(link);
                                /* link_enter_failed() may detach multiple requests from the queue.
                                 * Hence, we need to exit from the loop. */
                                break;
                        }
                }
                if (r > 0 && !req->waiting_reply)
                        /* If the request sends netlink message, e.g. for Address or so, the Request object is
                         * referenced by the netlink slot, and will be detached later by its destroy callback.
                         * Otherwise, e.g. for DHCP client or so, detach the request from queue now. */
                        request_detach(req);

                if (manager->request_queued)
                        break; /* New request is queued. Exit from the loop. */
        }

        return 0;
}

static int request_netlink_handler(sd_netlink *nl, sd_netlink_message *m, Request *req) {
        assert(req);

        if (req->counter) {
                assert(*req->counter > 0);
                (*req->counter)--;
                req->counter = NULL; /* To prevent double decrement on free. */
        }

        if (req->link && IN_SET(req->link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        if (req->netlink_handler)
                return req->netlink_handler(nl, m, req, req->link, req->userdata);

        return 0;
}

int request_call_netlink_async(sd_netlink *nl, sd_netlink_message *m, Request *req) {
        int r;

        assert(nl);
        assert(m);
        assert(req);

        r = netlink_call_async(nl, NULL, m, request_netlink_handler, request_destroy_callback, req);
        if (r < 0)
                return r;

        request_ref(req);
        req->waiting_reply = true;
        return 0;
}

static const char *const request_type_table[_REQUEST_TYPE_MAX] = {
        [REQUEST_TYPE_ACTIVATE_LINK]                    = "activate link",
        [REQUEST_TYPE_ADDRESS]                          = "address",
        [REQUEST_TYPE_ADDRESS_LABEL]                    = "address label",
        [REQUEST_TYPE_BRIDGE_FDB]                       = "bridge FDB",
        [REQUEST_TYPE_BRIDGE_MDB]                       = "bridge MDB",
        [REQUEST_TYPE_DHCP_SERVER]                      = "DHCP server",
        [REQUEST_TYPE_DHCP4_CLIENT]                     = "DHCPv4 client",
        [REQUEST_TYPE_DHCP6_CLIENT]                     = "DHCPv6 client",
        [REQUEST_TYPE_IPV6_PROXY_NDP]                   = "IPv6 proxy NDP",
        [REQUEST_TYPE_NDISC]                            = "NDisc",
        [REQUEST_TYPE_NEIGHBOR]                         = "neighbor",
        [REQUEST_TYPE_NETDEV_INDEPENDENT]               = "independent netdev",
        [REQUEST_TYPE_NETDEV_STACKED]                   = "stacked netdev",
        [REQUEST_TYPE_NEXTHOP]                          = "nexthop",
        [REQUEST_TYPE_RADV]                             = "RADV",
        [REQUEST_TYPE_ROUTE]                            = "route",
        [REQUEST_TYPE_ROUTING_POLICY_RULE]              = "routing policy rule",
        [REQUEST_TYPE_SET_LINK_ADDRESS_GENERATION_MODE] = "IPv6LL address generation mode",
        [REQUEST_TYPE_SET_LINK_BOND]                    = "bond configurations",
        [REQUEST_TYPE_SET_LINK_BRIDGE]                  = "bridge configurations",
        [REQUEST_TYPE_SET_LINK_BRIDGE_VLAN]             = "bridge VLAN configurations (step 1)",
        [REQUEST_TYPE_DEL_LINK_BRIDGE_VLAN]             = "bridge VLAN configurations (step 2)",
        [REQUEST_TYPE_SET_LINK_CAN]                     = "CAN interface configurations",
        [REQUEST_TYPE_SET_LINK_FLAGS]                   = "link flags",
        [REQUEST_TYPE_SET_LINK_GROUP]                   = "interface group",
        [REQUEST_TYPE_SET_LINK_IPOIB]                   = "IPoIB configurations",
        [REQUEST_TYPE_SET_LINK_MAC]                     = "MAC address",
        [REQUEST_TYPE_SET_LINK_MASTER]                  = "master interface",
        [REQUEST_TYPE_SET_LINK_MTU]                     = "MTU",
        [REQUEST_TYPE_SRIOV_VF_MAC]                     = "SR-IOV VF MAC address",
        [REQUEST_TYPE_SRIOV_VF_SPOOFCHK]                = "SR-IOV VF spoof check",
        [REQUEST_TYPE_SRIOV_VF_RSS_QUERY_EN]            = "SR-IOV VF RSS query",
        [REQUEST_TYPE_SRIOV_VF_TRUST]                   = "SR-IOV VF trust",
        [REQUEST_TYPE_SRIOV_VF_LINK_STATE]              = "SR-IOV VF link state",
        [REQUEST_TYPE_SRIOV_VF_VLAN_LIST]               = "SR-IOV VF vlan list",
        [REQUEST_TYPE_TC_QDISC]                         = "QDisc",
        [REQUEST_TYPE_TC_CLASS]                         = "TClass",
        [REQUEST_TYPE_UP_DOWN]                          = "bring link up or down",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(request_type, RequestType);

static RemoveRequest* remove_request_free(RemoveRequest *req) {
        if (!req)
                return NULL;

        if (req->manager)
                ordered_set_remove(req->manager->remove_request_queue, req);

        if (req->unref_func)
                req->unref_func(req->userdata);

        link_unref(req->link);
        sd_netlink_unref(req->netlink);
        sd_netlink_message_unref(req->message);

        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(RemoveRequest*, remove_request_free);
DEFINE_TRIVIAL_DESTRUCTOR(remove_request_destroy_callback, RemoveRequest, remove_request_free);
DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                remove_request_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                remove_request_free);

int remove_request_add(
                Manager *manager,
                Link *link,
                void *userdata,
                mfree_func_t unref_func,
                sd_netlink *netlink,
                sd_netlink_message *message,
                remove_request_netlink_handler_t netlink_handler) {

        _cleanup_(remove_request_freep) RemoveRequest *req = NULL;
        int r;

        assert(manager);
        assert(userdata);
        assert(netlink);
        assert(message);

        /* Unlike request_new(), remove requests will be also processed when the manager is in
         * MANAGER_TERMINATING or MANAGER_RESTARTING. When the manager is in MANAGER_STOPPED, we cannot
         * queue new remove requests anymore with the same reason explained in request_new(). */
        if (manager->state == MANAGER_STOPPED)
                return 0; /* ignored */

        req = new(RemoveRequest, 1);
        if (!req)
                return -ENOMEM;

        *req = (RemoveRequest) {
                .link = link_ref(link), /* link may be NULL, but link_ref() handles it gracefully. */
                .userdata = userdata,
                .netlink = sd_netlink_ref(netlink),
                .message = sd_netlink_message_ref(message),
                .netlink_handler = netlink_handler,
        };

        r = ordered_set_ensure_put(&manager->remove_request_queue, &remove_request_hash_ops, req);
        if (r < 0)
                return r;
        assert(r > 0);

        req->manager = manager;
        req->unref_func = unref_func;

        TAKE_PTR(req);
        return 1; /* queued */
}

int manager_process_remove_requests(Manager *manager) {
        RemoveRequest *req;
        int r;

        assert(manager);

        while ((req = ordered_set_first(manager->remove_request_queue))) {

                /* Do not make the reply callback queue in sd-netlink full. */
                if (netlink_get_reply_callback_count(req->netlink) >= REPLY_CALLBACK_COUNT_THRESHOLD)
                        return 0;

                r = netlink_call_async(
                                req->netlink, NULL, req->message,
                                req->netlink_handler,
                                remove_request_destroy_callback,
                                req);
                if (r < 0) {
                        _cleanup_(link_unrefp) Link *link = link_ref(req->link);

                        log_link_warning_errno(link, r, "Failed to call netlink message: %m");

                        /* First free the request. */
                        remove_request_free(req);

                        /* Then, make the link enter the failed state. */
                        if (link)
                                link_enter_failed(link);

                } else {
                        /* On success, netlink needs to be unref()ed. Otherwise, the netlink and remove
                         * request may not freed on shutting down. */
                        req->netlink = sd_netlink_unref(req->netlink);
                        ordered_set_remove(manager->remove_request_queue, req);
                }
        }

        return 0;
}

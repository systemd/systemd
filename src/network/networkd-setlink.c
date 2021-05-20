/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "string-table.h"

static const char *const set_link_operation_table[_SET_LINK_OPERATION_MAX] = {
        [SET_LINK_MTU]                     = "MTU",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(set_link_operation, SetLinkOperation);

static int set_link_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, SetLinkOperation op, bool ignore) {
        int r;

        assert(m);
        assert(link);
        assert(link->set_link_messages > 0);
        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);

        link->set_link_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                const char *error_msg;

                error_msg = strjoina("Failed to set ", set_link_operation_to_string(op), ignore ? ", ignoring" : "");
                log_link_message_warning_errno(link, m, r, error_msg);

                if (!ignore)
                        link_enter_failed(link);
                return 0;
        }

        log_link_debug(link, "%s set.", set_link_operation_to_string(op));
        return 1;
}

static int link_set_mtu_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = set_link_handler_internal(rtnl, m, link, SET_LINK_MTU, true);
        if (r <= 0)
                return r;

        /* The kernel resets ipv6 mtu after changing device mtu;
         * we must set this here, after we've set device mtu */
        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to set IPv6 MTU, ignoring: %m");

        if (link->entering_to_join_netdev) {
                r = link_enter_join_netdev(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 0;
}

static int link_configure(
                Link *link,
                SetLinkOperation op,
                void *userdata,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->network);
        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);
        assert(callback);

        log_link_debug(link, "Setting %s", set_link_operation_to_string(op));

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        switch (op) {
        case SET_LINK_MTU:
                r = sd_netlink_message_append_u32(req, IFLA_MTU, PTR_TO_UINT32(userdata));
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_MTU attribute: %m");
                break;
        default:
                assert_not_reached("Invalid set link operation");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send RTM_SETLINK message: %m");

        link_ref(link);
        return 0;
}

static bool link_is_ready_to_call_set_link(Request *req) {
        Link *link;

        assert(req);

        link = req->link;

        if (!IN_SET(link->state, LINK_STATE_INITIALIZED, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        return true;
}

int request_process_set_link(Request *req) {
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_SET_LINK);
        assert(req->set_link_operation >= 0 && req->set_link_operation < _SET_LINK_OPERATION_MAX);
        assert(req->netlink_handler);

        if (!link_is_ready_to_call_set_link(req))
                return 0;

        r = link_configure(req->link, req->set_link_operation, req->userdata, req->netlink_handler);
        if (r < 0)
                return log_link_error_errno(req->link, r, "Failed to set %s: %m",
                                            set_link_operation_to_string(req->set_link_operation));

        return 1;
}

static int link_request_set_link(
                Link *link,
                SetLinkOperation op,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        Request *req;
        int r;

        assert(link);
        assert(op >= 0 && op < _SET_LINK_OPERATION_MAX);
        assert(netlink_handler);

        r = link_queue_request(link, REQUEST_TYPE_SET_LINK, INT_TO_PTR(op), false,
                               &link->set_link_messages, netlink_handler, &req);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request to set %s: %m",
                                            set_link_operation_to_string(op));

        log_link_debug(link, "Requested to set %s", set_link_operation_to_string(op));

        if (ret)
                *ret = req;
        return 0;
}

int link_request_to_set_mtu(Link *link, uint32_t mtu) {
        Request *req = NULL;  /* avoid false maybe-uninitialized warning */
        int r;

        assert(link);

        /* IPv6 protocol requires a minimum MTU of IPV6_MTU_MIN(1280) bytes on the interface. Bump up
         * MTU bytes to IPV6_MTU_MIN. */
        if (mtu < IPV6_MIN_MTU && link_ipv6_enabled(link)) {
                log_link_warning(link, "Bumping MTU to " STRINGIFY(IPV6_MIN_MTU) ", as IPv6 is enabled "
                                 "and requires a minimum MTU of " STRINGIFY(IPV6_MIN_MTU) " bytes");
                mtu = IPV6_MIN_MTU;
        }

        if (link->mtu == mtu)
                return 0;

        r = link_request_set_link(link, SET_LINK_MTU, link_set_mtu_handler, &req);
        if (r < 0)
                return r;

        req->userdata = UINT32_TO_PTR(mtu);
        return 0;
}

static bool link_reduces_vlan_mtu(Link *link) {
        /* See netif_reduces_vlan_mtu() in kernel. */
        return streq_ptr(link->kind, "macsec");
}

static uint32_t link_get_requested_mtu_by_stacked_netdevs(Link *link) {
        uint32_t mtu = 0;
        NetDev *dev;

        HASHMAP_FOREACH(dev, link->network->stacked_netdevs)
                if (dev->kind == NETDEV_KIND_VLAN && dev->mtu > 0)
                        /* See vlan_dev_change_mtu() in kernel. */
                        mtu = MAX(mtu, link_reduces_vlan_mtu(link) ? dev->mtu + 4 : dev->mtu);

                else if (dev->kind == NETDEV_KIND_MACVLAN && dev->mtu > mtu)
                        /* See macvlan_change_mtu() in kernel. */
                        mtu = dev->mtu;

        return mtu;
}

int link_configure_mtu(Link *link) {
        uint32_t mtu;

        assert(link);
        assert(link->network);

        if (link->network->mtu > 0)
                return link_request_to_set_mtu(link, link->network->mtu);

        mtu = link_get_requested_mtu_by_stacked_netdevs(link);
        if (link->mtu >= mtu)
                return 0;

        log_link_notice(link, "Bumping MTU bytes from %"PRIu32" to %"PRIu32" because of stacked device. "
                        "If it is not desired, then please explicitly specify MTUBytes= setting.",
                        link->mtu, mtu);

        return link_request_to_set_mtu(link, mtu);
}

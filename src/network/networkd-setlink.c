/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"

typedef struct SetLinkInfo {
        uint32_t mtu;
} SetLinkInfo;

static const struct {
        SetLinkFlag flag;
        const char *name;
} set_link_flag_map[] = {
        { SET_LINK_MTU,         "MTU" },
        {}
};

static int set_link_flags_to_string(SetLinkFlag flags, char **ret) {
        _cleanup_free_ char *str = NULL;

        assert(ret);

        for (unsigned i = 0; set_link_flag_map[i].name; i++)
                if (FLAGS_SET(flags, set_link_flag_map[i].flag) &&
                    !strextend_with_separator(&str, ", ", set_link_flag_map[i].name))
                        return -ENOMEM;

        *ret = TAKE_PTR(str);
        return 0;
}

static int link_configure(
                Link *link,
                SetLinkFlag flags,
                SetLinkInfo *info,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(flags != 0);
        assert(info);
        assert(callback);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        if (FLAGS_SET(flags, SET_LINK_MTU)) {
                log_link_debug(link, "Setting MTU: %" PRIu32, info->mtu);

                r = sd_netlink_message_append_u32(req, IFLA_MTU, info->mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not append IFLA_MTU attribute: %m");
        }

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not send RTM_SETLINK message: %m");

        link->set_link_flags = flags;

        link_ref(link);
        return 1;
}

static int set_link_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        _cleanup_free_ char *str = NULL;
        SetLinkFlag flags;
        int r;

        assert(m);
        assert(link);
        assert(link->set_link_messages > 0);
        assert(link->set_link_flags != 0);

        link->set_link_messages--;
        flags = link->set_link_flags;
        link->set_link_flags = 0;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        (void) set_link_flags_to_string(flags, &str);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                const char *joined;

                joined = strjoina("Could not set ", strna(str));
                log_link_message_warning_errno(link, m, r, joined);
                link_enter_failed(link);
                return 0;
        }

        if (FLAGS_SET(flags, SET_LINK_MTU)) {
                /* The kernel resets ipv6 mtu after changing device mtu; we must set this here, after
                 * we've set device mtu */
                r = link_set_ipv6_mtu(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Cannot set IPv6 MTU for interface, ignoring: %m");
        }

        log_link_debug(link, "Setting %s done.", strna(str));
        return 0;
}

static bool link_is_ready_to_call_set_link(Link *link) {
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_INITIALIZED, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        return link->set_link_flags == 0;
}

static SetLinkFlag link_adjust_set_link_flags(Link *link, SetLinkFlag flags, SetLinkInfo *info) {
        assert(link);
        assert(info);

        if (FLAGS_SET(flags, SET_LINK_MTU) && info->mtu == link->mtu)
                SET_FLAG(flags, SET_LINK_MTU, false);

        return flags;
}

int request_process_set_link(Request *req) {
        SetLinkFlag flags;
        SetLinkInfo *info;
        Link *link;
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_SET_LINK);
        assert(req->set_link_flags != 0);
        assert(req->userdata);
        assert(req->message_counter);

        link = req->link;
        flags = req->set_link_flags;
        info = req->userdata;

        if (!link_is_ready_to_call_set_link(link))
                return 0;

        flags = link_adjust_set_link_flags(link, flags, info);
        if (flags == 0) {
                /* Do nothing. Do not forget to decrement the message counter. */
                (*req->message_counter)--;
                return 1;
        }

        r = link_configure(link, flags, info, req->netlink_handler);
        if (r < 0) {
                _cleanup_free_ char *str = NULL;

                (void) set_link_flags_to_string(flags, &str);
                return log_link_warning_errno(link, r, "Failed to set %s: %m", strna(str));
        }

        return 1;
}

static void setlink_request_on_free(Request *req) {
        assert(req);

        free(req->userdata);
}

static int link_request_set_link(Link *link, SetLinkFlag flags, Request **ret) {
        Request *req;
        int r;

        assert(link);
        assert(flags != 0);

        r = link_queue_request(link, REQUEST_TYPE_SET_LINK, UINT_TO_PTR(flags), false,
                               &link->set_link_messages, set_link_handler, &req);
        if (r < 0)
                return r;
        if (r == 0)
                /* request already exists, merging flags. */
                req->set_link_flags |= flags;
        else {
                SetLinkInfo *info;

                /* request is new */

                info = new0(SetLinkInfo, 1);
                if (!info) {
                        request_drop(req);
                        return log_oom();
                }

                req->userdata = info;
                req->on_free = setlink_request_on_free;
        }

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

        r = link_request_set_link(link, SET_LINK_MTU, &req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request to set MTU: %m");

        ((SetLinkInfo*) req->userdata)->mtu = mtu;

        log_link_debug(link, "Requested to set MTU: %"PRIu32, mtu);

        return 0;
}

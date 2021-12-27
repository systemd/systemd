/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "netlink-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-sriov.h"

static int sr_iov_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->sr_iov_messages > 0);
        link->sr_iov_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set up SR-IOV");
                link_enter_failed(link);
                return 1;
        }

        if (link->sr_iov_messages == 0) {
                log_link_debug(link, "SR-IOV configured");
                link->sr_iov_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int sr_iov_configure(Link *link, SRIOV *sr_iov) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);

        log_link_debug(link, "Setting SR-IOV virtual function %"PRIu32, sr_iov->vf);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sr_iov_set_netlink_message(sr_iov, req);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, req, sr_iov_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return r;

        link_ref(link);
        link->sr_iov_messages++;

        return 0;
}

int link_configure_sr_iov(Link *link) {
        SRIOV *sr_iov;
        int r;

        assert(link);
        assert(link->network);

        if (link->sr_iov_messages != 0) {
                log_link_debug(link, "SR-IOV is configuring.");
                return 0;
        }

        link->sr_iov_configured = false;

        ORDERED_HASHMAP_FOREACH(sr_iov, link->network->sr_iov_by_section) {
                r = sr_iov_configure(link, sr_iov);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "Failed to configure SR-IOV virtual function %"PRIu32": %m",
                                                      sr_iov->vf);
        }

        if (link->sr_iov_messages == 0)
                link->sr_iov_configured = true;
        else
                log_link_debug(link, "Configuring SR-IOV");

        return 0;
}

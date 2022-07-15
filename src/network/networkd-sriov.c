/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-sriov.h"

static int sr_iov_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, SRIOV *sr_iov) {
        int r;

        assert(m);
        assert(link);

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

static int sr_iov_configure(SRIOV *sr_iov, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(sr_iov);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(req);

        log_link_debug(link, "Setting SR-IOV virtual function %"PRIu32".", sr_iov->vf);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = sr_iov_set_netlink_message(sr_iov, m);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static int sr_iov_process_request(Request *req, Link *link, SRIOV *sr_iov) {
        int r;

        assert(req);
        assert(link);
        assert(sr_iov);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        r = sr_iov_configure(sr_iov, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "Failed to configure SR-IOV virtual function %"PRIu32": %m",
                                              sr_iov->vf);

        return 1;
}

int link_request_sr_iov_vfs(Link *link) {
        SRIOV *sr_iov;
        int r;

        assert(link);
        assert(link->network);

        link->sr_iov_configured = false;

        ORDERED_HASHMAP_FOREACH(sr_iov, link->network->sr_iov_by_section) {
                r = link_queue_request_safe(link, REQUEST_TYPE_SRIOV,
                                            sr_iov, NULL,
                                            sr_iov_hash_func,
                                            sr_iov_compare_func,
                                            sr_iov_process_request,
                                            &link->sr_iov_messages,
                                            sr_iov_handler,
                                            NULL);
                if (r < 0)
                        return log_link_warning_errno(link, r,
                                                      "Failed to request SR-IOV virtual function %"PRIu32": %m",
                                                      sr_iov->vf);
        }

        if (link->sr_iov_messages == 0) {
                link->sr_iov_configured = true;
                link_check_ready(link);
        } else
                log_link_debug(link, "Configuring SR-IOV");

        return 0;
}

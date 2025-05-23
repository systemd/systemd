/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>

#include "netlink-types-internal.h"
#include "netlink-types.h"

static const NLAPolicy unix_diag_req_policies[] = {
};
DEFINE_POLICY_SET(unix_diag_req);

static const NLAPolicy sdnl_req_policies[] = {
        [SOCK_DIAG_BY_FAMILY] = BUILD_POLICY_NESTED_WITH_SIZE(unix_diag_req, sizeof(struct unix_diag_req)),
};

DEFINE_POLICY_SET(sdnl_req);

static const NLAPolicy unix_diag_msg_policies[] = {
        [UNIX_DIAG_RQLEN] = BUILD_POLICY_WITH_SIZE(BINARY, sizeof(struct unix_diag_rqlen)),
};
DEFINE_POLICY_SET(unix_diag_msg);

static const NLAPolicy sdnl_msg_policies[] = {
        [SOCK_DIAG_BY_FAMILY] = BUILD_POLICY_NESTED_WITH_SIZE(unix_diag_msg, sizeof(struct unix_diag_msg)),
};

DEFINE_POLICY_SET(sdnl_msg);

const NLAPolicy *sdnl_get_policy(uint16_t nlmsg_type, uint16_t flags) {
        /* for sock_diag we need to look at whether a message is a response or request to determine how to decode it. */
        if (flags & NLM_F_REQUEST)
                return policy_set_get_policy(&sdnl_req_policy_set, nlmsg_type);

        return policy_set_get_policy(&sdnl_msg_policy_set, nlmsg_type);
}

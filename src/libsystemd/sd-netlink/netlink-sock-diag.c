/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/sock_diag.h>
#include <linux/unix_diag.h>

#include "netlink-internal.h"
#include "netlink-sock-diag.h"

int sd_sock_diag_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_SOCK_DIAG);
}

int sd_sock_diag_message_new_unix(
                sd_netlink *sdnl,
                sd_netlink_message **ret,
                ino_t inode,
                uint64_t cookie,
                uint32_t show) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(sdnl, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(sdnl, &m, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_ACK);
        if (r < 0)
                return r;

        *(struct unix_diag_req*) NLMSG_DATA(m->hdr) = (struct unix_diag_req) {
                .sdiag_family = AF_UNIX,
                .udiag_ino = inode,
                .udiag_show = show,
                .udiag_cookie = {
                        cookie & UINT32_MAX,
                        (cookie >> 32) & UINT32_MAX,
                },
        };

        *ret = TAKE_PTR(m);
        return 0;
}

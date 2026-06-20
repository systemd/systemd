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

int sd_sock_diag_message_new_unix_dump(
                sd_netlink *sdnl,
                sd_netlink_message **ret,
                uint32_t states,
                uint32_t show) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert_return(sdnl, -EINVAL);
        assert_return(ret, -EINVAL);

        r = message_new(sdnl, &m, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP);
        if (r < 0)
                return r;

        /* Unlike sd_sock_diag_message_new_unix() this requests a dump of all AF_UNIX sockets matching the
         * specified state mask, rather than looking up a single socket by inode/cookie. The kernel's dump
         * handler ignores udiag_ino/udiag_cookie, hence we leave them zeroed. */

        *(struct unix_diag_req*) NLMSG_DATA(m->hdr) = (struct unix_diag_req) {
                .sdiag_family = AF_UNIX,
                .udiag_states = states,
                .udiag_show = show,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

int sd_sock_diag_message_get_unix(sd_netlink_message *m, struct unix_diag_msg *ret) {
        assert_return(m, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(ret, -EINVAL);

        if (m->hdr->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                return -EINVAL;

        if (NLMSG_PAYLOAD(m->hdr, 0) < sizeof(struct unix_diag_msg))
                return -EBADMSG;

        /* Reads out the fixed-size unix_diag_msg header that precedes the attributes in a reply. There's no
         * sd-netlink attribute for this leading family header, hence we read it directly. */

        *ret = *(struct unix_diag_msg*) NLMSG_DATA(m->hdr);
        return 0;
}

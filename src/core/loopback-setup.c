/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <net/if.h>
#include <stdlib.h>

#include "sd-netlink.h"

#include "loopback-setup.h"
#include "missing.h"
#include "netlink-util.h"

#define LOOPBACK_SETUP_TIMEOUT_USEC (5 * USEC_PER_SEC)

struct state {
        unsigned n_messages;
        int rcode;
        const char *title;
};

static int generic_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        struct state *s = userdata;

        assert(s);
        assert(s->n_messages > 0);
        s->n_messages--;

        errno = 0;
        log_debug_errno(sd_netlink_message_get_errno(m), "Failed to %s: %m", s->title);

        s->rcode = sd_netlink_message_get_errno(m);

        return 0;
}

static int start_loopback(sd_netlink *rtnl, struct state *s) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);
        assert(s);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_SETLINK, LOOPBACK_IFINDEX);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        if (r < 0)
                return r;

        r = sd_netlink_call_async(rtnl, req, generic_handler, s, LOOPBACK_SETUP_TIMEOUT_USEC, NULL);
        if (r < 0)
                return r;

        s->n_messages ++;
        return 0;
}

static int add_ipv4_address(sd_netlink *rtnl, struct state *s) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);
        assert(s);

        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_NEWADDR, LOOPBACK_IFINDEX, AF_INET);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_prefixlen(req, 8);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_flags(req, IFA_F_PERMANENT);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_scope(req, RT_SCOPE_HOST);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in_addr(req, IFA_LOCAL, &(struct in_addr) { .s_addr = htobe32(INADDR_LOOPBACK) } );
        if (r < 0)
                return r;

        r = sd_netlink_call_async(rtnl, req, generic_handler, s, USEC_INFINITY, NULL);
        if (r < 0)
                return r;

        s->n_messages ++;
        return 0;
}

static int add_ipv6_address(sd_netlink *rtnl, struct state *s) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);
        assert(s);

        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_NEWADDR, LOOPBACK_IFINDEX, AF_INET6);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_prefixlen(req, 128);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_flags(req, IFA_F_PERMANENT);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_scope(req, RT_SCOPE_HOST);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in6_addr(req, IFA_LOCAL, &in6addr_loopback);
        if (r < 0)
                return r;

        r = sd_netlink_call_async(rtnl, req, generic_handler, s, USEC_INFINITY, NULL);
        if (r < 0)
                return r;

        s->n_messages ++;
        return 0;
}

static bool check_loopback(sd_netlink *rtnl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        unsigned flags;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, LOOPBACK_IFINDEX);
        if (r < 0)
                return false;

        r = sd_netlink_call(rtnl, req, USEC_INFINITY, &reply);
        if (r < 0)
                return false;

        r = sd_rtnl_message_link_get_flags(reply, &flags);
        if (r < 0)
                return false;

        return flags & IFF_UP;
}

int loopback_setup(void) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        struct state state_4 = { .title = "add address 127.0.0.1 to loopback interface" },
                     state_6 = { .title = "add address ::1 to loopback interface"},
                     state_up = { .title = "bring loopback interface up" };
        int r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink: %m");

        /* Note that we add the IP addresses here explicitly even though the kernel does that too implicitly when
         * setting up the loopback device. The reason we do this here a second time (and possibly race against the
         * kernel) is that we want to synchronously wait until the IP addresses are set up correctly, see
         *
         * https://github.com/systemd/systemd/issues/5641 */

        r = add_ipv4_address(rtnl, &state_4);
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue IPv4 loopback address add request: %m");

        r = add_ipv6_address(rtnl, &state_6);
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue IPv6 loopback address add request: %m");

        r = start_loopback(rtnl, &state_up);
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue loopback interface start request: %m");

        while (state_4.n_messages + state_6.n_messages + state_up.n_messages > 0) {
                r = sd_netlink_wait(rtnl, LOOPBACK_SETUP_TIMEOUT_USEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for netlink event: %m");

                r = sd_netlink_process(rtnl, NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to process netlink event: %m");
        }

        /* Note that we don't really care whether the addresses could be added or not */
        if (state_up.rcode != 0) {
                /* If we lack the permissions to configure the loopback device,
                 * but we find it to be already configured, let's exit cleanly,
                 * in order to supported unprivileged containers. */
                if (state_up.rcode == -EPERM && check_loopback(rtnl))
                        return 0;

                return log_warning_errno(state_up.rcode, "Failed to configure loopback device: %m");
        }

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <stdlib.h>

#include "sd-netlink.h"

#include "loopback-setup.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "time-util.h"

#define LOOPBACK_SETUP_TIMEOUT_USEC (5 * USEC_PER_SEC)

struct state {
        unsigned n_messages;
        int rcode;
        const char *error_message;
        const char *success_message;
        const char *eexist_message;
};

static int generic_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        struct state *s = ASSERT_PTR(userdata);
        int r;

        assert(s->n_messages > 0);
        s->n_messages--;

        errno = 0;

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST && s->eexist_message)
                log_debug_errno(r, "%s", s->eexist_message);
        else if (r < 0)
                log_debug_errno(r, "%s: %m", s->error_message);
        else
                log_debug("%s", s->success_message);

        s->rcode = r;
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

        r = sd_netlink_call_async(rtnl, NULL, req, generic_handler, NULL, s, LOOPBACK_SETUP_TIMEOUT_USEC, "systemd-start-loopback");
        if (r < 0)
                return r;

        s->n_messages++;
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

        r = sd_netlink_call_async(rtnl, NULL, req, generic_handler, NULL, s, USEC_INFINITY, "systemd-loopback-ipv4");
        if (r < 0)
                return r;

        s->n_messages++;
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

        uint32_t flags = IFA_F_PERMANENT|IFA_F_NOPREFIXROUTE;
        r = sd_rtnl_message_addr_set_flags(req, flags & 0xffu); /* rtnetlink wants low 8 bit of flags via regular flags field… */
        if (r < 0)
                return r;
        if ((flags & ~0xffu) != 0) {
                r = sd_netlink_message_append_u32(req, IFA_FLAGS, flags); /* …and the rest of the flags via IFA_FLAGS */
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_addr_set_scope(req, RT_SCOPE_HOST);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in6_addr(req, IFA_LOCAL, &in6addr_loopback);
        if (r < 0)
                return r;

        r = sd_netlink_call_async(rtnl, NULL, req, generic_handler, NULL, s, USEC_INFINITY, "systemd-loopback-ipv6");
        if (r < 0)
                return r;

        s->n_messages++;
        return 0;
}

static int check_loopback(sd_netlink *rtnl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        unsigned flags;
        int r;

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, LOOPBACK_IFINDEX);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, USEC_INFINITY, &reply);
        if (r < 0)
                return r;

        r = sd_rtnl_message_link_get_flags(reply, &flags);
        if (r < 0)
                return r;

        return flags & IFF_UP;
}

int loopback_setup(void) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        struct state state_4 = {
                .error_message = "Failed to add address 127.0.0.1 to loopback interface",
                .success_message = "Successfully added address 127.0.0.1 to loopback interface",
                .eexist_message = "127.0.0.1 has already been added to loopback interface",
        }, state_6 = {
                .error_message = "Failed to add address ::1 to loopback interface",
                .success_message = "Successfully added address ::1 to loopback interface",
                .eexist_message = "::1 has already been added to loopback interface",
        }, state_up = {
                .error_message = "Failed to bring loopback interface up",
                .success_message = "Successfully brought loopback interface up",
        };
        int r;

        /* Note, we, generally assume callers ignore the return code here (except test cases), hence only log add LOG_WARN level. */

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_warning_errno(r, "Failed to open netlink, ignoring: %m");

        /* Note that we add the IP addresses here explicitly even though the kernel does that too implicitly when
         * setting up the loopback device. The reason we do this here a second time (and possibly race against the
         * kernel) is that we want to synchronously wait until the IP addresses are set up correctly, see
         *
         * https://github.com/systemd/systemd/issues/5641 */

        r = add_ipv4_address(rtnl, &state_4);
        if (r < 0)
                return log_warning_errno(r, "Failed to enqueue IPv4 loopback address add request, ignoring: %m");

        r = add_ipv6_address(rtnl, &state_6);
        if (r < 0)
                return log_warning_errno(r, "Failed to enqueue IPv6 loopback address add request, ignoring: %m");

        r = start_loopback(rtnl, &state_up);
        if (r < 0)
                return log_warning_errno(r, "Failed to enqueue loopback interface start request, ignoring: %m");

        while (state_4.n_messages + state_6.n_messages + state_up.n_messages > 0) {
                r = sd_netlink_wait(rtnl, LOOPBACK_SETUP_TIMEOUT_USEC);
                if (r < 0)
                        return log_warning_errno(r, "Failed to wait for netlink event, ignoring: %m");

                r = sd_netlink_process(rtnl, NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to process netlink event, ignoring: %m");
        }

        /* Note that we don't really care whether the addresses could be added or not */
        if (state_up.rcode != 0) {

                /* If we lack the permissions to configure the loopback device, but we find it to be already
                 * configured, let's exit cleanly, in order to supported unprivileged containers. */
                if (ERRNO_IS_PRIVILEGE(state_up.rcode)) {
                        r = check_loopback(rtnl);
                        if (r < 0)
                                log_debug_errno(r, "Failed to check if loopback device might already be up, ignoring: %m");
                        else if (r > 0) {
                                log_debug("Configuring loopback failed, but device is already up, suppressing failure.");
                                return 0;
                        }
                }

                return log_warning_errno(state_up.rcode, "Failed to configure loopback network device, ignoring: %m");
        }

        return 0;
}

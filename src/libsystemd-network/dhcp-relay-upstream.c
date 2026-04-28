/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-event.h"

#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "dhcp-relay-internal.h"
#include "in-addr-util.h"
#include "prioq.h"

int sd_dhcp_relay_upstream_set_priority(sd_dhcp_relay_interface *interface, int64_t priority) {
        assert_return(interface, -EINVAL);
        assert_return(interface->upstream, -EINVAL);
        assert_return(!sd_dhcp_relay_interface_is_running(interface), -EBUSY);

        interface->priority = priority;
        return 0;
}

static int upstream_compare_func(const sd_dhcp_relay_interface *a, const sd_dhcp_relay_interface *b) {
        assert(a);
        assert(a->upstream);
        assert(b);
        assert(b->upstream);

        /* Higher priority first */
        return CMP(b->priority, a->priority);
}

int upstream_register(sd_dhcp_relay_interface *interface) {
        assert(interface);
        assert(interface->relay);
        assert(interface->upstream);
        assert(!sd_dhcp_relay_interface_is_running(interface));

        interface->priority_idx = PRIOQ_IDX_NULL;
        return prioq_ensure_put(&interface->relay->upstream_interfaces, upstream_compare_func, interface, &interface->priority_idx);
}

void upstream_unregister(sd_dhcp_relay_interface *interface) {
        assert(interface);
        assert(interface->relay);
        assert(interface->upstream);

        (void) prioq_remove(interface->relay->upstream_interfaces, interface, &interface->priority_idx);
}

void upstream_done(sd_dhcp_relay_interface *interface) {
        upstream_unregister(interface);
}

int upstream_get(sd_dhcp_relay *relay, sd_dhcp_relay_interface **ret) {
        sd_dhcp_relay_interface *interface = prioq_peek(relay->upstream_interfaces);
        if (!interface)
                return -ENETDOWN;

        assert(interface->upstream);

        if (!interface->io_event_source)
                return -ENETDOWN;

        if (ret)
                *ret = interface;
        return 0;
}

int upstream_process_message(
                sd_dhcp_relay_interface *interface,
                const struct iovec *iov,
                const struct in_pktinfo *pktinfo) {

        int r;

        assert(interface);
        assert(interface->relay);
        assert(interface->upstream);
        assert(iov);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_parse(
                        iov,
                        BOOTREPLY,
                        /* xid= */ NULL,
                        ARPHRD_NONE,
                        /* hw_addr= */ NULL,
                        &message);
        if (r < 0)
                return r;

        if (message->header.giaddr == INADDR_ANY)
                return 0; /* Not a relay message, so it is probably not for us. */

        log_dhcp_relay_interface(interface, "Received BOOTREPLY (0x%"PRIx32")", be32toh(message->header.xid));

        sd_dhcp_relay_interface *downstream;
        r = downstream_get(interface->relay, message, &downstream);
        if (r < 0)
                return r;

        /* RFC 3046 abstract:
         * The DHCP Server echoes the option back verbatim to the relay agent in server-to-client
         * replies, and the relay agent strips the option before forwarding the reply to the client.
         *
         * RFC 3046 section 2.1:
         * The Relay Agent Information option echoed by a server MUST be removed by either the relay
         * agent or the trusted downstream network element which added it when forwarding a
         * server-to-client response back to the client.
         *
         * Here, we do not check the contents of the option, and unconditionally remove it. */
        dhcp_message_remove_option(message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION);

        return downstream_send_message(downstream, message);
}

int upstream_send_message(sd_dhcp_relay_interface *interface, sd_dhcp_message *message) {
        int r;

        assert(interface);
        assert(interface->upstream);
        assert(message);
        assert(message->header.op == BOOTREQUEST);
        assert(message->header.giaddr != INADDR_ANY);

        int fd = sd_event_source_get_io_fd(interface->io_event_source);
        if (fd < 0)
                return fd;

        r = dhcp_message_send_udp(
                        message,
                        fd,
                        INADDR_ANY,
                        interface->relay->server_address.s_addr,
                        interface->relay->server_port);
        if (r < 0)
                return r;

        log_dhcp_relay_interface(interface, "Forwarded BOOTREQUEST (0x%"PRIx32") to %s (UDP).",
                                 be32toh(message->header.xid),
                                 IN4_ADDR_TO_STRING(&interface->relay->server_address));
        return 0;
}

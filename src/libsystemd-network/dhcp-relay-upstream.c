/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "dhcp-relay-internal.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "prioq.h"
#include "socket-util.h"

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

int upstream_open_socket(sd_dhcp_relay_interface *interface) {
        int r;

        assert(interface);
        assert(interface->upstream);

        _cleanup_close_ int fd = RET_NERRNO(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (fd < 0)
                return fd;

        r = socket_bind_to_ifindex(fd, interface->ifindex);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, tos_to_priority(interface->ip_service_type));
        if (r < 0)
                return r;

        r = setsockopt_int(fd, IPPROTO_IP, IP_TOS, interface->ip_service_type);
        if (r < 0)
                return r;

        union sockaddr_union src = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(interface->port),
                .in.sin_addr = interface->address,
        };

        if (bind(fd, &src.sa, sizeof(src.in)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

int upstream_process_message(sd_dhcp_relay_interface *interface, const struct iovec *iov) {
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

int upstream_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_relay_interface *interface = ASSERT_PTR(userdata);
        int r;

        assert(interface->upstream);
        assert(fd >= 0);

        ssize_t buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp_relay_interface_errno(
                                interface, buflen,
                                "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        _cleanup_free_ void *buf = malloc0(buflen);
        if (!buf)
                return log_oom_debug();

        struct msghdr msg = {
                .msg_iov = &IOVEC_MAKE(buf, buflen),
                .msg_iovlen = 1,
        };

        ssize_t len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_relay_interface_errno(
                                interface, len,
                                "Could not receive message, ignoring: %m");
                return 0;
        }

        r = upstream_process_message(interface, &IOVEC_MAKE(buf, len));
        if (r < 0)
                log_dhcp_relay_interface_errno(
                                interface, r,
                                "Could not process message, ignoring: %m");

        return 0;
}

int upstream_send_message(sd_dhcp_relay_interface *interface, sd_dhcp_message *message) {
        int r;

        assert(interface);
        assert(interface->relay);
        assert(interface->upstream);
        assert(message);
        assert(message->header.op == BOOTREQUEST);
        assert(message->header.giaddr != INADDR_ANY);

        int fd = sd_event_source_get_io_fd(interface->io_event_source);
        if (fd < 0)
                return fd;

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        r = dhcp_message_build(message, &payload);
        if (r < 0)
                return r;

        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(interface->relay->server_port),
                .in.sin_addr = interface->relay->server_address,
        };

        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa.in),
                .msg_iov = payload.iovec,
                .msg_iovlen = payload.count,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        log_dhcp_relay_interface(interface, "Forwarded BOOTREQUEST (0x%"PRIx32") to %s",
                                be32toh(message->header.xid),
                                IN4_ADDR_TO_STRING(&interface->relay->server_address));
        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-protocol.h"
#include "dhcp-relay-internal.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "string-util.h"

static sd_dhcp_relay_interface* dhcp_relay_interface_free(sd_dhcp_relay_interface *interface) {
        if (!interface)
                return NULL;

        assert(interface->relay);

        sd_event_source_disable_unref(interface->io_event_source);
        safe_close(interface->socket_fd);

        if (interface->upstream)
                upstream_done(interface);
        else
                downstream_done(interface);

        hashmap_remove_value(interface->relay->interfaces, INT_TO_PTR(interface->ifindex), interface);
        sd_dhcp_relay_unref(interface->relay);

        free(interface->ifname);
        return mfree(interface);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_relay_interface, sd_dhcp_relay_interface, dhcp_relay_interface_free);

int sd_dhcp_relay_add_interface(sd_dhcp_relay *relay, int ifindex, int is_upstream, sd_dhcp_relay_interface **ret) {
        int r;

        assert_return(relay, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *interface = new(sd_dhcp_relay_interface, 1);
        if (!interface)
                return -ENOMEM;

        /* RFC 1542 section 5.4:
         * The server SHOULD next check the 'giaddr' field. If this field is non-zero, the server SHOULD send
         * the BOOTREPLY as an IP unicast to the IP address identified in the 'giaddr' field. The UDP
         * destination port MUST be set to BOOTPS (67).
         *
         * Hence, the relay agent needs to use DHCP_PORT_SERVER (67) for both source and destination port. */
        *interface = (sd_dhcp_relay_interface) {
                .n_ref = 1,
                .relay = sd_dhcp_relay_ref(relay),
                .upstream = !!is_upstream,
                .ifindex = ifindex,
                .port = DHCP_PORT_SERVER,
                .socket_fd = -EBADF,
                .ip_service_type = IPTOS_CLASS_CS6, /* Defaults to CS6 (Internetwork Control). */
        };

        r = hashmap_ensure_put(&relay->interfaces, NULL, INT_TO_PTR(interface->ifindex), interface);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(interface);
        return 0;
}

int sd_dhcp_relay_interface_set_ifname(sd_dhcp_relay_interface *interface, const char *ifname) {
        assert_return(interface, -EINVAL);

        return free_and_strdup(&interface->ifname, ifname);
}

int sd_dhcp_relay_interface_get_ifname(sd_dhcp_relay_interface *interface, const char **ret) {
        int r;

        assert_return(interface, -EINVAL);

        r = get_ifname(interface->ifindex, &interface->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = interface->ifname;

        return 0;
}

int sd_dhcp_relay_interface_set_address(sd_dhcp_relay_interface *interface, const struct in_addr *address) {
        assert_return(interface, -EINVAL);
        assert_return(interface->relay, -ESTALE);
        assert_return(!sd_dhcp_relay_interface_is_running(interface), -EBUSY);

        if (address)
                interface->address = *address;
        else
                interface->address = (struct in_addr) {};

        return 0;
}

int sd_dhcp_relay_interface_set_port(sd_dhcp_relay_interface *interface, uint16_t port) {
        assert_return(interface, -EINVAL);
        assert_return(interface->relay, -ESTALE);
        assert_return(!sd_dhcp_relay_interface_is_running(interface), -EBUSY);

        interface->port = port;
        return 0;
}

int sd_dhcp_relay_interface_set_ip_service_type(sd_dhcp_relay_interface *interface, uint8_t type) {
        assert_return(interface, -EINVAL);
        assert_return(interface->relay, -ESTALE);
        assert_return(!interface->io_event_source, -EBUSY);

        interface->ip_service_type = type;
        return 0;
}

int sd_dhcp_relay_interface_is_running(sd_dhcp_relay_interface *interface) {
        return interface && sd_event_source_get_enabled(interface->io_event_source, /* ret= */ NULL) > 0;
}

int sd_dhcp_relay_interface_start(sd_dhcp_relay_interface *interface) {
        int r;

        assert_return(interface, -EINVAL);
        assert_return(interface->relay, -ESTALE);
        assert_return(interface->relay->event, -EINVAL);

        if (in4_addr_is_null(&interface->address))
                return -EADDRNOTAVAIL;

        if (sd_event_source_get_enabled(interface->io_event_source, /* ret= */ NULL) > 0)
                return 0; /* Already enabled. */

        _cleanup_close_ int fd_close = -EBADF;
        int fd;
        if (interface->socket_fd >= 0)
                /* When a socket fd is given externally, unconditionally use it and do not close the socket
                 * even if we fail to set up the event source. */
                fd = interface->socket_fd;
        else {
                /* Otherwise, open a new socket. */
                if (interface->upstream)
                        fd = upstream_open_socket(interface);
                else
                        fd = downstream_open_socket(interface);
                if (fd < 0)
                        return fd;

                fd_close = fd;
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(interface->relay->event, &s, fd, EPOLLIN,
                            interface->upstream ? upstream_receive_message : downstream_receive_message,
                            interface);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, interface->relay->event_priority);
        if (r < 0)
                return r;

        const char *name, *description;
        if (sd_dhcp_relay_interface_get_ifname(interface, &name) >= 0)
                description = strjoina("dhcp-relay-interface-io-event-source-", name);
        else
                description = "dhcp-relay-interface-io-event-source";
        (void) sd_event_source_set_description(s, description);

        if (fd_close >= 0) {
                r = sd_event_source_set_io_fd_own(s, true);
                if (r < 0)
                        return r;
                TAKE_FD(fd_close);
        }

        /* This may potentially fail, in which case the event source should be discarded. */
        if (interface->upstream)
                r = upstream_register(interface);
        else
                r = downstream_register(interface);
        if (r < 0)
                return r;

        sd_event_source_disable_unref(interface->io_event_source);
        interface->io_event_source = TAKE_PTR(s);
        return 0;
}

int sd_dhcp_relay_interface_stop(sd_dhcp_relay_interface *interface) {
        if (!interface)
                return 0;

        interface->io_event_source = sd_event_source_disable_unref(interface->io_event_source);

        if (interface->upstream)
                upstream_unregister(interface);
        else
                downstream_unregister(interface);
        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-dhcp6-relay.h"
#include "sd-event.h"

#include "sd-dhcp6-protocol.h"

#include "alloc-util.h"
#include "dhcp6-protocol.h"
#include "dhcp6-relay-internal.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "network-common.h"
#include "socket-util.h"
#include "string-util.h"
#include "unaligned.h"

static sd_dhcp6_relay *dhcp6_relay_free(sd_dhcp6_relay *relay) {
        if (!relay)
                return NULL;

        sd_dhcp6_relay_stop(relay);

        sd_event_unref(relay->event);

        free(relay->ifname);
        free(relay->interface_id);

        return mfree(relay);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_relay, sd_dhcp6_relay, dhcp6_relay_free);

int sd_dhcp6_relay_new(sd_dhcp6_relay **ret) {
        _cleanup_(sd_dhcp6_relay_unrefp) sd_dhcp6_relay *relay = NULL;

        assert_return(ret, -EINVAL);

        relay = new(sd_dhcp6_relay, 1);
        if (!relay)
                return -ENOMEM;

        *relay = (sd_dhcp6_relay) {
                .n_ref = 1,
                .fd = -EBADF,
        };

        *ret = TAKE_PTR(relay);
        return 0;
}

int sd_dhcp6_relay_set_ifindex(sd_dhcp6_relay *relay, int ifindex) {
        assert_return(relay, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        relay->ifindex = ifindex;
        return 0;
}

int sd_dhcp6_relay_set_ifname(sd_dhcp6_relay *relay, const char *ifname) {
        assert_return(relay, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&relay->ifname, ifname);
}

int sd_dhcp6_relay_get_ifname(sd_dhcp6_relay *relay, const char **ret) {
        int r;

        assert_return(relay, -EINVAL);

        r = get_ifname(relay->ifindex, &relay->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = relay->ifname;

        return 0;
}

int sd_dhcp6_relay_attach_event(sd_dhcp6_relay *relay, sd_event *event, int64_t priority) {
        assert_return(relay, -EINVAL);
        assert_return(!relay->event, -EBUSY);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        if (event)
                relay->event = sd_event_ref(event);
        else {
                int r;

                r = sd_event_default(&relay->event);
                if (r < 0)
                        return r;
        }

        relay->event_priority = priority;
        return 0;
}

int sd_dhcp6_relay_detach_event(sd_dhcp6_relay *relay) {
        assert_return(relay, -EINVAL);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        relay->event = sd_event_unref(relay->event);
        return 0;
}

sd_event *sd_dhcp6_relay_get_event(sd_dhcp6_relay *relay) {
        assert_return(relay, NULL);

        return relay->event;
}

int sd_dhcp6_relay_set_link_address(sd_dhcp6_relay *relay, const struct in6_addr *address) {
        assert_return(relay, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        relay->link_address = *address;
        return 0;
}

int sd_dhcp6_relay_set_relay_target(sd_dhcp6_relay *relay, const struct in6_addr *target) {
        assert_return(relay, -EINVAL);
        assert_return(target, -EINVAL);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        relay->relay_target = *target;
        return 0;
}

int sd_dhcp6_relay_set_interface_id(sd_dhcp6_relay *relay, const char *interface_id) {
        assert_return(relay, -EINVAL);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        return free_and_strdup(&relay->interface_id, interface_id);
}

int sd_dhcp6_relay_is_running(sd_dhcp6_relay *relay) {
        if (!relay)
                return false;

        return relay->running;
}

static int dhcp6_relay_send_message(sd_dhcp6_relay *relay, const struct in6_addr *destination, uint16_t port, const void *message, size_t len) {
        union sockaddr_union dest = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = *ASSERT_PTR(destination),
                .in6.sin6_port = htobe16(port),
        };

        assert(relay);
        assert(message);

        /* For link-local and multicast destinations, set scope_id */
        if (in6_addr_is_link_local(destination) || in6_addr_is_multicast(destination))
                dest.in6.sin6_scope_id = relay->ifindex;

        if (sendto(relay->fd, message, len, 0, &dest.sa, sizeof(dest.in6)) < 0)
                return -errno;

        return 0;
}

static int dhcp6_relay_forward_client_message(
                sd_dhcp6_relay *relay,
                const uint8_t *message,
                size_t len,
                const struct in6_addr *peer_address) {

        _cleanup_free_ uint8_t *buf = NULL;
        size_t offset, interface_id_len, total_len;

        assert(relay);
        assert(message);
        assert(peer_address);
        assert(len > 0);

        if (len > UINT16_MAX)
                return -EMSGSIZE;

        interface_id_len = relay->interface_id ? strlen(relay->interface_id) : 0;

        /* Calculate total message size:
         * relay header (34) + Relay-Message option (4 + len) + optional Interface-Id option (4 + interface_id_len) */
        total_len = DHCP6_RELAY_HEADER_SIZE + 4 + len;
        if (interface_id_len > 0)
                total_len += 4 + interface_id_len;

        buf = new(uint8_t, total_len);
        if (!buf)
                return -ENOMEM;

        /* Build Relay-Forward header */
        offset = 0;
        buf[offset++] = DHCP6_MESSAGE_RELAY_FORWARD;
        buf[offset++] = 0; /* hop-count = 0 for client messages */
        memcpy(buf + offset, &relay->link_address, sizeof(struct in6_addr)); /* link-address */
        offset += sizeof(struct in6_addr);
        memcpy(buf + offset, peer_address, sizeof(struct in6_addr)); /* peer-address */
        offset += sizeof(struct in6_addr);

        /* Append Interface-Id option (type 18) if set */
        if (interface_id_len > 0) {
                unaligned_write_be16(buf + offset, SD_DHCP6_OPTION_INTERFACE_ID);
                offset += 2;
                unaligned_write_be16(buf + offset, interface_id_len);
                offset += 2;
                memcpy(buf + offset, relay->interface_id, interface_id_len);
                offset += interface_id_len;
        }

        /* Append Relay-Message option (type 9) */
        unaligned_write_be16(buf + offset, SD_DHCP6_OPTION_RELAY_MSG);
        offset += 2;
        unaligned_write_be16(buf + offset, len);
        offset += 2;
        memcpy(buf + offset, message, len);
        offset += len;

        assert(offset == total_len);

        log_dhcp6_relay(relay, "Forwarding client message (type %u, %zu bytes) to server", message[0], len);

        return dhcp6_relay_send_message(relay, &relay->relay_target, DHCP6_PORT_SERVER, buf, total_len);
}

static int dhcp6_relay_forward_relay_message(
                sd_dhcp6_relay *relay,
                const uint8_t *message,
                size_t len,
                const struct in6_addr *peer_address) {

        _cleanup_free_ uint8_t *buf = NULL;
        size_t offset, interface_id_len, total_len;
        uint8_t hop_count;

        assert(relay);
        assert(message);
        assert(peer_address);
        assert(len >= DHCP6_RELAY_HEADER_SIZE);

        if (len > UINT16_MAX)
                return -EMSGSIZE;

        /* Extract hop count from the original relay-forward and increment */
        hop_count = message[1];
        if (hop_count >= DHCP6_HOP_COUNT_LIMIT) {
                log_dhcp6_relay(relay, "Hop count limit reached (%u), discarding.", hop_count);
                return -ELOOP;
        }

        interface_id_len = relay->interface_id ? strlen(relay->interface_id) : 0;

        total_len = DHCP6_RELAY_HEADER_SIZE + 4 + len;
        if (interface_id_len > 0)
                total_len += 4 + interface_id_len;

        buf = new(uint8_t, total_len);
        if (!buf)
                return -ENOMEM;

        offset = 0;
        buf[offset++] = DHCP6_MESSAGE_RELAY_FORWARD;
        buf[offset++] = hop_count + 1;
        memcpy(buf + offset, &relay->link_address, sizeof(struct in6_addr));
        offset += sizeof(struct in6_addr);
        memcpy(buf + offset, peer_address, sizeof(struct in6_addr));
        offset += sizeof(struct in6_addr);

        if (interface_id_len > 0) {
                unaligned_write_be16(buf + offset, SD_DHCP6_OPTION_INTERFACE_ID);
                offset += 2;
                unaligned_write_be16(buf + offset, interface_id_len);
                offset += 2;
                memcpy(buf + offset, relay->interface_id, interface_id_len);
                offset += interface_id_len;
        }

        unaligned_write_be16(buf + offset, SD_DHCP6_OPTION_RELAY_MSG);
        offset += 2;
        unaligned_write_be16(buf + offset, len);
        offset += 2;
        memcpy(buf + offset, message, len);
        offset += len;

        assert(offset == total_len);

        log_dhcp6_relay(relay, "Re-wrapping relay-forward message (hop %u, %zu bytes)", (unsigned) (hop_count + 1), len);

        return dhcp6_relay_send_message(relay, &relay->relay_target, DHCP6_PORT_SERVER, buf, total_len);
}

static int dhcp6_relay_handle_reply(sd_dhcp6_relay *relay, const uint8_t *message, size_t len) {
        struct in6_addr peer_address;
        const uint8_t *options, *inner_message = NULL;
        size_t options_len, inner_message_len = 0;
        size_t offset;

        assert(relay);
        assert(message);

        if (len < DHCP6_RELAY_HEADER_SIZE) {
                log_dhcp6_relay(relay, "Relay-Reply too short (%zu bytes), discarding.", len);
                return -EBADMSG;
        }

        /* Verify link-address matches our own (RFC 8415 section 19.3).
         * The server copies link-address from Relay-Forward into Relay-Reply,
         * so it must always match what we sent. */
        struct in6_addr link_address;
        memcpy(&link_address, message + 2, sizeof(struct in6_addr));
        if (!in6_addr_equal(&link_address, &relay->link_address)) {
                log_dhcp6_relay(relay, "Relay-Reply link-address does not match our address, discarding.");
                return -EBADMSG;
        }

        /* Extract peer-address from bytes 18-33 */
        memcpy(&peer_address, message + 2 + sizeof(struct in6_addr), sizeof(struct in6_addr));

        /* Parse options after the relay header */
        options = message + DHCP6_RELAY_HEADER_SIZE;
        options_len = len - DHCP6_RELAY_HEADER_SIZE;

        offset = 0;
        while (offset + 4 <= options_len) {
                uint16_t opt_code = unaligned_read_be16(options + offset);
                uint16_t opt_len = unaligned_read_be16(options + offset + 2);

                if (offset + 4 + opt_len > options_len) {
                        log_dhcp6_relay(relay, "Truncated option in Relay-Reply, discarding.");
                        return -EBADMSG;
                }

                if (opt_code == SD_DHCP6_OPTION_RELAY_MSG) {
                        inner_message = options + offset + 4;
                        inner_message_len = opt_len;
                }

                offset += 4 + opt_len;
        }

        if (!inner_message || inner_message_len == 0) {
                log_dhcp6_relay(relay, "Relay-Reply without Relay-Message option, discarding.");
                return -EBADMSG;
        }

        /* If inner message is a Relay-Reply (nested relay), send to server port; otherwise to client port */
        uint16_t dest_port = (inner_message_len > 0 && inner_message[0] == DHCP6_MESSAGE_RELAY_REPLY)
                ? DHCP6_PORT_SERVER : DHCP6_PORT_CLIENT;

        log_dhcp6_relay(relay, "Forwarding reply (type %u, %zu bytes) to %s",
                        inner_message[0], inner_message_len,
                        dest_port == DHCP6_PORT_SERVER ? "relay" : "client");

        return dhcp6_relay_send_message(relay, &peer_address, dest_port, inner_message, inner_message_len);
}

static int dhcp6_relay_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp6_relay *relay = ASSERT_PTR(userdata);
        _cleanup_free_ uint8_t *buf = NULL;
        union sockaddr_union peer_addr = {};
        struct iovec iov;
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_name = &peer_addr.sa,
                .msg_namelen = sizeof(peer_addr),
        };
        ssize_t datagram_size, len;
        uint8_t msg_type;
        int r;

        datagram_size = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(datagram_size) || ERRNO_IS_NEG_DISCONNECT(datagram_size))
                return 0;
        if (datagram_size < 0) {
                log_dhcp6_relay_errno(relay, datagram_size, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        buf = new(uint8_t, datagram_size);
        if (!buf)
                return -ENOMEM;

        iov = IOVEC_MAKE(buf, datagram_size);

        len = recvmsg_safe(fd, &msg, 0);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp6_relay_errno(relay, len, "Could not receive message, ignoring: %m");
                return 0;
        }

        if (len < 1)
                return 0;

        msg_type = buf[0];

        if (msg_type == DHCP6_MESSAGE_RELAY_FORWARD) {
                if ((size_t) len < DHCP6_RELAY_HEADER_SIZE) {
                        log_dhcp6_relay(relay, "Relay-Forward too short, ignoring.");
                        return 0;
                }
                r = dhcp6_relay_forward_relay_message(relay, buf, len, &peer_addr.in6.sin6_addr);
                if (r < 0)
                        log_dhcp6_relay_errno(relay, r, "Failed to forward relay message: %m");

        } else if (msg_type == DHCP6_MESSAGE_RELAY_REPLY) {
                r = dhcp6_relay_handle_reply(relay, buf, len);
                if (r < 0)
                        log_dhcp6_relay_errno(relay, r, "Failed to handle relay reply: %m");

        } else {
                /* Relay all other messages as client messages (RFC 8415 §19.1) */
                r = dhcp6_relay_forward_client_message(relay, buf, len, &peer_addr.in6.sin6_addr);
                if (r < 0)
                        log_dhcp6_relay_errno(relay, r, "Failed to forward client message: %m");
        }

        return 0;
}

static int dhcp6_relay_open_socket(sd_dhcp6_relay *relay) {
        _cleanup_close_ int s = -EBADF;
        union sockaddr_union src = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = IN6ADDR_ANY_INIT,
                .in6.sin6_port = htobe16(DHCP6_PORT_SERVER),
        };
        struct ipv6_mreq mreq = {
                .ipv6mr_multiaddr = IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS,
                .ipv6mr_ifindex = relay->ifindex,
        };
        int r;

        assert(relay);
        assert(relay->ifindex > 0);

        s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, false);
        if (r < 0)
                return r;

        /* Bind to the specific interface to avoid conflicts with DHCPv6 servers on other interfaces */
        r = socket_bind_to_ifindex(s, relay->ifindex);
        if (r < 0)
                return r;

        r = bind(s, &src.sa, sizeof(src.in6));
        if (r < 0)
                return -errno;

        /* Join multicast group ff02::1:2 (All_DHCP_Relay_Agents_and_Servers) */
        r = setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

int sd_dhcp6_relay_start(sd_dhcp6_relay *relay) {
        int r;

        assert_return(relay, -EINVAL);
        assert_return(relay->event, -EINVAL);
        assert_return(relay->ifindex > 0, -EINVAL);
        assert_return(in6_addr_is_set(&relay->relay_target), -EINVAL);
        assert_return(!sd_dhcp6_relay_is_running(relay), -EBUSY);

        r = dhcp6_relay_open_socket(relay);
        if (r < 0)
                return log_dhcp6_relay_errno(relay, r, "Failed to open socket: %m");

        relay->fd = r;

        r = sd_event_add_io(relay->event, &relay->receive_message, relay->fd, EPOLLIN, dhcp6_relay_receive_message, relay);
        if (r < 0) {
                sd_dhcp6_relay_stop(relay);
                return log_dhcp6_relay_errno(relay, r, "Failed to add event source: %m");
        }

        r = sd_event_source_set_priority(relay->receive_message, relay->event_priority);
        if (r < 0) {
                sd_dhcp6_relay_stop(relay);
                return log_dhcp6_relay_errno(relay, r, "Failed to set event priority: %m");
        }

        (void) sd_event_source_set_description(relay->receive_message, "dhcp6-relay-receive-message");

        relay->running = true;

        log_dhcp6_relay(relay, "Started DHCPv6 relay agent");

        return 0;
}

int sd_dhcp6_relay_stop(sd_dhcp6_relay *relay) {
        bool running;

        if (!relay)
                return 0;

        running = relay->running;

        relay->receive_message = sd_event_source_disable_unref(relay->receive_message);
        relay->fd = safe_close(relay->fd);
        relay->running = false;

        if (running)
                log_dhcp6_relay(relay, "Stopped DHCPv6 relay agent");

        return 0;
}

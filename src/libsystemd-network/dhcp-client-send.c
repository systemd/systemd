/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-event.h"

#include "dhcp-client-internal.h"
#include "dhcp-client-send.h"
#include "dhcp-lease-internal.h"  /* IWYU pragma: keep */
#include "dhcp-message.h"
#include "dhcp-network.h"
#include "fd-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "socket-util.h"

static int client_get_socket(sd_dhcp_client *client, int domain) {
        int r, d, fd;

        assert(client);
        assert(IN_SET(domain, AF_PACKET, AF_INET));

        /* When a socket fd is given externally, unconditionally use it. */
        if (client->socket_fd >= 0)
                return client->socket_fd;

        if (!client->receive_message)
                return -EBADF;

        fd = sd_event_source_get_io_fd(client->receive_message);
        if (fd < 0)
                return fd;

        r = getsockopt_int(fd, SOL_SOCKET, SO_DOMAIN, &d);
        if (r < 0)
                return r;

        if (d != domain)
                return -EBADF;

        return fd;
}

static int client_setup_io_event(
                sd_dhcp_client *client,
                int fd,
                sd_event_io_handler_t callback,
                const char *description) {

        int r;

        assert(client);
        assert(fd >= 0);
        assert(callback);
        assert(description);

        /* When the socket fd is given externally, the fd is used for both UDP and RAW packet operations.
         * Hence, first we need to disable the previous event source, otherwise sd_event_add_io() will fail
         * with -EEXIST. */
        if (fd == client->socket_fd)
                client->receive_message = sd_event_source_disable_unref(client->receive_message);

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(client->event, &s, fd, EPOLLIN, callback, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, client->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, description);
        if (r < 0)
                return r;

        /* When the socket fd is given externally, do not close it while we are running. The IO event source
         * is freed when not necessary, hence the lifetime of the socket fd should not be tied to the one of
         * the event source in that case. */
        if (fd != client->socket_fd) {
                r = sd_event_source_set_io_fd_own(s, true);
                if (r < 0)
                        return r;
        }

        sd_event_source_disable_unref(client->receive_message);
        client->receive_message = TAKE_PTR(s);
        return 0;
}

static int client_send_raw(
                sd_dhcp_client *client,
                sd_dhcp_message *message,
                bool expect_reply) {

        _cleanup_close_ int fd_close = -EBADF;
        int r, fd;

        assert(client);
        assert(message);

        fd = client_get_socket(client, AF_PACKET);
        if (fd < 0) {
                fd = dhcp_network_bind_raw_socket(
                                client->ifindex,
                                &client->link,
                                client->xid,
                                &client->hw_addr,
                                &client->bcast_addr,
                                client->arp_type,
                                client->port,
                                /* so_priority_set= */ true,
                                client->socket_priority);
                if (fd < 0)
                        return fd;

                fd_close = fd;
        }

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        r = dhcp_message_build(message, &payload);
        if (r < 0)
                return r;

        struct iphdr ip;
        struct udphdr udp;
        r = udp_packet_build(
                        INADDR_ANY,
                        client->port,
                        INADDR_BROADCAST,
                        client->server_port,
                        client->ip_service_type,
                        &payload,
                        &ip,
                        &udp);
        if (r < 0)
                return r;

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        r = iovw_put(&iovw, &ip, sizeof(struct iphdr));
        if (r < 0)
                return r;

        r = iovw_put(&iovw, &udp, sizeof(struct udphdr));
        if (r < 0)
                return r;

        r = iovw_put_iovw(&iovw, &payload);
        if (r < 0)
                return r;

        r = dhcp_network_send_raw_socket(fd, &client->link, &iovw);
        if (r < 0)
                return r;

        if (!expect_reply) {
                /* We do not expect any replies, hence stop the IO event source if enabled. */
                client->receive_message = sd_event_source_disable_unref(client->receive_message);
                return 0;
        }

        if (fd_close < 0 && fd != client->socket_fd)
                return 0; /* Already opened socket is reused. Not necessary to setup new IO event source. */

        r = client_setup_io_event(client, fd, client_receive_message_raw, "dhcp4-receive-message-raw");
        if (r < 0)
                return r;

        TAKE_FD(fd_close);
        return 0;
}

static int client_send_udp(
                sd_dhcp_client *client,
                sd_dhcp_message *message,
                bool expect_reply) {

        _cleanup_close_ int fd_close = -EBADF;
        int r, fd;

        assert(client);
        assert(message);

        if (!client->lease || client->lease->address == 0)
                return -EADDRNOTAVAIL;

        fd = client_get_socket(client, AF_INET);
        if (fd < 0) {
                fd = dhcp_network_bind_udp_socket(
                                client->ifindex,
                                client->lease->address,
                                client->port,
                                client->ip_service_type);
                if (fd < 0)
                        return fd;

                fd_close = fd;
        }

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        r = dhcp_message_build(message, &payload);
        if (r < 0)
                return r;

        r = dhcp_network_send_udp_socket(
                        fd,
                        client->lease->server_address,
                        client->server_port,
                        &payload);
        if (r < 0)
                return r;

        if (!expect_reply) {
                /* We do not expect any replies, hence stop the IO event source if enabled. */
                client->receive_message = sd_event_source_disable_unref(client->receive_message);
                return 0;
        }

        if (fd_close < 0 && fd != client->socket_fd)
                return 0; /* Already opened socket is reused. Not necessary to setup new IO event source. */

        r = client_setup_io_event(client, fd, client_receive_message_udp, "dhcp4-receive-message-udp");
        if (r < 0)
                return r;

        TAKE_FD(fd_close);
        return 0;
}

static int client_new_message(sd_dhcp_client *client, uint8_t type, sd_dhcp_message **ret) {
        int r;

        assert(client);
        assert(IN_SET(type, DHCP_DISCOVER, DHCP_REQUEST, DHCP_RELEASE, DHCP_DECLINE));
        assert(ret);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        r = dhcp_message_init_header(
                        message,
                        BOOTREQUEST,
                        client->xid,
                        client->arp_type,
                        &client->hw_addr);
        if (r < 0)
                return r;

        /* Although 'secs' field is a SHOULD in RFC 2131, certain DHCP servers refuse to issue a DHCP lease
         * if 'secs' is set to zero. */
        usec_t time_now;
        r = sd_event_now(client->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;
        assert(time_now >= client->start_time);

        /* Seconds between sending first and last DISCOVER must always be strictly positive to deal with
         * broken servers. */
        message->header.secs = usec_to_be16_sec(usec_sub_unsigned(time_now, client->start_time) ?: 1 * USEC_PER_SEC);

        /* RFC2131 section 4.1
         * A client that cannot receive unicast IP datagrams until its protocol software has been configured
         * with an IP address SHOULD set the BROADCAST bit in the 'flags' field to 1 in any DHCPDISCOVER or
         * DHCPREQUEST messages that client sends. The BROADCAST bit will provide a hint to the DHCP server
         * and BOOTP relay agent to broadcast any messages to the client on the client's subnet.
         *
         * Note: some interfaces needs this to be enabled, but some networks need this to be disabled as
         * broadcasts are filtered, so this needs to be configurable. */
        dhcp_message_set_broadcast_flag(message, client->request_broadcast || client->arp_type != ARPHRD_ETHER);

        /* We append no vendor options on BOOTP mode. */
        if (client->bootp) {
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* DHCP Message Type (53): Mandatory. */
        r = dhcp_message_append_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, type);
        if (r < 0)
                return r;

        /* Server Identifier (54): mandatory in DHCPREQUEST on REQUESTING state. It is also mandatory when
         * DHCPRELEASE and DHCPDECLINE. */
        if ((type == DHCP_REQUEST && client->state == DHCP_STATE_REQUESTING) ||
            IN_SET(type, DHCP_RELEASE, DHCP_DECLINE)) {
                r = dhcp_message_append_option_be32(
                                message,
                                SD_DHCP_OPTION_SERVER_IDENTIFIER,
                                ASSERT_PTR(client->lease)->server_address);
                if (r < 0)
                        return r;
        }

        /* Client Identifier (61): Not mandatory, but some DHCP servers will reject messages without client
         * identifier option. Hence, we always set it. */
        r = dhcp_message_append_option_client_id(message, &client->client_id);
        if (r < 0)
                return r;

        /* Requested IP Address option (50) or ciaddr
         *
         * See RFC2131 section 4.3.2 (note that there is a typo in the RFC, SELECTING should be REQUESTING). */
        be32_t addr = INADDR_ANY;
        switch (type) {
        case DHCP_DISCOVER:
                /* the client may suggest values for the network address and lease time in the DHCPDISCOVER
                 * message. The client may include the ’requested IP address’ option to suggest that a
                 * particular IP address be assigned, and may include the ’IP address lease time’ option to
                 * suggest the lease time it would like.
                 *
                 * RFC7844 section 3:
                 * SHOULD NOT contain any other option (when running on anonymize mode). */
                if (!client->anonymize)
                        addr = client->last_addr;
                break;

        case DHCP_REQUEST:
                switch (client->state) {

                case DHCP_STATE_REQUESTING:
                        /* ’ciaddr’ MUST be zero, ’requested IP address’ MUST be filled in with the
                         * yiaddr value from the chosen DHCPOFFER. */
                        addr = ASSERT_PTR(client->lease)->address;
                        break;

                case DHCP_STATE_REBOOTING:
                        /* ’requested IP address’ option MUST be filled in with client’s notion of its
                         * previously assigned address. ’ciaddr’ MUST be zero. */
                        addr = client->last_addr;
                        break;

                case DHCP_STATE_RENEWING:
                case DHCP_STATE_REBINDING:
                        /* ’requested IP address’ option MUST NOT be filled in, ’ciaddr’ MUST be filled
                         * in with client’s IP address. */
                        message->header.ciaddr = ASSERT_PTR(client->lease)->address;
                        break;

                default:
                        assert_not_reached();
                }
                break;

        case DHCP_RELEASE:
                /* The acquired address must be set in ciaddr. */
                message->header.ciaddr = ASSERT_PTR(client->lease)->address;
                break;

        case DHCP_DECLINE:
                /* The acquired address must be set in Requested IP Address option. */
                addr = ASSERT_PTR(client->lease)->address;
                break;

        default:
                assert_not_reached();
        }

        if (addr != INADDR_ANY) {
                r = dhcp_message_append_option_be32(message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr);
                if (r < 0)
                        return r;
        }

        /* DHCPRELEASE and DHCPDECLINE MUST NOT contain any other options. */
        if (IN_SET(type, DHCP_RELEASE, DHCP_DECLINE)) {
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* Parameter Request List (55)
         *
         * RFC2131 section 3.5:
         * in its initial DHCPDISCOVER or DHCPREQUEST message, a client may provide the server with a list of
         * specific parameters the client is interested in. If the client includes a list of parameters in a
         * DHCPDISCOVER message, it MUST include that list in any subsequent DHCPREQUEST messages.
         *
         * RFC7844 section 3:
         * MAY contain the Parameter Request List option.
         *
         * RFC7844 section 3.6:
         * The client intending to protect its privacy SHOULD only request a minimal number of options in the
         * PRL and SHOULD also randomly shuffle the ordering of option codes in the PRL. If this random
         * ordering cannot be implemented, the client MAY order the option codes in the PRL by option code
         * number (lowest to highest).
         *
         * NOTE: using PRL options that Windows 10 RFC7844 implementation uses. */
        if (client->anonymize) {
                static const uint8_t default_req_opts_anonymize[] = {
                        SD_DHCP_OPTION_SUBNET_MASK,                     /* 1 */
                        SD_DHCP_OPTION_ROUTER,                          /* 3 */
                        SD_DHCP_OPTION_DOMAIN_NAME_SERVER,              /* 6 */
                        SD_DHCP_OPTION_DOMAIN_NAME,                     /* 15 */
                        SD_DHCP_OPTION_ROUTER_DISCOVERY,                /* 31 */
                        SD_DHCP_OPTION_STATIC_ROUTE,                    /* 33 */
                        SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,     /* 43 */
                        SD_DHCP_OPTION_NETBIOS_NAME_SERVER,             /* 44 */
                        SD_DHCP_OPTION_NETBIOS_NODE_TYPE,               /* 46 */
                        SD_DHCP_OPTION_NETBIOS_SCOPE,                   /* 47 */
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,          /* 121 */
                        SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE,  /* 249 */
                        SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,     /* 252 */
                };

                r = dhcp_message_append_option(
                                message,
                                SD_DHCP_OPTION_PARAMETER_REQUEST_LIST,
                                ELEMENTSOF(default_req_opts_anonymize),
                                default_req_opts_anonymize);
                if (r < 0)
                        return r;

                /* RFC7844 section 3:
                 * SHOULD NOT contain any other option (when running on anonymize mode). */
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* When not on anonymized mode, use the default + user requested options. */
        r = dhcp_message_append_option_parameter_request_list(message, client->req_opts);
        if (r < 0)
                return r;

        /* Maximum Message Size (57)
         *
         * RFC2131 section 3.5:
         * The client SHOULD include the ’maximum DHCP message size’ option to let the server know how
         * large the server may make its DHCP messages.
         *
         * Note (from ConnMan): Some DHCP servers will send bigger DHCP packets than the defined default size
         * unless the Maximum Message Size option is explicitly set.
         *
         * RFC3442 "Requirements to Avoid Sizing Constraints":
         * Because a full routing table can be quite large, the standard 576 octet maximum size for a DHCP
         * message may be too short to contain some legitimate Classless Static Route options. Because of
         * this, clients implementing the Classless Static Route option SHOULD send a Maximum DHCP Message
         * Size [4] option if the DHCP client's TCP/IP stack is capable of receiving larger IP datagrams.
         * In this case, the client SHOULD set the value of this option to at least the MTU of the interface
         * that the client is configuring. The client MAY set the value of this option higher, up to the size
         * of the largest UDP packet it is prepared to accept. (Note that the value specified in the Maximum
         * DHCP Message Size option is the total maximum packet size, including IP and UDP headers.) */
        r = dhcp_message_append_option_u16(
                        message,
                        SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
                        CLAMP(client->mtu, (uint32_t) IPV4_MIN_REASSEMBLY_SIZE, (uint32_t) UINT16_MAX));
        if (r < 0)
                return r;

        /* Hostname (12) or FQDN (81)
         *
         * Note, it is unclear from RFC 2131 if client should send hostname in DHCPDISCOVER but dhclient does
         * and so we do as well. */
        r = dhcp_message_append_option_hostname(
                        message,
                        DHCP_FQDN_FLAG_S, /* Request server to perform A RR DNS updates */
                        /* is_client= */ true,
                        client->hostname);
        if (r < 0)
                return r;

        /* Vendor Specific (43) */
        r = dhcp_message_append_option_sub_tlv(
                        message,
                        SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,
                        client->vendor_options);
        if (r < 0)
                return r;

        /* Vendor Class Identifier (60) */
        r = dhcp_message_append_option_string(
                        message,
                        SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER,
                        client->vendor_class_identifier);
        if (r < 0)
                return r;

        /* User Class (77) */
        r = dhcp_message_append_option_length_prefixed_data(
                        message,
                        SD_DHCP_OPTION_USER_CLASS,
                        /* length_size= */ 1,
                        &client->user_class);
        if (r < 0)
                return r;

        /* Rapid Commit (80): only for DHCPDISCOVER */
        if (client->rapid_commit && type == DHCP_DISCOVER) {
                r = dhcp_message_append_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return r;
        }

        /* MUD URL (161) */
        r = dhcp_message_append_option_string(message, SD_DHCP_OPTION_MUD_URL, client->mudurl);
        if (r < 0)
                return r;

        r = dhcp_message_append_option_tlv(message, client->extra_options);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_client_send_message(sd_dhcp_client *client, uint8_t type) {
        int r;

        assert(client);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = client_new_message(client, type, &message);
        if (r < 0)
                return r;

        switch (type) {
        case DHCP_DISCOVER:
                r = client_send_raw(client, message, /* expect_reply= */ true);
                break;
        case DHCP_REQUEST:
                if (client->state == DHCP_STATE_RENEWING)
                        r = client_send_udp(client, message, /* expect_reply= */ true);
                else
                        r = client_send_raw(client, message, /* expect_reply= */ true);
                break;
        case DHCP_RELEASE:
                r = client_send_udp(client, message, /* expect_reply= */ false);
                break;
        case DHCP_DECLINE:
                r = client_send_raw(client, message, /* expect_reply= */ false);
                break;
        default:
                r = -EINVAL;
        }
        if (r < 0)
                return r;

        if (client->bootp)
                log_dhcp_client(client, "BOOTREQUEST");
        else if (type == DHCP_REQUEST)
                log_dhcp_client(client, "%s (%s)",
                                dhcp_message_type_to_string(type),
                                dhcp_state_to_string(client->state));
        else
                log_dhcp_client(client, "%s", dhcp_message_type_to_string(type));
        return 0;
}

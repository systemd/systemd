/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-request.h"
#include "dhcp-server-send.h"
#include "errno-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "ip-util.h"
#include "set.h"
#include "siphash24.h"
#include "socket-util.h"
#include "string-util.h"

static sd_dhcp_request* dhcp_request_free(sd_dhcp_request *req) {
        if (!req)
                return NULL;

        sd_dhcp_message_unref(req->message);
        set_free(req->parameter_request_list);

        return mfree(req);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_request, sd_dhcp_request, dhcp_request_free);

static void dhcp_request_set_timestamp(sd_dhcp_request *req, const triple_timestamp *timestamp) {
        assert(req);

        if (timestamp && triple_timestamp_is_set(timestamp))
                req->timestamp = *timestamp;
        else
                triple_timestamp_now(&req->timestamp);
}

int dhcp_request_get_lifetime_timestamp(sd_dhcp_request *req, clockid_t clock, usec_t *ret) {
        assert(req);
        assert(TRIPLE_TIMESTAMP_HAS_CLOCK(clock));
        assert(clock_supported(clock));
        assert(ret);

        if (req->lifetime <= 0)
                return -ENODATA;

        if (!triple_timestamp_is_set(&req->timestamp))
                return -ENODATA;

        *ret = usec_add(triple_timestamp_by_clock(&req->timestamp, clock), req->lifetime);
        return 0;
}

static int dhcp_request_set_client_id(sd_dhcp_request *req) {
        assert(req);
        assert(req->message);

        /* Genuine client ID from Client Identifier option. The option may not be set. */
        (void) dhcp_message_get_option_client_id(req->message, &req->client_id);

        /* Fake client ID generated from the DHCP header.
         * The client ID type 0 and 255 are special. So do not use if htype is 0 or 255.
         * Note, Some hardware type (e.g. Infiniband) may not set chaddr field. */
        if (!IN_SET(req->message->header.htype, 0, UINT8_MAX))
                (void) sd_dhcp_client_id_set(
                                &req->client_id_by_header,
                                req->message->header.htype,
                                req->message->header.chaddr,
                                req->message->header.hlen);

        /* If Client Identifier option is unspecified, use the generated one. */
        if (!sd_dhcp_client_id_is_set(&req->client_id))
                req->client_id = req->client_id_by_header;

        /* We manage bound leases by client ID. Hence, at least one of them are necessary. */
        if (!sd_dhcp_client_id_is_set(&req->client_id))
                return -EBADMSG;

        return 0;
}

static int dhcp_request_set_server_identifier(sd_dhcp_request *req) {
        int r;

        assert(req);
        assert(req->message);

        bool mandatory = IN_SET(req->type, DHCP_RELEASE, DHCP_DECLINE);

        be32_t a;
        r = dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_SERVER_IDENTIFIER, &a);
        if (r < 0)
                return mandatory ? r : 0;

        req->server_address = a;
        return 0;
}

static int dhcp_request_set_maximum_message_size(sd_dhcp_request *req) {
        int r;

        assert(req);
        assert(req->message);

        uint16_t sz;
        r = dhcp_message_get_option_u16(req->message, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &sz);
        if (r < 0)
                return r;

        /* RFC 2132 section 9.10:
         * The minimum legal value is 576 octets. */
        if (sz < IPV4_MIN_REASSEMBLY_SIZE)
                return -EBADMSG;

        req->max_message_size = sz;
        return 0;
}

static int dhcp_request_set_lifetime(sd_dhcp_request *req, sd_dhcp_server *server) {
        assert(req);
        assert(req->message);
        assert(server);

        (void) dhcp_message_get_option_sec(
                        req->message,
                        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
                        /* max_as_infinity= */ true,
                        &req->lifetime);

        /* If unset (or zero is specified...), use the default lease time. */
        if (req->lifetime <= 0)
                req->lifetime = MAX(30 * USEC_PER_SEC, server->default_lease_time);

        /* If the requested lifetime is too long, then cap it with the maximum lease time. */
        if (server->max_lease_time > 0 && req->lifetime > server->max_lease_time)
                req->lifetime = server->max_lease_time;

        return 0;
}

static int dhcp_server_parse_message(sd_dhcp_server *server, const struct iovec *iov, sd_dhcp_request **ret) {
        int r;

        assert(server);
        assert(iov);
        assert(ret);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_parse(
                        iov,
                        sd_dhcp_server_is_in_relay_mode(server) ? 0 : BOOTREQUEST,
                        /* xid= */ NULL,
                        ARPHRD_NONE,
                        /* hw_addr= */ NULL,
                        &message);
        if (r < 0)
                return r;

        _cleanup_(sd_dhcp_request_unrefp) sd_dhcp_request *req = new(sd_dhcp_request, 1);
        if (!req)
                return -ENOMEM;

        *req = (sd_dhcp_request) {
                .n_ref = 1,
                .message = sd_dhcp_message_ref(message),
                .max_message_size = UINT16_MAX, /* maximum UDP packet size */
        };

        /* client hardware address
         * Note, hlen and chaddr may not be set for non-ethernet interface.
         * See RFC2131 section 4.1. */
        r = dhcp_message_get_hw_addr(req->message, &req->hw_addr);
        if (r < 0)
                return r;

        /* Message Type: mandatory */
        r = dhcp_message_get_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, &req->type);
        if (r < 0)
                return r;

        /* Client Identifier: Mandatory. If not set, fall back to use chaddr. */
        r = dhcp_request_set_client_id(req);
        if (r < 0)
                return r;

        /* Server Identifier */
        r = dhcp_request_set_server_identifier(req);
        if (r < 0)
                return r;

        /* Maximum Message Size: optional */
        (void) dhcp_request_set_maximum_message_size(req);

        /* Lifetime: optional */
        (void) dhcp_request_set_lifetime(req, server);

        /* Parameter Request List: optional */
        (void) dhcp_message_get_option_parameter_request_list(message, &req->parameter_request_list);

        *ret = TAKE_PTR(req);
        return 0;
}

static int dhcp_server_ack(sd_dhcp_server *server, sd_dhcp_request *req) {
        int r;

        assert(server);
        assert(req);
        assert(req->address != INADDR_ANY);

        r = dhcp_server_set_lease(server, req);
        if (r < 0)
                return r;

        r = dhcp_server_send_reply(server, req, DHCP_ACK);
        if (r < 0)
                return r;

        dhcp_server_on_lease_change(server);
        return 0;
}

static int dhcp_server_process_discover(sd_dhcp_server *server, sd_dhcp_request *req) {
        assert(server);
        assert(req);

        sd_dhcp_server_lease
                *existing_lease = hashmap_get(server->bound_leases_by_client_id, &req->client_id),
                *static_lease = dhcp_server_get_static_lease(server, req);

        log_dhcp_server(server, "DISCOVER (0x%x)", be32toh(req->message->header.xid));

        if (server->pool_size == 0)
                return -EADDRNOTAVAIL; /* no pool allocated */

        /* for now pick a random free address from the pool */
        if (static_lease) {
                sd_dhcp_server_lease *l = hashmap_get(server->bound_leases_by_address, UINT32_TO_PTR(static_lease->address));
                if (l && l != existing_lease)
                        /* The address is already assigned to another host. Refusing. */
                        return -EADDRINUSE;

                /* Found a matching static lease. */
                req->static_lease = static_lease;
                req->address = static_lease->address;

        } else if (existing_lease && address_is_in_pool(server, existing_lease->address))
                /* If we previously assigned an address to the host, then reuse it. */
                req->address = existing_lease->address;

        else {
                struct siphash state;
                uint64_t hash;

                /* Even with no persistence of leases, we try to offer the same client the same IP address.
                 * We do this by using the hash of the client ID as the offset into the pool of leases when
                 * finding the next free one. */

#define HASH_KEY SD_ID128_MAKE(0d,1d,fe,bd,f1,24,bd,b3,47,f1,dd,6e,73,21,93,30)

                siphash24_init(&state, HASH_KEY.bytes);
                client_id_hash_func(&req->client_id, &state);
                hash = htole64(siphash24_finalize(&state));

                for (unsigned i = 0; i < server->pool_size; i++) {
                        be32_t a = server->subnet | htobe32(server->pool_offset + (hash + i) % server->pool_size);
                        if (address_available(server, a)) {
                                req->address = a;
                                break;
                        }
                }
        }

        if (req->address == INADDR_ANY)
                return -EADDRNOTAVAIL; /* no free addresses left */

        if (server->rapid_commit &&
            dhcp_message_get_option_flag(req->message, SD_DHCP_OPTION_RAPID_COMMIT) >= 0)
                return dhcp_server_ack(server, req);

        return dhcp_server_send_reply(server, req, DHCP_OFFER);
}

static int dhcp_server_process_request(sd_dhcp_server *server, sd_dhcp_request *req) {
        int r;

        assert(server);
        assert(req);

        sd_dhcp_server_lease
                *existing_lease = hashmap_get(server->bound_leases_by_client_id, &req->client_id),
                *static_lease = dhcp_server_get_static_lease(server, req);

        const char *state;
        be32_t address;

        /* see RFC 2131, section 4.3.2 */
        if (req->server_address != INADDR_ANY) {
                state = "selecting";

                if (req->server_address != server->address) /* client did not pick us */
                        return 0; /* The message is not for us. Let's silently ignore the packet. */

                if (req->message->header.ciaddr != INADDR_ANY) /* this MUST be zero */
                        return -EBADMSG;

                /* this must be filled in with the yiaddr from the chosen OFFER */
                r = dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &address);
                if (r < 0)
                        return r;

                if (address == INADDR_ANY)
                        return -EBADMSG;

        } else if (req->message->header.ciaddr != INADDR_ANY) {
                state = "rebinding/renewing";

                /* this must NOT be filled */
                if (dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, /* ret= */ NULL) >= 0)
                        return -EBADMSG;

                address = req->message->header.ciaddr;

        } else {
                state = "init-reboot";

                r = dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &address);
                if (r < 0)
                        return r;

                if (address == INADDR_ANY)
                        return -EBADMSG;
        }

        log_dhcp_server(server, "REQUEST (%s) (0x%x)", state, be32toh(req->message->header.xid));

        /* Check if the requested address is already assigned to another host.
         * - if 'l' is NULL, then the address is not assigned to any host.
         * - if 'l' is non-NULL, and equivalent to 'existing_lease', then the address is assigned to the host.
         * - if 'l' is non-NULL, but different from 'existing_lease', then the address is already assigned to
         *   another host. In this case, We explicitly know that the address should not be used by the host.
         *   Hence, we should send DHCPNAK.
         *
         * TODO: Maybe, we should not send DHCPNAK some cases. If the network has multiple DHCP servers, and
         * our DB is unfortunately broken, then we may wrongly send DHCPNAK for a valid request to another
         * server. */
        sd_dhcp_server_lease *l = hashmap_get(server->bound_leases_by_address, UINT32_TO_PTR(address));
        if (l && l != existing_lease)
                return dhcp_server_send_reply(server, req, DHCP_NAK);

        /* Check if the request is consistent with the static lease. */
        if (static_lease) {
                /* Found a static lease for the client ID. In this case, the server is explicitly configured
                 * to manage the host. Hence, send NAK when the request is invalid. */

                if (static_lease->address != address)
                        /* The client requested an address which is different from the static lease. Refusing. */
                        return dhcp_server_send_reply(server, req, DHCP_NAK);

                req->static_lease = static_lease;
                req->address = address;

                return dhcp_server_ack(server, req);
        }

        if (address_is_in_pool(server, address)) {
                /* The requested address is in the pool. In the above, we have checked the address is free or
                 * already assigned to the host. Hence, ACK. */
                req->address = address;

                return dhcp_server_ack(server, req);
        }

        /* If no static lease is configured for the host, and the requested address is not in our pool, then
         * NAK the request only when the request is definitely sent to us. Otherwise, silently ignore the
         * request. This is because, the network may have multiple DHCP servers, and the address may be
         * managed by another server, and the request may be for that server. */
        if (req->server_address == server->address)
                return dhcp_server_send_reply(server, req, DHCP_NAK);

        return 0;
}

static int dhcp_server_process_decline(sd_dhcp_server *server, sd_dhcp_request *req) {
        assert(server);
        assert(req);

        /* TODO: make sure we don't offer this address again for a while */

        _cleanup_free_ char *e = NULL;
        (void) dhcp_message_get_option_string(req->message, SD_DHCP_OPTION_ERROR_MESSAGE, &e);
        log_dhcp_server(server, "DECLINE (0x%x): %s", be32toh(req->message->header.xid), strna(e));
        return 0;
}

static int dhcp_server_process_release(sd_dhcp_server *server, sd_dhcp_request *req) {
        assert(server);
        assert(req);

        sd_dhcp_server_lease *existing_lease = hashmap_get(server->bound_leases_by_client_id, &req->client_id);
        if (!existing_lease)
                return -ENOENT;

        if (existing_lease->address != req->message->header.ciaddr)
                return -EBADMSG;

        sd_dhcp_server_lease_unref(existing_lease);
        dhcp_server_on_lease_change(server);

        log_dhcp_server(server, "RELEASE (0x%x)", be32toh(req->message->header.xid));
        return 0;
}

int dhcp_server_process_message(sd_dhcp_server *server, const struct iovec *iov, const triple_timestamp *timestamp) {
        int r;

        assert(server);
        assert(iov);

        _cleanup_(sd_dhcp_request_unrefp) sd_dhcp_request *req = NULL;
        r = dhcp_server_parse_message(server, iov, &req);
        if (r < 0)
                return r;

        dhcp_request_set_timestamp(req, timestamp);

        r = dhcp_server_cleanup_expired_leases(server);
        if (r < 0)
                return r;

        switch (req->type) {
        case DHCP_DISCOVER:
                return dhcp_server_process_discover(server, req);
        case DHCP_REQUEST:
                return dhcp_server_process_request(server, req);
        case DHCP_DECLINE:
                return dhcp_server_process_decline(server, req);
        case DHCP_RELEASE:
                return dhcp_server_process_release(server, req);
        default:
                return -EBADMSG;
        }
}

static int dhcp_message_set_relay_agent_information(sd_dhcp_message *message, sd_dhcp_server *server) {
        int r;

        assert(message);
        assert(server);

        dhcp_message_remove_option(message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION);

        if (!server->agent_circuit_id && !server->agent_remote_id)
                return 0;

        _cleanup_hashmap_free_ Hashmap *suboptions = NULL;
        if (!isempty(server->agent_circuit_id)) {
                r = dhcp_options_append(
                                &suboptions,
                                SD_DHCP_RELAY_AGENT_CIRCUIT_ID,
                                strlen(server->agent_circuit_id),
                                server->agent_circuit_id);
                if (r < 0)
                        return r;
        }

        if (!isempty(server->agent_remote_id)) {
                r = dhcp_options_append(
                                &suboptions,
                                SD_DHCP_RELAY_AGENT_REMOTE_ID,
                                strlen(server->agent_remote_id),
                                server->agent_remote_id);
                if (r < 0)
                        return r;
        }

        if (hashmap_isempty(suboptions))
                return 0;

        _cleanup_(iovec_done) struct iovec iov = {};
        r = dhcp_options_build(suboptions, &iov);
        if (r < 0)
                return r;

        /* dhcp_option_build() always appends END tag, but Relay Agent Information option does not take it. */
        assert(iov.iov_len > 0);
        return dhcp_message_append_option(message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION, iov.iov_len - 1, iov.iov_base);
}

int dhcp_server_relay_message(sd_dhcp_server *server, const struct iovec *iov) {
        int r;

        assert(server);
        assert(iov);

        _cleanup_(sd_dhcp_request_unrefp) sd_dhcp_request *req = NULL;
        r = dhcp_server_parse_message(server, iov, &req);
        if (r < 0)
                return r;

        switch (req->message->header.op) {
        case BOOTREQUEST:
                if (req->message->header.hops >= 16)
                        return -ETIME;
                req->message->header.hops++;

                /* RFC 1542 Section 4.1.1 */
                if (req->message->header.giaddr == 0)
                        req->message->header.giaddr = server->address;

                r = dhcp_message_set_relay_agent_information(req->message, server);
                if (r < 0)
                        return r;

                r = dhcp_server_send_udp(server, server->relay_target.s_addr, DHCP_PORT_SERVER, req->message);
                if (r < 0)
                        return r;

                log_dhcp_server(server, "(relay agent) BOOTREQUEST (0x%x)", be32toh(req->message->header.xid));
                return 0;

        case BOOTREPLY: {
                if (req->message->header.giaddr != server->address)
                        return -EBADMSG;

                dhcp_message_remove_option(req->message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION);

                r = dhcp_server_send_message(server, req, req->type, req->message);
                if (r < 0)
                        return r;

                log_dhcp_server(server, "(relay agent) BOOTREPLY (0x%x)", be32toh(req->message->header.xid));
                return 0;
        }
        default:
                return -EBADMSG;
        }
}

int dhcp_server_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_server *server = ASSERT_PTR(userdata);
        int r;

        ssize_t buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp_server_errno(server, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        _cleanup_free_ void *buf = malloc0(buflen);
        if (!buf)
                return -ENOMEM;

        /* This needs to be initialized with zero. See #20741.
         * The issue is fixed on glibc-2.35 (8fba672472ae0055387e9315fc2eddfa6775ca79). */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL +
                         CMSG_SPACE(sizeof(struct in_pktinfo))) control = {};
        struct iovec iov = IOVEC_MAKE(buf, buflen);
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        ssize_t len = recvmsg_safe(fd, &msg, 0);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_server_errno(server, len, "Could not receive message, ignoring: %m");
                return 0;
        }

        /* TODO: figure out if this can be done as a filter on the socket, like for IPv6 */
        struct in_pktinfo *info = CMSG_FIND_DATA(&msg, IPPROTO_IP, IP_PKTINFO, struct in_pktinfo);
        if (info && info->ipi_ifindex != server->ifindex)
                return 0;

        if (sd_dhcp_server_is_in_relay_mode(server)) {
                r = dhcp_server_relay_message(server, &IOVEC_MAKE(buf, len));
                if (r < 0)
                        log_dhcp_server_errno(server, r, "Couldn't relay message, ignoring: %m");
        } else {
                r = dhcp_server_process_message(server, &IOVEC_MAKE(buf, len), TRIPLE_TIMESTAMP_FROM_CMSG(&msg));
                if (r < 0)
                        log_dhcp_server_errno(server, r, "Couldn't process incoming message, ignoring: %m");
        }

        return 0;
}

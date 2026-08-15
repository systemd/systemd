/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  DHCPv6 Address Registration (RFC 9686).
***/

#include <linux/ipv6.h>
#include <netinet/in.h>
#include <string.h>

#include "sd-dhcp6-option.h"

#include "alloc-util.h"
#include "dhcp6-addr-reg.h"
#include "dhcp6-internal.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "random-util.h"
#include "socket-util.h"
#include "time-util.h"

/* RFC 9686 Section 4.5: initial retransmission time: 1 sec, maximum retry count: 3 */
#define DHCP6_ADDR_REG_IRT (1 * USEC_PER_SEC)
#define DHCP6_ADDR_REG_MRC 3U

/* RFC 9686 Section 4.6.1: refresh interval is 80% of the current valid lifetime */
#define DHCP6_ADDR_REG_REFRESH_RATIO 0.8

 /* Errata 8600 replaces the original 1% tolerance interval of RFC 9686 4.6.1 with 3 seconds */
#define DHCP6_ADDR_REG_LIFETIME_TOLERANCE_USEC (3 * USEC_PER_SEC)

/* RFC 9686 Section 4.6.2: static addresses refreshed every 4 hours */
#define DHCP6_ADDR_REG_STATIC_REFRESH_USEC (4 * USEC_PER_HOUR)

typedef struct DHCP6AddrRegistration {
        sd_dhcp6_client *client;
        struct in6_addr address;

        sd_event_source *timeout_resend;
        sd_event_source *timeout_refresh;

        be32_t transaction_id;
        usec_t transaction_start;
        usec_t retransmit_time;
        unsigned retransmit_count;

        usec_t valid_until_usec;     /* absolute CLOCK_BOOTTIME timestamp, or 0 for de-registration, or USEC_INFINITY */
        usec_t preferred_until_usec; /* absolute CLOCK_BOOTTIME timestamp, or 0, or USEC_INFINITY */

        usec_t next_refresh_time; /* NextAddrRegRefreshTime, absolute */
} DHCP6AddrRegistration;

static DHCP6AddrRegistration *dhcp6_addr_reg_free(DHCP6AddrRegistration *reg);
DEFINE_TRIVIAL_CLEANUP_FUNC(DHCP6AddrRegistration *, dhcp6_addr_reg_free);

static int dhcp6_addr_reg_update_refresh_time(DHCP6AddrRegistration *reg);

static int dhcp6_network_bind_addr_reg_socket(int ifindex) {
        union sockaddr_union src = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = in6addr_any,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        /*
         * Address registration uses the global-scoped address being registered as the
         * source address for ADDR-REG-INFORM messages and as destination address for
         * the ADDR-REG-REPLY. Since the main DHCPv6 client socket is bound to the
         * link-local address, it can't be used here and we need a dedicated socket.
         * Linux delivers each incoming datagram to the most specific matching socket;
         * therefore, the ADDR-REG-REPLY message to the global-scoped address will
         * be delivered to this socket. */
        s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, false);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, true);
        if (r < 0)
                return r;

        r = socket_bind_to_ifindex(s, ifindex);
        if (r < 0)
                return r;

        r = bind(s, &src.sa, sizeof(src.in6));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

static int dhcp6_network_send_addr_reg(
                int s, int ifindex, const struct in6_addr *src_address, const void *packet, size_t len) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        union sockaddr_union dest = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS,
                .in6.sin6_port = htobe16(DHCP6_PORT_SERVER),
        };
        struct iovec iov = IOVEC_MAKE((void *) packet, len);
        struct msghdr msg = {
                .msg_name = &dest.sa,
                .msg_namelen = sizeof(dest.in6),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;

        assert(src_address);
        assert(ifindex > 0);
        assert(packet);
        assert(len > 0);

        /* 4.2: the ADDR-REG-INFORM message MUST be sent from the address being registered */
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;

        *CMSG_TYPED_DATA(cmsg, struct in6_pktinfo) = (struct in6_pktinfo) {
                .ipi6_addr = *src_address,
                .ipi6_ifindex = ifindex,
        };

        if (sendmsg(s, &msg, 0) < 0)
                return -errno;

        return 0;
}

static DHCP6AddrRegistration *dhcp6_addr_reg_free(DHCP6AddrRegistration *reg) {
        if (!reg)
                return NULL;

        if (reg->client)
                hashmap_remove(reg->client->addr_registrations, &reg->address);

        sd_event_source_disable_unref(reg->timeout_resend);
        sd_event_source_disable_unref(reg->timeout_refresh);

        return mfree(reg);
}

static int dhcp6_addr_reg_new(sd_dhcp6_client *client, const struct in6_addr *address, DHCP6AddrRegistration **ret) {
        _cleanup_(dhcp6_addr_reg_freep) DHCP6AddrRegistration *reg = NULL;

        assert(client);
        assert(address);
        assert(ret);

        reg = new(DHCP6AddrRegistration, 1);
        if (!reg)
                return -ENOMEM;

        *reg = (DHCP6AddrRegistration) {
                .client = client,
                .address = *address,
        };

        *ret = TAKE_PTR(reg);
        return 0;
}

static usec_t addr_reg_timeout_compute_random(usec_t val) {
        return usec_sub_unsigned(val, random_u64_range(val / 10));
}

static uint32_t addr_reg_lifetime_to_sec(usec_t lifetime_usec, usec_t now_usec) {
        if (lifetime_usec == USEC_INFINITY)
                return UINT32_MAX;
        if (now_usec >= lifetime_usec)
                return 0;

        return (uint32_t) ((lifetime_usec - now_usec) / USEC_PER_SEC);
}

static int dhcp6_addr_reg_send(DHCP6AddrRegistration *reg) {
        sd_dhcp6_client *client;
        _cleanup_free_ uint8_t *buf = NULL;
        DHCP6Message *message;
        struct iaaddr iaaddr;
        usec_t now_usec, elapsed_usec;
        be16_t elapsed_time;
        size_t offset;
        int r;

        assert(reg);
        client = reg->client;
        assert(client);

        if (!GREEDY_REALLOC0(buf, offsetof(DHCP6Message, options)))
                return -ENOMEM;

        message = (DHCP6Message *) buf;
        message->transaction_id = reg->transaction_id;
        message->type = DHCP6_MESSAGE_ADDR_REG_INFORM;

        offset = offsetof(DHCP6Message, options);

        /* 4.2: the client MUST include the Client Identifier option [RFC8415] in the ADDR-REG-INFORM message. */
        assert(sd_dhcp_duid_is_set(&client->duid));
        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_CLIENTID, client->duid.size, &client->duid.duid);
        if (r < 0)
                return r;

        r = sd_event_now(client->event, CLOCK_BOOTTIME, &now_usec);
        if (r < 0)
                return r;

        iaaddr = (struct iaaddr) {
                .address = reg->address,
                .lifetime_valid = htobe32(addr_reg_lifetime_to_sec(reg->valid_until_usec, now_usec)),
                .lifetime_preferred = htobe32(addr_reg_lifetime_to_sec(reg->preferred_until_usec, now_usec)),
        };

        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_IAADDR, sizeof(struct iaaddr), &iaaddr);
        if (r < 0)
                return r;

        /* RFC 8415 21.9: A client MUST include an Elapsed Time option in messages to indicate how long
         * the client has been trying to complete a DHCP message exchange. */
        elapsed_usec = MIN(
                        usec_sub_unsigned(now_usec, reg->transaction_start) / USEC_PER_MSEC / 10,
                        (usec_t) UINT16_MAX);
        elapsed_time = htobe16(elapsed_usec);
        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_ELAPSED_TIME, sizeof(elapsed_time), &elapsed_time);
        if (r < 0)
                return r;

        r = dhcp6_network_send_addr_reg(client->addr_reg_fd, client->ifindex, &reg->address, buf, offset);
        if (r < 0)
                return r;

        log_dhcp6_client(
                        client,
                        "Address registration: sent ADDR-REG-INFORM (%u/%u) for %s",
                        reg->retransmit_count + 1,
                        DHCP6_ADDR_REG_MRC,
                        IN6_ADDR_TO_STRING(&reg->address));

        return 0;
}

static int dhcp6_addr_reg_timeout_resend(sd_event_source *s, uint64_t usec, void *userdata) {
        DHCP6AddrRegistration *reg = ASSERT_PTR(userdata);
        int r;

        if (reg->retransmit_count >= DHCP6_ADDR_REG_MRC) {
                log_dhcp6_client(
                                reg->client,
                                "Address registration: no reply received for %s",
                                IN6_ADDR_TO_STRING(&reg->address));

                if (reg->valid_until_usec == 0)
                        /* The address is no longer valid and was (unsuccessfully) unregistered */
                        dhcp6_addr_reg_free(reg);

                return 0;
        }

        r = dhcp6_addr_reg_send(reg);
        if (r < 0)
                log_dhcp6_client_errno(
                                reg->client,
                                r,
                                "Address registration: failed to send ADDR-REG-INFORM for %s: %m",
                                IN6_ADDR_TO_STRING(&reg->address));

        reg->retransmit_count++;

        if (reg->retransmit_time == 0)
                reg->retransmit_time = addr_reg_timeout_compute_random(DHCP6_ADDR_REG_IRT);
        else
                reg->retransmit_time = usec_add(
                                reg->retransmit_time, addr_reg_timeout_compute_random(reg->retransmit_time));

        return event_reset_time_relative(
                        reg->client->event,
                        &reg->timeout_resend,
                        CLOCK_BOOTTIME,
                        reg->retransmit_time,
                        10 * USEC_PER_MSEC,
                        dhcp6_addr_reg_timeout_resend,
                        reg,
                        reg->client->event_priority,
                        "dhcp6-addr-reg-resend",
                        true);
}

static int dhcp6_addr_reg_start_transaction(DHCP6AddrRegistration *reg, bool one_shot) {
        sd_dhcp6_client *client;
        int r;

        assert(reg);
        client = reg->client;
        assert(client);

        r = sd_event_now(client->event, CLOCK_BOOTTIME, &reg->transaction_start);
        if (r < 0)
                return r;

        reg->retransmit_count = 0;
        reg->retransmit_time = 0;
        reg->transaction_id = random_u32() & htobe32(0x00ffffff);

        if (one_shot)
                return dhcp6_addr_reg_send(reg);

        return event_reset_time(
                        client->event,
                        &reg->timeout_resend,
                        CLOCK_BOOTTIME,
                        0,
                        0,
                        dhcp6_addr_reg_timeout_resend,
                        reg,
                        client->event_priority,
                        "dhcp6-addr-reg-resend",
                        true);
}

static usec_t addr_reg_refresh_interval(DHCP6AddrRegistration *reg, usec_t now) {
        if (reg->valid_until_usec == USEC_INFINITY)
                return DHCP6_ADDR_REG_STATIC_REFRESH_USEC;

        if (reg->valid_until_usec <= now)
                return 0;

        return (usec_t) ((double) usec_sub_unsigned(reg->valid_until_usec, now) *
                         DHCP6_ADDR_REG_REFRESH_RATIO * reg->client->addr_reg_desync_multiplier);
}

static int dhcp6_addr_reg_timeout_refresh(sd_event_source *s, uint64_t usec, void *userdata) {
        DHCP6AddrRegistration *reg = ASSERT_PTR(userdata);
        sd_dhcp6_client *client;
        int r;

        client = reg->client;
        assert(client);

        log_dhcp6_client(
                        client,
                        "Address registration: refreshing registration for %s",
                        IN6_ADDR_TO_STRING(&reg->address));

        r = dhcp6_addr_reg_update_refresh_time(reg);
        if (r < 0) {
                log_dhcp6_client_errno(
                                client,
                                r,
                                "Address registration: failed to set next refresh for %s: %m",
                                IN6_ADDR_TO_STRING(&reg->address));
                /* Still proceed with the current refresh */
        }

        r = dhcp6_addr_reg_start_transaction(reg, false);
        if (r < 0) {
                log_dhcp6_client_errno(
                                client,
                                r,
                                "Address registration: failed to start refresh for %s: %m",
                                IN6_ADDR_TO_STRING(&reg->address));
        }

        return 0;
}

/*
 * Updates the NextAddrRegRefreshTime as per RFC 9686 4.6.1 (for SLAAC addresses) and
 * 4.6.2 (for static addresses).
 */
static int dhcp6_addr_reg_update_refresh_time(DHCP6AddrRegistration *reg) {
        sd_dhcp6_client *client;
        usec_t now;
        int r;

        assert(reg);
        client = reg->client;
        assert(client);

        if (reg->valid_until_usec == 0)
                /* Already de-registered */
                return 0;

        r = sd_event_now(client->event, CLOCK_BOOTTIME, &now);
        if (r < 0)
                return r;

        reg->next_refresh_time = usec_add(now, addr_reg_refresh_interval(reg, now));

        if (reg->valid_until_usec == USEC_INFINITY)
                /* Section 4.6.2: static addresses are refreshed on a fixed interval */
                return event_reset_time(
                                client->event,
                                &reg->timeout_refresh,
                                CLOCK_BOOTTIME,
                                reg->next_refresh_time,
                                USEC_PER_SEC,
                                dhcp6_addr_reg_timeout_refresh,
                                reg,
                                client->event_priority,
                                "dhcp6-addr-reg-refresh",
                                true);

        /* Section 4.6.1: for SLAAC addresses, NextAddrRegRefreshTime is recorded but no
         * timer is armed. Refreshes are event-driven: when a PIO changes the valid
         * lifetime by more than the tolerance, we schedule a refresh. */
        (void) event_source_disable(reg->timeout_refresh);

        return 0;
}

static int dhcp6_addr_reg_receive(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ DHCP6Message *message = NULL;
        sd_dhcp6_client *client = ASSERT_PTR(userdata);
        DHCP6AddrRegistration *reg;
        struct iovec iov;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        union sockaddr_union sa = {};
        struct msghdr msg = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct in6_pktinfo *pktinfo;
        bool iaaddr_found;
        ssize_t buflen;
        ssize_t len;
        int r;

        buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp6_client_errno(
                                client,
                                buflen,
                                "Address registration: failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        message = malloc(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp6_client_errno(
                                client, len, "Address registration: could not receive message, ignoring: %m");
                return 0;
        }
        if ((size_t) len < sizeof(DHCP6Message)) {
                log_dhcp6_client(client, "Address registration: too small to be DHCPv6 message: ignoring");
                return 0;
        }

        if (msg.msg_namelen != sizeof(struct sockaddr_in6) || sa.in6.sin6_family != AF_INET6 ||
            sa.in6.sin6_port != htobe16(DHCP6_PORT_SERVER)) {
                log_dhcp6_client(client, "Address registration: received message from invalid source, ignoring.");
                return 0;
        }

        if (message->type != DHCP6_MESSAGE_ADDR_REG_REPLY)
                return 0;

        pktinfo = CMSG_FIND_DATA(&msg, IPPROTO_IPV6, IPV6_PKTINFO, struct in6_pktinfo);
        if (!pktinfo) {
                log_dhcp6_client(
                                client,
                                "Address registration: cannot determine destination address for reply, ignoring");
                return 0;
        }

        reg = hashmap_get(client->addr_registrations, &pktinfo->ipi6_addr);
        if (!reg) {
                log_dhcp6_client(client, "Address registration: got reply for unregistered address, ignoring");
                return 0;
        }

        if (reg->transaction_id != (message->transaction_id & htobe32(0x00ffffff))) {
                log_dhcp6_client(client, "Address registration: wrong transaction id in reply, ignoring");
                return 0;
        }

        /* Check that the message contains an IA Address option with the address being registered */
        iaaddr_found = false;
        len -= sizeof(DHCP6Message);
        for (size_t offset = 0; offset < (size_t) len;) {
                uint16_t optcode;
                size_t optlen;
                const uint8_t *optval;

                r = dhcp6_option_parse(message->options, len, &offset, &optcode, &optlen, &optval);
                if (r < 0)
                        break;

                if (optcode == SD_DHCP6_OPTION_IAADDR && optlen >= sizeof(struct iaaddr)) {
                        struct iaaddr ia_addr;
                        struct in6_addr addr;

                        memcpy(&ia_addr, optval, sizeof(ia_addr));
                        addr = ia_addr.address;

                        if (in6_addr_equal(&addr, &reg->address)) {
                                iaaddr_found = true;
                                break;
                        }
                }
        }
        if (!iaaddr_found) {
                log_dhcp6_client(
                                client,
                                "Address registration: missing IA Address option in reply for %s",
                                IN6_ADDR_TO_STRING(&reg->address));
                return 0;
        }

        log_dhcp6_client(
                        client,
                        "Address registration: received ADDR-REG-REPLY for %s",
                        IN6_ADDR_TO_STRING(&reg->address));

        reg->timeout_resend = sd_event_source_disable_unref(reg->timeout_resend);

        if (reg->valid_until_usec == 0) {
                /* The address is no longer valid and was unregistered */
                dhcp6_addr_reg_free(reg);
        }

        return 0;
}

static int dhcp6_client_ensure_addr_reg_socket(sd_dhcp6_client *client) {
        int r;

        assert(client);

        if (client->addr_reg_fd >= 0)
                return 0;

        /* 4.6.1: AddrRegDesyncMultiplier is a random value uniformly distributed between 0.9 and 1.1
         * (inclusive) and is chosen by the client when it starts the registration process. */
        client->addr_reg_desync_multiplier = 0.9 + 0.2 * ((double) random_u32() / (double) UINT32_MAX);

        r = dhcp6_network_bind_addr_reg_socket(client->ifindex);
        if (r < 0)
                return log_dhcp6_client_errno(client, r, "Address registration: failed to bind socket: %m");

        client->addr_reg_fd = r;

        r = sd_event_add_io(
                        client->event,
                        &client->addr_reg_receive,
                        client->addr_reg_fd,
                        EPOLLIN,
                        dhcp6_addr_reg_receive,
                        client);
        if (r < 0) {
                client->addr_reg_fd = safe_close(client->addr_reg_fd);
                return r;
        }

        sd_event_source_set_description(client->addr_reg_receive, "dhcp6-addr-reg-receive");
        sd_event_source_set_priority(client->addr_reg_receive, client->event_priority);

        return 0;
}

static bool addr_reg_lifetime_changed_with_tolerance(usec_t old_usec, usec_t new_usec) {
        usec_t diff;

        if (old_usec == new_usec)
                return false;

        if (old_usec == USEC_INFINITY || new_usec == USEC_INFINITY)
                return true;

        diff = old_usec > new_usec ? (old_usec - new_usec) : (new_usec - old_usec);
        return diff > DHCP6_ADDR_REG_LIFETIME_TOLERANCE_USEC;
}

static int dhcp6_addr_reg_update_lifetime(
                DHCP6AddrRegistration *reg, usec_t valid_until_usec, usec_t preferred_until_usec) {
        sd_dhcp6_client *client;
        bool changed;
        usec_t refresh_time;
        usec_t now;
        int r;

        assert(reg);
        client = reg->client;
        assert(client);

        r = sd_event_now(reg->client->event, CLOCK_BOOTTIME, &now);
        if (r < 0)
                return r;

        changed = addr_reg_lifetime_changed_with_tolerance(reg->valid_until_usec, valid_until_usec);

        reg->valid_until_usec = valid_until_usec;
        reg->preferred_until_usec = preferred_until_usec;

        if (valid_until_usec == 0) {
                log_dhcp6_client(
                                client,
                                "Address registration: deregistering %s",
                                IN6_ADDR_TO_STRING(&reg->address));
                return dhcp6_addr_reg_start_transaction(reg, false);
        }

        if (!changed)
                return 0;

        refresh_time = MIN(reg->next_refresh_time, usec_add(now, addr_reg_refresh_interval(reg, now)));

        if (refresh_time <= now)
                return dhcp6_addr_reg_start_transaction(reg, false);

        return event_reset_time_relative(
                        reg->client->event,
                        &reg->timeout_refresh,
                        CLOCK_BOOTTIME,
                        usec_sub_unsigned(refresh_time, now),
                        USEC_PER_SEC,
                        dhcp6_addr_reg_timeout_refresh,
                        reg,
                        reg->client->event_priority,
                        "dhcp6-addr-reg-refresh",
                        true);
}

int dhcp6_client_register_address(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t valid_until_usec,
                usec_t preferred_until_usec) {
        DHCP6AddrRegistration *reg;
        int r;

        assert(client);
        assert(address);

        reg = hashmap_get(client->addr_registrations, address);
        if (reg)
                return dhcp6_addr_reg_update_lifetime(reg, valid_until_usec, preferred_until_usec);

        if (valid_until_usec == 0)
                return 0;

        r = dhcp6_client_ensure_addr_reg_socket(client);
        if (r < 0)
                return r;

        r = dhcp6_addr_reg_new(client, address, &reg);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&client->addr_registrations, &in6_addr_hash_ops, &reg->address, reg);
        if (r < 0) {
                dhcp6_addr_reg_free(reg);
                return r;
        }

        reg->valid_until_usec = valid_until_usec;
        reg->preferred_until_usec = preferred_until_usec;

        r = dhcp6_addr_reg_update_refresh_time(reg);
        if (r < 0) {
                log_dhcp6_client_errno(
                                client,
                                r,
                                "Address registration: failed to set next refresh for %s: %m",
                                IN6_ADDR_TO_STRING(&reg->address));
                /* Still proceed with the registration */
        }

        log_dhcp6_client(client, "Address registration: registering %s", IN6_ADDR_TO_STRING(address));

        return dhcp6_addr_reg_start_transaction(reg, false);
}

void dhcp6_client_drop_address_registration(sd_dhcp6_client *client, const struct in6_addr *address) {
        DHCP6AddrRegistration *reg;

        assert(client);
        assert(address);

        reg = hashmap_get(client->addr_registrations, address);
        if (reg)
                dhcp6_addr_reg_free(reg);
}

void dhcp6_client_addr_reg_flush(sd_dhcp6_client *client) {
        DHCP6AddrRegistration *reg;

        assert(client);

        while ((reg = hashmap_first(client->addr_registrations))) {
                if (reg->valid_until_usec != 0) {
                        reg->valid_until_usec = 0;
                        reg->preferred_until_usec = 0;
                        (void) dhcp6_addr_reg_start_transaction(reg, true);
                }
                dhcp6_addr_reg_free(reg);
        }

        client->addr_reg_receive = sd_event_source_disable_unref(client->addr_reg_receive);
        client->addr_registrations = hashmap_free(client->addr_registrations);
        client->addr_reg_fd = safe_close(client->addr_reg_fd);
}

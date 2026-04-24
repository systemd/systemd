/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/if.h>

#include "sd-dhcp6-server.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "dhcp-duid-internal.h"
#include "dhcp6-server-internal.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "network-common.h"
#include "siphash24.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "unaligned.h"

#define DHCP6_DEFAULT_LEASE_TIME_USEC   (1 * USEC_PER_HOUR)
#define DHCP6_MAX_LEASE_TIME_USEC       (12 * USEC_PER_HOUR)

/* RFC 8415, Section 7.1 - All_DHCP_Relay_Agents_and_Servers: ff02::1:2 */
static const struct in6_addr all_dhcp6_relay_agents_and_servers = IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS;

DHCP6ServerLease *dhcp6_server_lease_free(DHCP6ServerLease *lease) {
        if (!lease)
                return NULL;

        free(lease->client_id);
        return mfree(lease);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DHCP6ServerLease*, dhcp6_server_lease_free);

static void dhcp6_server_lease_hash_func(const DHCP6ServerLease *l, struct siphash *state) {
        assert(l);
        siphash24_compress(&l->client_id_len, sizeof(l->client_id_len), state);
        siphash24_compress(l->client_id, l->client_id_len, state);
}

static int dhcp6_server_lease_compare_func(const DHCP6ServerLease *a, const DHCP6ServerLease *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->client_id_len, b->client_id_len);
        if (r != 0)
                return r;

        return memcmp(a->client_id, b->client_id, a->client_id_len);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dhcp6_server_lease_hash_ops,
                DHCP6ServerLease,
                dhcp6_server_lease_hash_func,
                dhcp6_server_lease_compare_func,
                DHCP6ServerLease,
                dhcp6_server_lease_free);

static int dhcp6_server_generate_duid(sd_dhcp6_server *server) {
        sd_dhcp_duid duid = {};
        int r;

        assert(server);

        r = sd_dhcp_duid_set_en(&duid);
        if (r < 0)
                return r;

        assert(duid.size <= sizeof(server->server_id));
        memcpy(server->server_id, &duid.duid, duid.size);
        server->server_id_len = duid.size;

        return 0;
}

static sd_dhcp6_server *dhcp6_server_free(sd_dhcp6_server *server) {
        if (!server)
                return NULL;

        log_dhcp6_server(server, "UNREF");

        sd_dhcp6_server_stop(server);

        sd_event_unref(server->event);

        hashmap_free(server->leases);
        free(server->pool_bitmap);
        free(server->timezone);
        free(server->dns);
        free(server->ntp);
        free(server->ifname);

        return mfree(server);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_server, sd_dhcp6_server, dhcp6_server_free);

int sd_dhcp6_server_new(sd_dhcp6_server **ret, int ifindex) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;

        assert_return(ret, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        server = new(sd_dhcp6_server, 1);
        if (!server)
                return -ENOMEM;

        *server = (sd_dhcp6_server) {
                .n_ref = 1,
                .fd = -EBADF,
                .ifindex = ifindex,
                .address = IN6ADDR_ANY_INIT,
                .default_lease_time = DHCP6_DEFAULT_LEASE_TIME_USEC,
                .max_lease_time = DHCP6_MAX_LEASE_TIME_USEC,
        };

        *ret = TAKE_PTR(server);

        return 0;
}

int sd_dhcp6_server_set_ifname(sd_dhcp6_server *server, const char *ifname) {
        assert_return(server, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&server->ifname, ifname);
}

int sd_dhcp6_server_get_ifname(sd_dhcp6_server *server, const char **ret) {
        int r;

        assert_return(server, -EINVAL);

        r = get_ifname(server->ifindex, &server->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = server->ifname;

        return 0;
}

int sd_dhcp6_server_attach_event(sd_dhcp6_server *server, sd_event *event, int64_t priority) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!server->event, -EBUSY);

        if (event)
                server->event = sd_event_ref(event);
        else {
                r = sd_event_default(&server->event);
                if (r < 0)
                        return r;
        }

        server->event_priority = priority;

        return 0;
}

int sd_dhcp6_server_detach_event(sd_dhcp6_server *server) {
        assert_return(server, -EINVAL);

        server->event = sd_event_unref(server->event);

        return 0;
}

sd_event *sd_dhcp6_server_get_event(sd_dhcp6_server *server) {
        assert_return(server, NULL);

        return server->event;
}

int sd_dhcp6_server_is_running(sd_dhcp6_server *server) {
        assert_return(server, false);

        return !!server->receive_message;
}

int sd_dhcp6_server_stop(sd_dhcp6_server *server) {
        if (!server)
                return 0;

        server->receive_message = sd_event_source_disable_unref(server->receive_message);
        server->fd = safe_close(server->fd);

        log_dhcp6_server(server, "STOPPED");

        return 0;
}

int sd_dhcp6_server_set_address(sd_dhcp6_server *server, const struct in6_addr *address, unsigned char prefixlen) {
        assert_return(server, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(prefixlen > 0 && prefixlen <= 128, -EINVAL);

        server->address = *address;
        server->prefixlen = prefixlen;

        return 0;
}

int sd_dhcp6_server_set_timezone(sd_dhcp6_server *server, const char *tz) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(timezone_is_valid(tz, LOG_DEBUG), -EINVAL);

        if (streq_ptr(tz, server->timezone))
                return 0;

        r = free_and_strdup(&server->timezone, tz);
        if (r < 0)
                return r;

        return 1;
}

int sd_dhcp6_server_set_dns(sd_dhcp6_server *server, const struct in6_addr dns[], size_t n) {
        assert_return(server, -EINVAL);
        assert_return(dns || n == 0, -EINVAL);

        if (n > 0) {
                struct in6_addr *c;

                c = newdup(struct in6_addr, dns, n);
                if (!c)
                        return -ENOMEM;

                free_and_replace(server->dns, c);
        } else
                server->dns = mfree(server->dns);

        server->n_dns = n;
        return 0;
}

int sd_dhcp6_server_set_ntp(sd_dhcp6_server *server, const struct in6_addr ntp[], size_t n) {
        assert_return(server, -EINVAL);
        assert_return(ntp || n == 0, -EINVAL);

        if (n > 0) {
                struct in6_addr *c;

                c = newdup(struct in6_addr, ntp, n);
                if (!c)
                        return -ENOMEM;

                free_and_replace(server->ntp, c);
        } else
                server->ntp = mfree(server->ntp);

        server->n_ntp = n;
        return 0;
}

int sd_dhcp6_server_set_max_lease_time(sd_dhcp6_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        server->max_lease_time = t;
        return 0;
}

int sd_dhcp6_server_set_default_lease_time(sd_dhcp6_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        server->default_lease_time = t;
        return 0;
}

int sd_dhcp6_server_set_rapid_commit(sd_dhcp6_server *server, int enabled) {
        assert_return(server, -EINVAL);

        server->rapid_commit = enabled;
        return 0;
}

/* Compute the nth address in the pool starting from pool_start */
static void pool_address_at(const struct in6_addr *base, uint64_t offset, struct in6_addr *ret) {
        struct in6_addr addr = *base;
        uint64_t carry = offset;

        /* Add offset to the address, starting from the least significant byte */
        for (int i = 15; i >= 0 && carry > 0; i--) {
                carry += addr.s6_addr[i];
                addr.s6_addr[i] = carry & 0xff;
                carry >>= 8;
        }

        *ret = addr;
}

int sd_dhcp6_server_configure_pool(sd_dhcp6_server *server, const struct in6_addr *address,
                                   unsigned char prefixlen, uint64_t pool_offset, uint64_t pool_size) {
        assert_return(server, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(prefixlen > 0 && prefixlen <= 128, -EINVAL);

        /* Compute the network prefix and the host part range */
        struct in6_addr network = *address;

        /* Mask out host bits to get the network address */
        for (unsigned i = prefixlen; i < 128; i++)
                network.s6_addr[i / 8] &= ~(1 << (7 - (i % 8)));

        /* The number of host bits */
        unsigned host_bits = 128 - prefixlen;
        uint64_t max_hosts;

        if (host_bits >= 64)
                max_hosts = UINT64_MAX; /* cap at uint64 */
        else
                max_hosts = (UINT64_C(1) << host_bits);

        /* Apply offset - skip first 'pool_offset' addresses (offset 0 = network address) */
        uint64_t offset = pool_offset > 0 ? pool_offset : 1; /* skip network address by default */

        if (offset >= max_hosts)
                return -ERANGE;

        uint64_t available = max_hosts - offset;
        uint64_t size = pool_size > 0 ? MIN(pool_size, available) : MIN(available, UINT64_C(256));

        /* Cap pool size to prevent bitmap overflow. A bitmap of 128MB supports ~1 billion addresses,
         * which is more than enough for any practical deployment. */
        if (size > UINT64_C(1) << 30)
                size = UINT64_C(1) << 30;

        /* Allocate bitmap before updating state to avoid inconsistency on OOM */
        size_t bitmap_size = (size + 7) / 8;
        uint8_t *bitmap = new0(uint8_t, bitmap_size);
        if (!bitmap)
                return -ENOMEM;

        /* Now commit the new pool configuration */
        pool_address_at(&network, offset, &server->pool_start);
        server->pool_size = size;
        free_and_replace(server->pool_bitmap, bitmap);

        /* Drop any existing leases */
        hashmap_clear(server->leases);

        return 0;
}

static int pool_allocate_address(sd_dhcp6_server *server, struct in6_addr *ret) {
        assert(server);
        assert(ret);

        if (!server->pool_bitmap || server->pool_size == 0)
                return -ENXIO;

        for (uint64_t i = 0; i < server->pool_size; i++) {
                if (!(server->pool_bitmap[i / 8] & (1 << (i % 8)))) {
                        server->pool_bitmap[i / 8] |= (1 << (i % 8));
                        pool_address_at(&server->pool_start, i, ret);
                        return 0;
                }
        }

        return -EADDRNOTAVAIL;
}

/* Compute the offset of an address from base. Returns negative if not in range. */
static int64_t pool_address_offset(const struct in6_addr *base, const struct in6_addr *address) {
        uint64_t offset = 0;
        int borrow = 0;

        for (int i = 15; i >= 0; i--) {
                int diff = (int) address->s6_addr[i] - (int) base->s6_addr[i] - borrow;
                if (diff < 0) {
                        diff += 256;
                        borrow = 1;
                } else
                        borrow = 0;

                if (i >= 8) /* Lower 8 bytes (indices 8-15) fit in uint64_t */
                        offset |= (uint64_t)(uint8_t) diff << ((15 - i) * 8);
                else if ((uint8_t) diff != 0)
                        return -1; /* Offset too large, upper bytes differ */
        }

        if (borrow)
                return -1; /* address < base */

        return (int64_t) offset;
}

static void pool_release_address(sd_dhcp6_server *server, const struct in6_addr *address) {
        int64_t offset;

        assert(server);
        assert(address);

        if (!server->pool_bitmap || server->pool_size == 0)
                return;

        offset = pool_address_offset(&server->pool_start, address);
        if (offset < 0 || (uint64_t) offset >= server->pool_size)
                return;

        server->pool_bitmap[offset / 8] &= ~(1 << (offset % 8));
}

static DHCP6ServerLease *dhcp6_server_find_lease(sd_dhcp6_server *server,
                                                  const uint8_t *client_id,
                                                  size_t client_id_len) {
        DHCP6ServerLease key = {
                .client_id = (uint8_t *) client_id,
                .client_id_len = client_id_len,
        };

        return hashmap_get(server->leases, &key);
}

static void dhcp6_server_cleanup_expired_leases(sd_dhcp6_server *server) {
        DHCP6ServerLease *lease;
        usec_t now_usec;

        assert(server);

        assert_se(sd_event_now(server->event, CLOCK_BOOTTIME, &now_usec) >= 0);

        HASHMAP_FOREACH(lease, server->leases)
                if (lease->expiration <= now_usec) {
                        pool_release_address(server, &lease->address);
                        hashmap_remove_value(server->leases, lease, lease);
                        dhcp6_server_lease_free(lease);
                }
}

static int dhcp6_server_send_udp(sd_dhcp6_server *server,
                                 const struct in6_addr *destination,
                                 const void *message, size_t len) {
        union sockaddr_union dest = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
                .in6.sin6_addr = *destination,
                .in6.sin6_scope_id = server->ifindex,
        };
        struct iovec iov = {
                .iov_base = (void *) message,
                .iov_len = len,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        struct msghdr msg = {
                .msg_name = &dest,
                .msg_namelen = sizeof(dest.in6),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        assert(server);
        assert(server->fd >= 0);
        assert(message);
        assert(len > sizeof(DHCP6Message));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        assert(cmsg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        struct in6_pktinfo *pktinfo = CMSG_TYPED_DATA(cmsg, struct in6_pktinfo);
        pktinfo->ipi6_ifindex = server->ifindex;
        pktinfo->ipi6_addr = server->address;

        if (sendmsg(server->fd, &msg, 0) < 0)
                return -errno;

        return 0;
}

typedef struct DHCP6ServerRequest {
        const uint8_t *client_id;
        size_t client_id_len;
        const uint8_t *server_id;
        size_t server_id_len;

        bool has_ia_na;
        be32_t ia_na_id;

        bool rapid_commit;

        /* Source address of the client */
        struct in6_addr client_address;
} DHCP6ServerRequest;

static int dhcp6_server_parse_message(
                sd_dhcp6_server *server,
                const DHCP6Message *message,
                size_t len,
                DHCP6ServerRequest *req) {

        size_t offset = 0;

        assert(server);
        assert(message);
        assert(req);
        assert(len >= sizeof(DHCP6Message));

        size_t options_len = len - sizeof(DHCP6Message);

        while (offset < options_len) {
                uint16_t option_code;
                size_t option_data_len;
                const uint8_t *option_data;
                int r;

                r = dhcp6_option_parse(message->options, options_len, &offset,
                                       &option_code, &option_data_len, &option_data);
                if (r < 0)
                        return r;

                switch (option_code) {

                case SD_DHCP6_OPTION_CLIENTID:
                        req->client_id = option_data;
                        req->client_id_len = option_data_len;
                        break;

                case SD_DHCP6_OPTION_SERVERID:
                        req->server_id = option_data;
                        req->server_id_len = option_data_len;
                        break;

                case SD_DHCP6_OPTION_IA_NA:
                        if (option_data_len >= sizeof(struct ia_header)) {
                                req->has_ia_na = true;
                                memcpy(&req->ia_na_id, option_data, sizeof(be32_t));
                        }
                        break;

                case SD_DHCP6_OPTION_RAPID_COMMIT:
                        req->rapid_commit = true;
                        break;

                default:
                        break;
                }
        }

        /* Client ID is mandatory */
        if (!req->client_id || req->client_id_len == 0)
                return -EINVAL;

        return 0;
}

static int dhcp6_server_build_reply(
                sd_dhcp6_server *server,
                uint8_t type,
                be32_t transaction_id,
                DHCP6ServerRequest *req,
                const struct in6_addr *assigned_address,
                DHCP6Status ia_na_status, /* status when assigned_address is NULL and has_ia_na */
                uint8_t **ret_buf,
                size_t *ret_len) {

        _cleanup_free_ uint8_t *buf = NULL;
        size_t buflen = sizeof(DHCP6Message) + DHCP6_MIN_OPTIONS_SIZE;
        size_t offset = sizeof(DHCP6Message);
        DHCP6Message *reply;
        int r;

        assert(server);
        assert(req);
        assert(ret_buf);
        assert(ret_len);

        buf = new0(uint8_t, buflen);
        if (!buf)
                return -ENOMEM;

        reply = (DHCP6Message *) buf;
        reply->transaction_id = transaction_id;
        reply->transaction_id &= htobe32(0x00ffffff);
        reply->type = type;

        /* Server ID option */
        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_SERVERID,
                                server->server_id_len, server->server_id);
        if (r < 0)
                return r;

        /* Client ID option - echo back */
        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_CLIENTID,
                                req->client_id_len, req->client_id);
        if (r < 0)
                return r;

        /* IA_NA with address */
        if (req->has_ia_na && assigned_address) {
                uint32_t default_lt_sec = MIN(DIV_ROUND_UP(server->default_lease_time, USEC_PER_SEC), (usec_t) UINT32_MAX);
                uint32_t max_lt_sec = MIN(DIV_ROUND_UP(server->max_lease_time, USEC_PER_SEC), (usec_t) UINT32_MAX);
                uint32_t preferred_lt_sec = MIN(default_lt_sec, max_lt_sec); /* RFC 8415: preferred <= valid */
                uint32_t t1 = max_lt_sec / 2;
                uint32_t t2 = MIN((uint64_t) max_lt_sec * 4 / 5, (uint64_t) UINT32_MAX);

                /* Build IA_NA option with embedded IAADDR sub-option */
                struct ia_header ia_hdr = {
                        .id = req->ia_na_id,
                        .lifetime_t1 = htobe32(t1),
                        .lifetime_t2 = htobe32(t2),
                };

                struct iaaddr addr_opt = {
                        .address = *assigned_address,
                        .lifetime_preferred = htobe32(preferred_lt_sec),
                        .lifetime_valid = htobe32(max_lt_sec),
                };

                /* IA_NA option = ia_header + IAADDR sub-option */
                size_t ia_na_len = sizeof(ia_hdr) +
                                   sizeof(uint16_t) + sizeof(uint16_t) + sizeof(addr_opt); /* code + len + data */

                _cleanup_free_ uint8_t *ia_na_buf = new(uint8_t, ia_na_len);
                if (!ia_na_buf)
                        return -ENOMEM;

                size_t pos = 0;
                memcpy(ia_na_buf + pos, &ia_hdr, sizeof(ia_hdr));
                pos += sizeof(ia_hdr);

                /* IAADDR sub-option header */
                unaligned_write_be16(ia_na_buf + pos, SD_DHCP6_OPTION_IAADDR);
                pos += sizeof(uint16_t);
                unaligned_write_be16(ia_na_buf + pos, sizeof(addr_opt));
                pos += sizeof(uint16_t);
                memcpy(ia_na_buf + pos, &addr_opt, sizeof(addr_opt));

                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_IA_NA,
                                        ia_na_len, ia_na_buf);
                if (r < 0)
                        return r;
        } else if (req->has_ia_na && !assigned_address) {
                /* No address available - send IA_NA with NoAddrsAvail status (RFC 8415, Section 18.4.2) */
                struct ia_header ia_hdr = {
                        .id = req->ia_na_id,
                };

                /* IA_NA with embedded Status Code sub-option */
                size_t ia_na_len = sizeof(ia_hdr) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t);

                _cleanup_free_ uint8_t *ia_na_buf = new(uint8_t, ia_na_len);
                if (!ia_na_buf)
                        return -ENOMEM;

                size_t pos = 0;
                memcpy(ia_na_buf + pos, &ia_hdr, sizeof(ia_hdr));
                pos += sizeof(ia_hdr);

                unaligned_write_be16(ia_na_buf + pos, SD_DHCP6_OPTION_STATUS_CODE);
                pos += sizeof(uint16_t);
                unaligned_write_be16(ia_na_buf + pos, sizeof(uint16_t));
                pos += sizeof(uint16_t);
                unaligned_write_be16(ia_na_buf + pos, ia_na_status);

                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_IA_NA,
                                        ia_na_len, ia_na_buf);
                if (r < 0)
                        return r;
        }

        /* Top-level Status Code - only emit SUCCESS when no IA-level error */
        if (!req->has_ia_na || assigned_address) {
                uint8_t status_data[2];
                unaligned_write_be16(status_data, DHCP6_STATUS_SUCCESS);
                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_STATUS_CODE,
                                        sizeof(status_data), status_data);
                if (r < 0)
                        return r;
        }

        /* DNS servers */
        if (server->n_dns > 0) {
                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_DNS_SERVER,
                                        server->n_dns * sizeof(struct in6_addr), server->dns);
                if (r < 0)
                        return r;
        }

        /* NTP server option (RFC 5908) - all suboptions in a single option */
        if (server->n_ntp > 0) {
                size_t suboption_size = sizeof(uint16_t) + sizeof(uint16_t) + sizeof(struct in6_addr);
                size_t ntp_total_len = server->n_ntp * suboption_size;
                _cleanup_free_ uint8_t *ntp_buf = new(uint8_t, ntp_total_len);
                if (!ntp_buf)
                        return -ENOMEM;

                for (size_t i = 0; i < server->n_ntp; i++) {
                        size_t pos = i * suboption_size;
                        unaligned_write_be16(ntp_buf + pos, DHCP6_NTP_SUBOPTION_SRV_ADDR);
                        unaligned_write_be16(ntp_buf + pos + 2, sizeof(struct in6_addr));
                        memcpy(ntp_buf + pos + 4, &server->ntp[i], sizeof(struct in6_addr));
                }

                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_NTP_SERVER,
                                        ntp_total_len, ntp_buf);
                if (r < 0)
                        return r;
        }

        /* Timezone option (RFC 4833) */
        if (server->timezone) {
                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_TZDB_TIMEZONE,
                                        strlen(server->timezone), server->timezone);
                if (r < 0)
                        return r;
        }

        /* Rapid commit if applicable */
        if (req->rapid_commit && server->rapid_commit && type == DHCP6_MESSAGE_REPLY) {
                r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_RAPID_COMMIT, 0, NULL);
                if (r < 0)
                        return r;
        }

        *ret_buf = TAKE_PTR(buf);
        *ret_len = offset;

        return 0;
}

static int dhcp6_server_handle_solicit(sd_dhcp6_server *server,
                                       const DHCP6Message *message,
                                       size_t len,
                                       DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        /* Must not contain a Server ID (RFC 8415, Section 16.2) */
        if (req->server_id)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "SOLICIT contains Server ID, ignoring.");

        dhcp6_server_cleanup_expired_leases(server);

        struct in6_addr assigned = {};
        bool have_address = false;
        bool newly_allocated = false;

        if (req->has_ia_na) {
                /* Check if client already has a lease */
                DHCP6ServerLease *existing = dhcp6_server_find_lease(server, req->client_id, req->client_id_len);
                if (existing) {
                        assigned = existing->address;
                        have_address = true;
                } else {
                        r = pool_allocate_address(server, &assigned);
                        if (r < 0) {
                                log_dhcp6_server(server, "No addresses available for client.");
                                have_address = false;
                        } else {
                                have_address = true;
                                newly_allocated = true;
                        }
                }
        }

        /* Rapid commit: if both client and server support it, send REPLY directly */
        if (req->rapid_commit && server->rapid_commit && have_address) {
                usec_t now_usec;
                assert_se(sd_event_now(server->event, CLOCK_BOOTTIME, &now_usec) >= 0);

                /* Check if client already has a lease - if so, just refresh it */
                DHCP6ServerLease *existing = dhcp6_server_find_lease(server, req->client_id, req->client_id_len);
                if (existing) {
                        existing->expiration = usec_add(now_usec, server->max_lease_time);
                } else {
                        /* Create a new lease */
                        _cleanup_(dhcp6_server_lease_freep) DHCP6ServerLease *lease = NULL;

                        lease = new(DHCP6ServerLease, 1);
                        if (!lease) {
                                pool_release_address(server, &assigned);
                                return -ENOMEM;
                        }

                        *lease = (DHCP6ServerLease) {
                                .address = assigned,
                        };

                        lease->client_id = memdup(req->client_id, req->client_id_len);
                        if (!lease->client_id) {
                                pool_release_address(server, &assigned);
                                return -ENOMEM;
                        }
                        lease->client_id_len = req->client_id_len;
                        lease->expiration = usec_add(now_usec, server->max_lease_time);

                        r = hashmap_ensure_put(&server->leases, &dhcp6_server_lease_hash_ops, lease, lease);
                        if (r < 0) {
                                pool_release_address(server, &assigned);
                                return r;
                        }
                        TAKE_PTR(lease);
                }

                r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                             message->transaction_id, req,
                                             &assigned, DHCP6_STATUS_SUCCESS,
                                             &reply_buf, &reply_len);
                if (r < 0)
                        return r;

                log_dhcp6_server(server, "Sending REPLY (rapid commit) to client.");
        } else {
                /* Normal SOLICIT -> ADVERTISE */
                if (newly_allocated) {
                        /* Release the tentatively allocated address - it will be
                         * properly allocated when the REQUEST comes in */
                        pool_release_address(server, &assigned);
                }

                r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_ADVERTISE,
                                             message->transaction_id, req,
                                             have_address ? &assigned : NULL,
                                             DHCP6_STATUS_NO_ADDRS_AVAIL,
                                             &reply_buf, &reply_len);
                if (r < 0)
                        return r;

                log_dhcp6_server(server, "Sending ADVERTISE to client.");
        }

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_request(sd_dhcp6_server *server,
                                        const DHCP6Message *message,
                                        size_t len,
                                        DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        /* Must contain a Server ID matching ours (RFC 8415, Section 16.4) */
        if (!req->server_id ||
            req->server_id_len != server->server_id_len ||
            memcmp(req->server_id, server->server_id, server->server_id_len) != 0)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "REQUEST has wrong Server ID, ignoring.");

        dhcp6_server_cleanup_expired_leases(server);

        usec_t now_usec;
        assert_se(sd_event_now(server->event, CLOCK_BOOTTIME, &now_usec) >= 0);

        struct in6_addr assigned = {};
        bool have_address = false;

        if (req->has_ia_na) {
                /* Check for existing lease */
                DHCP6ServerLease *existing = dhcp6_server_find_lease(server, req->client_id, req->client_id_len);
                if (existing) {
                        assigned = existing->address;
                        have_address = true;

                        /* Refresh expiration */
                        existing->expiration = usec_add(now_usec, server->max_lease_time);
                } else {
                        /* Allocate a new address */
                        r = pool_allocate_address(server, &assigned);
                        if (r < 0) {
                                log_dhcp6_server(server, "No addresses available for REQUEST.");
                                have_address = false;
                        } else {
                                have_address = true;

                                /* Create lease */
                                _cleanup_(dhcp6_server_lease_freep) DHCP6ServerLease *lease = NULL;

                                lease = new(DHCP6ServerLease, 1);
                                if (!lease) {
                                        pool_release_address(server, &assigned);
                                        return -ENOMEM;
                                }

                                *lease = (DHCP6ServerLease) {
                                        .address = assigned,
                                };

                                lease->client_id = memdup(req->client_id, req->client_id_len);
                                if (!lease->client_id) {
                                        pool_release_address(server, &assigned);
                                        return -ENOMEM;
                                }
                                lease->client_id_len = req->client_id_len;

                                lease->expiration = usec_add(now_usec, server->max_lease_time);

                                r = hashmap_ensure_put(&server->leases, &dhcp6_server_lease_hash_ops, lease, lease);
                                if (r < 0) {
                                        pool_release_address(server, &assigned);
                                        return r;
                                }
                                TAKE_PTR(lease);
                        }
                }
        }

        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                     message->transaction_id, req,
                                     have_address ? &assigned : NULL,
                                     DHCP6_STATUS_NO_ADDRS_AVAIL,
                                     &reply_buf, &reply_len);
        if (r < 0)
                return r;

        log_dhcp6_server(server, "Sending REPLY to client.");

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_renew_rebind(sd_dhcp6_server *server,
                                             const DHCP6Message *message,
                                             size_t len,
                                             DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        if (message->type == DHCP6_MESSAGE_RENEW) {
                /* RFC 8415, Section 16.5: Server ID must match */
                if (!req->server_id ||
                    req->server_id_len != server->server_id_len ||
                    memcmp(req->server_id, server->server_id, server->server_id_len) != 0)
                        return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                                      "RENEW has wrong Server ID, ignoring.");
        } else {
                /* RFC 8415, Section 16.7: REBIND must not contain Server ID */
                if (req->server_id)
                        return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                                      "REBIND contains Server ID, ignoring.");
        }

        dhcp6_server_cleanup_expired_leases(server);

        const struct in6_addr *reply_address = NULL;

        if (req->has_ia_na) {
                DHCP6ServerLease *existing = dhcp6_server_find_lease(server, req->client_id, req->client_id_len);
                if (!existing) {
                        /* RFC 8415, Section 18.3.5: send Reply with NoBinding status */
                        log_dhcp6_server(server, "No lease found for RENEW/REBIND client, sending NoBinding.");

                        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                                     message->transaction_id, req,
                                                     NULL, DHCP6_STATUS_NO_BINDING,
                                                     &reply_buf, &reply_len);
                        if (r < 0)
                                return r;

                        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
                }

                /* Refresh the lease */
                usec_t now_usec;
                assert_se(sd_event_now(server->event, CLOCK_BOOTTIME, &now_usec) >= 0);
                existing->expiration = usec_add(now_usec, server->max_lease_time);
                reply_address = &existing->address;
        }

        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                     message->transaction_id, req,
                                     reply_address, DHCP6_STATUS_SUCCESS,
                                     &reply_buf, &reply_len);
        if (r < 0)
                return r;

        log_dhcp6_server(server, "Sending REPLY to RENEW/REBIND.");

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_release(sd_dhcp6_server *server,
                                        const DHCP6Message *message,
                                        size_t len,
                                        DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        /* Server ID must match (RFC 8415, Section 16.8) */
        if (!req->server_id ||
            req->server_id_len != server->server_id_len ||
            memcmp(req->server_id, server->server_id, server->server_id_len) != 0)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "RELEASE has wrong Server ID, ignoring.");

        dhcp6_server_cleanup_expired_leases(server);

        DHCP6ServerLease *existing = dhcp6_server_find_lease(server, req->client_id, req->client_id_len);
        if (existing) {
                pool_release_address(server, &existing->address);
                hashmap_remove_value(server->leases, existing, existing);
                dhcp6_server_lease_free(existing);
                log_dhcp6_server(server, "Released lease for client.");
        }

        /* Send reply even if no lease found */
        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                     message->transaction_id, req,
                                     NULL, DHCP6_STATUS_SUCCESS,
                                     &reply_buf, &reply_len);
        if (r < 0)
                return r;

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_confirm(sd_dhcp6_server *server,
                                        const DHCP6Message *message,
                                        size_t len,
                                        DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        /* RFC 8415, Section 16.6: discard if Server Identifier is present */
        if (req->server_id)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "CONFIRM contains Server ID, ignoring.");

        /* RFC 8415, Section 16.6: discard if no IA options present */
        if (!req->has_ia_na)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "CONFIRM contains no IA options, ignoring.");

        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                     message->transaction_id, req,
                                     NULL, DHCP6_STATUS_SUCCESS,
                                     &reply_buf, &reply_len);
        if (r < 0)
                return r;

        log_dhcp6_server(server, "Sending REPLY to CONFIRM.");

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_information_request(sd_dhcp6_server *server,
                                                    const DHCP6Message *message,
                                                    size_t len,
                                                    DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        /* RFC 8415, Section 16.12: if Server ID is present, it must match ours */
        if (req->server_id &&
            (req->server_id_len != server->server_id_len ||
             memcmp(req->server_id, server->server_id, server->server_id_len) != 0))
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "INFORMATION-REQUEST has wrong Server ID, ignoring.");

        /* RFC 8415, Section 16.12: discard if IA options are present */
        if (req->has_ia_na)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "INFORMATION-REQUEST contains IA option, ignoring.");

        /* Stateless - just send configuration options, no address */
        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                     message->transaction_id, req,
                                     NULL, DHCP6_STATUS_SUCCESS,
                                     &reply_buf, &reply_len);
        if (r < 0)
                return r;

        log_dhcp6_server(server, "Sending REPLY to INFORMATION-REQUEST.");

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_decline(sd_dhcp6_server *server,
                                        const DHCP6Message *message,
                                        size_t len,
                                        DHCP6ServerRequest *req) {
        _cleanup_free_ uint8_t *reply_buf = NULL;
        size_t reply_len;
        int r;

        assert(server);
        assert(message);
        assert(req);

        /* Server ID must match (RFC 8415, Section 16.9) */
        if (!req->server_id ||
            req->server_id_len != server->server_id_len ||
            memcmp(req->server_id, server->server_id, server->server_id_len) != 0)
                return log_dhcp6_server_errno(server, SYNTHETIC_ERRNO(EINVAL),
                                              "DECLINE has wrong Server ID, ignoring.");

        /* Client is reporting address conflict - remove the lease but keep the
         * address reserved in the pool bitmap to avoid reassigning a conflicting
         * address (RFC 8415, Section 18.4.7). */
        log_dhcp6_server(server, "Received DECLINE from client, marking address as unavailable.");
        if (req->has_ia_na) {
                DHCP6ServerLease *existing = dhcp6_server_find_lease(server, req->client_id, req->client_id_len);
                if (existing) {
                        /* Do not call pool_release_address() - keep bitmap bit set */
                        hashmap_remove_value(server->leases, existing, existing);
                        dhcp6_server_lease_free(existing);
                }
        }

        /* Send REPLY acknowledging the DECLINE */
        r = dhcp6_server_build_reply(server, DHCP6_MESSAGE_REPLY,
                                     message->transaction_id, req,
                                     NULL, DHCP6_STATUS_SUCCESS,
                                     &reply_buf, &reply_len);
        if (r < 0)
                return r;

        return dhcp6_server_send_udp(server, &req->client_address, reply_buf, reply_len);
}

static int dhcp6_server_handle_message(sd_dhcp6_server *server,
                                        const DHCP6Message *message,
                                        size_t len,
                                        const struct in6_addr *source_address) {
        DHCP6ServerRequest req = {};
        uint8_t type;
        int r;

        assert(server);
        assert(message);
        assert(len >= sizeof(DHCP6Message));

        type = message->type;

        r = dhcp6_server_parse_message(server, message, len, &req);
        if (r < 0) {
                log_dhcp6_server_errno(server, r, "Failed to parse %s message, ignoring: %m",
                                       dhcp6_message_type_to_string(type) ?: "unknown");
                return 0;
        }

        req.client_address = *source_address;

        log_dhcp6_server(server, "Received %s message.",
                         dhcp6_message_type_to_string(type) ?: "unknown");

        switch (type) {

        case DHCP6_MESSAGE_SOLICIT:
                return dhcp6_server_handle_solicit(server, message, len, &req);

        case DHCP6_MESSAGE_REQUEST:
                return dhcp6_server_handle_request(server, message, len, &req);

        case DHCP6_MESSAGE_RENEW:
        case DHCP6_MESSAGE_REBIND:
                return dhcp6_server_handle_renew_rebind(server, message, len, &req);

        case DHCP6_MESSAGE_RELEASE:
                return dhcp6_server_handle_release(server, message, len, &req);

        case DHCP6_MESSAGE_CONFIRM:
                return dhcp6_server_handle_confirm(server, message, len, &req);

        case DHCP6_MESSAGE_INFORMATION_REQUEST:
                return dhcp6_server_handle_information_request(server, message, len, &req);

        case DHCP6_MESSAGE_DECLINE:
                return dhcp6_server_handle_decline(server, message, len, &req);

        /* Server-to-client message types - should not be received by server */
        case DHCP6_MESSAGE_ADVERTISE:
        case DHCP6_MESSAGE_REPLY:
        case DHCP6_MESSAGE_RECONFIGURE:
                return 0;

        default:
                log_dhcp6_server(server, "Unsupported message type %u, ignoring.", type);
                return 0;
        }
}

static int dhcp6_server_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_free_ DHCP6Message *message = NULL;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in6_pktinfo))) control = {};
        sd_dhcp6_server *server = ASSERT_PTR(userdata);
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        union sockaddr_union sender = {};
        struct cmsghdr *cmsg;
        struct in6_addr source_address = {};
        ssize_t buflen, len;
        int r;

        msg.msg_name = &sender;
        msg.msg_namelen = sizeof(sender);

        buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp6_server_errno(server, buflen, "Failed to determine datagram size: %m");
                return 0;
        }

        message = malloc(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg_safe(fd, &msg, 0);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp6_server_errno(server, len, "Failed to receive message: %m");
                return 0;
        }
        if ((size_t) len < sizeof(DHCP6Message))
                return 0;

        /* Get the source address from recvmsg */
        source_address = sender.in6.sin6_addr;

        /* Verify the message came in on our interface */
        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                    cmsg->cmsg_type == IPV6_PKTINFO &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
                        struct in6_pktinfo *info = CMSG_TYPED_DATA(cmsg, struct in6_pktinfo);

                        if (server->ifindex != info->ipi6_ifindex)
                                return 0;

                        break;
                }
        }

        r = dhcp6_server_handle_message(server, message, (size_t) len, &source_address);
        if (r < 0)
                log_dhcp6_server_errno(server, r, "Couldn't process incoming message: %m");

        return 0;
}

static int dhcp6_server_init_socket(sd_dhcp6_server *server) {
        union sockaddr_union src = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_addr = IN6ADDR_ANY_INIT, /* Bind to any address to receive multicast */
                .in6.sin6_port = htobe16(DHCP6_PORT_SERVER),
                .in6.sin6_scope_id = server->ifindex,
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(server);

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

        r = socket_bind_to_ifindex(s, server->ifindex);
        if (r < 0)
                return r;

        r = bind(s, &src.sa, sizeof(src.in6));
        if (r < 0)
                return -errno;

        /* Join multicast group: All_DHCP_Relay_Agents_and_Servers (ff02::1:2) */
        struct ipv6_mreq mreq = {
                .ipv6mr_multiaddr = all_dhcp6_relay_agents_and_servers,
                .ipv6mr_ifindex = server->ifindex,
        };

        r = setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if (r < 0)
                return -errno;

        server->fd = TAKE_FD(s);
        return 0;
}

int sd_dhcp6_server_start(sd_dhcp6_server *server) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(server->event, -EINVAL);
        assert_return(!in6_addr_is_null(&server->address), -EINVAL);
        assert_return(!server->receive_message, -EBUSY);
        assert_return(server->fd < 0, -EBUSY);

        r = dhcp6_server_generate_duid(server);
        if (r < 0)
                return log_dhcp6_server_errno(server, r, "Failed to generate server DUID: %m");

        r = dhcp6_server_init_socket(server);
        if (r < 0) {
                sd_dhcp6_server_stop(server);
                return log_dhcp6_server_errno(server, r, "Failed to initialize socket: %m");
        }

        r = sd_event_add_io(server->event, &server->receive_message, server->fd, EPOLLIN,
                            dhcp6_server_receive_message, server);
        if (r < 0) {
                sd_dhcp6_server_stop(server);
                return r;
        }

        r = sd_event_source_set_priority(server->receive_message, server->event_priority);
        if (r < 0) {
                sd_dhcp6_server_stop(server);
                return r;
        }

        log_dhcp6_server(server, "STARTED");

        return 0;
}

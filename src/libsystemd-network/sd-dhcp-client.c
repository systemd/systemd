/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/if_infiniband.h>

#include "sd-dhcp-client.h"

#include "alloc-util.h"
#include "device-util.h"
#include "dhcp-client-id-internal.h"
#include "dhcp-client-internal.h"
#include "dhcp-lease-internal.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "iovec-util.h"
#include "memory-util.h"
#include "network-common.h"
#include "random-util.h"
#include "set.h"
#include "sort-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "web-util.h"

#define MAX_MAC_ADDR_LEN CONST_MAX(INFINIBAND_ALEN, ETH_ALEN)

#define RESTART_AFTER_NAK_MIN_USEC (1 * USEC_PER_SEC)
#define RESTART_AFTER_NAK_MAX_USEC (30 * USEC_PER_MINUTE)

#define TRANSIENT_FAILURE_ATTEMPTS 3 /* Arbitrary limit: how many attempts are considered enough to report
                                      * transient failure. */

struct sd_dhcp_client {
        unsigned n_ref;

        DHCPState state;
        sd_event *event;
        int event_priority;
        sd_event_source *timeout_resend;

        int ifindex;
        char *ifname;

        sd_device *dev;

        int fd;
        uint16_t port;
        union sockaddr_union link;
        sd_event_source *receive_message;
        bool request_broadcast;
        Set *req_opts;
        bool anonymize;
        bool rapid_commit;
        be32_t last_addr;
        struct hw_addr_data hw_addr;
        struct hw_addr_data bcast_addr;
        uint16_t arp_type;
        sd_dhcp_client_id client_id;
        char *hostname;
        char *vendor_class_identifier;
        char *mudurl;
        char **user_class;
        uint32_t mtu;
        usec_t fallback_lease_lifetime;
        uint32_t xid;
        usec_t start_time;
        usec_t t1_time;
        usec_t t2_time;
        usec_t expire_time;
        uint64_t attempt;
        uint64_t max_attempts;
        OrderedHashmap *extra_options;
        OrderedHashmap *vendor_options;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;
        sd_event_source *timeout_expire;
        sd_event_source *timeout_ipv6_only_mode;
        sd_dhcp_client_callback_t callback;
        void *userdata;
        sd_dhcp_client_callback_t state_callback;
        void *state_userdata;
        sd_dhcp_lease *lease;
        usec_t start_delay;
        int ip_service_type;
        int socket_priority;
        bool socket_priority_set;
        bool ipv6_acquired;
};

static const uint8_t default_req_opts[] = {
        SD_DHCP_OPTION_SUBNET_MASK,
        SD_DHCP_OPTION_ROUTER,
        SD_DHCP_OPTION_HOST_NAME,
        SD_DHCP_OPTION_DOMAIN_NAME,
        SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
};

/* RFC7844 section 3:
   MAY contain the Parameter Request List option.
   RFC7844 section 3.6:
   The client intending to protect its privacy SHOULD only request a
   minimal number of options in the PRL and SHOULD also randomly shuffle
   the ordering of option codes in the PRL.  If this random ordering
   cannot be implemented, the client MAY order the option codes in the
   PRL by option code number (lowest to highest).
*/
/* NOTE: using PRL options that Windows 10 RFC7844 implementation uses */
static const uint8_t default_req_opts_anonymize[] = {
        SD_DHCP_OPTION_SUBNET_MASK,                     /* 1 */
        SD_DHCP_OPTION_ROUTER,                          /* 3 */
        SD_DHCP_OPTION_DOMAIN_NAME_SERVER,              /* 6 */
        SD_DHCP_OPTION_DOMAIN_NAME,                     /* 15 */
        SD_DHCP_OPTION_ROUTER_DISCOVERY,                /* 31 */
        SD_DHCP_OPTION_STATIC_ROUTE,                    /* 33 */
        SD_DHCP_OPTION_VENDOR_SPECIFIC,                 /* 43 */
        SD_DHCP_OPTION_NETBIOS_NAME_SERVER,             /* 44 */
        SD_DHCP_OPTION_NETBIOS_NODE_TYPE,               /* 46 */
        SD_DHCP_OPTION_NETBIOS_SCOPE,                   /* 47 */
        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,          /* 121 */
        SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE,  /* 249 */
        SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,     /* 252 */
};

static int client_receive_message_raw(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata);
static int client_receive_message_udp(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata);
static void client_stop(sd_dhcp_client *client, int error);

int dhcp_client_set_state_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata) {

        assert_return(client, -EINVAL);

        client->state_callback = cb;
        client->state_userdata = userdata;

        return 0;
}

int sd_dhcp_client_set_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata) {

        assert_return(client, -EINVAL);

        client->callback = cb;
        client->userdata = userdata;

        return 0;
}

int sd_dhcp_client_set_request_broadcast(sd_dhcp_client *client, int broadcast) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->request_broadcast = broadcast;

        return 0;
}

int sd_dhcp_client_set_request_option(sd_dhcp_client *client, uint8_t option) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        switch (option) {

        case SD_DHCP_OPTION_PAD:
        case SD_DHCP_OPTION_OVERLOAD:
        case SD_DHCP_OPTION_MESSAGE_TYPE:
        case SD_DHCP_OPTION_PARAMETER_REQUEST_LIST:
        case SD_DHCP_OPTION_END:
                return -EINVAL;

        default:
                break;
        }

        return set_ensure_put(&client->req_opts, NULL, UINT8_TO_PTR(option));
}

static int client_request_contains(sd_dhcp_client *client, uint8_t option) {
        assert(client);

        return set_contains(client->req_opts, UINT8_TO_PTR(option));
}

int sd_dhcp_client_set_request_address(
                sd_dhcp_client *client,
                const struct in_addr *last_addr) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        if (last_addr)
                client->last_addr = last_addr->s_addr;
        else
                client->last_addr = INADDR_ANY;

        return 0;
}

int sd_dhcp_client_set_ifindex(sd_dhcp_client *client, int ifindex) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(ifindex > 0, -EINVAL);

        client->ifindex = ifindex;
        return 0;
}

int sd_dhcp_client_set_ifname(sd_dhcp_client *client, const char *ifname) {
        assert_return(client, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&client->ifname, ifname);
}

int sd_dhcp_client_get_ifname(sd_dhcp_client *client, const char **ret) {
        int r;

        assert_return(client, -EINVAL);

        r = get_ifname(client->ifindex, &client->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = client->ifname;

        return 0;
}

int sd_dhcp_client_set_mac(
                sd_dhcp_client *client,
                const uint8_t *hw_addr,
                const uint8_t *bcast_addr,
                size_t addr_len,
                uint16_t arp_type) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(IN_SET(arp_type, ARPHRD_ETHER, ARPHRD_INFINIBAND), -EINVAL);
        assert_return(hw_addr, -EINVAL);
        assert_return(addr_len == (arp_type == ARPHRD_ETHER ? ETH_ALEN : INFINIBAND_ALEN), -EINVAL);

        client->arp_type = arp_type;
        hw_addr_set(&client->hw_addr, hw_addr, addr_len);
        hw_addr_set(&client->bcast_addr, bcast_addr, bcast_addr ? addr_len : 0);

        return 0;
}

int sd_dhcp_client_get_client_id(sd_dhcp_client *client, const sd_dhcp_client_id **ret) {
        assert_return(client, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!sd_dhcp_client_id_is_set(&client->client_id))
                return -ENODATA;

        *ret = &client->client_id;
        return 0;
}

int sd_dhcp_client_set_client_id(
                sd_dhcp_client *client,
                uint8_t type,
                const uint8_t *data,
                size_t data_len) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(data, -EINVAL);
        assert_return(client_id_data_size_is_valid(data_len), -EINVAL);

        /* For hardware types, log debug message about unexpected data length.
         *
         * Note that infiniband's INFINIBAND_ALEN is 20 bytes long, but only
         * the last 8 bytes of the address are stable and suitable to put into
         * the client-id. The caller is advised to account for that. */
        if ((type == ARPHRD_ETHER && data_len != ETH_ALEN) ||
            (type == ARPHRD_INFINIBAND && data_len != 8))
                log_dhcp_client(client,
                                "Changing client ID to hardware type %u with unexpected address length %zu",
                                type, data_len);

        return sd_dhcp_client_id_set(&client->client_id, type, data, data_len);
}

static int dhcp_client_set_iaid_duid(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                sd_dhcp_duid *duid) {

        int r;

        if (!iaid_set) {
                r = dhcp_identifier_set_iaid(client->dev, &client->hw_addr,
                                             /* legacy_unstable_byteorder = */ true,
                                             &iaid);
                if (r < 0)
                        return r;

                iaid = be32toh(iaid);
        }

        return sd_dhcp_client_id_set_iaid_duid(&client->client_id, iaid, duid);
}

int sd_dhcp_client_set_iaid_duid_llt(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                usec_t llt_time) {

        sd_dhcp_duid duid;
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        r = sd_dhcp_duid_set_llt(&duid, client->hw_addr.bytes, client->hw_addr.length, client->arp_type, llt_time);
        if (r < 0)
                return r;

        return dhcp_client_set_iaid_duid(client, iaid_set, iaid, &duid);
}

int sd_dhcp_client_set_iaid_duid_ll(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid) {

        sd_dhcp_duid duid;
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        r = sd_dhcp_duid_set_ll(&duid, client->hw_addr.bytes, client->hw_addr.length, client->arp_type);
        if (r < 0)
                return r;

        return dhcp_client_set_iaid_duid(client, iaid_set, iaid, &duid);
}

int sd_dhcp_client_set_iaid_duid_en(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid) {

        sd_dhcp_duid duid;
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        r = sd_dhcp_duid_set_en(&duid);
        if (r < 0)
                return r;

        return dhcp_client_set_iaid_duid(client, iaid_set, iaid, &duid);
}

int sd_dhcp_client_set_iaid_duid_uuid(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid) {

        sd_dhcp_duid duid;
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        r = sd_dhcp_duid_set_uuid(&duid);
        if (r < 0)
                return r;

        return dhcp_client_set_iaid_duid(client, iaid_set, iaid, &duid);
}

int sd_dhcp_client_set_iaid_duid_raw(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                uint16_t duid_type,
                const uint8_t *duid_data,
                size_t duid_data_len) {

        sd_dhcp_duid duid;
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(duid_data || duid_data_len == 0, -EINVAL);

        r = sd_dhcp_duid_set(&duid, duid_type, duid_data, duid_data_len);
        if (r < 0)
                return r;

        return dhcp_client_set_iaid_duid(client, iaid_set, iaid, &duid);
}

int sd_dhcp_client_set_rapid_commit(sd_dhcp_client *client, bool rapid_commit) {
        assert_return(client, -EINVAL);

        client->rapid_commit = !client->anonymize && rapid_commit;
        return 0;
}

int sd_dhcp_client_set_hostname(
                sd_dhcp_client *client,
                const char *hostname) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        /* Make sure hostnames qualify as DNS and as Linux hostnames */
        if (hostname &&
            !(hostname_is_valid(hostname, 0) && dns_name_is_valid(hostname) > 0))
                return -EINVAL;

        return free_and_strdup(&client->hostname, hostname);
}

int sd_dhcp_client_set_vendor_class_identifier(
                sd_dhcp_client *client,
                const char *vci) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        return free_and_strdup(&client->vendor_class_identifier, vci);
}

int sd_dhcp_client_set_mud_url(
                sd_dhcp_client *client,
                const char *mudurl) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(mudurl, -EINVAL);
        assert_return(strlen(mudurl) <= 255, -EINVAL);
        assert_return(http_url_is_valid(mudurl), -EINVAL);

        return free_and_strdup(&client->mudurl, mudurl);
}

int sd_dhcp_client_set_user_class(
                sd_dhcp_client *client,
                char * const *user_class) {

        char **s = NULL;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(!strv_isempty(user_class), -EINVAL);

        STRV_FOREACH(p, user_class) {
                size_t n = strlen(*p);

                if (n > 255 || n == 0)
                        return -EINVAL;
        }

        s = strv_copy(user_class);
        if (!s)
                return -ENOMEM;

        return strv_free_and_replace(client->user_class, s);
}

int sd_dhcp_client_set_client_port(
                sd_dhcp_client *client,
                uint16_t port) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->port = port;

        return 0;
}

int sd_dhcp_client_set_mtu(sd_dhcp_client *client, uint32_t mtu) {
        assert_return(client, -EINVAL);
        assert_return(mtu >= DHCP_MIN_PACKET_SIZE, -ERANGE);

        /* MTU may be changed by the acquired lease. Hence, we cannot require that the client is stopped here.
         * Please do not add assertion for !sd_dhcp_client_is_running(client) here. */

        client->mtu = mtu;

        return 0;
}

int sd_dhcp_client_set_max_attempts(sd_dhcp_client *client, uint64_t max_attempts) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->max_attempts = max_attempts;

        return 0;
}

int sd_dhcp_client_add_option(sd_dhcp_client *client, sd_dhcp_option *v) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(v, -EINVAL);

        r = ordered_hashmap_ensure_put(&client->extra_options, &dhcp_option_hash_ops, UINT_TO_PTR(v->option), v);
        if (r < 0)
                return r;

        sd_dhcp_option_ref(v);
        return 0;
}

int sd_dhcp_client_add_vendor_option(sd_dhcp_client *client, sd_dhcp_option *v) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(v, -EINVAL);

        r = ordered_hashmap_ensure_allocated(&client->vendor_options, &dhcp_option_hash_ops);
        if (r < 0)
                return -ENOMEM;

        r = ordered_hashmap_put(client->vendor_options, v, v);
        if (r < 0)
                return r;

        sd_dhcp_option_ref(v);

        return 1;
}

int sd_dhcp_client_get_lease(sd_dhcp_client *client, sd_dhcp_lease **ret) {
        assert_return(client, -EINVAL);

        if (!client->lease)
                return -EADDRNOTAVAIL;

        if (ret)
                *ret = client->lease;

        return 0;
}

int sd_dhcp_client_set_service_type(sd_dhcp_client *client, int type) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->ip_service_type = type;

        return 0;
}

int sd_dhcp_client_set_socket_priority(sd_dhcp_client *client, int socket_priority) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->socket_priority_set = true;
        client->socket_priority = socket_priority;

        return 0;
}

int sd_dhcp_client_set_fallback_lease_lifetime(sd_dhcp_client *client, uint64_t fallback_lease_lifetime) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);
        assert_return(fallback_lease_lifetime > 0, -EINVAL);

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));
        client->fallback_lease_lifetime = fallback_lease_lifetime;

        return 0;
}

static void client_set_state(sd_dhcp_client *client, DHCPState state) {
        assert(client);

        if (client->state == state)
                return;

        log_dhcp_client(client, "State changed: %s -> %s",
                        dhcp_state_to_string(client->state), dhcp_state_to_string(state));

        client->state = state;

        if (client->state_callback)
                client->state_callback(client, state, client->state_userdata);
}

int dhcp_client_get_state(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);

        return client->state;
}

static int client_notify(sd_dhcp_client *client, int event) {
        assert(client);

        if (client->callback)
                return client->callback(client, event, client->userdata);

        return 0;
}

static int client_initialize(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);

        client->receive_message = sd_event_source_disable_unref(client->receive_message);

        client->fd = safe_close(client->fd);

        (void) event_source_disable(client->timeout_resend);
        (void) event_source_disable(client->timeout_t1);
        (void) event_source_disable(client->timeout_t2);
        (void) event_source_disable(client->timeout_expire);
        (void) event_source_disable(client->timeout_ipv6_only_mode);

        client->attempt = 0;

        client_set_state(client, DHCP_STATE_STOPPED);
        client->xid = 0;

        client->lease = sd_dhcp_lease_unref(client->lease);

        return 0;
}

static void client_stop(sd_dhcp_client *client, int error) {
        assert(client);

        if (error < 0)
                log_dhcp_client_errno(client, error, "STOPPED: %m");
        else if (error == SD_DHCP_CLIENT_EVENT_STOP)
                log_dhcp_client(client, "STOPPED");
        else
                log_dhcp_client(client, "STOPPED: Unknown event");

        client_notify(client, error);

        client_initialize(client);
}

/* RFC2131 section 4.1:
 * retransmission delays should include -1 to +1 sec of random 'fuzz'. */
#define RFC2131_RANDOM_FUZZ \
        ((int64_t)(random_u64() % (2 * USEC_PER_SEC)) - (int64_t)USEC_PER_SEC)

/* RFC2131 section 4.1:
 * for retransmission delays, timeout should start at 4s then double
 * each attempt with max of 64s, with -1 to +1 sec of random 'fuzz' added.
 * This assumes the first call will be using attempt 1. */
static usec_t client_compute_request_timeout(usec_t now, uint64_t attempt) {
        usec_t timeout = (UINT64_C(1) << MIN(attempt + 1, UINT64_C(6))) * USEC_PER_SEC;

        return usec_sub_signed(usec_add(now, timeout), RFC2131_RANDOM_FUZZ);
}

/* RFC2131 section 4.4.5:
 * T1 defaults to (0.5 * duration_of_lease).
 * T2 defaults to (0.875 * duration_of_lease). */
#define T1_DEFAULT(lifetime) ((lifetime) / 2)
#define T2_DEFAULT(lifetime) (((lifetime) * 7) / 8)

/* RFC2131 section 4.4.5:
 * the client SHOULD wait one-half of the remaining time until T2 (in RENEWING state)
 * and one-half of the remaining lease time (in REBINDING state), down to a minimum
 * of 60 seconds.
 * Note that while the default T1/T2 initial times do have random 'fuzz' applied,
 * the RFC sec 4.4.5 does not mention adding any fuzz to retries. */
static usec_t client_compute_reacquisition_timeout(usec_t now, usec_t expire) {
        return now + MAX(usec_sub_unsigned(expire, now) / 2, 60 * USEC_PER_SEC);
}

static int cmp_uint8(const uint8_t *a, const uint8_t *b) {
        return CMP(*a, *b);
}

static int client_message_init(
                sd_dhcp_client *client,
                DHCPPacket **ret,
                uint8_t type,
                size_t *_optlen,
                size_t *_optoffset) {

        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t optlen, optoffset, size;
        usec_t time_now;
        uint16_t secs;
        int r;

        assert(client);
        assert(client->start_time);
        assert(ret);
        assert(_optlen);
        assert(_optoffset);
        assert(IN_SET(type, DHCP_DISCOVER, DHCP_REQUEST, DHCP_RELEASE, DHCP_DECLINE));

        optlen = DHCP_MIN_OPTIONS_SIZE;
        size = sizeof(DHCPPacket) + optlen;

        packet = malloc0(size);
        if (!packet)
                return -ENOMEM;

        r = dhcp_message_init(&packet->dhcp, BOOTREQUEST, client->xid, type,
                              client->arp_type, client->hw_addr.length, client->hw_addr.bytes,
                              optlen, &optoffset);
        if (r < 0)
                return r;

        /* Although 'secs' field is a SHOULD in RFC 2131, certain DHCP servers
           refuse to issue an DHCP lease if 'secs' is set to zero */
        r = sd_event_now(client->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;
        assert(time_now >= client->start_time);

        /* seconds between sending first and last DISCOVER
         * must always be strictly positive to deal with broken servers */
        secs = ((time_now - client->start_time) / USEC_PER_SEC) ?: 1;
        packet->dhcp.secs = htobe16(secs);

        /* RFC2131 section 4.1
           A client that cannot receive unicast IP datagrams until its protocol
           software has been configured with an IP address SHOULD set the
           BROADCAST bit in the 'flags' field to 1 in any DHCPDISCOVER or
           DHCPREQUEST messages that client sends.  The BROADCAST bit will
           provide a hint to the DHCP server and BOOTP relay agent to broadcast
           any messages to the client on the client's subnet.

           Note: some interfaces needs this to be enabled, but some networks
           needs this to be disabled as broadcasts are filteretd, so this
           needs to be configurable */
        if (client->request_broadcast || client->arp_type != ARPHRD_ETHER)
                packet->dhcp.flags = htobe16(0x8000);

        /* Some DHCP servers will refuse to issue an DHCP lease if the Client
           Identifier option is not set */
        r = dhcp_option_append(&packet->dhcp, optlen, &optoffset, 0,
                               SD_DHCP_OPTION_CLIENT_IDENTIFIER,
                               client->client_id.size,
                               client->client_id.raw);
        if (r < 0)
                return r;

        /* RFC2131 section 3.5:
           in its initial DHCPDISCOVER or DHCPREQUEST message, a
           client may provide the server with a list of specific
           parameters the client is interested in. If the client
           includes a list of parameters in a DHCPDISCOVER message,
           it MUST include that list in any subsequent DHCPREQUEST
           messages.
         */

        /* RFC7844 section 3:
           MAY contain the Parameter Request List option. */
        /* NOTE: in case that there would be an option to do not send
         * any PRL at all, the size should be checked before sending */
        if (!set_isempty(client->req_opts) && type != DHCP_RELEASE) {
                _cleanup_free_ uint8_t *opts = NULL;
                size_t n_opts, i = 0;
                void *val;

                n_opts = set_size(client->req_opts);
                opts = new(uint8_t, n_opts);
                if (!opts)
                        return -ENOMEM;

                SET_FOREACH(val, client->req_opts)
                        opts[i++] = PTR_TO_UINT8(val);
                assert(i == n_opts);

                /* For anonymizing the request, let's sort the options. */
                typesafe_qsort(opts, n_opts, cmp_uint8);

                r = dhcp_option_append(&packet->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_PARAMETER_REQUEST_LIST,
                                       n_opts, opts);
                if (r < 0)
                        return r;
        }

        /* RFC2131 section 3.5:
           The client SHOULD include the ’maximum DHCP message size’ option to
           let the server know how large the server may make its DHCP messages.

           Note (from ConnMan): Some DHCP servers will send bigger DHCP packets
           than the defined default size unless the Maximum Message Size option
           is explicitly set

           RFC3442 "Requirements to Avoid Sizing Constraints":
           Because a full routing table can be quite large, the standard 576
           octet maximum size for a DHCP message may be too short to contain
           some legitimate Classless Static Route options.  Because of this,
           clients implementing the Classless Static Route option SHOULD send a
           Maximum DHCP Message Size [4] option if the DHCP client's TCP/IP
           stack is capable of receiving larger IP datagrams.  In this case, the
           client SHOULD set the value of this option to at least the MTU of the
           interface that the client is configuring.  The client MAY set the
           value of this option higher, up to the size of the largest UDP packet
           it is prepared to accept.  (Note that the value specified in the
           Maximum DHCP Message Size option is the total maximum packet size,
           including IP and UDP headers.)
         */
        /* RFC7844 section 3:
           SHOULD NOT contain any other option. */
        if (!client->anonymize && IN_SET(type, DHCP_DISCOVER, DHCP_REQUEST)) {
                be16_t max_size = htobe16(MIN(client->mtu - DHCP_IP_UDP_SIZE, (uint32_t) UINT16_MAX));
                r = dhcp_option_append(&packet->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
                                       2, &max_size);
                if (r < 0)
                        return r;
        }

        *_optlen = optlen;
        *_optoffset = optoffset;
        *ret = TAKE_PTR(packet);

        return 0;
}

static int client_append_fqdn_option(
                DHCPMessage *message,
                size_t optlen,
                size_t *optoffset,
                const char *fqdn) {

        uint8_t buffer[3 + DHCP_MAX_FQDN_LENGTH];
        int r;

        buffer[0] = DHCP_FQDN_FLAG_S | /* Request server to perform A RR DNS updates */
                    DHCP_FQDN_FLAG_E;  /* Canonical wire format */
        buffer[1] = 0;                 /* RCODE1 (deprecated) */
        buffer[2] = 0;                 /* RCODE2 (deprecated) */

        r = dns_name_to_wire_format(fqdn, buffer + 3, sizeof(buffer) - 3, false);
        if (r > 0)
                r = dhcp_option_append(message, optlen, optoffset, 0,
                                       SD_DHCP_OPTION_FQDN, 3 + r, buffer);

        return r;
}

static int dhcp_client_send_raw(
                sd_dhcp_client *client,
                DHCPPacket *packet,
                size_t len) {

        dhcp_packet_append_ip_headers(packet, INADDR_ANY, client->port,
                                      INADDR_BROADCAST, DHCP_PORT_SERVER, len, client->ip_service_type);

        return dhcp_network_send_raw_socket(client->fd, &client->link,
                                            packet, len);
}

static int client_append_common_discover_request_options(sd_dhcp_client *client, DHCPPacket *packet, size_t *optoffset, size_t optlen) {
        sd_dhcp_option *j;
        int r;

        assert(client);

        if (client->hostname) {
                /* According to RFC 4702 "clients that send the Client FQDN option in
                   their messages MUST NOT also send the Host Name option". Just send
                   one of the two depending on the hostname type.
                */
                if (dns_name_is_single_label(client->hostname)) {
                        /* it is unclear from RFC 2131 if client should send hostname in
                           DHCPDISCOVER but dhclient does and so we do as well
                        */
                        r = dhcp_option_append(&packet->dhcp, optlen, optoffset, 0,
                                               SD_DHCP_OPTION_HOST_NAME,
                                               strlen(client->hostname), client->hostname);
                } else
                        r = client_append_fqdn_option(&packet->dhcp, optlen, optoffset,
                                                      client->hostname);
                if (r < 0)
                        return r;
        }

        if (client->vendor_class_identifier) {
                r = dhcp_option_append(&packet->dhcp, optlen, optoffset, 0,
                                       SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER,
                                       strlen(client->vendor_class_identifier),
                                       client->vendor_class_identifier);
                if (r < 0)
                        return r;
        }

        if (client->mudurl) {
                r = dhcp_option_append(&packet->dhcp, optlen, optoffset, 0,
                                       SD_DHCP_OPTION_MUD_URL,
                                       strlen(client->mudurl),
                                       client->mudurl);
                if (r < 0)
                        return r;
        }

        if (client->user_class) {
                r = dhcp_option_append(&packet->dhcp, optlen, optoffset, 0,
                                       SD_DHCP_OPTION_USER_CLASS,
                                       strv_length(client->user_class),
                                       client->user_class);
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH(j, client->extra_options) {
                r = dhcp_option_append(&packet->dhcp, optlen, optoffset, 0,
                                       j->option, j->length, j->data);
                if (r < 0)
                        return r;
        }

        if (!ordered_hashmap_isempty(client->vendor_options)) {
                r = dhcp_option_append(
                                &packet->dhcp, optlen, optoffset, 0,
                                SD_DHCP_OPTION_VENDOR_SPECIFIC,
                                ordered_hashmap_size(client->vendor_options), client->vendor_options);
                if (r < 0)
                        return r;
        }


        return 0;
}

static int client_send_discover(sd_dhcp_client *client) {
        _cleanup_free_ DHCPPacket *discover = NULL;
        size_t optoffset, optlen;
        int r;

        assert(client);
        assert(IN_SET(client->state, DHCP_STATE_INIT, DHCP_STATE_SELECTING));

        r = client_message_init(client, &discover, DHCP_DISCOVER,
                                &optlen, &optoffset);
        if (r < 0)
                return r;

        /* the client may suggest values for the network address
           and lease time in the DHCPDISCOVER message. The client may include
           the ’requested IP address’ option to suggest that a particular IP
           address be assigned, and may include the ’IP address lease time’
           option to suggest the lease time it would like.
         */
        /* RFC7844 section 3:
           SHOULD NOT contain any other option. */
        if (!client->anonymize && client->last_addr != INADDR_ANY) {
                r = dhcp_option_append(&discover->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                       4, &client->last_addr);
                if (r < 0)
                        return r;
        }

        if (client->rapid_commit) {
                r = dhcp_option_append(&discover->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_RAPID_COMMIT, 0, NULL);
                if (r < 0)
                        return r;
        }

        r = client_append_common_discover_request_options(client, discover, &optoffset, optlen);
        if (r < 0)
                return r;

        r = dhcp_option_append(&discover->dhcp, optlen, &optoffset, 0,
                               SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        /* We currently ignore:
           The client SHOULD wait a random time between one and ten seconds to
           desynchronize the use of DHCP at startup.
         */
        r = dhcp_client_send_raw(client, discover, sizeof(DHCPPacket) + optoffset);
        if (r < 0)
                return r;

        log_dhcp_client(client, "DISCOVER");

        return 0;
}

static int client_send_request(sd_dhcp_client *client) {
        _cleanup_free_ DHCPPacket *request = NULL;
        size_t optoffset, optlen;
        int r;

        assert(client);

        r = client_message_init(client, &request, DHCP_REQUEST, &optlen, &optoffset);
        if (r < 0)
                return r;

        switch (client->state) {
        /* See RFC2131 section 4.3.2 (note that there is a typo in the RFC,
           SELECTING should be REQUESTING)
         */

        case DHCP_STATE_REQUESTING:
                /* Client inserts the address of the selected server in ’server
                   identifier’, ’ciaddr’ MUST be zero, ’requested IP address’ MUST be
                   filled in with the yiaddr value from the chosen DHCPOFFER.
                 */

                r = dhcp_option_append(&request->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_SERVER_IDENTIFIER,
                                       4, &client->lease->server_address);
                if (r < 0)
                        return r;

                r = dhcp_option_append(&request->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                       4, &client->lease->address);
                if (r < 0)
                        return r;

                break;

        case DHCP_STATE_INIT_REBOOT:
                /* ’server identifier’ MUST NOT be filled in, ’requested IP address’
                   option MUST be filled in with client’s notion of its previously
                   assigned address. ’ciaddr’ MUST be zero.
                 */
                r = dhcp_option_append(&request->dhcp, optlen, &optoffset, 0,
                                       SD_DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                       4, &client->last_addr);
                if (r < 0)
                        return r;
                break;

        case DHCP_STATE_RENEWING:
                /* ’server identifier’ MUST NOT be filled in, ’requested IP address’
                   option MUST NOT be filled in, ’ciaddr’ MUST be filled in with
                   client’s IP address.
                */

        case DHCP_STATE_REBINDING:
                /* ’server identifier’ MUST NOT be filled in, ’requested IP address’
                   option MUST NOT be filled in, ’ciaddr’ MUST be filled in with
                   client’s IP address.

                   This message MUST be broadcast to the 0xffffffff IP broadcast address.
                 */
                request->dhcp.ciaddr = client->lease->address;

                break;

        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:
        case DHCP_STATE_STOPPED:
        default:
                return -EINVAL;
        }

        r = client_append_common_discover_request_options(client, request, &optoffset, optlen);
        if (r < 0)
                return r;

        r = dhcp_option_append(&request->dhcp, optlen, &optoffset, 0,
                               SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        if (client->state == DHCP_STATE_RENEWING)
                r = dhcp_network_send_udp_socket(client->fd,
                                                 client->lease->server_address,
                                                 DHCP_PORT_SERVER,
                                                 &request->dhcp,
                                                 sizeof(DHCPMessage) + optoffset);
        else
                r = dhcp_client_send_raw(client, request, sizeof(DHCPPacket) + optoffset);
        if (r < 0)
                return r;

        switch (client->state) {

        case DHCP_STATE_REQUESTING:
                log_dhcp_client(client, "REQUEST (requesting)");
                break;

        case DHCP_STATE_INIT_REBOOT:
                log_dhcp_client(client, "REQUEST (init-reboot)");
                break;

        case DHCP_STATE_RENEWING:
                log_dhcp_client(client, "REQUEST (renewing)");
                break;

        case DHCP_STATE_REBINDING:
                log_dhcp_client(client, "REQUEST (rebinding)");
                break;

        default:
                log_dhcp_client(client, "REQUEST (invalid)");
                break;
        }

        return 0;
}

static int client_start(sd_dhcp_client *client);

static int client_timeout_resend(
                sd_event_source *s,
                uint64_t usec,
                void *userdata) {

        sd_dhcp_client *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);
        usec_t time_now, next_timeout;
        int r;

        assert(s);
        assert(client->event);

        r = sd_event_now(client->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                goto error;

        switch (client->state) {

        case DHCP_STATE_RENEWING:
                next_timeout = client_compute_reacquisition_timeout(time_now, client->t2_time);
                break;

        case DHCP_STATE_REBINDING:
                next_timeout = client_compute_reacquisition_timeout(time_now, client->expire_time);
                break;

        case DHCP_STATE_REBOOTING:
                /* start over as we did not receive a timely ack or nak */
                r = client_initialize(client);
                if (r < 0)
                        goto error;

                r = client_start(client);
                if (r < 0)
                        goto error;

                log_dhcp_client(client, "REBOOTED");
                return 0;

        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_BOUND:
                if (client->attempt >= client->max_attempts)
                        goto error;

                client->attempt++;
                next_timeout = client_compute_request_timeout(time_now, client->attempt);
                break;

        case DHCP_STATE_STOPPED:
                r = -EINVAL;
                goto error;

        default:
                assert_not_reached();
        }

        r = event_reset_time(client->event, &client->timeout_resend,
                             CLOCK_BOOTTIME,
                             next_timeout, 10 * USEC_PER_MSEC,
                             client_timeout_resend, client,
                             client->event_priority, "dhcp4-resend-timer", true);
        if (r < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_INIT:
                r = client_send_discover(client);
                if (r >= 0) {
                        client_set_state(client, DHCP_STATE_SELECTING);
                        client->attempt = 0;
                } else if (client->attempt >= client->max_attempts)
                        goto error;
                break;

        case DHCP_STATE_SELECTING:
                r = client_send_discover(client);
                if (r < 0 && client->attempt >= client->max_attempts)
                        goto error;
                break;

        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                r = client_send_request(client);
                if (r < 0 && client->attempt >= client->max_attempts)
                         goto error;

                if (client->state == DHCP_STATE_INIT_REBOOT)
                        client_set_state(client, DHCP_STATE_REBOOTING);
                break;

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:
                break;

        case DHCP_STATE_STOPPED:
        default:
                r = -EINVAL;
                goto error;
        }

        if (client->attempt >= TRANSIENT_FAILURE_ATTEMPTS)
                client_notify(client, SD_DHCP_CLIENT_EVENT_TRANSIENT_FAILURE);

        return 0;

error:
        client_stop(client, r);

        /* Errors were dealt with when stopping the client, don't spill
           errors into the event loop handler */
        return 0;
}

static int client_initialize_io_events(
                sd_dhcp_client *client,
                sd_event_io_handler_t io_callback) {

        int r;

        assert(client);
        assert(client->event);

        r = sd_event_add_io(client->event, &client->receive_message,
                            client->fd, EPOLLIN, io_callback,
                            client);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(client->receive_message,
                                         client->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(client->receive_message, "dhcp4-receive-message");
        if (r < 0)
                goto error;

error:
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_initialize_time_events(sd_dhcp_client *client) {
        usec_t usec = 0;
        int r;

        assert(client);
        assert(client->event);

        (void) event_source_disable(client->timeout_ipv6_only_mode);

        if (client->start_delay > 0) {
                assert_se(sd_event_now(client->event, CLOCK_BOOTTIME, &usec) >= 0);
                usec = usec_add(usec, client->start_delay);
        }

        r = event_reset_time(client->event, &client->timeout_resend,
                             CLOCK_BOOTTIME,
                             usec, 0,
                             client_timeout_resend, client,
                             client->event_priority, "dhcp4-resend-timer", true);
        if (r < 0)
                client_stop(client, r);

        return 0;

}

static int client_initialize_events(sd_dhcp_client *client, sd_event_io_handler_t io_callback) {
        client_initialize_io_events(client, io_callback);
        client_initialize_time_events(client);

        return 0;
}

static int client_start_delayed(sd_dhcp_client *client) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(client->fd < 0, -EBUSY);
        assert_return(client->xid == 0, -EINVAL);
        assert_return(IN_SET(client->state, DHCP_STATE_STOPPED, DHCP_STATE_INIT_REBOOT), -EBUSY);

        client->xid = random_u32();

        r = dhcp_network_bind_raw_socket(client->ifindex, &client->link, client->xid,
                                         &client->hw_addr, &client->bcast_addr,
                                         client->arp_type, client->port,
                                         client->socket_priority_set, client->socket_priority);
        if (r < 0) {
                client_stop(client, r);
                return r;
        }
        client->fd = r;

        client->start_time = now(CLOCK_BOOTTIME);

        if (client->state == DHCP_STATE_STOPPED)
                client->state = DHCP_STATE_INIT;

        return client_initialize_events(client, client_receive_message_raw);
}

static int client_start(sd_dhcp_client *client) {
        client->start_delay = 0;
        return client_start_delayed(client);
}

static int client_timeout_expire(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = userdata;
        DHCP_CLIENT_DONT_DESTROY(client);

        log_dhcp_client(client, "EXPIRED");

        client_notify(client, SD_DHCP_CLIENT_EVENT_EXPIRED);

        /* lease was lost, start over if not freed or stopped in callback */
        if (client->state != DHCP_STATE_STOPPED) {
                client_initialize(client);
                client_start(client);
        }

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        client->receive_message = sd_event_source_disable_unref(client->receive_message);
        client->fd = safe_close(client->fd);

        client_set_state(client, DHCP_STATE_REBINDING);
        client->attempt = 0;

        r = dhcp_network_bind_raw_socket(client->ifindex, &client->link, client->xid,
                                         &client->hw_addr, &client->bcast_addr,
                                         client->arp_type, client->port,
                                         client->socket_priority_set, client->socket_priority);
        if (r < 0) {
                client_stop(client, r);
                return 0;
        }
        client->fd = r;

        return client_initialize_events(client, client_receive_message_raw);
}

static int client_timeout_t1(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = userdata;
        DHCP_CLIENT_DONT_DESTROY(client);

        if (client->lease)
                client_set_state(client, DHCP_STATE_RENEWING);
        else if (client->state != DHCP_STATE_INIT)
                client_set_state(client, DHCP_STATE_INIT_REBOOT);
        client->attempt = 0;

        return client_initialize_time_events(client);
}

static int client_parse_message(
                sd_dhcp_client *client,
                DHCPMessage *message,
                size_t len,
                sd_dhcp_lease **ret) {

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_free_ char *error_message = NULL;
        int r;

        assert(client);
        assert(message);
        assert(ret);

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        if (sd_dhcp_client_id_is_set(&client->client_id)) {
                r = dhcp_lease_set_client_id(lease,
                                             client->client_id.raw,
                                             client->client_id.size);
                if (r < 0)
                        return r;
        }

        r = dhcp_option_parse(message, len, dhcp_lease_parse_options, lease, &error_message);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to parse DHCP options, ignoring: %m");

        switch (client->state) {
        case DHCP_STATE_SELECTING:
                if (r == DHCP_ACK) {
                        if (!client->rapid_commit)
                                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                                             "received unexpected ACK, ignoring.");
                        if (!lease->rapid_commit)
                                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                                             "received rapid ACK without Rapid Commit option, ignoring.");
                } else if (r == DHCP_OFFER) {
                        if (lease->rapid_commit) {
                                /* Some RFC incompliant servers provides an OFFER with a rapid commit option.
                                 * See https://github.com/systemd/systemd/issues/29904.
                                 * Let's support such servers gracefully. */
                                log_dhcp_client(client, "received OFFER with Rapid Commit option, ignoring.");
                                lease->rapid_commit = false;
                        }
                        if (lease->lifetime == 0 && client->fallback_lease_lifetime > 0)
                                lease->lifetime = client->fallback_lease_lifetime;
                } else
                        return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                                     "received unexpected message, ignoring.");

                break;

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                if (r == DHCP_NAK) {
                        if (client->lease && client->lease->server_address != lease->server_address)
                                    return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                                                 "NAK from unexpected server, ignoring: %s",
                                                                 strna(error_message));
                        return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                     "NAK: %s", strna(error_message));
                }
                if (r != DHCP_ACK)
                        return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                                     "received message was not an ACK, ignoring.");
                break;

        default:
                assert_not_reached();
        }

        lease->next_server = message->siaddr;
        lease->address = message->yiaddr;

        if (lease->address == 0 ||
            lease->server_address == 0 ||
            lease->lifetime == 0)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                             "received lease lacks address, server address or lease lifetime, ignoring.");

        r = dhcp_lease_set_default_subnet_mask(lease);
        if (r < 0)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                             "received lease lacks subnet mask, and a fallback one cannot be generated, ignoring.");

        /* RFC 8925 section 3.2
         * If the client did not include the IPv6-Only Preferred option code in the Parameter Request List in
         * the DHCPDISCOVER or DHCPREQUEST message, it MUST ignore the IPv6-Only Preferred option in any
         * messages received from the server. */
        if (lease->ipv6_only_preferred_usec > 0 &&
            !client_request_contains(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED)) {
                log_dhcp_client(client, "Received message with unrequested IPv6-only preferred option, ignoring the option.");
                lease->ipv6_only_preferred_usec = 0;
        }

        *ret = TAKE_PTR(lease);
        return 0;
}

static int client_handle_offer_or_rapid_ack(sd_dhcp_client *client, DHCPMessage *message, size_t len, const triple_timestamp *timestamp) {
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        int r;

        assert(client);
        assert(message);

        r = client_parse_message(client, message, len, &lease);
        if (r < 0)
                return r;

        dhcp_lease_set_timestamp(lease, timestamp);

        dhcp_lease_unref_and_replace(client->lease, lease);

        if (client->lease->rapid_commit) {
                log_dhcp_client(client, "ACK");
                return SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;
        }

        if (client_notify(client, SD_DHCP_CLIENT_EVENT_SELECTING) < 0)
                return -ENOMSG;

        log_dhcp_client(client, "OFFER");
        return 0;
}

static int client_enter_requesting_now(sd_dhcp_client *client) {
        assert(client);

        client_set_state(client, DHCP_STATE_REQUESTING);
        client->attempt = 0;

        return event_reset_time(client->event, &client->timeout_resend,
                                CLOCK_BOOTTIME, 0, 0,
                                client_timeout_resend, client,
                                client->event_priority, "dhcp4-resend-timer",
                                /* force_reset = */ true);
}

static int client_enter_requesting_delayed(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        r = client_enter_requesting_now(client);
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_enter_requesting(sd_dhcp_client *client) {
        assert(client);
        assert(client->lease);

        (void) event_source_disable(client->timeout_resend);

        if (client->lease->ipv6_only_preferred_usec > 0) {
                if (client->ipv6_acquired) {
                        log_dhcp_client(client,
                                        "Received an OFFER with IPv6-only preferred option, and the host already acquired IPv6 connectivity, stopping DHCPv4 client.");
                        return sd_dhcp_client_stop(client);
                }

                log_dhcp_client(client,
                                "Received an OFFER with IPv6-only preferred option, delaying to send REQUEST with %s.",
                                FORMAT_TIMESPAN(client->lease->ipv6_only_preferred_usec, USEC_PER_SEC));

                return event_reset_time_relative(client->event, &client->timeout_ipv6_only_mode,
                                                 CLOCK_BOOTTIME,
                                                 client->lease->ipv6_only_preferred_usec, 0,
                                                 client_enter_requesting_delayed, client,
                                                 client->event_priority, "dhcp4-ipv6-only-mode-timer",
                                                 /* force_reset = */ true);
        }

        return client_enter_requesting_now(client);
}

static int client_handle_forcerenew(sd_dhcp_client *client, DHCPMessage *force, size_t len) {
        int r;

        r = dhcp_option_parse(force, len, NULL, NULL, NULL);
        if (r != DHCP_FORCERENEW)
                return -ENOMSG;

#if 0
        log_dhcp_client(client, "FORCERENEW");
        return 0;
#else
        /* FIXME: Ignore FORCERENEW requests until we implement RFC3118 (Authentication for DHCP
         * Messages) and/or RFC6704 (Forcerenew Nonce Authentication), as unauthenticated FORCERENEW
         * requests causes a security issue (TALOS-2020-1142, CVE-2020-13529). */
        return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(ENOMSG),
                                     "Received FORCERENEW, ignoring.");
#endif
}

static bool lease_equal(const sd_dhcp_lease *a, const sd_dhcp_lease *b) {
        if (a->address != b->address)
                return false;

        if (a->subnet_mask != b->subnet_mask)
                return false;

        if (a->router_size != b->router_size)
                return false;

        for (size_t i = 0; i < a->router_size; i++)
                if (a->router[i].s_addr != b->router[i].s_addr)
                        return false;

        return true;
}

static int client_handle_ack(sd_dhcp_client *client, DHCPMessage *message, size_t len, const triple_timestamp *timestamp) {
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        int r;

        assert(client);
        assert(message);

        r = client_parse_message(client, message, len, &lease);
        if (r < 0)
                return r;

        dhcp_lease_set_timestamp(lease, timestamp);

        if (!client->lease)
                r = SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;
        else if (lease_equal(client->lease, lease))
                r = SD_DHCP_CLIENT_EVENT_RENEW;
        else
                r = SD_DHCP_CLIENT_EVENT_IP_CHANGE;

        dhcp_lease_unref_and_replace(client->lease, lease);

        log_dhcp_client(client, "ACK");
        return r;
}

static int client_set_lease_timeouts(sd_dhcp_client *client) {
        usec_t time_now;
        int r;

        assert(client);
        assert(client->event);
        assert(client->lease);
        assert(client->lease->lifetime > 0);
        assert(triple_timestamp_is_set(&client->lease->timestamp));

        /* don't set timers for infinite leases */
        if (client->lease->lifetime == USEC_INFINITY) {
                (void) event_source_disable(client->timeout_t1);
                (void) event_source_disable(client->timeout_t2);
                (void) event_source_disable(client->timeout_expire);

                return 0;
        }

        r = sd_event_now(client->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;

        /* verify that 0 < t2 < lifetime */
        if (client->lease->t2 == 0 || client->lease->t2 >= client->lease->lifetime)
                client->lease->t2 = T2_DEFAULT(client->lease->lifetime);
        /* verify that 0 < t1 < lifetime */
        if (client->lease->t1 == 0 || client->lease->t1 >= client->lease->t2)
                client->lease->t1 = T1_DEFAULT(client->lease->lifetime);
        /* now, if t1 >= t2, t1 *must* be T1_DEFAULT, since the previous check
         * could not evaluate to false if t1 >= t2; so setting t2 to T2_DEFAULT
         * guarantees t1 < t2. */
        if (client->lease->t1 >= client->lease->t2)
                client->lease->t2 = T2_DEFAULT(client->lease->lifetime);

        assert(client->lease->t1 > 0);
        assert(client->lease->t1 < client->lease->t2);
        assert(client->lease->t2 < client->lease->lifetime);

        r = sd_dhcp_lease_get_lifetime_timestamp(client->lease, CLOCK_BOOTTIME, &client->expire_time);
        if (r < 0)
                return r;
        r = sd_dhcp_lease_get_t1_timestamp(client->lease, CLOCK_BOOTTIME, &client->t1_time);
        if (r < 0)
                return r;
        r = sd_dhcp_lease_get_t2_timestamp(client->lease, CLOCK_BOOTTIME, &client->t2_time);
        if (r < 0)
                return r;

        /* RFC2131 section 4.4.5:
         * Times T1 and T2 SHOULD be chosen with some random "fuzz".
         * Since the RFC doesn't specify here the exact 'fuzz' to use,
         * we use the range from section 4.1: -1 to +1 sec. */
        client->t1_time = usec_sub_signed(client->t1_time, RFC2131_RANDOM_FUZZ);
        client->t2_time = usec_sub_signed(client->t2_time, RFC2131_RANDOM_FUZZ);

        /* after fuzzing, ensure t2 is still >= t1 */
        client->t2_time = MAX(client->t1_time, client->t2_time);

        /* arm lifetime timeout */
        r = event_reset_time(client->event, &client->timeout_expire,
                             CLOCK_BOOTTIME,
                             client->expire_time, 10 * USEC_PER_MSEC,
                             client_timeout_expire, client,
                             client->event_priority, "dhcp4-lifetime", true);
        if (r < 0)
                return r;

        /* don't arm earlier timeouts if this has already expired */
        if (client->expire_time <= time_now)
                return 0;

        log_dhcp_client(client, "lease expires in %s",
                        FORMAT_TIMESPAN(client->expire_time - time_now, USEC_PER_SEC));

        /* arm T2 timeout */
        r = event_reset_time(client->event, &client->timeout_t2,
                             CLOCK_BOOTTIME,
                             client->t2_time, 10 * USEC_PER_MSEC,
                             client_timeout_t2, client,
                             client->event_priority, "dhcp4-t2-timeout", true);
        if (r < 0)
                return r;

        /* don't arm earlier timeout if this has already expired */
        if (client->t2_time <= time_now)
                return 0;

        log_dhcp_client(client, "T2 expires in %s",
                        FORMAT_TIMESPAN(client->t2_time - time_now, USEC_PER_SEC));

        /* arm T1 timeout */
        r = event_reset_time(client->event, &client->timeout_t1,
                             CLOCK_BOOTTIME,
                             client->t1_time, 10 * USEC_PER_MSEC,
                             client_timeout_t1, client,
                             client->event_priority, "dhcp4-t1-timer", true);
        if (r < 0)
                return r;

        if (client->t1_time > time_now)
                log_dhcp_client(client, "T1 expires in %s",
                                FORMAT_TIMESPAN(client->t1_time - time_now, USEC_PER_SEC));

        return 0;
}

static int client_enter_bound_now(sd_dhcp_client *client, int notify_event) {
        int r;

        assert(client);

        if (IN_SET(client->state, DHCP_STATE_REQUESTING, DHCP_STATE_REBOOTING))
                notify_event = SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;

        client_set_state(client, DHCP_STATE_BOUND);
        client->attempt = 0;

        client->last_addr = client->lease->address;

        r = client_set_lease_timeouts(client);
        if (r < 0)
                log_dhcp_client_errno(client, r, "could not set lease timeouts: %m");

        r = dhcp_network_bind_udp_socket(client->ifindex, client->lease->address, client->port, client->ip_service_type);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "could not bind UDP socket: %m");

        client->receive_message = sd_event_source_disable_unref(client->receive_message);
        close_and_replace(client->fd, r);
        client_initialize_io_events(client, client_receive_message_udp);

        client_notify(client, notify_event);

        return 0;
}

static int client_enter_bound_delayed(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        r = client_enter_bound_now(client, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_enter_bound(sd_dhcp_client *client, int notify_event) {
        assert(client);
        assert(client->lease);

        client->start_delay = 0;
        (void) event_source_disable(client->timeout_resend);

        /* RFC 8925 section 3.2
         * If the client is in the INIT-REBOOT state, it SHOULD stop the DHCPv4 configuration process or
         * disable the IPv4 stack completely for V6ONLY_WAIT seconds or until the network attachment event,
         * whichever happens first.
         *
         * In the below, the condition uses REBOOTING, instead of INIT-REBOOT, as the client state has
         * already transitioned from INIT-REBOOT to REBOOTING after sending a DHCPREQUEST message. */
        if (client->state == DHCP_STATE_REBOOTING && client->lease->ipv6_only_preferred_usec > 0) {
                if (client->ipv6_acquired) {
                        log_dhcp_client(client,
                                        "Received an ACK with IPv6-only preferred option, and the host already acquired IPv6 connectivity, stopping DHCPv4 client.");
                        return sd_dhcp_client_stop(client);
                }

                log_dhcp_client(client,
                                "Received an ACK with IPv6-only preferred option, delaying to enter bound state with %s.",
                                FORMAT_TIMESPAN(client->lease->ipv6_only_preferred_usec, USEC_PER_SEC));

                return event_reset_time_relative(client->event, &client->timeout_ipv6_only_mode,
                                                 CLOCK_BOOTTIME,
                                                 client->lease->ipv6_only_preferred_usec, 0,
                                                 client_enter_bound_delayed, client,
                                                 client->event_priority, "dhcp4-ipv6-only-mode",
                                                 /* force_reset = */ true);
        }

        return client_enter_bound_now(client, notify_event);
}

static int client_restart(sd_dhcp_client *client) {
        int r;
        assert(client);

        client_notify(client, SD_DHCP_CLIENT_EVENT_EXPIRED);

        r = client_initialize(client);
        if (r < 0)
                return r;

        r = client_start_delayed(client);
        if (r < 0)
                return r;

        log_dhcp_client(client, "REBOOT in %s", FORMAT_TIMESPAN(client->start_delay, USEC_PER_SEC));

        client->start_delay = CLAMP(client->start_delay * 2,
                                    RESTART_AFTER_NAK_MIN_USEC, RESTART_AFTER_NAK_MAX_USEC);
        return 0;
}

static int client_verify_message_header(sd_dhcp_client *client, DHCPMessage *message, size_t len) {
        const uint8_t *expected_chaddr = NULL;
        uint8_t expected_hlen = 0;

        assert(client);
        assert(message);

        if (len < sizeof(DHCPMessage))
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Too small to be a DHCP message, ignoring.");

        if (be32toh(message->magic) != DHCP_MAGIC_COOKIE)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Not a DHCP message, ignoring.");

        if (message->op != BOOTREPLY)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Not a BOOTREPLY message, ignoring.");

        if (message->htype != client->arp_type)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Packet type does not match client type, ignoring.");

        if (client->arp_type == ARPHRD_ETHER) {
                expected_hlen = ETH_ALEN;
                expected_chaddr = client->hw_addr.bytes;
        }

        if (message->hlen != expected_hlen)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Received packet hlen (%u) does not match expected (%u), ignoring.",
                                             message->hlen, expected_hlen);

        if (memcmp_safe(message->chaddr, expected_chaddr, expected_hlen))
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Received chaddr does not match expected, ignoring.");

        if (client->state != DHCP_STATE_BOUND &&
            be32toh(message->xid) != client->xid)
                /* in BOUND state, we may receive FORCERENEW with xid set by server,
                   so ignore the xid in this case */
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Received xid (%u) does not match expected (%u), ignoring.",
                                             be32toh(message->xid), client->xid);

        return 0;
}

static int client_handle_message(sd_dhcp_client *client, DHCPMessage *message, size_t len, const triple_timestamp *timestamp) {
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        assert(client);
        assert(message);
        assert(timestamp);

        if (client_verify_message_header(client, message, len) < 0)
                return 0;

        switch (client->state) {
        case DHCP_STATE_SELECTING:

                r = client_handle_offer_or_rapid_ack(client, message, len, timestamp);
                if (ERRNO_IS_NEG_RESOURCE(r))
                        return r;
                if (r == -EADDRNOTAVAIL)
                        /* got a rapid NAK, let's restart the client */
                        return client_restart(client);
                if (r < 0)
                        return 0; /* invalid message, let's ignore it */

                if (client->lease->rapid_commit)
                        /* got a successful rapid commit */
                        return client_enter_bound(client, r);

                return client_enter_requesting(client);

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                r = client_handle_ack(client, message, len, timestamp);
                if (ERRNO_IS_NEG_RESOURCE(r))
                        return r;
                if (r == -EADDRNOTAVAIL)
                        /* got a NAK, let's restart the client */
                        return client_restart(client);
                if (r < 0)
                        return 0; /* invalid message, let's ignore it */

                return client_enter_bound(client, r);

        case DHCP_STATE_BOUND:
                r = client_handle_forcerenew(client, message, len);
                if (ERRNO_IS_NEG_RESOURCE(r))
                        return r;
                if (r < 0)
                        return 0; /* invalid message, let's ignore it */

                return client_timeout_t1(NULL, 0, client);

        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
                log_dhcp_client(client, "Unexpectedly receive message without sending any requests, ignoring.");
                return 0;

        default:
                assert_not_reached();
        }

        return 0;
}

static int client_receive_message_udp(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata) {

        sd_dhcp_client *client = ASSERT_PTR(userdata);
        _cleanup_free_ DHCPMessage *message = NULL;
        ssize_t len, buflen;
        /* This needs to be initialized with zero. See #20741. */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL) control = {};
        struct iovec iov;
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        int r;

        assert(s);

        buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp_client_errno(client, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        message = malloc0(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_client_errno(client, len, "Could not receive message from UDP socket, ignoring: %m");
                return 0;
        }

        log_dhcp_client(client, "Received message from UDP socket, processing.");
        r = client_handle_message(client, message, len, TRIPLE_TIMESTAMP_FROM_CMSG(&msg));
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_receive_message_raw(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata) {

        sd_dhcp_client *client = ASSERT_PTR(userdata);
        _cleanup_free_ DHCPPacket *packet = NULL;
        /* This needs to be initialized with zero. See #20741. */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL +
                         CMSG_SPACE(sizeof(struct tpacket_auxdata))) control = {};
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        bool checksum = true;
        ssize_t buflen, len;
        int r;

        assert(s);

        buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp_client_errno(client, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        packet = malloc0(buflen);
        if (!packet)
                return -ENOMEM;

        iov = IOVEC_MAKE(packet, buflen);

        len = recvmsg_safe(fd, &msg, 0);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_client_errno(client, len, "Could not receive message from raw socket, ignoring: %m");
                return 0;
        }

        struct tpacket_auxdata *aux = CMSG_FIND_DATA(&msg, SOL_PACKET, PACKET_AUXDATA, struct tpacket_auxdata);
        if (aux)
                checksum = !(aux->tp_status & TP_STATUS_CSUMNOTREADY);

        if (dhcp_packet_verify_headers(packet, len, checksum, client->port) < 0)
                return 0;

        len -= DHCP_IP_UDP_SIZE;

        log_dhcp_client(client, "Received message from RAW socket, processing.");
        r = client_handle_message(client, &packet->dhcp, len, TRIPLE_TIMESTAMP_FROM_CMSG(&msg));
        if (r < 0)
                client_stop(client, r);

        return 0;
}

int sd_dhcp_client_send_renew(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);
        assert_return(sd_dhcp_client_is_running(client), -ESTALE);
        assert_return(client->fd >= 0, -EINVAL);

        if (client->state != DHCP_STATE_BOUND)
                return 0;

        assert(client->lease);

        client->start_delay = 0;
        client->attempt = 1;
        client_set_state(client, DHCP_STATE_RENEWING);

        return client_initialize_time_events(client);
}

int sd_dhcp_client_is_running(sd_dhcp_client *client) {
        if (!client)
                return 0;

        return client->state != DHCP_STATE_STOPPED;
}

int sd_dhcp_client_start(sd_dhcp_client *client) {
        int r;

        assert_return(client, -EINVAL);

        /* Note, do not reset the flag in client_initialize(), as it is also called on expire. */
        client->ipv6_acquired = false;

        r = client_initialize(client);
        if (r < 0)
                return r;

        /* If no client identifier exists, construct an RFC 4361-compliant one */
        if (!sd_dhcp_client_id_is_set(&client->client_id)) {
                r = sd_dhcp_client_set_iaid_duid_en(client, /* iaid_set = */ false, /* iaid = */ 0);
                if (r < 0)
                        return r;
        }

        /* RFC7844 section 3.3:
           SHOULD perform a complete four-way handshake, starting with a
           DHCPDISCOVER, to obtain a new address lease.  If the client can
           ascertain that this is exactly the same network to which it was
           previously connected, and if the link-layer address did not change,
           the client MAY issue a DHCPREQUEST to try to reclaim the current
           address. */
        if (client->last_addr && !client->anonymize)
                client_set_state(client, DHCP_STATE_INIT_REBOOT);

        r = client_start(client);
        if (r >= 0)
                log_dhcp_client(client, "STARTED on ifindex %i", client->ifindex);

        return r;
}

int sd_dhcp_client_send_release(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);
        assert_return(sd_dhcp_client_is_running(client), -ESTALE);
        assert_return(client->lease, -EUNATCH);

        _cleanup_free_ DHCPPacket *release = NULL;
        size_t optoffset, optlen;
        int r;

        r = client_message_init(client, &release, DHCP_RELEASE, &optlen, &optoffset);
        if (r < 0)
                return r;

        /* Fill up release IP and MAC */
        release->dhcp.ciaddr = client->lease->address;
        memcpy(&release->dhcp.chaddr, client->hw_addr.bytes, client->hw_addr.length);

        r = dhcp_option_append(&release->dhcp, optlen, &optoffset, 0,
                               SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        r = dhcp_network_send_udp_socket(client->fd,
                                         client->lease->server_address,
                                         DHCP_PORT_SERVER,
                                         &release->dhcp,
                                         sizeof(DHCPMessage) + optoffset);
        if (r < 0)
                return r;

        log_dhcp_client(client, "RELEASE");

        return 0;
}

int sd_dhcp_client_send_decline(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);
        assert_return(sd_dhcp_client_is_running(client), -ESTALE);
        assert_return(client->lease, -EUNATCH);

        _cleanup_free_ DHCPPacket *release = NULL;
        size_t optoffset, optlen;
        int r;

        r = client_message_init(client, &release, DHCP_DECLINE, &optlen, &optoffset);
        if (r < 0)
                return r;

        release->dhcp.ciaddr = client->lease->address;
        memcpy(&release->dhcp.chaddr, client->hw_addr.bytes, client->hw_addr.length);

        r = dhcp_option_append(&release->dhcp, optlen, &optoffset, 0,
                               SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        r = dhcp_network_send_udp_socket(client->fd,
                                         client->lease->server_address,
                                         DHCP_PORT_SERVER,
                                         &release->dhcp,
                                         sizeof(DHCPMessage) + optoffset);
        if (r < 0)
                return r;

        log_dhcp_client(client, "DECLINE");

        client_stop(client, SD_DHCP_CLIENT_EVENT_STOP);

        if (client->state != DHCP_STATE_STOPPED) {
                r = sd_dhcp_client_start(client);
                if (r < 0)
                        return r;
        }

        return 0;
}

int sd_dhcp_client_stop(sd_dhcp_client *client) {
        if (!client)
                return 0;

        DHCP_CLIENT_DONT_DESTROY(client);

        client_stop(client, SD_DHCP_CLIENT_EVENT_STOP);

        return 0;
}

int sd_dhcp_client_set_ipv6_connectivity(sd_dhcp_client *client, int have) {
        if (!client)
                return 0;

        /* We have already received a message with IPv6-Only preferred option, and are waiting for IPv6
         * connectivity or timeout, let's stop the client. */
        if (have && sd_event_source_get_enabled(client->timeout_ipv6_only_mode, NULL) > 0)
                return sd_dhcp_client_stop(client);

        /* Otherwise, save that the host already has IPv6 connectivity. */
        client->ipv6_acquired = have;
        return 0;
}

int sd_dhcp_client_interrupt_ipv6_only_mode(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);
        assert_return(sd_dhcp_client_is_running(client), -ESTALE);
        assert_return(client->fd >= 0, -EINVAL);

        if (sd_event_source_get_enabled(client->timeout_ipv6_only_mode, NULL) <= 0)
                return 0;

        client_initialize(client);
        return client_start(client);
}

int sd_dhcp_client_attach_event(sd_dhcp_client *client, sd_event *event, int64_t priority) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!client->event, -EBUSY);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        if (event)
                client->event = sd_event_ref(event);
        else {
                r = sd_event_default(&client->event);
                if (r < 0)
                        return 0;
        }

        client->event_priority = priority;

        return 0;
}

int sd_dhcp_client_detach_event(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->event = sd_event_unref(client->event);

        return 0;
}

sd_event *sd_dhcp_client_get_event(sd_dhcp_client *client) {
        assert_return(client, NULL);

        return client->event;
}

int sd_dhcp_client_attach_device(sd_dhcp_client *client, sd_device *dev) {
        assert_return(client, -EINVAL);

        return device_unref_and_replace(client->dev, dev);
}

static sd_dhcp_client *dhcp_client_free(sd_dhcp_client *client) {
        if (!client)
                return NULL;

        log_dhcp_client(client, "FREE");

        client_initialize(client);

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);
        client->timeout_t1 = sd_event_source_unref(client->timeout_t1);
        client->timeout_t2 = sd_event_source_unref(client->timeout_t2);
        client->timeout_expire = sd_event_source_unref(client->timeout_expire);

        sd_dhcp_client_detach_event(client);

        sd_device_unref(client->dev);

        set_free(client->req_opts);
        free(client->hostname);
        free(client->vendor_class_identifier);
        free(client->mudurl);
        client->user_class = strv_free(client->user_class);
        ordered_hashmap_free(client->extra_options);
        ordered_hashmap_free(client->vendor_options);
        free(client->ifname);
        return mfree(client);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_client, sd_dhcp_client, dhcp_client_free);

int sd_dhcp_client_new(sd_dhcp_client **ret, int anonymize) {
        const uint8_t *opts;
        size_t n_opts;
        int r;

        assert_return(ret, -EINVAL);

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = new(sd_dhcp_client, 1);
        if (!client)
                return -ENOMEM;

        *client = (sd_dhcp_client) {
                .n_ref = 1,
                .state = DHCP_STATE_STOPPED,
                .ifindex = -1,
                .fd = -EBADF,
                .mtu = DHCP_MIN_PACKET_SIZE,
                .port = DHCP_PORT_CLIENT,
                .anonymize = !!anonymize,
                .max_attempts = UINT64_MAX,
                .ip_service_type = -1,
        };
        /* NOTE: this could be moved to a function. */
        if (anonymize) {
                n_opts = ELEMENTSOF(default_req_opts_anonymize);
                opts = default_req_opts_anonymize;
        } else {
                n_opts = ELEMENTSOF(default_req_opts);
                opts = default_req_opts;
        }

        for (size_t i = 0; i < n_opts; i++) {
                r = sd_dhcp_client_set_request_option(client, opts[i]);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(client);

        return 0;
}

static const char* const dhcp_state_table[_DHCP_STATE_MAX] = {
        [DHCP_STATE_STOPPED]              = "stopped",
        [DHCP_STATE_INIT]                 = "initialization",
        [DHCP_STATE_SELECTING]            = "selecting",
        [DHCP_STATE_INIT_REBOOT]          = "init-reboot",
        [DHCP_STATE_REBOOTING]            = "rebooting",
        [DHCP_STATE_REQUESTING]           = "requesting",
        [DHCP_STATE_BOUND]                = "bound",
        [DHCP_STATE_RENEWING]             = "renewing",
        [DHCP_STATE_REBINDING]            = "rebinding",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(dhcp_state, DHCPState);

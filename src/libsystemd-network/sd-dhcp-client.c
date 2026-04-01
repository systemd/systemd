/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <linux/if_infiniband.h>
#include <net/if_arp.h>
#include <stdio.h>

#include "alloc-util.h"
#include "device-util.h"
#include "dhcp-client-internal.h"
#include "dhcp-client-send.h"
#include "dhcp-lease-internal.h"
#include "dns-domain.h"
#include "errno-util.h"
#include "event-util.h"
#include "hostname-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "network-common.h"
#include "random-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"
#include "web-util.h"

#define MAX_MAC_ADDR_LEN CONST_MAX(INFINIBAND_ALEN, ETH_ALEN)

#define RESTART_AFTER_NAK_MIN_USEC (1 * USEC_PER_SEC)
#define RESTART_AFTER_NAK_MAX_USEC (30 * USEC_PER_MINUTE)

#define MAX_REQUEST_ATTEMPTS_ON_REBOOTING 2
#define MAX_REQUEST_ATTEMPTS 5
#define TRANSIENT_FAILURE_ATTEMPTS 3 /* Arbitrary limit: how many attempts are considered enough to report
                                      * transient failure. */

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
        SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,     /* 43 */
        SD_DHCP_OPTION_NETBIOS_NAME_SERVER,             /* 44 */
        SD_DHCP_OPTION_NETBIOS_NODE_TYPE,               /* 46 */
        SD_DHCP_OPTION_NETBIOS_SCOPE,                   /* 47 */
        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,          /* 121 */
        SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE,  /* 249 */
        SD_DHCP_OPTION_PRIVATE_PROXY_AUTODISCOVERY,     /* 252 */
};

static void client_stop(sd_dhcp_client *client, int error);
static int client_restart(sd_dhcp_client *client);

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
                ;
        }

        return set_ensure_put(&client->req_opts, NULL, UINT8_TO_PTR(option));
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

        static const uint8_t default_eth_hwaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        switch (arp_type) {
        case ARPHRD_ETHER:
                assert_return(addr_len == ETH_ALEN, -EINVAL);
                assert_return(hw_addr, -EINVAL);
                break;

        case ARPHRD_INFINIBAND:
                assert_return(addr_len == INFINIBAND_ALEN, -EINVAL);
                assert_return(hw_addr, -EINVAL);
                break;

        case ARPHRD_RAWIP:
        case ARPHRD_NONE:
                /* Linux cellular modem drivers (e.g. qmi_wwan) present a network interface of type
                 * ARPHRD_RAWIP(519) or ARPHRD_NONE(65534) when in point-to-point mode, but these are not
                 * valid DHCP hardware-type values.
                 *
                 * Apparently, it's best to just pretend that these are ethernet devices. Other approaches
                 * have been tried, but resulted in incompatibilities with some server software. See
                 * https://lore.kernel.org/netdev/cover.1228948072.git.inaky@linux.intel.com/ */
                arp_type = ARPHRD_ETHER;
                if (addr_len == 0) {
                        /* If the specified hardware address length is 0, always use the default ones. */
                        addr_len = ETH_ALEN;
                        hw_addr = default_eth_hwaddr;
                        bcast_addr = NULL;
                } else if (addr_len == ETH_ALEN) {
                        /* If the specified hardware address length is ETH_ALEN, use the default ones when
                         * unspecified. */
                        if (!hw_addr)
                                hw_addr = default_eth_hwaddr;
                } else {
                        /* Otherwise, user must specify valid addresses. */
                        assert_return(hw_addr, -EINVAL);
                        assert_return(bcast_addr, -EINVAL);
                }
                break;

        default:
                return -EINVAL;
        }

        client->arp_type = arp_type;
        hw_addr_set(&client->hw_addr, hw_addr, addr_len);
        hw_addr_set(&client->bcast_addr, bcast_addr, bcast_addr ? addr_len : 0);
        return hw_addr_ensure_broadcast(&client->bcast_addr, arp_type);
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
                                             /* legacy_unstable_byteorder= */ true,
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

int dhcp_client_set_user_class(sd_dhcp_client *client, const struct iovec_wrapper *user_class) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        if (iovw_isempty(user_class)) {
                iovw_done_free(&client->user_class);
                return 0;
        }

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        FOREACH_ARRAY(iovec, user_class->iovec, user_class->count) {
                if (iovec->iov_len == 0 || iovec->iov_len > UINT8_MAX)
                        return -EINVAL;

                r = iovw_extend_iov(&iovw, iovec);
                if (r < 0)
                        return r;
        }

        iovw_done_free(&client->user_class);
        client->user_class = TAKE_STRUCT(iovw);
        return 0;
}

int sd_dhcp_client_set_client_port(
                sd_dhcp_client *client,
                uint16_t port) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->port = port;

        return 0;
}

int sd_dhcp_client_set_port(
                sd_dhcp_client *client,
                uint16_t port) {

        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->server_port = port;

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

        client->max_discover_attempts = max_attempts;

        return 0;
}

int dhcp_client_set_extra_options(sd_dhcp_client *client, TLV *options) {
        assert(client);
        assert(!sd_dhcp_client_is_running(client));

        return unref_and_replace_new_ref(client->extra_options, options, tlv_ref, tlv_unref);
}

int dhcp_client_set_vendor_options(sd_dhcp_client *client, TLV *options) {
        assert(client);
        assert(!sd_dhcp_client_is_running(client));

        return unref_and_replace_new_ref(client->vendor_options, options, tlv_ref, tlv_unref);
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

int sd_dhcp_client_set_bootp(sd_dhcp_client *client, int bootp) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp_client_is_running(client), -EBUSY);

        client->bootp = bootp;

        return 0;
}

int sd_dhcp_client_set_send_release(sd_dhcp_client *client, int enable) {
        assert_return(client, -EINVAL);

        client->send_release = enable;

        return 0;
}

static void client_set_state(sd_dhcp_client *client, DHCPState state) {
        assert(client);

        if (client->state == state)
                return;

        log_dhcp_client(client, "State changed: %s -> %s",
                        dhcp_state_to_string(client->state), dhcp_state_to_string(state));

        client->state = state;

        switch (state) {
        case DHCP_STATE_STOPPED:
        case DHCP_STATE_BOUND:
                /* In these cases, the next DHCPDISCOVER message will be sent in a new cycle.
                 * Hence, clear the counter for DHCPDISCOVER messages. */
                client->discover_attempt = 0;
                break;

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                /* In these cases, the next DHCPREQUEST message will be the first message in this new state.
                 * Hence, clear the counter for DHCPREQUEST messages. */
                client->request_attempt = 0;
                break;

        default:
                /* otherwise, do not reset the counters. */
                ;
        }

        // FIXME: If the state callback changes the state, we may not safely free/stop the client, and the
        // state machine diagram becomes needlessly complicated. Introduce a guard to avoid that. */
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

static void client_disable_event_sources(sd_dhcp_client *client) {
        assert(client);

        client->receive_message = sd_event_source_disable_unref(client->receive_message);

        (void) event_source_disable(client->timeout_resend);
        (void) event_source_disable(client->timeout_t1);
        (void) event_source_disable(client->timeout_t2);
        (void) event_source_disable(client->timeout_expire);
}

static void client_initialize(sd_dhcp_client *client) {
        assert(client);

        client_disable_event_sources(client);

        client_set_state(client, DHCP_STATE_STOPPED);
        client->xid = 0;

        client->lease = sd_dhcp_lease_unref(client->lease);
}

static void client_stop(sd_dhcp_client *client, int error) {
        assert(client);
        DHCP_CLIENT_DONT_DESTROY(client);

        if (sd_dhcp_client_is_running(client)) {
                if (error < 0)
                        log_dhcp_client_errno(client, error, "STOPPED: %m");
                else if (error == SD_DHCP_CLIENT_EVENT_STOP)
                        log_dhcp_client(client, "STOPPED");
                else
                        log_dhcp_client(client, "STOPPED: Unknown event");

                client_notify(client, error);
        } else if (error < 0) {
                log_dhcp_client_errno(client, error, "FAILED: %m");
                client_notify(client, error);
        }

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
static usec_t client_compute_request_timeout(uint64_t attempt) {
        usec_t timeout = (UINT64_C(1) << MIN(attempt + 1, UINT64_C(6))) * USEC_PER_SEC;
        return usec_sub_signed(timeout, RFC2131_RANDOM_FUZZ);
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
static usec_t client_compute_reacquisition_timeout(usec_t now_usec, usec_t expire) {
        return MAX(usec_sub_unsigned(expire, now_usec) / 2, 60 * USEC_PER_SEC);
}

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

        case DHCP_STATE_INIT:
                client_set_state(client, DHCP_STATE_SELECTING);
                _fallthrough_;

        case DHCP_STATE_SELECTING:
                if (client->discover_attempt >= client->max_discover_attempts) {
                        r = -ETIMEDOUT;
                        goto error;
                }

                client->discover_attempt++;
                next_timeout = client_compute_request_timeout(client->discover_attempt);
                break;

        case DHCP_STATE_INIT_REBOOT:
                client_set_state(client, DHCP_STATE_REBOOTING);
                _fallthrough_;

        case DHCP_STATE_REBOOTING:
                /* There is nothing explicitly mentioned about retry interval on reboot. Let's reuse the same
                 * algorithm as in the requesting state below, but slightly speed up for faster reboot. */

                if (client->request_attempt >= MAX_REQUEST_ATTEMPTS_ON_REBOOTING)
                        goto restart;

                client->request_attempt++;
                next_timeout = client_compute_request_timeout(client->request_attempt) / 4;
                break;

        case DHCP_STATE_REQUESTING:
                if (client->request_attempt >= MAX_REQUEST_ATTEMPTS)
                        goto restart;

                client->request_attempt++;
                next_timeout = client_compute_request_timeout(client->request_attempt);
                break;

        default:
                assert_not_reached();
        }

        r = event_reset_time_relative(
                        client->event, &client->timeout_resend,
                        CLOCK_BOOTTIME, next_timeout, 10 * USEC_PER_MSEC,
                        client_timeout_resend, client,
                        client->event_priority, "dhcp4-resend-timer", true);
        if (r < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_SELECTING:
                r = dhcp_client_send_message(client, DHCP_DISCOVER);
                if (r < 0 && client->discover_attempt >= client->max_discover_attempts)
                        goto error;

                if (client->discover_attempt >= TRANSIENT_FAILURE_ATTEMPTS)
                        client_notify(client, SD_DHCP_CLIENT_EVENT_TRANSIENT_FAILURE);
                break;

        case DHCP_STATE_REBOOTING:
                r = dhcp_client_send_message(client, DHCP_REQUEST);
                if (r < 0 && client->request_attempt >= MAX_REQUEST_ATTEMPTS_ON_REBOOTING)
                        goto restart;
                break;

        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                r = dhcp_client_send_message(client, DHCP_REQUEST);
                if (r < 0 && client->request_attempt >= MAX_REQUEST_ATTEMPTS)
                        goto restart;
                break;

        default:
                assert_not_reached();
        }

        return 0;

restart:
        /* Avoid REQUEST infinite loop. Per RFC 2131 section 3.1.5: if the client receives
           neither a DHCPACK or a DHCPNAK message after employing the retransmission algorithm,
           the client reverts to INIT state and restarts the initialization process */
        log_dhcp_client(client, "Max REQUEST attempts reached. Restarting...");
        r = client_restart(client);
        if (r >= 0)
                return 0;

error:
        client_stop(client, r);

        /* Errors were dealt with when stopping the client, don't spill
           errors into the event loop handler */
        return 0;
}

static int client_initialize_time_events(sd_dhcp_client *client) {
        assert(client);
        assert(client->event);

        return event_reset_time_relative(
                        client->event,
                        &client->timeout_resend,
                        CLOCK_BOOTTIME,
                        client->start_delay,
                        /* accuracy= */ 0,
                        client_timeout_resend,
                        client,
                        client->event_priority,
                        "dhcp4-resend-timer",
                        /* force_reset= */ true);
}

static int client_start_delayed(sd_dhcp_client *client) {
        assert(client);
        DHCP_CLIENT_DONT_DESTROY(client);

        client_disable_event_sources(client);
        client->lease = sd_dhcp_lease_unref(client->lease);

        client->xid = random_u32();
        client->start_time = now(CLOCK_BOOTTIME);

        if (client->state != DHCP_STATE_INIT_REBOOT)
                client_set_state(client, DHCP_STATE_INIT);

        return client_initialize_time_events(client);
}

static int client_start(sd_dhcp_client *client) {
        assert(client);

        client->start_delay = 0;
        return client_start_delayed(client);
}

static int client_restart(sd_dhcp_client *client) {
        assert(client);
        DHCP_CLIENT_DONT_DESTROY(client);

        /* This is called when we receive a DHCPNAK or could not receive any replies. */

        /* First, if we have a bound lease, then notify it is expired. */
        if (IN_SET(client->state, DHCP_STATE_BOUND, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING)) {
                client_notify(client, SD_DHCP_CLIENT_EVENT_EXPIRED);

                if (client->state == DHCP_STATE_STOPPED)
                        return 0; /* The notify callback stopped the client. */
        }

        /* On reboot, DHCPNAK or no reply suggests that the network is changed or the address is already
         * used by another host. Let's restart the client immediately without any delay to speed up the
         * reboot process. */
        if (client->state == DHCP_STATE_REBOOTING)
                return client_start(client);

        /* Otherwise, we should restart the client with a short delay. */
        client->start_delay = CLAMP(client->start_delay * 2,
                                    RESTART_AFTER_NAK_MIN_USEC, RESTART_AFTER_NAK_MAX_USEC);

        log_dhcp_client(client, "REBOOT in %s", FORMAT_TIMESPAN(client->start_delay, USEC_PER_SEC));
        return client_start_delayed(client);
}

static int client_timeout_expire(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = userdata;
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        log_dhcp_client(client, "EXPIRED");

        client_notify(client, SD_DHCP_CLIENT_EVENT_EXPIRED);

        if (client->state == DHCP_STATE_STOPPED)
                return 0; /* The notify callback stopped the client. */

        r = client_start(client);
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);

        /* Explicitly close the unicast socket opened during renewing. On success path, the socket will be
         * closed anyway on sending broadcast DHCPREQUEST, but let's explicitly close it here for failure
         * path to ignore all unicast replies from now on. */
        client->receive_message = sd_event_source_disable_unref(client->receive_message);

        client_set_state(client, DHCP_STATE_REBINDING);

        return client_timeout_resend(s, usec, userdata);
}

static int client_timeout_t1(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);

        client_set_state(client, DHCP_STATE_RENEWING);

        return client_timeout_resend(s, usec, userdata);
}

static int client_enter_requesting(sd_dhcp_client *client) {
        assert(client);
        assert(client->lease);

        client_disable_event_sources(client);

        client_set_state(client, DHCP_STATE_REQUESTING);

        if (sd_dhcp_client_is_waiting_for_ipv6_connectivity(client)) {
                if (client->ipv6_acquired) {
                        log_dhcp_client(client,
                                        "Received an OFFER with IPv6-only preferred option, and the host already acquired IPv6 connectivity, stopping DHCPv4 client.");
                        return sd_dhcp_client_stop(client);
                }

                log_dhcp_client(client,
                                "Received an OFFER with IPv6-only preferred option, delaying to send REQUEST with %s.",
                                FORMAT_TIMESPAN(client->lease->ipv6_only_preferred_usec, USEC_PER_SEC));
        }

        return event_reset_time_relative(
                        client->event,
                        &client->timeout_resend,
                        CLOCK_BOOTTIME,
                        client->lease->ipv6_only_preferred_usec,
                        /* accuracy= */ 0,
                        client_timeout_resend,
                        client,
                        client->event_priority,
                        "dhcp4-resend-timer",
                        /* force_reset= */ true);
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

static int client_enter_bound(sd_dhcp_client *client, sd_dhcp_lease *lease) {
        int r;

        assert(client);
        assert(lease);

        int notify_event;
        switch (client->state) {
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_REBOOTING:
                notify_event = SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;
                break;
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                assert(client->lease);
                if (lease_equal(client->lease, lease))
                        notify_event = SD_DHCP_CLIENT_EVENT_RENEW;
                else
                        notify_event = SD_DHCP_CLIENT_EVENT_IP_CHANGE;
                break;
        default:
                assert_not_reached();
        }

        unref_and_replace_new_ref(client->lease, lease, sd_dhcp_lease_ref, sd_dhcp_lease_unref);

        client_disable_event_sources(client);

        client->start_delay = 0;

        client_set_state(client, DHCP_STATE_BOUND);

        client->last_addr = client->lease->address;

        r = client_set_lease_timeouts(client);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to set lease timeouts: %m");

        client_notify(client, notify_event);
        return 0;
}

static int client_handle_message(sd_dhcp_client *client, const struct iovec *iov, const triple_timestamp *timestamp) {
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        assert(client);
        assert(iov);

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        r = dhcp_client_parse_message(client, iov, &lease);
        if (ERRNO_IS_NEG_RESOURCE(r))
                return r;
        if (r < 0)
                return 0; /* Ignore all parse errors. */

        switch (r) {

        case DHCP_OFFER:
                dhcp_lease_set_timestamp(lease, timestamp);

                unref_and_replace_new_ref(client->lease, lease, sd_dhcp_lease_ref, sd_dhcp_lease_unref);
                if (client_notify(client, SD_DHCP_CLIENT_EVENT_SELECTING) < 0)
                        return 0; /* networkd refused the server, ignoring the message. */
                if (client->state == DHCP_STATE_STOPPED)
                        return 0; /* The notify callback stopped the client. */
                return client_enter_requesting(client);

        case DHCP_ACK:
                dhcp_lease_set_timestamp(lease, timestamp);
                return client_enter_bound(client, lease);

        case DHCP_NAK:
                return client_restart(client);

        default:
                assert_not_reached();
        }
}

static int client_receive_message(sd_dhcp_client *client, int fd, bool raw) {
        int r;

        assert(client);
        assert(fd >= 0);

        ssize_t buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp_client_errno(client, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        _cleanup_free_ void *buf = malloc0(buflen);
        if (!buf)
                return -ENOMEM;

        /* This needs to be initialized with zero. See #20741.
         * The issue is fixed on glibc-2.35 (8fba672472ae0055387e9315fc2eddfa6775ca79). */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL +
                         CMSG_SPACE(sizeof(struct tpacket_auxdata))) control = {};
        struct msghdr msg = {
                .msg_iov = &IOVEC_MAKE(buf, buflen),
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        ssize_t len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_client_errno(client, len,
                                      "Could not receive message from %s socket, ignoring: %m",
                                      raw ? "RAW" : "UDP");
                return 0;
        }

        struct iovec payload = IOVEC_MAKE(buf, len);
        if (raw) {
                struct tpacket_auxdata *aux = CMSG_FIND_DATA(&msg, SOL_PACKET, PACKET_AUXDATA, struct tpacket_auxdata);
                bool checksum = !aux || !(aux->tp_status & TP_STATUS_CSUMNOTREADY);

                if (udp_packet_verify(&payload, client->port, checksum, &payload) < 0)
                        return 0;
        }

        log_dhcp_client(client, "Received message from %s socket, processing.", raw ? "RAW" : "UDP");
        r = client_handle_message(client, &payload, TRIPLE_TIMESTAMP_FROM_CMSG(&msg));
        if (r < 0)
                client_stop(client, r);

        return 0;
}

int client_receive_message_udp(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        return client_receive_message(userdata, fd, /* raw= */ false);
}

int client_receive_message_raw(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        return client_receive_message(userdata, fd, /* raw= */ true);
}

int sd_dhcp_client_send_renew(sd_dhcp_client *client) {
        if (!sd_dhcp_client_is_running(client) || client->state != DHCP_STATE_BOUND || client->bootp)
                return 0; /* do nothing */

        client_set_state(client, DHCP_STATE_RENEWING);

        client->start_delay = 0;
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
        assert_return(client->event, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(!hw_addr_is_null(&client->bcast_addr), -EINVAL);

        /* If no client identifier exists, construct an RFC 4361-compliant one */
        if (!sd_dhcp_client_id_is_set(&client->client_id)) {
                r = sd_dhcp_client_set_iaid_duid_en(client, /* iaid_set= */ false, /* iaid= */ 0);
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
        if (client->last_addr && !client->anonymize && !client->bootp)
                client_set_state(client, DHCP_STATE_INIT_REBOOT);

        /* We currently ignore:
         * The client SHOULD wait a random time between one and ten seconds to desynchronize the use of
         * DHCP at startup. */
        r = client_start(client);
        if (r >= 0)
                log_dhcp_client(client, "STARTED on ifindex %i", client->ifindex);

        return r;
}

int sd_dhcp_client_send_decline(sd_dhcp_client *client) {
        int r;

        if (!sd_dhcp_client_is_running(client) || !client->lease || client->bootp)
                return 0; /* there is nothing to decline */

        r = dhcp_client_send_message(client, DHCP_DECLINE);
        if (r < 0)
                return r;

        /* This function is mostly called when the acquired address conflicts with another host.
         * Restarting the daemon to acquire another address. */
        return client_restart(client);
}

static int client_send_release(sd_dhcp_client *client) {
        assert(client);

        if (!client->send_release)
                return 0;

        if (!sd_dhcp_client_is_running(client) || !client->lease || client->bootp)
                return 0; /* there is nothing to release */

        return dhcp_client_send_message(client, DHCP_RELEASE);
}

int sd_dhcp_client_stop(sd_dhcp_client *client) {
        if (!client)
                return 0;

        DHCP_CLIENT_DONT_DESTROY(client);

        (void) client_send_release(client);

        client_stop(client, SD_DHCP_CLIENT_EVENT_STOP);
        return 0;
}

int sd_dhcp_client_is_waiting_for_ipv6_connectivity(sd_dhcp_client *client) {
        /* Note that we intentionally do not implement the following behavior:
         *
         * RFC 8925, section 3.2:
         *   If the client is in the INIT-REBOOT state, it SHOULD stop the DHCPv4 configuration process or
         *   disable the IPv4 stack completely for V6ONLY_WAIT seconds or until the next network attachment
         *   event, whichever occurs first.
         *
         * Delaying the application of an acquired IPv4 address after DHCPACK introduces several issues:
         *
         * - If T1 is reached before the address is assigned to the interface, the client cannot send a
         *   unicast DHCPREQUEST during RENEWING.
         *
         * - If the client is stopped before the address is configured, it cannot send a DHCPRELEASE message,
         *   which also requires a valid source address.
         *
         * While these issues could be worked around, doing so would significantly complicate the
         * implementation and violate assumptions in the DHCP state machine as defined in RFC 2131.
         *
         * Instead, we only honor the IPv6-Only Preferred delay (Option 108) in the REQUESTING state, i.e.
         * before any DHCPREQUEST has been sent. */

        return
                client &&
                client->state == DHCP_STATE_REQUESTING &&
                client->request_attempt == 0 &&
                client->lease &&
                client->lease->ipv6_only_preferred_usec > 0;
}

int sd_dhcp_client_set_ipv6_connectivity(sd_dhcp_client *client, int have) {
        if (!client)
                return 0;

        client->ipv6_acquired = have;

        if (have && sd_dhcp_client_is_waiting_for_ipv6_connectivity(client)) {
                log_dhcp_client(client,
                                "Acquired IPv6 connectivity before sending REQUEST, stopping DHCPv4 client.");
                return sd_dhcp_client_stop(client);
        }

        return 0;
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

sd_event* sd_dhcp_client_get_event(sd_dhcp_client *client) {
        assert_return(client, NULL);

        return client->event;
}

int sd_dhcp_client_attach_device(sd_dhcp_client *client, sd_device *dev) {
        assert_return(client, -EINVAL);

        return device_unref_and_replace_new_ref(client->dev, dev);
}

static sd_dhcp_client* dhcp_client_free(sd_dhcp_client *client) {
        if (!client)
                return NULL;

        log_dhcp_client(client, "FREE");

        client_initialize(client);

        sd_event_source_unref(client->timeout_resend);
        sd_event_source_unref(client->timeout_t1);
        sd_event_source_unref(client->timeout_t2);
        sd_event_source_unref(client->timeout_expire);

        sd_dhcp_client_detach_event(client);

        sd_device_unref(client->dev);

        set_free(client->req_opts);
        free(client->hostname);
        free(client->vendor_class_identifier);
        free(client->mudurl);
        iovw_done_free(&client->user_class);
        tlv_unref(client->extra_options);
        tlv_unref(client->vendor_options);
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
                .mtu = DHCP_MIN_PACKET_SIZE,
                .port = DHCP_PORT_CLIENT,
                .server_port = DHCP_PORT_SERVER,
                .anonymize = !!anonymize,
                .max_discover_attempts = UINT64_MAX,
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

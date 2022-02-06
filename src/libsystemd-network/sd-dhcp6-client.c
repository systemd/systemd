/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <linux/if_infiniband.h>

#include "sd-dhcp6-client.h"

#include "alloc-util.h"
#include "dhcp-identifier.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "dns-domain.h"
#include "event-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"
#include "util.h"
#include "web-util.h"

static const uint16_t default_req_opts[] = {
        SD_DHCP6_OPTION_DNS_SERVERS,
        SD_DHCP6_OPTION_DOMAIN_LIST,
        SD_DHCP6_OPTION_NTP_SERVER,
        SD_DHCP6_OPTION_SNTP_SERVERS,
};

const char * dhcp6_message_type_table[_DHCP6_MESSAGE_TYPE_MAX] = {
        [DHCP6_MESSAGE_SOLICIT]             = "Solicit",
        [DHCP6_MESSAGE_ADVERTISE]           = "Advertise",
        [DHCP6_MESSAGE_REQUEST]             = "Request",
        [DHCP6_MESSAGE_CONFIRM]             = "Confirm",
        [DHCP6_MESSAGE_RENEW]               = "Renew",
        [DHCP6_MESSAGE_REBIND]              = "Rebind",
        [DHCP6_MESSAGE_REPLY]               = "Reply",
        [DHCP6_MESSAGE_RELEASE]             = "Release",
        [DHCP6_MESSAGE_DECLINE]             = "Decline",
        [DHCP6_MESSAGE_RECONFIGURE]         = "Reconfigure",
        [DHCP6_MESSAGE_INFORMATION_REQUEST] = "Information Request",
        [DHCP6_MESSAGE_RELAY_FORWARD]       = "Relay Forward",
        [DHCP6_MESSAGE_RELAY_REPLY]         = "Relay Reply",
        [DHCP6_MESSAGE_LEASE_QUERY]         = "Lease Query",
        [DHCP6_MESSAGE_LEASE_QUERY_REPLY]   = "Lease Query Reply",
        [DHCP6_MESSAGE_LEASE_QUERY_DONE]    = "Lease Query Done",
        [DHCP6_MESSAGE_LEASE_QUERY_DATA]    = "Lease Query Data",
        [DHCP6_MESSAGE_RECONFIGURE_REQUEST] = "Reconfigure Request",
        [DHCP6_MESSAGE_RECONFIGURE_REPLY]   = "Reconfigure Reply",
        [DHCP6_MESSAGE_DHCPV4_QUERY]        = "DHCPv4 Query",
        [DHCP6_MESSAGE_DHCPV4_RESPONSE]     = "DHCPv4 Response",
        [DHCP6_MESSAGE_ACTIVE_LEASE_QUERY]  = "Active Lease Query",
        [DHCP6_MESSAGE_START_TLS]           = "Start TLS",
        [DHCP6_MESSAGE_BINDING_UPDATE]      = "Binding Update",
        [DHCP6_MESSAGE_BINDING_REPLY]       = "Binding Reply",
        [DHCP6_MESSAGE_POOL_REQUEST]        = "Pool Request",
        [DHCP6_MESSAGE_POOL_RESPONSE]       = "Pool Response",
        [DHCP6_MESSAGE_UPDATE_REQUEST]      = "Update Request",
        [DHCP6_MESSAGE_UPDATE_REQUEST_ALL]  = "Update Request All",
        [DHCP6_MESSAGE_UPDATE_DONE]         = "Update Done",
        [DHCP6_MESSAGE_CONNECT]             = "Connect",
        [DHCP6_MESSAGE_CONNECT_REPLY]       = "Connect Reply",
        [DHCP6_MESSAGE_DISCONNECT]          = "Disconnect",
        [DHCP6_MESSAGE_STATE]               = "State",
        [DHCP6_MESSAGE_CONTACT]             = "Contact",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_type, int);

const char * dhcp6_message_status_table[_DHCP6_STATUS_MAX] = {
        [DHCP6_STATUS_SUCCESS]                      = "Success",
        [DHCP6_STATUS_UNSPEC_FAIL]                  = "Unspecified failure",
        [DHCP6_STATUS_NO_ADDRS_AVAIL]               = "No addresses available",
        [DHCP6_STATUS_NO_BINDING]                   = "Binding unavailable",
        [DHCP6_STATUS_NOT_ON_LINK]                  = "Not on link",
        [DHCP6_STATUS_USE_MULTICAST]                = "Use multicast",
        [DHCP6_STATUS_NO_PREFIX_AVAIL]              = "No prefix available",
        [DHCP6_STATUS_UNKNOWN_QUERY_TYPE]           = "Unknown query type",
        [DHCP6_STATUS_MALFORMED_QUERY]              = "Malformed query",
        [DHCP6_STATUS_NOT_CONFIGURED]               = "Not configured",
        [DHCP6_STATUS_NOT_ALLOWED]                  = "Not allowed",
        [DHCP6_STATUS_QUERY_TERMINATED]             = "Query terminated",
        [DHCP6_STATUS_DATA_MISSING]                 = "Data missing",
        [DHCP6_STATUS_CATCHUP_COMPLETE]             = "Catch up complete",
        [DHCP6_STATUS_NOT_SUPPORTED]                = "Not supported",
        [DHCP6_STATUS_TLS_CONNECTION_REFUSED]       = "TLS connection refused",
        [DHCP6_STATUS_ADDRESS_IN_USE]               = "Address in use",
        [DHCP6_STATUS_CONFIGURATION_CONFLICT]       = "Configuration conflict",
        [DHCP6_STATUS_MISSING_BINDING_INFORMATION]  = "Missing binding information",
        [DHCP6_STATUS_OUTDATED_BINDING_INFORMATION] = "Outdated binding information",
        [DHCP6_STATUS_SERVER_SHUTTING_DOWN]         = "Server shutting down",
        [DHCP6_STATUS_DNS_UPDATE_NOT_SUPPORTED]     = "DNS update not supported",
        [DHCP6_STATUS_EXCESSIVE_TIME_SKEW]          = "Excessive time skew",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_status, int);

#define DHCP6_CLIENT_DONT_DESTROY(client) \
        _cleanup_(sd_dhcp6_client_unrefp) _unused_ sd_dhcp6_client *_dont_destroy_##client = sd_dhcp6_client_ref(client)

static int client_set_state(sd_dhcp6_client *client, DHCP6State state);

int sd_dhcp6_client_set_callback(
                sd_dhcp6_client *client,
                sd_dhcp6_client_callback_t cb,
                void *userdata) {

        assert_return(client, -EINVAL);

        client->callback = cb;
        client->userdata = userdata;

        return 0;
}

int sd_dhcp6_client_set_ifindex(sd_dhcp6_client *client, int ifindex) {
        assert_return(client, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->ifindex = ifindex;
        return 0;
}

int sd_dhcp6_client_set_ifname(sd_dhcp6_client *client, const char *ifname) {
        assert_return(client, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&client->ifname, ifname);
}

int sd_dhcp6_client_get_ifname(sd_dhcp6_client *client, const char **ret) {
        int r;

        assert_return(client, -EINVAL);

        r = get_ifname(client->ifindex, &client->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = client->ifname;

        return 0;
}

int sd_dhcp6_client_set_local_address(
                sd_dhcp6_client *client,
                const struct in6_addr *local_address) {

        assert_return(client, -EINVAL);
        assert_return(local_address, -EINVAL);
        assert_return(in6_addr_is_link_local(local_address) > 0, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->local_address = *local_address;

        return 0;
}

int sd_dhcp6_client_set_mac(
                sd_dhcp6_client *client,
                const uint8_t *addr, size_t addr_len,
                uint16_t arp_type) {

        assert_return(client, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(addr_len <= HW_ADDR_MAX_SIZE, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (arp_type == ARPHRD_ETHER)
                assert_return(addr_len == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(addr_len == INFINIBAND_ALEN, -EINVAL);
        else {
                client->arp_type = ARPHRD_NONE;
                client->mac_addr_len = 0;
                return 0;
        }

        memcpy(&client->mac_addr, addr, addr_len);
        client->mac_addr_len = addr_len;
        client->arp_type = arp_type;

        return 0;
}

int sd_dhcp6_client_set_prefix_delegation_hint(
                sd_dhcp6_client *client,
                uint8_t prefixlen,
                const struct in6_addr *pd_prefix) {

        _cleanup_free_ DHCP6Address *prefix = NULL;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (!pd_prefix) {
                /* clear previous assignments. */
                dhcp6_ia_clear_addresses(&client->ia_pd);
                return 0;
        }

        assert_return(prefixlen > 0 && prefixlen <= 128, -EINVAL);

        prefix = new(DHCP6Address, 1);
        if (!prefix)
                return -ENOMEM;

        *prefix = (DHCP6Address) {
                .iapdprefix.address = *pd_prefix,
                .iapdprefix.prefixlen = prefixlen,
        };

        LIST_PREPEND(addresses, client->ia_pd.addresses, TAKE_PTR(prefix));
        return 1;
}

int sd_dhcp6_client_add_vendor_option(sd_dhcp6_client *client, sd_dhcp6_option *v) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(v, -EINVAL);

        r = ordered_hashmap_ensure_put(&client->vendor_options, &dhcp6_option_hash_ops, v, v);
        if (r < 0)
                return r;

        sd_dhcp6_option_ref(v);

        return 1;
}

static int client_ensure_duid(sd_dhcp6_client *client) {
        if (client->duid_len != 0)
                return 0;

        return dhcp_identifier_set_duid_en(&client->duid, &client->duid_len);
}

/**
 * Sets DUID. If duid is non-null, the DUID is set to duid_type + duid
 * without further modification. Otherwise, if duid_type is supported, DUID
 * is set based on that type. Otherwise, an error is returned.
 */
static int dhcp6_client_set_duid_internal(
                sd_dhcp6_client *client,
                uint16_t duid_type,
                const void *duid,
                size_t duid_len,
                usec_t llt_time) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(duid_len == 0 || duid != NULL, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (duid) {
                r = dhcp_validate_duid_len(duid_type, duid_len, true);
                if (r < 0) {
                        r = dhcp_validate_duid_len(duid_type, duid_len, false);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to validate length of DUID: %m");

                        log_dhcp6_client(client, "Using DUID of type %u of incorrect length, proceeding.", duid_type);
                }

                client->duid.type = htobe16(duid_type);
                memcpy(&client->duid.raw.data, duid, duid_len);
                client->duid_len = sizeof(client->duid.type) + duid_len;
        } else
                switch (duid_type) {
                case DUID_TYPE_LLT:
                        if (client->mac_addr_len == 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to set DUID-LLT, MAC address is not set.");

                        r = dhcp_identifier_set_duid_llt(&client->duid, llt_time, client->mac_addr, client->mac_addr_len, client->arp_type, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-LLT: %m");
                        break;
                case DUID_TYPE_EN:
                        r = dhcp_identifier_set_duid_en(&client->duid, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-EN: %m");
                        break;
                case DUID_TYPE_LL:
                        if (client->mac_addr_len == 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to set DUID-LL, MAC address is not set.");

                        r = dhcp_identifier_set_duid_ll(&client->duid, client->mac_addr, client->mac_addr_len, client->arp_type, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-LL: %m");
                        break;
                case DUID_TYPE_UUID:
                        r = dhcp_identifier_set_duid_uuid(&client->duid, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-UUID: %m");
                        break;
                default:
                        return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "Invalid DUID type");
                }

        return 0;
}

int sd_dhcp6_client_set_duid(
                sd_dhcp6_client *client,
                uint16_t duid_type,
                const void *duid,
                size_t duid_len) {
        return dhcp6_client_set_duid_internal(client, duid_type, duid, duid_len, 0);
}

int sd_dhcp6_client_set_duid_llt(
                sd_dhcp6_client *client,
                usec_t llt_time) {
        return dhcp6_client_set_duid_internal(client, DUID_TYPE_LLT, NULL, 0, llt_time);
}

static const char* const dhcp6_duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_LLT]  = "DUID-LLT",
        [DUID_TYPE_EN]   = "DUID-EN/Vendor",
        [DUID_TYPE_LL]   = "DUID-LL",
        [DUID_TYPE_UUID] = "UUID",
};
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(dhcp6_duid_type, DUIDType);

int sd_dhcp6_client_duid_as_string(
                sd_dhcp6_client *client,
                char **duid) {
        _cleanup_free_ char *p = NULL, *s = NULL, *t = NULL;
        const char *v;
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->duid_len > 0, -ENODATA);
        assert_return(duid, -EINVAL);

        v = dhcp6_duid_type_to_string(be16toh(client->duid.type));
        if (v) {
                s = strdup(v);
                if (!s)
                        return -ENOMEM;
        } else {
                r = asprintf(&s, "%0x", client->duid.type);
                if (r < 0)
                        return -ENOMEM;
        }

        t = hexmem(&client->duid.raw.data, client->duid_len);
        if (!t)
                return -ENOMEM;

        p = strjoin(s, ":", t);
        if (!p)
                return -ENOMEM;

        *duid = TAKE_PTR(p);

        return 0;
}

int sd_dhcp6_client_set_iaid(sd_dhcp6_client *client, uint32_t iaid) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->ia_na.header.id = htobe32(iaid);
        client->ia_pd.header.id = htobe32(iaid);
        client->iaid_set = true;

        return 0;
}

void dhcp6_client_set_test_mode(sd_dhcp6_client *client, bool test_mode) {
        assert(client);

        client->test_mode = test_mode;
}

int sd_dhcp6_client_get_iaid(sd_dhcp6_client *client, uint32_t *iaid) {
        assert_return(client, -EINVAL);
        assert_return(iaid, -EINVAL);

        if (!client->iaid_set)
                return -ENODATA;

        *iaid = be32toh(client->ia_na.header.id);

        return 0;
}

int sd_dhcp6_client_set_fqdn(
                sd_dhcp6_client *client,
                const char *fqdn) {

        assert_return(client, -EINVAL);

        /* Make sure FQDN qualifies as DNS and as Linux hostname */
        if (fqdn &&
            !(hostname_is_valid(fqdn, 0) && dns_name_is_valid(fqdn) > 0))
                return -EINVAL;

        return free_and_strdup(&client->fqdn, fqdn);
}

int sd_dhcp6_client_set_information_request(sd_dhcp6_client *client, int enabled) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->information_request = enabled;

        return 0;
}

int sd_dhcp6_client_get_information_request(sd_dhcp6_client *client, int *enabled) {
        assert_return(client, -EINVAL);
        assert_return(enabled, -EINVAL);

        *enabled = client->information_request;

        return 0;
}

int sd_dhcp6_client_set_request_option(sd_dhcp6_client *client, uint16_t option) {
        size_t t;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (!dhcp6_option_can_request(option))
                return -EINVAL;

        for (t = 0; t < client->req_opts_len; t++)
                if (client->req_opts[t] == htobe16(option))
                        return -EEXIST;

        if (!GREEDY_REALLOC(client->req_opts, client->req_opts_len + 1))
                return -ENOMEM;

        client->req_opts[client->req_opts_len++] = htobe16(option);

        return 0;
}

int sd_dhcp6_client_set_request_mud_url(sd_dhcp6_client *client, const char *mudurl) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);
        assert_return(mudurl, -EINVAL);
        assert_return(strlen(mudurl) <= UINT8_MAX, -EINVAL);
        assert_return(http_url_is_valid(mudurl), -EINVAL);

        return free_and_strdup(&client->mudurl, mudurl);
}

int sd_dhcp6_client_set_request_user_class(sd_dhcp6_client *client, char * const *user_class) {
        char * const *p;
        char **s;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);
        assert_return(!strv_isempty(user_class), -EINVAL);

        STRV_FOREACH(p, user_class) {
                size_t len = strlen(*p);

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;
        }

        s = strv_copy(user_class);
        if (!s)
                return -ENOMEM;

        return strv_free_and_replace(client->user_class, s);
}

int sd_dhcp6_client_set_request_vendor_class(sd_dhcp6_client *client, char * const *vendor_class) {
        char * const *p;
        char **s;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);
        assert_return(!strv_isempty(vendor_class), -EINVAL);

        STRV_FOREACH(p, vendor_class) {
                size_t len = strlen(*p);

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;
        }

        s = strv_copy(vendor_class);
        if (!s)
                return -ENOMEM;

        return strv_free_and_replace(client->vendor_class, s);
}

int sd_dhcp6_client_get_prefix_delegation(sd_dhcp6_client *client, int *delegation) {
        assert_return(client, -EINVAL);
        assert_return(delegation, -EINVAL);

        *delegation = FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD);

        return 0;
}

int sd_dhcp6_client_set_prefix_delegation(sd_dhcp6_client *client, int delegation) {
        assert_return(client, -EINVAL);

        SET_FLAG(client->request_ia, DHCP6_REQUEST_IA_PD, delegation);

        return 0;
}

int sd_dhcp6_client_get_address_request(sd_dhcp6_client *client, int *request) {
        assert_return(client, -EINVAL);
        assert_return(request, -EINVAL);

        *request = FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA);

        return 0;
}

int sd_dhcp6_client_set_address_request(sd_dhcp6_client *client, int request) {
        assert_return(client, -EINVAL);

        SET_FLAG(client->request_ia, DHCP6_REQUEST_IA_NA, request);

        return 0;
}

int sd_dhcp6_client_set_transaction_id(sd_dhcp6_client *client, uint32_t transaction_id) {
        assert_return(client, -EINVAL);

        client->transaction_id = transaction_id;

        return 0;
}

int sd_dhcp6_client_get_lease(sd_dhcp6_client *client, sd_dhcp6_lease **ret) {
        assert_return(client, -EINVAL);

        if (!client->lease)
                return -ENOMSG;

        if (ret)
                *ret = client->lease;

        return 0;
}

int sd_dhcp6_client_add_option(sd_dhcp6_client *client, sd_dhcp6_option *v) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(v, -EINVAL);

        r = ordered_hashmap_ensure_put(&client->extra_options, &dhcp6_option_hash_ops, UINT_TO_PTR(v->option), v);
        if (r < 0)
                return r;

        sd_dhcp6_option_ref(v);
        return 0;
}

static void client_notify(sd_dhcp6_client *client, int event) {
        assert(client);

        if (client->callback)
                client->callback(client, event, client->userdata);
}

static void client_reset(sd_dhcp6_client *client) {
        assert(client);

        client->lease = sd_dhcp6_lease_unref(client->lease);

        client->receive_message = sd_event_source_disable_unref(client->receive_message);

        client->transaction_id = 0;
        client->transaction_start = 0;

        client->retransmit_time = 0;
        client->retransmit_count = 0;

        (void) event_source_disable(client->timeout_resend);
        (void) event_source_disable(client->timeout_resend_expire);
        (void) event_source_disable(client->timeout_t1);
        (void) event_source_disable(client->timeout_t2);

        client->state = DHCP6_STATE_STOPPED;
}

static void client_stop(sd_dhcp6_client *client, int error) {
        DHCP6_CLIENT_DONT_DESTROY(client);

        assert(client);

        client_notify(client, error);

        client_reset(client);
}

static int client_append_common_options_in_managed_mode(
                sd_dhcp6_client *client,
                uint8_t **opt,
                size_t *optlen,
                const DHCP6IA *ia_na,
                const DHCP6IA *ia_pd) {

        int r;

        assert(client);
        assert(IN_SET(client->state,
                      DHCP6_STATE_SOLICITATION,
                      DHCP6_STATE_REQUEST,
                      DHCP6_STATE_RENEW,
                      DHCP6_STATE_REBIND));
        assert(opt);
        assert(optlen);

        if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA) && ia_na) {
                r = dhcp6_option_append_ia(opt, optlen, ia_na);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD) && ia_pd) {
                r = dhcp6_option_append_ia(opt, optlen, ia_pd);
                if (r < 0)
                        return r;
        }

        if (client->fqdn) {
                r = dhcp6_option_append_fqdn(opt, optlen, client->fqdn);
                if (r < 0)
                        return r;
        }

        if (client->user_class) {
                r = dhcp6_option_append_user_class(opt, optlen, client->user_class);
                if (r < 0)
                        return r;
        }

        if (client->vendor_class) {
                r = dhcp6_option_append_vendor_class(opt, optlen, client->vendor_class);
                if (r < 0)
                        return r;
        }

        if (!ordered_hashmap_isempty(client->vendor_options)) {
                r = dhcp6_option_append_vendor_option(opt, optlen, client->vendor_options);
                if (r < 0)
                        return r;
        }

        return 0;
}

static DHCP6MessageType client_message_type_from_state(sd_dhcp6_client *client) {
        assert(client);

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                return DHCP6_MESSAGE_INFORMATION_REQUEST;
        case DHCP6_STATE_SOLICITATION:
                return DHCP6_MESSAGE_SOLICIT;
        case DHCP6_STATE_REQUEST:
                return DHCP6_MESSAGE_REQUEST;
        case DHCP6_STATE_RENEW:
                return DHCP6_MESSAGE_RENEW;
        case DHCP6_STATE_REBIND:
                return DHCP6_MESSAGE_REBIND;
        default:
                return -EINVAL;
        }
}

static int client_send_message(sd_dhcp6_client *client, usec_t time_now) {
        _cleanup_free_ DHCP6Message *message = NULL;
        struct in6_addr all_servers =
                IN6ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS_INIT;
        DHCP6MessageType message_type;
        struct sd_dhcp6_option *j;
        size_t len, optlen = 512;
        uint8_t *opt;
        usec_t elapsed_usec;
        be16_t elapsed_time;
        int r;

        assert(client);

        len = sizeof(DHCP6Message) + optlen;

        message = malloc0(len);
        if (!message)
                return -ENOMEM;

        opt = (uint8_t *)(message + 1);

        message->transaction_id = client->transaction_id;

        message_type = client_message_type_from_state(client);
        if (message_type < 0)
                return message_type;

        message->type = message_type;

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                break;

        case DHCP6_STATE_SOLICITATION:
                r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_RAPID_COMMIT, 0, NULL);
                if (r < 0)
                        return r;

                r = client_append_common_options_in_managed_mode(client, &opt, &optlen,
                                                                 &client->ia_na, &client->ia_pd);
                if (r < 0)
                        return r;
                break;

        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:

                r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_SERVERID,
                                        client->lease->serverid_len,
                                        client->lease->serverid);
                if (r < 0)
                        return r;

                _fallthrough_;
        case DHCP6_STATE_REBIND:

                assert(client->lease);

                r = client_append_common_options_in_managed_mode(client, &opt, &optlen,
                                                                 client->lease->ia_na, client->lease->ia_pd);
                if (r < 0)
                        return r;
                break;

        case DHCP6_STATE_STOPPED:
        case DHCP6_STATE_BOUND:
                return -EINVAL;
        default:
                assert_not_reached();
        }

        if (client->mudurl) {
                r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_MUD_URL_V6,
                                        strlen(client->mudurl), client->mudurl);
                if (r < 0)
                        return r;
        }

        r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_ORO,
                                client->req_opts_len * sizeof(be16_t),
                                client->req_opts);
        if (r < 0)
                return r;

        assert(client->duid_len);
        r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_CLIENTID,
                                client->duid_len, &client->duid);
        if (r < 0)
                return r;

        /* RFC 8415 Section 21.9.
         * A client MUST include an Elapsed Time option in messages to indicate how long the client has
         * been trying to complete a DHCP message exchange. */
        elapsed_usec = MIN(usec_sub_unsigned(time_now, client->transaction_start) / USEC_PER_MSEC / 10, (usec_t) UINT16_MAX);
        elapsed_time = htobe16(elapsed_usec);
        r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_ELAPSED_TIME, sizeof(elapsed_time), &elapsed_time);
        if (r < 0)
                return r;

        ORDERED_HASHMAP_FOREACH(j, client->extra_options) {
                r = dhcp6_option_append(&opt, &optlen, j->option, j->length, j->data);
                if (r < 0)
                        return r;
        }

        r = dhcp6_network_send_udp_socket(client->fd, &all_servers, message,
                                          len - optlen);
        if (r < 0)
                return r;

        log_dhcp6_client(client, "Sent %s",
                         dhcp6_message_type_to_string(message->type));

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp6_client *client = userdata;

        assert(s);
        assert(client);
        assert(client->lease);

        (void) event_source_disable(client->timeout_t2);

        log_dhcp6_client(client, "Timeout T2");

        client_set_state(client, DHCP6_STATE_REBIND);

        return 0;
}

static int client_timeout_t1(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp6_client *client = userdata;

        assert(s);
        assert(client);
        assert(client->lease);

        (void) event_source_disable(client->timeout_t1);

        log_dhcp6_client(client, "Timeout T1");

        client_set_state(client, DHCP6_STATE_RENEW);

        return 0;
}

static int client_timeout_resend_expire(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp6_client *client = userdata;
        DHCP6_CLIENT_DONT_DESTROY(client);
        DHCP6State state;

        assert(s);
        assert(client);
        assert(client->event);

        state = client->state;

        client_stop(client, SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE);

        /* RFC 3315, section 18.1.4., says that "...the client may choose to
           use a Solicit message to locate a new DHCP server..." */
        if (state == DHCP6_STATE_REBIND)
                client_set_state(client, DHCP6_STATE_SOLICITATION);

        return 0;
}

static usec_t client_timeout_compute_random(usec_t val) {
        return val - (random_u32() % USEC_PER_SEC) * val / 10 / USEC_PER_SEC;
}

static int client_timeout_resend(sd_event_source *s, uint64_t usec, void *userdata) {
        int r = 0;
        sd_dhcp6_client *client = userdata;
        usec_t time_now, init_retransmit_time = 0, max_retransmit_time = 0;
        usec_t max_retransmit_duration = 0;
        uint8_t max_retransmit_count = 0;

        assert(s);
        assert(client);
        assert(client->event);

        (void) event_source_disable(client->timeout_resend);

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                init_retransmit_time = DHCP6_INF_TIMEOUT;
                max_retransmit_time = DHCP6_INF_MAX_RT;

                break;

        case DHCP6_STATE_SOLICITATION:

                if (client->retransmit_count > 0 && client->lease) {
                        client_set_state(client, DHCP6_STATE_REQUEST);
                        return 0;
                }

                init_retransmit_time = DHCP6_SOL_TIMEOUT;
                max_retransmit_time = DHCP6_SOL_MAX_RT;

                break;

        case DHCP6_STATE_REQUEST:
                init_retransmit_time = DHCP6_REQ_TIMEOUT;
                max_retransmit_time = DHCP6_REQ_MAX_RT;
                max_retransmit_count = DHCP6_REQ_MAX_RC;

                break;

        case DHCP6_STATE_RENEW:
                init_retransmit_time = DHCP6_REN_TIMEOUT;
                max_retransmit_time = DHCP6_REN_MAX_RT;

                /* RFC 3315, section 18.1.3. says max retransmit duration will
                   be the remaining time until T2. Instead of setting MRD,
                   wait for T2 to trigger with the same end result */

                break;

        case DHCP6_STATE_REBIND:
                init_retransmit_time = DHCP6_REB_TIMEOUT;
                max_retransmit_time = DHCP6_REB_MAX_RT;

                if (event_source_is_enabled(client->timeout_resend_expire) <= 0) {
                        r = dhcp6_lease_get_max_retransmit_duration(client->lease, &max_retransmit_duration);
                        if (r < 0) {
                                client_stop(client, r);
                                return 0;
                        }
                }

                break;

        case DHCP6_STATE_STOPPED:
        case DHCP6_STATE_BOUND:
                return 0;
        default:
                assert_not_reached();
        }

        if (max_retransmit_count > 0 &&
            client->retransmit_count >= max_retransmit_count) {
                client_stop(client, SD_DHCP6_CLIENT_EVENT_RETRANS_MAX);
                return 0;
        }

        r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                goto error;

        r = client_send_message(client, time_now);
        if (r >= 0)
                client->retransmit_count++;

        if (client->retransmit_time == 0) {
                client->retransmit_time =
                        client_timeout_compute_random(init_retransmit_time);

                if (client->state == DHCP6_STATE_SOLICITATION)
                        client->retransmit_time += init_retransmit_time / 10;

        } else {
                assert(max_retransmit_time > 0);
                if (client->retransmit_time > max_retransmit_time / 2)
                        client->retransmit_time = client_timeout_compute_random(max_retransmit_time);
                else
                        client->retransmit_time += client_timeout_compute_random(client->retransmit_time);
        }

        log_dhcp6_client(client, "Next retransmission in %s",
                         FORMAT_TIMESPAN(client->retransmit_time, USEC_PER_SEC));

        r = event_reset_time(client->event, &client->timeout_resend,
                             clock_boottime_or_monotonic(),
                             time_now + client->retransmit_time, 10 * USEC_PER_MSEC,
                             client_timeout_resend, client,
                             client->event_priority, "dhcp6-resend-timer", true);
        if (r < 0)
                goto error;

        if (max_retransmit_duration > 0 && event_source_is_enabled(client->timeout_resend_expire) <= 0) {

                log_dhcp6_client(client, "Max retransmission duration %"PRIu64" secs",
                                 max_retransmit_duration / USEC_PER_SEC);

                r = event_reset_time(client->event, &client->timeout_resend_expire,
                                     clock_boottime_or_monotonic(),
                                     time_now + max_retransmit_duration, USEC_PER_SEC,
                                     client_timeout_resend_expire, client,
                                     client->event_priority, "dhcp6-resend-expire-timer", true);
                if (r < 0)
                        goto error;
        }

error:
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_ensure_iaid(sd_dhcp6_client *client) {
        int r;
        uint32_t iaid;

        assert(client);

        if (client->iaid_set)
                return 0;

        r = dhcp_identifier_set_iaid(client->ifindex, client->mac_addr, client->mac_addr_len,
                                     /* legacy_unstable_byteorder = */ true,
                                     /* use_mac = */ client->test_mode,
                                     &iaid);
        if (r < 0)
                return r;

        client->ia_na.header.id = iaid;
        client->ia_pd.header.id = iaid;
        client->iaid_set = true;

        return 0;
}

static int log_invalid_message_type(sd_dhcp6_client *client, const DHCP6Message *message) {
        const char *type_str;

        assert(client);
        assert(message);

        type_str = dhcp6_message_type_to_string(message->type);
        if (type_str)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received unexpected %s message, ignoring.", type_str);
        else
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received unsupported message type %u, ignoring.", message->type);
}

static int client_process_information(
                sd_dhcp6_client *client,
                DHCP6Message *message,
                size_t len,
                const triple_timestamp *timestamp,
                const struct in6_addr *server_address) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        int r;

        if (message->type != DHCP6_MESSAGE_REPLY)
                return log_invalid_message_type(client, message);

        r = dhcp6_lease_new_from_message(client, message, len, timestamp, server_address, &lease);
        if (r < 0)
                return log_dhcp6_client_errno(client, r, "Failed to process received reply message, ignoring: %m");

        sd_dhcp6_lease_unref(client->lease);
        client->lease = TAKE_PTR(lease);

        client_notify(client, SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST);
        return client_set_state(client, DHCP6_STATE_STOPPED);
}

static int client_process_reply(
                sd_dhcp6_client *client,
                DHCP6Message *message,
                size_t len,
                const triple_timestamp *timestamp,
                const struct in6_addr *server_address) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        int r;

        assert(client);
        assert(message);

        if (message->type != DHCP6_MESSAGE_REPLY)
                return log_invalid_message_type(client, message);

        r = dhcp6_lease_new_from_message(client, message, len, timestamp, server_address, &lease);
        if (r < 0)
                return log_dhcp6_client_errno(client, r, "Failed to process received reply message, ignoring: %m");

        sd_dhcp6_lease_unref(client->lease);
        client->lease = TAKE_PTR(lease);

        r = client_set_state(client, DHCP6_STATE_BOUND);
        if (r < 0)
                return r;

        client_notify(client, SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE);
        return 0;
}

static int client_process_advertise_or_rapid_commit_reply(
                sd_dhcp6_client *client,
                DHCP6Message *message,
                size_t len,
                const triple_timestamp *timestamp,
                const struct in6_addr *server_address) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        uint8_t pref_advertise, pref_lease = 0;
        int r;

        assert(client);
        assert(message);

        if (!IN_SET(message->type, DHCP6_MESSAGE_ADVERTISE, DHCP6_MESSAGE_REPLY))
                return log_invalid_message_type(client, message);

        r = dhcp6_lease_new_from_message(client, message, len, timestamp, server_address, &lease);
        if (r < 0)
                return log_dhcp6_client_errno(client, r, "Failed to process received %s message, ignoring: %m",
                                              dhcp6_message_type_to_string(message->type));

        if (message->type == DHCP6_MESSAGE_REPLY) {
                bool rapid_commit;

                r = dhcp6_lease_get_rapid_commit(lease, &rapid_commit);
                if (r < 0)
                        return r;

                if (!rapid_commit)
                        return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                                      "Received reply message without rapid commit flag, ignoring.");

                sd_dhcp6_lease_unref(client->lease);
                client->lease = TAKE_PTR(lease);

                r = client_set_state(client, DHCP6_STATE_BOUND);
                if (r < 0)
                        return r;

                client_notify(client, SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE);
                return 0;
        }

        r = dhcp6_lease_get_preference(lease, &pref_advertise);
        if (r < 0)
                return r;

        if (client->lease) {
                r = dhcp6_lease_get_preference(client->lease, &pref_lease);
                if (r < 0)
                        return r;
        }

        if (!client->lease || pref_advertise > pref_lease) {
                /* If this is the first advertise message or has higher preference, then save the lease. */
                sd_dhcp6_lease_unref(client->lease);
                client->lease = TAKE_PTR(lease);
        }

        if (pref_advertise == 255 || client->retransmit_count > 1) {
                r = client_set_state(client, DHCP6_STATE_REQUEST);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int client_receive_message(
                sd_event_source *s,
                int fd, uint32_t
                revents,
                void *userdata) {

        sd_dhcp6_client *client = userdata;
        DHCP6_CLIENT_DONT_DESTROY(client);
        /* This needs to be initialized with zero. See #20741. */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL) control = {};
        struct iovec iov;
        union sockaddr_union sa = {};
        struct msghdr msg = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        triple_timestamp t = {};
        _cleanup_free_ DHCP6Message *message = NULL;
        struct in6_addr *server_address = NULL;
        ssize_t buflen, len;

        assert(s);
        assert(client);
        assert(client->event);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0) {
                if (ERRNO_IS_TRANSIENT(buflen) || ERRNO_IS_DISCONNECT(buflen))
                        return 0;

                log_dhcp6_client_errno(client, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        message = malloc(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (len < 0) {
                if (ERRNO_IS_TRANSIENT(len) || ERRNO_IS_DISCONNECT(len))
                        return 0;

                log_dhcp6_client_errno(client, len, "Could not receive message from UDP socket, ignoring: %m");
                return 0;
        }
        if ((size_t) len < sizeof(DHCP6Message)) {
                log_dhcp6_client(client, "Too small to be DHCP6 message: ignoring");
                return 0;
        }

        /* msg_namelen == 0 happens when running the test-suite over a socketpair */
        if (msg.msg_namelen > 0) {
                if (msg.msg_namelen != sizeof(struct sockaddr_in6) || sa.in6.sin6_family != AF_INET6) {
                        log_dhcp6_client(client, "Received message from invalid source, ignoring.");
                        return 0;
                }

                server_address = &sa.in6.sin6_addr;
        }

        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SO_TIMESTAMP &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
                        triple_timestamp_from_realtime(&t, timeval_load((struct timeval*) CMSG_DATA(cmsg)));
        }

        if (client->transaction_id != (message->transaction_id & htobe32(0x00ffffff)))
                return 0;

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                if (client_process_information(client, message, len, &t, server_address) < 0)
                        return 0;
                break;

        case DHCP6_STATE_SOLICITATION:
                if (client_process_advertise_or_rapid_commit_reply(client, message, len, &t, server_address) < 0)
                        return 0;
                break;

        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:
        case DHCP6_STATE_REBIND:
                if (client_process_reply(client, message, len, &t, server_address) < 0)
                        return 0;
                break;

        case DHCP6_STATE_BOUND:
        case DHCP6_STATE_STOPPED:
                return 0;

        default:
                assert_not_reached();
        }

        log_dhcp6_client(client, "Recv %s",
                         dhcp6_message_type_to_string(message->type));

        return 0;
}

static int client_set_state(sd_dhcp6_client *client, DHCP6State state) {
        usec_t timeout, time_now, lifetime_t1, lifetime_t2;
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(client->state != state, -EINVAL);

        (void) event_source_disable(client->timeout_resend_expire);
        (void) event_source_disable(client->timeout_resend);
        client->retransmit_time = 0;
        client->retransmit_count = 0;

        r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                goto error;

        if (!client->receive_message) {
                r = sd_event_add_io(client->event, &client->receive_message,
                                    client->fd, EPOLLIN, client_receive_message,
                                    client);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_priority(client->receive_message,
                                                 client->event_priority);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_description(client->receive_message,
                                                    "dhcp6-receive-message");
                if (r < 0)
                        goto error;
        }

        switch (state) {
        case DHCP6_STATE_STOPPED:
                if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                        client->state = DHCP6_STATE_STOPPED;

                        return 0;
                }

                _fallthrough_;
        case DHCP6_STATE_SOLICITATION:
                client->state = DHCP6_STATE_SOLICITATION;

                break;

        case DHCP6_STATE_INFORMATION_REQUEST:
        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:
        case DHCP6_STATE_REBIND:

                client->state = state;

                break;

        case DHCP6_STATE_BOUND:

                assert(client->lease);

                r = dhcp6_lease_get_lifetime(client->lease, &lifetime_t1, &lifetime_t2);
                if (r < 0)
                        goto error;

                if (lifetime_t1 == USEC_INFINITY || lifetime_t2 == USEC_INFINITY) {
                        log_dhcp6_client(client, "Infinite T1 or T2");
                        return 0;
                }

                timeout = client_timeout_compute_random(lifetime_t1);

                log_dhcp6_client(client, "T1 expires in %s", FORMAT_TIMESPAN(timeout, USEC_PER_SEC));

                r = event_reset_time(client->event, &client->timeout_t1,
                                     clock_boottime_or_monotonic(),
                                     time_now + timeout, 10 * USEC_PER_SEC,
                                     client_timeout_t1, client,
                                     client->event_priority, "dhcp6-t1-timeout", true);
                if (r < 0)
                        goto error;

                timeout = client_timeout_compute_random(lifetime_t2);

                log_dhcp6_client(client, "T2 expires in %s", FORMAT_TIMESPAN(timeout, USEC_PER_SEC));

                r = event_reset_time(client->event, &client->timeout_t2,
                                     clock_boottime_or_monotonic(),
                                     time_now + timeout, 10 * USEC_PER_SEC,
                                     client_timeout_t2, client,
                                     client->event_priority, "dhcp6-t2-timeout", true);
                if (r < 0)
                        goto error;

                client->state = state;

                return 0;
        default:
                assert_not_reached();
        }

        client->transaction_id = random_u32() & htobe32(0x00ffffff);
        client->transaction_start = time_now;

        r = event_reset_time(client->event, &client->timeout_resend,
                             clock_boottime_or_monotonic(),
                             0, 0,
                             client_timeout_resend, client,
                             client->event_priority, "dhcp6-resend-timeout", true);
        if (r < 0)
                goto error;

        return 0;

error:
        client_stop(client, r);
        return r;
}

int sd_dhcp6_client_stop(sd_dhcp6_client *client) {
        if (!client)
                return 0;

        client_stop(client, SD_DHCP6_CLIENT_EVENT_STOP);

        client->fd = safe_close(client->fd);

        return 0;
}

int sd_dhcp6_client_is_running(sd_dhcp6_client *client) {
        assert_return(client, -EINVAL);

        return client->state != DHCP6_STATE_STOPPED;
}

int sd_dhcp6_client_start(sd_dhcp6_client *client) {
        DHCP6State state = DHCP6_STATE_SOLICITATION;
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(in6_addr_is_link_local(&client->local_address) > 0, -EINVAL);

        if (client->state != DHCP6_STATE_STOPPED)
                return -EBUSY;

        if (!client->information_request && client->request_ia == 0)
                return -EINVAL;

        client_reset(client);

        r = client_ensure_iaid(client);
        if (r < 0)
                return r;

        r = client_ensure_duid(client);
        if (r < 0)
                return r;

        if (client->fd < 0) {
                r = dhcp6_network_bind_udp_socket(client->ifindex, &client->local_address);
                if (r < 0) {
                        _cleanup_free_ char *p = NULL;

                        (void) in6_addr_to_string(&client->local_address, &p);
                        return log_dhcp6_client_errno(client, r,
                                                      "Failed to bind to UDP socket at address %s: %m", strna(p));
                }

                client->fd = r;
        }

        if (client->information_request) {
                usec_t t = now(CLOCK_MONOTONIC);

                if (t < usec_add(client->information_request_time_usec, client->information_refresh_time_usec))
                        return 0;

                client->information_request_time_usec = t;
                state = DHCP6_STATE_INFORMATION_REQUEST;
        }

        log_dhcp6_client(client, "Started in %s mode",
                         client->information_request ? "Information request" : "Managed");

        return client_set_state(client, state);
}

int sd_dhcp6_client_attach_event(sd_dhcp6_client *client, sd_event *event, int64_t priority) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!client->event, -EBUSY);

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

int sd_dhcp6_client_detach_event(sd_dhcp6_client *client) {
        assert_return(client, -EINVAL);

        client->event = sd_event_unref(client->event);

        return 0;
}

sd_event *sd_dhcp6_client_get_event(sd_dhcp6_client *client) {
        assert_return(client, NULL);

        return client->event;
}

static sd_dhcp6_client *dhcp6_client_free(sd_dhcp6_client *client) {
        assert(client);

        sd_dhcp6_lease_unref(client->lease);

        sd_event_source_disable_unref(client->receive_message);
        sd_event_source_disable_unref(client->timeout_resend);
        sd_event_source_disable_unref(client->timeout_resend_expire);
        sd_event_source_disable_unref(client->timeout_t1);
        sd_event_source_disable_unref(client->timeout_t2);

        client->fd = safe_close(client->fd);

        sd_dhcp6_client_detach_event(client);

        free(client->req_opts);
        free(client->fqdn);
        free(client->mudurl);
        dhcp6_ia_clear_addresses(&client->ia_pd);
        ordered_hashmap_free(client->extra_options);
        strv_free(client->user_class);
        strv_free(client->vendor_class);
        free(client->ifname);

        return mfree(client);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_client, sd_dhcp6_client, dhcp6_client_free);

int sd_dhcp6_client_new(sd_dhcp6_client **ret) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_free_ be16_t *req_opts = NULL;
        size_t t;

        assert_return(ret, -EINVAL);

        req_opts = new(be16_t, ELEMENTSOF(default_req_opts));
        if (!req_opts)
                return -ENOMEM;

        for (t = 0; t < ELEMENTSOF(default_req_opts); t++)
                req_opts[t] = htobe16(default_req_opts[t]);

        client = new(sd_dhcp6_client, 1);
        if (!client)
                return -ENOMEM;

        *client = (sd_dhcp6_client) {
                .n_ref = 1,
                .ia_na.type = SD_DHCP6_OPTION_IA_NA,
                .ia_pd.type = SD_DHCP6_OPTION_IA_PD,
                .ifindex = -1,
                .request_ia = DHCP6_REQUEST_IA_NA | DHCP6_REQUEST_IA_PD,
                .fd = -1,
                .req_opts_len = ELEMENTSOF(default_req_opts),
                .req_opts = TAKE_PTR(req_opts),
        };

        *ret = TAKE_PTR(client);

        return 0;
}

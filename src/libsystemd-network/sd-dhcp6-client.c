/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_infiniband.h>

#include "udev.h"
#include "udev-util.h"
#include "util.h"
#include "refcnt.h"
#include "random-util.h"

#include "network-internal.h"
#include "sd-dhcp6-client.h"
#include "dhcp6-protocol.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp-identifier.h"

#define MAX_MAC_ADDR_LEN INFINIBAND_ALEN

struct sd_dhcp6_client {
        RefCount n_ref;

        enum DHCP6State state;
        sd_event *event;
        int event_priority;
        int index;
        uint8_t mac_addr[MAX_MAC_ADDR_LEN];
        size_t mac_addr_len;
        uint16_t arp_type;
        DHCP6IA ia_na;
        be32_t transaction_id;
        usec_t transaction_start;
        struct sd_dhcp6_lease *lease;
        int fd;
        bool information_request;
        be16_t *req_opts;
        size_t req_opts_allocated;
        size_t req_opts_len;
        sd_event_source *receive_message;
        usec_t retransmit_time;
        uint8_t retransmit_count;
        sd_event_source *timeout_resend;
        sd_event_source *timeout_resend_expire;
        sd_dhcp6_client_cb_t cb;
        void *userdata;
        struct duid duid;
        size_t duid_len;
};

static const uint16_t default_req_opts[] = {
        DHCP6_OPTION_DNS_SERVERS,
        DHCP6_OPTION_DOMAIN_LIST,
        DHCP6_OPTION_NTP_SERVER,
};

const char * dhcp6_message_type_table[_DHCP6_MESSAGE_MAX] = {
        [DHCP6_SOLICIT] = "SOLICIT",
        [DHCP6_ADVERTISE] = "ADVERTISE",
        [DHCP6_REQUEST] = "REQUEST",
        [DHCP6_CONFIRM] = "CONFIRM",
        [DHCP6_RENEW] = "RENEW",
        [DHCP6_REBIND] = "REBIND",
        [DHCP6_REPLY] = "REPLY",
        [DHCP6_RELEASE] = "RELEASE",
        [DHCP6_DECLINE] = "DECLINE",
        [DHCP6_RECONFIGURE] = "RECONFIGURE",
        [DHCP6_INFORMATION_REQUEST] = "INFORMATION-REQUEST",
        [DHCP6_RELAY_FORW] = "RELAY-FORW",
        [DHCP6_RELAY_REPL] = "RELAY-REPL",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_type, int);

const char * dhcp6_message_status_table[_DHCP6_STATUS_MAX] = {
        [DHCP6_STATUS_SUCCESS] = "Success",
        [DHCP6_STATUS_UNSPEC_FAIL] = "Unspecified failure",
        [DHCP6_STATUS_NO_ADDRS_AVAIL] = "No addresses available",
        [DHCP6_STATUS_NO_BINDING] = "Binding unavailable",
        [DHCP6_STATUS_NOT_ON_LINK] = "Not on link",
        [DHCP6_STATUS_USE_MULTICAST] = "Use multicast",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_status, int);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp6_client*, sd_dhcp6_client_unref);
#define _cleanup_dhcp6_client_unref_ _cleanup_(sd_dhcp6_client_unrefp)

#define DHCP6_CLIENT_DONT_DESTROY(client) \
        _cleanup_dhcp6_client_unref_ _unused_ sd_dhcp6_client *_dont_destroy_##client = sd_dhcp6_client_ref(client)

static int client_start(sd_dhcp6_client *client, enum DHCP6State state);

int sd_dhcp6_client_set_callback(sd_dhcp6_client *client,
                                 sd_dhcp6_client_cb_t cb, void *userdata)
{
        assert_return(client, -EINVAL);

        client->cb = cb;
        client->userdata = userdata;

        return 0;
}

int sd_dhcp6_client_set_index(sd_dhcp6_client *client, int interface_index)
{
        assert_return(client, -EINVAL);
        assert_return(interface_index >= -1, -EINVAL);

        client->index = interface_index;

        return 0;
}

int sd_dhcp6_client_set_mac(sd_dhcp6_client *client, const uint8_t *addr,
                            size_t addr_len, uint16_t arp_type)
{
        assert_return(client, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(addr_len > 0 && addr_len <= MAX_MAC_ADDR_LEN, -EINVAL);
        assert_return(arp_type > 0, -EINVAL);

        if (arp_type == ARPHRD_ETHER)
                assert_return(addr_len == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(addr_len == INFINIBAND_ALEN, -EINVAL);
        else
                return -EINVAL;

        if (client->mac_addr_len == addr_len &&
            memcmp(&client->mac_addr, addr, addr_len) == 0)
                return 0;

        memcpy(&client->mac_addr, addr, addr_len);
        client->mac_addr_len = addr_len;
        client->arp_type = arp_type;

        return 0;
}

static int client_ensure_duid(sd_dhcp6_client *client)
{
        if (client->duid_len != 0)
                return 0;
        return dhcp_identifier_set_duid_en(&client->duid, &client->duid_len);
}

int sd_dhcp6_client_set_duid(sd_dhcp6_client *client, uint16_t type, uint8_t *duid,
                             size_t duid_len)
{
        assert_return(client, -EINVAL);
        assert_return(duid, -EINVAL);
        assert_return(duid_len > 0 && duid_len <= MAX_DUID_LEN, -EINVAL);

        switch (type) {
        case DHCP6_DUID_LLT:
                if (duid_len <= sizeof(client->duid.llt))
                        return -EINVAL;
                break;
        case DHCP6_DUID_EN:
                if (duid_len != sizeof(client->duid.en))
                        return -EINVAL;
                break;
        case DHCP6_DUID_LL:
                if (duid_len <= sizeof(client->duid.ll))
                        return -EINVAL;
                break;
        case DHCP6_DUID_UUID:
                if (duid_len != sizeof(client->duid.uuid))
                        return -EINVAL;
                break;
        default:
                /* accept unknown type in order to be forward compatible */
                break;
        }

        client->duid.type = htobe16(type);
        memcpy(&client->duid.raw.data, duid, duid_len);
        client->duid_len = duid_len + sizeof(client->duid.type);

        return 0;
}

int sd_dhcp6_client_set_information_request(sd_dhcp6_client *client,
                                            bool enabled) {
        assert_return(client, -EINVAL);

        client->information_request = enabled;

        return 0;
}

int sd_dhcp6_client_get_information_request(sd_dhcp6_client *client,
                                            bool *enabled) {
        assert_return(client, -EINVAL);
        assert_return(enabled, -EINVAL);

        *enabled = client->information_request;

        return 0;
}

int sd_dhcp6_client_set_request_option(sd_dhcp6_client *client,
                                       uint16_t option) {
        size_t t;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        switch(option) {
        case DHCP6_OPTION_DNS_SERVERS:
        case DHCP6_OPTION_DOMAIN_LIST:
        case DHCP6_OPTION_SNTP_SERVERS:
        case DHCP6_OPTION_NTP_SERVER:
                break;

        default:
                return -EINVAL;
        }

        for (t = 0; t < client->req_opts_len; t++)
                if (client->req_opts[t] == htobe16(option))
                        return -EEXIST;

        if (!GREEDY_REALLOC(client->req_opts, client->req_opts_allocated,
                            client->req_opts_len + 1))
                return -ENOMEM;

        client->req_opts[client->req_opts_len++] = htobe16(option);

        return 0;
}

int sd_dhcp6_client_get_lease(sd_dhcp6_client *client, sd_dhcp6_lease **ret) {
        assert_return(client, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!client->lease)
                return -ENOMSG;

        *ret = sd_dhcp6_lease_ref(client->lease);

        return 0;
}

static void client_notify(sd_dhcp6_client *client, int event) {
        if (client->cb)
                client->cb(client, event, client->userdata);
}

static int client_reset(sd_dhcp6_client *client) {
        assert_return(client, -EINVAL);

        client->receive_message =
                sd_event_source_unref(client->receive_message);

        client->fd = safe_close(client->fd);

        client->transaction_id = 0;
        client->transaction_start = 0;

        client->ia_na.timeout_t1 =
                sd_event_source_unref(client->ia_na.timeout_t1);
        client->ia_na.timeout_t2 =
                sd_event_source_unref(client->ia_na.timeout_t2);

        client->retransmit_time = 0;
        client->retransmit_count = 0;
        client->timeout_resend = sd_event_source_unref(client->timeout_resend);
        client->timeout_resend_expire =
                sd_event_source_unref(client->timeout_resend_expire);

        client->state = DHCP6_STATE_STOPPED;

        return 0;
}

static void client_stop(sd_dhcp6_client *client, int error) {
        DHCP6_CLIENT_DONT_DESTROY(client);

        assert(client);

        client_notify(client, error);

        client_reset(client);
}

static int client_send_message(sd_dhcp6_client *client, usec_t time_now) {
        _cleanup_free_ DHCP6Message *message = NULL;
        struct in6_addr all_servers =
                IN6ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS_INIT;
        size_t len, optlen = 512;
        uint8_t *opt;
        int r;
        usec_t elapsed_usec;
        be16_t elapsed_time;

        len = sizeof(DHCP6Message) + optlen;

        message = malloc0(len);
        if (!message)
                return -ENOMEM;

        opt = (uint8_t *)(message + 1);

        message->transaction_id = client->transaction_id;

        switch(client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                message->type = DHCP6_INFORMATION_REQUEST;

                break;

        case DHCP6_STATE_SOLICITATION:
                message->type = DHCP6_SOLICIT;

                r = dhcp6_option_append(&opt, &optlen,
                                        DHCP6_OPTION_RAPID_COMMIT, 0, NULL);
                if (r < 0)
                        return r;

                r = dhcp6_option_append_ia(&opt, &optlen, &client->ia_na);
                if (r < 0)
                        return r;

                break;

        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:

                if (client->state == DHCP6_STATE_REQUEST)
                        message->type = DHCP6_REQUEST;
                else
                        message->type = DHCP6_RENEW;

                r = dhcp6_option_append(&opt, &optlen, DHCP6_OPTION_SERVERID,
                                        client->lease->serverid_len,
                                        client->lease->serverid);
                if (r < 0)
                        return r;

                r = dhcp6_option_append_ia(&opt, &optlen, &client->lease->ia);
                if (r < 0)
                        return r;

                break;

        case DHCP6_STATE_REBIND:
                message->type = DHCP6_REBIND;

                r = dhcp6_option_append_ia(&opt, &optlen, &client->lease->ia);
                if (r < 0)
                        return r;

                break;

        case DHCP6_STATE_STOPPED:
        case DHCP6_STATE_BOUND:
                return -EINVAL;
        }

        r = dhcp6_option_append(&opt, &optlen, DHCP6_OPTION_ORO,
                                client->req_opts_len * sizeof(be16_t),
                                client->req_opts);
        if (r < 0)
                return r;

        assert (client->duid_len);
        r = dhcp6_option_append(&opt, &optlen, DHCP6_OPTION_CLIENTID,
                                client->duid_len, &client->duid);
        if (r < 0)
                return r;

        elapsed_usec = time_now - client->transaction_start;
        if (elapsed_usec < 0xffff * USEC_PER_MSEC * 10)
                elapsed_time = htobe16(elapsed_usec / USEC_PER_MSEC / 10);
        else
                elapsed_time = 0xffff;

        r = dhcp6_option_append(&opt, &optlen, DHCP6_OPTION_ELAPSED_TIME,
                                sizeof(elapsed_time), &elapsed_time);
        if (r < 0)
                return r;

        r = dhcp6_network_send_udp_socket(client->fd, &all_servers, message,
                                          len - optlen);
        if (r < 0)
                return r;

        log_dhcp6_client(client, "Sent %s",
                         dhcp6_message_type_to_string(message->type));

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec,
                             void *userdata) {
        sd_dhcp6_client *client = userdata;

        assert_return(s, -EINVAL);
        assert_return(client, -EINVAL);
        assert_return(client->lease, -EINVAL);

        client->lease->ia.timeout_t2 =
                sd_event_source_unref(client->lease->ia.timeout_t2);

        log_dhcp6_client(client, "Timeout T2");

        client_start(client, DHCP6_STATE_REBIND);

        return 0;
}

static int client_timeout_t1(sd_event_source *s, uint64_t usec,
                             void *userdata) {
        sd_dhcp6_client *client = userdata;

        assert_return(s, -EINVAL);
        assert_return(client, -EINVAL);
        assert_return(client->lease, -EINVAL);

        client->lease->ia.timeout_t1 =
                sd_event_source_unref(client->lease->ia.timeout_t1);

        log_dhcp6_client(client, "Timeout T1");

        client_start(client, DHCP6_STATE_RENEW);

        return 0;
}

static int client_timeout_resend_expire(sd_event_source *s, uint64_t usec,
                                        void *userdata) {
        sd_dhcp6_client *client = userdata;
        DHCP6_CLIENT_DONT_DESTROY(client);
        enum DHCP6State state;

        assert(s);
        assert(client);
        assert(client->event);

        state = client->state;

        client_stop(client, DHCP6_EVENT_RESEND_EXPIRE);

        /* RFC 3315, section 18.1.4., says that "...the client may choose to
           use a Solicit message to locate a new DHCP server..." */
        if (state == DHCP6_STATE_REBIND)
                client_start(client, DHCP6_STATE_SOLICITATION);

        return 0;
}

static usec_t client_timeout_compute_random(usec_t val) {
        return val - val / 10 +
                (random_u32() % (2 * USEC_PER_SEC)) * val / 10 / USEC_PER_SEC;
}

static int client_timeout_resend(sd_event_source *s, uint64_t usec,
                                 void *userdata) {
        int r = 0;
        sd_dhcp6_client *client = userdata;
        usec_t time_now, init_retransmit_time = 0, max_retransmit_time = 0;
        usec_t max_retransmit_duration = 0;
        uint8_t max_retransmit_count = 0;
        char time_string[FORMAT_TIMESPAN_MAX];
        uint32_t expire = 0;

        assert(s);
        assert(client);
        assert(client->event);

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                init_retransmit_time = DHCP6_INF_TIMEOUT;
                max_retransmit_time = DHCP6_INF_MAX_RT;

                break;

        case DHCP6_STATE_SOLICITATION:

                if (client->retransmit_count && client->lease) {
                        client_start(client, DHCP6_STATE_REQUEST);
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

                if (!client->timeout_resend_expire) {
                        r = dhcp6_lease_ia_rebind_expire(&client->lease->ia,
                                                         &expire);
                        if (r < 0) {
                                client_stop(client, r);
                                return 0;
                        }
                        max_retransmit_duration = expire * USEC_PER_SEC;
                }

                break;

        case DHCP6_STATE_STOPPED:
        case DHCP6_STATE_BOUND:
                return 0;
        }

        if (max_retransmit_count &&
            client->retransmit_count >= max_retransmit_count) {
                client_stop(client, DHCP6_EVENT_RETRANS_MAX);
                return 0;
        }

        r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                goto error;

        r = client_send_message(client, time_now);
        if (r >= 0)
                client->retransmit_count++;

        if (!client->retransmit_time) {
                client->retransmit_time =
                        client_timeout_compute_random(init_retransmit_time);

                if (client->state == DHCP6_STATE_SOLICITATION)
                        client->retransmit_time += init_retransmit_time / 10;

        } else {
                if (max_retransmit_time &&
                    client->retransmit_time > max_retransmit_time / 2)
                        client->retransmit_time = client_timeout_compute_random(max_retransmit_time);
                else
                        client->retransmit_time += client_timeout_compute_random(client->retransmit_time);
        }

        log_dhcp6_client(client, "Next retransmission in %s",
                         format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                                         client->retransmit_time, 0));

        r = sd_event_add_time(client->event, &client->timeout_resend,
                              clock_boottime_or_monotonic(),
                              time_now + client->retransmit_time,
                              10 * USEC_PER_MSEC, client_timeout_resend,
                              client);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(client->timeout_resend,
                                         client->event_priority);
        if (r < 0)
                goto error;

        r = sd_event_source_set_description(client->timeout_resend, "dhcp6-resend-timer");
        if (r < 0)
                goto error;

        if (max_retransmit_duration && !client->timeout_resend_expire) {

                log_dhcp6_client(client, "Max retransmission duration %"PRIu64" secs",
                                 max_retransmit_duration / USEC_PER_SEC);

                r = sd_event_add_time(client->event,
                                      &client->timeout_resend_expire,
                                      clock_boottime_or_monotonic(),
                                      time_now + max_retransmit_duration,
                                      USEC_PER_SEC,
                                      client_timeout_resend_expire, client);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_priority(client->timeout_resend_expire,
                                                 client->event_priority);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_description(client->timeout_resend_expire, "dhcp6-resend-expire-timer");
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

        assert(client);

        if (client->ia_na.id)
                return 0;

        r = dhcp_identifier_set_iaid(client->index, client->mac_addr, client->mac_addr_len, &client->ia_na.id);
        if (r < 0)
                return r;

        return 0;
}

static int client_parse_message(sd_dhcp6_client *client,
                                DHCP6Message *message, size_t len,
                                sd_dhcp6_lease *lease) {
        int r;
        uint8_t *optval, *option, *id = NULL;
        uint16_t optcode, status;
        size_t optlen, id_len;
        bool clientid = false;
        be32_t iaid_lease;

        option = (uint8_t *)message + sizeof(DHCP6Message);
        len -= sizeof(DHCP6Message);

        while ((r = dhcp6_option_parse(&option, &len, &optcode, &optlen,
                                       &optval)) >= 0) {
                switch (optcode) {
                case DHCP6_OPTION_CLIENTID:
                        if (clientid) {
                                log_dhcp6_client(client, "%s contains multiple clientids",
                                                 dhcp6_message_type_to_string(message->type));
                                return -EINVAL;
                        }

                        if (optlen != client->duid_len ||
                            memcmp(&client->duid, optval, optlen) != 0) {
                                log_dhcp6_client(client, "%s DUID does not match",
                                                 dhcp6_message_type_to_string(message->type));

                                return -EINVAL;
                        }
                        clientid = true;

                        break;

                case DHCP6_OPTION_SERVERID:
                        r = dhcp6_lease_get_serverid(lease, &id, &id_len);
                        if (r >= 0 && id) {
                                log_dhcp6_client(client, "%s contains multiple serverids",
                                                 dhcp6_message_type_to_string(message->type));
                                return -EINVAL;
                        }

                        r = dhcp6_lease_set_serverid(lease, optval, optlen);
                        if (r < 0)
                                return r;

                        break;

                case DHCP6_OPTION_PREFERENCE:
                        if (optlen != 1)
                                return -EINVAL;

                        r = dhcp6_lease_set_preference(lease, *optval);
                        if (r < 0)
                                return r;

                        break;

                case DHCP6_OPTION_STATUS_CODE:
                        if (optlen < 2)
                                return -EINVAL;

                        status = optval[0] << 8 | optval[1];
                        if (status) {
                                log_dhcp6_client(client, "%s Status %s",
                                                 dhcp6_message_type_to_string(message->type),
                                                 dhcp6_message_status_to_string(status));
                                return -EINVAL;
                        }

                        break;

                case DHCP6_OPTION_IA_NA:
                        if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                                log_dhcp6_client(client, "Information request ignoring IA NA option");

                                break;
                        }

                        r = dhcp6_option_parse_ia(&optval, &optlen, optcode,
                                                  &lease->ia);
                        if (r < 0 && r != -ENOMSG)
                                return r;

                        r = dhcp6_lease_get_iaid(lease, &iaid_lease);
                        if (r < 0)
                                return r;

                        if (client->ia_na.id != iaid_lease) {
                                log_dhcp6_client(client, "%s has wrong IAID",
                                                 dhcp6_message_type_to_string(message->type));
                                return -EINVAL;
                        }

                        break;

                case DHCP6_OPTION_RAPID_COMMIT:
                        r = dhcp6_lease_set_rapid_commit(lease);
                        if (r < 0)
                                return r;

                        break;
                }
        }

        if (r == -ENOMSG)
                r = 0;

        if (r < 0 || !clientid) {
                log_dhcp6_client(client, "%s has incomplete options",
                                 dhcp6_message_type_to_string(message->type));
                return -EINVAL;
        }

        if (client->state != DHCP6_STATE_INFORMATION_REQUEST) {
                r = dhcp6_lease_get_serverid(lease, &id, &id_len);
                if (r < 0)
                        log_dhcp6_client(client, "%s has no server id",
                                         dhcp6_message_type_to_string(message->type));
        }

        return r;
}

static int client_receive_reply(sd_dhcp6_client *client, DHCP6Message *reply,
                                size_t len)
{
        int r;
        _cleanup_dhcp6_lease_free_ sd_dhcp6_lease *lease = NULL;
        bool rapid_commit;

        if (reply->type != DHCP6_REPLY)
                return 0;

        r = dhcp6_lease_new(&lease);
        if (r < 0)
                return -ENOMEM;

        r = client_parse_message(client, reply, len, lease);
        if (r < 0)
                return r;

        if (client->state == DHCP6_STATE_SOLICITATION) {
                r = dhcp6_lease_get_rapid_commit(lease, &rapid_commit);
                if (r < 0)
                        return r;

                if (!rapid_commit)
                        return 0;
        }

        if (client->lease) {
                dhcp6_lease_clear_timers(&client->lease->ia);
                client->lease = sd_dhcp6_lease_unref(client->lease);
        }

        if (client->state != DHCP6_STATE_INFORMATION_REQUEST) {
                client->lease = lease;
                lease = NULL;
        }

        return DHCP6_STATE_BOUND;
}

static int client_receive_advertise(sd_dhcp6_client *client,
                                    DHCP6Message *advertise, size_t len) {
        int r;
        _cleanup_dhcp6_lease_free_ sd_dhcp6_lease *lease = NULL;
        uint8_t pref_advertise = 0, pref_lease = 0;

        if (advertise->type != DHCP6_ADVERTISE)
                return 0;

        r = dhcp6_lease_new(&lease);
        if (r < 0)
                return r;

        r = client_parse_message(client, advertise, len, lease);
        if (r < 0)
                return r;

        r = dhcp6_lease_get_preference(lease, &pref_advertise);
        if (r < 0)
                return r;

        r = dhcp6_lease_get_preference(client->lease, &pref_lease);

        if (r < 0 || pref_advertise > pref_lease) {
                sd_dhcp6_lease_unref(client->lease);
                client->lease = lease;
                lease = NULL;
                r = 0;
        }

        if (pref_advertise == 255 || client->retransmit_count > 1)
                r = DHCP6_STATE_REQUEST;

        return r;
}

static int client_receive_message(sd_event_source *s, int fd, uint32_t revents,
                                  void *userdata) {
        sd_dhcp6_client *client = userdata;
        DHCP6_CLIENT_DONT_DESTROY(client);
        _cleanup_free_ DHCP6Message *message;
        int r, buflen, len;

        assert(s);
        assert(client);
        assert(client->event);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0 || buflen <= 0)
                buflen = DHCP6_MIN_OPTIONS_SIZE;

        message = malloc0(buflen);
        if (!message)
                return -ENOMEM;

        len = read(fd, message, buflen);
        if ((size_t)len < sizeof(DHCP6Message)) {
                log_dhcp6_client(client, "could not receive message from UDP socket: %m");
                return 0;
        }

        switch(message->type) {
        case DHCP6_SOLICIT:
        case DHCP6_REQUEST:
        case DHCP6_CONFIRM:
        case DHCP6_RENEW:
        case DHCP6_REBIND:
        case DHCP6_RELEASE:
        case DHCP6_DECLINE:
        case DHCP6_INFORMATION_REQUEST:
        case DHCP6_RELAY_FORW:
        case DHCP6_RELAY_REPL:
                return 0;

        case DHCP6_ADVERTISE:
        case DHCP6_REPLY:
        case DHCP6_RECONFIGURE:
                break;

        default:
                log_dhcp6_client(client, "unknown message type %d",
                                 message->type);
                return 0;
        }

        if (client->transaction_id != (message->transaction_id &
                                       htobe32(0x00ffffff)))
                return 0;

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                r = client_receive_reply(client, message, len);
                if (r < 0)
                        return 0;

                client_notify(client, DHCP6_EVENT_INFORMATION_REQUEST);

                client_start(client, DHCP6_STATE_STOPPED);

                break;

        case DHCP6_STATE_SOLICITATION:
                r = client_receive_advertise(client, message, len);

                if (r == DHCP6_STATE_REQUEST) {
                        client_start(client, r);

                        break;
                }

                /* fall through for Soliciation Rapid Commit option check */
        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:
        case DHCP6_STATE_REBIND:

                r = client_receive_reply(client, message, len);
                if (r < 0)
                        return 0;

                if (r == DHCP6_STATE_BOUND) {

                        r = client_start(client, DHCP6_STATE_BOUND);
                        if (r < 0) {
                                client_stop(client, r);
                                return 0;
                        }

                        client_notify(client, DHCP6_EVENT_IP_ACQUIRE);
                }

                break;

        case DHCP6_STATE_BOUND:

                break;

        case DHCP6_STATE_STOPPED:
                return 0;
        }

        if (r >= 0) {
                log_dhcp6_client(client, "Recv %s",
                                 dhcp6_message_type_to_string(message->type));
        }

        return 0;
}

static int client_start(sd_dhcp6_client *client, enum DHCP6State state)
{
        int r;
        usec_t timeout, time_now;
        char time_string[FORMAT_TIMESPAN_MAX];

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->index > 0, -EINVAL);
        assert_return(client->state != state, -EINVAL);

        client->timeout_resend_expire =
                sd_event_source_unref(client->timeout_resend_expire);
        client->timeout_resend = sd_event_source_unref(client->timeout_resend);
        client->retransmit_time = 0;
        client->retransmit_count = 0;

        r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return r;

        switch (state) {
        case DHCP6_STATE_STOPPED:
                if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                        client->state = DHCP6_STATE_STOPPED;

                        return 0;
                }

                /* fall through */
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

                if (client->lease->ia.lifetime_t1 == 0xffffffff ||
                    client->lease->ia.lifetime_t2 == 0xffffffff) {

                        log_dhcp6_client(client, "infinite T1 0x%08x or T2 0x%08x",
                                         be32toh(client->lease->ia.lifetime_t1),
                                         be32toh(client->lease->ia.lifetime_t2));

                        return 0;
                }

                timeout = client_timeout_compute_random(be32toh(client->lease->ia.lifetime_t1) * USEC_PER_SEC);

                log_dhcp6_client(client, "T1 expires in %s",
                                 format_timespan(time_string,
                                                 FORMAT_TIMESPAN_MAX,
                                                 timeout, 0));

                r = sd_event_add_time(client->event,
                                      &client->lease->ia.timeout_t1,
                                      clock_boottime_or_monotonic(), time_now + timeout,
                                      10 * USEC_PER_SEC, client_timeout_t1,
                                      client);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(client->lease->ia.timeout_t1,
                                                 client->event_priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_description(client->lease->ia.timeout_t1, "dhcp6-t1-timeout");
                if (r < 0)
                        return r;

                timeout = client_timeout_compute_random(be32toh(client->lease->ia.lifetime_t2) * USEC_PER_SEC);

                log_dhcp6_client(client, "T2 expires in %s",
                                 format_timespan(time_string,
                                                 FORMAT_TIMESPAN_MAX,
                                                 timeout, 0));

                r = sd_event_add_time(client->event,
                                      &client->lease->ia.timeout_t2,
                                      clock_boottime_or_monotonic(), time_now + timeout,
                                      10 * USEC_PER_SEC, client_timeout_t2,
                                      client);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(client->lease->ia.timeout_t2,
                                                 client->event_priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_description(client->lease->ia.timeout_t2, "dhcp6-t2-timeout");
                if (r < 0)
                        return r;

                client->state = state;

                return 0;
        }

        client->transaction_id = random_u32() & htobe32(0x00ffffff);
        client->transaction_start = time_now;

        r = sd_event_add_time(client->event, &client->timeout_resend,
                              clock_boottime_or_monotonic(), 0, 0, client_timeout_resend,
                              client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_resend,
                                         client->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(client->timeout_resend, "dhcp6-resend-timeout");
        if (r < 0)
                return r;

        return 0;
}

int sd_dhcp6_client_stop(sd_dhcp6_client *client)
{
        client_stop(client, DHCP6_EVENT_STOP);

        return 0;
}

int sd_dhcp6_client_start(sd_dhcp6_client *client)
{
        int r = 0;
        enum DHCP6State state = DHCP6_STATE_SOLICITATION;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->index > 0, -EINVAL);

        r = client_reset(client);
        if (r < 0)
                return r;

        r = client_ensure_iaid(client);
        if (r < 0)
                return r;

        r = client_ensure_duid(client);
        if (r < 0)
                return r;

        r = dhcp6_network_bind_udp_socket(client->index, NULL);
        if (r < 0)
                return r;

        client->fd = r;

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

        if (client->information_request)
                state = DHCP6_STATE_INFORMATION_REQUEST;

        log_dhcp6_client(client, "Started in %s mode",
                        client->information_request? "Information request":
                        "Managed");

        return client_start(client, state);

error:
        client_reset(client);
        return r;
}

int sd_dhcp6_client_attach_event(sd_dhcp6_client *client, sd_event *event,
                                 int priority)
{
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
        if (!client)
                return NULL;

        return client->event;
}

sd_dhcp6_client *sd_dhcp6_client_ref(sd_dhcp6_client *client) {
        if (client)
                assert_se(REFCNT_INC(client->n_ref) >= 2);

        return client;
}

sd_dhcp6_client *sd_dhcp6_client_unref(sd_dhcp6_client *client) {
        if (client && REFCNT_DEC(client->n_ref) == 0) {
                client_reset(client);

                sd_dhcp6_client_detach_event(client);
                sd_dhcp6_lease_unref(client->lease);

                free(client->req_opts);
                free(client);

                return NULL;
        }

        return client;
}

int sd_dhcp6_client_new(sd_dhcp6_client **ret)
{
        _cleanup_dhcp6_client_unref_ sd_dhcp6_client *client = NULL;
        size_t t;

        assert_return(ret, -EINVAL);

        client = new0(sd_dhcp6_client, 1);
        if (!client)
                return -ENOMEM;

        client->n_ref = REFCNT_INIT;

        client->ia_na.type = DHCP6_OPTION_IA_NA;

        client->index = -1;

        client->fd = -1;

        client->req_opts_len = ELEMENTSOF(default_req_opts);

        client->req_opts = new0(be16_t, client->req_opts_len);
        if (!client->req_opts)
                return -ENOMEM;

        for (t = 0; t < client->req_opts_len; t++)
                client->req_opts[t] = htobe16(default_req_opts[t]);

        *ret = client;
        client = NULL;

        return 0;
}

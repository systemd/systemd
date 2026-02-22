/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <linux/if_addr.h>
#include <stdio.h>

#include "sd-dhcp6-protocol.h"

#include "conf-parser.h"
#include "dhcp6-client-internal.h"
#include "dhcp6-lease-internal.h"
#include "errno-util.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "networkd-address.h"
#include "networkd-dhcp-prefix-delegation.h"
#include "networkd-dhcp6.h"
#include "networkd-dhcp6-bus.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-ntp.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-state-file.h"
#include "networkd-wwan.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"

bool link_dhcp6_with_address_enabled(Link *link) {
        if (!link_dhcp6_enabled(link))
                return false;

        return link->network->dhcp6_use_address;
}

static DHCP6ClientStartMode link_get_dhcp6_client_start_mode(Link *link) {
        assert(link);

        if (!link->network)
                return DHCP6_CLIENT_START_MODE_NO;

        /* When WithoutRA= is explicitly specified, then honor it. */
        if (link->network->dhcp6_client_start_mode >= 0)
                return link->network->dhcp6_client_start_mode;

        /* When this interface itself is an uplink interface, then start dhcp6 client in solicit mode. */
        if (dhcp_pd_is_uplink(link, link, /* accept_auto= */ false))
                return DHCP6_CLIENT_START_MODE_SOLICIT;

        /* Otherwise, start dhcp6 client when RA is received. */
        return DHCP6_CLIENT_START_MODE_NO;
}

static int dhcp6_remove(Link *link, bool only_marked) {
        Address *address;
        Route *route;
        int ret = 0;

        assert(link);
        assert(link->manager);

        if (!only_marked)
                link->dhcp6_configured = false;

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_DHCP6)
                        continue;
                if (only_marked && !route_is_marked(route))
                        continue;

                RET_GATHER(ret, route_remove_and_cancel(route, link->manager));
        }

        SET_FOREACH(address, link->addresses) {
                if (address->source != NETWORK_CONFIG_SOURCE_DHCP6)
                        continue;
                if (only_marked && !address_is_marked(address))
                        continue;

                RET_GATHER(ret, address_remove_and_cancel(address, link));
        }

        return ret;
}

static int dhcp6_address_ready_callback(Address *address) {
        Address *a;

        assert(address);
        assert(address->link);

        SET_FOREACH(a, address->link->addresses)
                if (a->source == NETWORK_CONFIG_SOURCE_DHCP6)
                        a->callback = NULL;

        return dhcp6_check_ready(address->link);
}

int dhcp6_check_ready(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp6_messages > 0) {
                log_link_debug(link, "%s(): DHCPv6 addresses and routes are not set.", __func__);
                return 0;
        }

        if (link->network->dhcp6_use_address &&
            sd_dhcp6_lease_has_address(link->dhcp6_lease) &&
            !link_check_addresses_ready(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                Address *address;

                SET_FOREACH(address, link->addresses)
                        if (address->source == NETWORK_CONFIG_SOURCE_DHCP6)
                                address->callback = dhcp6_address_ready_callback;

                log_link_debug(link, "%s(): no DHCPv6 address is ready.", __func__);
                return 0;
        }

        link->dhcp6_configured = true;
        log_link_debug(link, "DHCPv6 addresses and routes set.");

        r = dhcp6_remove(link, /* only_marked= */ true);
        if (r < 0)
                return r;

        r = link_request_stacked_netdevs(link, NETDEV_LOCAL_ADDRESS_DHCP6);
        if (r < 0)
                return r;

        link_check_ready(link);
        return 0;
}

static int dhcp6_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);
        assert(address);

        r = address_configure_handler_internal(m, link, address);
        if (r <= 0)
                return r;

        r = dhcp6_check_ready(link);
        if (r < 0)
                link_enter_failed(link);

        return 1;
}

static int verify_dhcp6_address(Link *link, const Address *address) {
        assert(link);
        assert(address);
        assert(address->family == AF_INET6);

        Address *existing = NULL;
        (void) address_get_harder(link, address, &existing);

        if (!existing || address_can_update(existing, address)) {
                log_link_full(link,
                              /* Downgrade the log level if the address already exists or has been requested. */
                              existing ? LOG_DEBUG : LOG_INFO,
                              "DHCPv6 address %s (valid %s, preferred %s)",
                              IN6_ADDR_PREFIX_TO_STRING(&address->in_addr.in6, address->prefixlen),
                              FORMAT_LIFETIME(address->lifetime_valid_usec),
                              FORMAT_LIFETIME(address->lifetime_preferred_usec));
                return 0;
        }

        bool by_ndisc = existing->source == NETWORK_CONFIG_SOURCE_NDISC;

        log_link_full(link,
                      /* Downgrade the log level if we have logged about the conflict previously. */
                      existing->also_requested_by_dhcp6 ? LOG_DEBUG : LOG_WARNING,
                      "Ignoring DHCPv6 address %s (valid %s, preferred %s) which conflicts with %s%s.%s",
                      IN6_ADDR_PREFIX_TO_STRING(&address->in_addr.in6, address->prefixlen),
                      FORMAT_LIFETIME(address->lifetime_valid_usec),
                      FORMAT_LIFETIME(address->lifetime_preferred_usec),
                      IN6_ADDR_PREFIX_TO_STRING(&existing->in_addr.in6, existing->prefixlen),
                      by_ndisc ? " assigned by NDisc" : "",
                      by_ndisc ? "\nHint: use IPv6Token= setting to change the address generated by NDisc or set UseAutonomousPrefix=no." : "");

        existing->also_requested_by_dhcp6 = true;
        return -EEXIST;
}

static int dhcp6_request_address(
                Link *link,
                const struct in6_addr *server_address,
                const struct in6_addr *ip6_addr,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        _cleanup_(address_unrefp) Address *addr = NULL;
        Address *existing;
        int r;

        r = address_new(&addr);
        if (r < 0)
                return log_oom();

        addr->source = NETWORK_CONFIG_SOURCE_DHCP6;
        addr->provider.in6 = *server_address;
        addr->family = AF_INET6;
        addr->in_addr.in6 = *ip6_addr;
        addr->flags = IFA_F_NOPREFIXROUTE;
        addr->prefixlen = 128;
        addr->lifetime_preferred_usec = lifetime_preferred_usec;
        addr->lifetime_valid_usec = lifetime_valid_usec;

        if (verify_dhcp6_address(link, addr) < 0)
                return 0;

        r = free_and_strdup_warn(&addr->netlabel, link->network->dhcp6_netlabel);
        if (r < 0)
                return r;

        if (address_get(link, addr, &existing) < 0)
                link->dhcp6_configured = false;
        else
                address_unmark(existing);

        r = link_request_address(link, addr, &link->dhcp6_messages,
                                 dhcp6_address_handler, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to request DHCPv6 address %s/128: %m",
                                            IN6_ADDR_TO_STRING(ip6_addr));
        return 0;
}

static int dhcp6_address_acquired(Link *link) {
        struct in6_addr server_address;
        int r;

        assert(link);
        assert(link->network);
        assert(link->dhcp6_lease);

        if (!link->network->dhcp6_use_address)
                return 0;

        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &server_address);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to get server address of DHCPv6 lease: %m");

        FOREACH_DHCP6_ADDRESS(link->dhcp6_lease) {
                usec_t lifetime_preferred_usec, lifetime_valid_usec;
                struct in6_addr ip6_addr;

                r = sd_dhcp6_lease_get_address(link->dhcp6_lease, &ip6_addr);
                if (r < 0)
                        return r;

                r = sd_dhcp6_lease_get_address_lifetime_timestamp(link->dhcp6_lease, CLOCK_BOOTTIME,
                                                                  &lifetime_preferred_usec, &lifetime_valid_usec);
                if (r < 0)
                        return r;

                r = dhcp6_request_address(link, &server_address, &ip6_addr,
                                          lifetime_preferred_usec,
                                          lifetime_valid_usec);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dhcp6_request_hostname(Link *link) {
        _cleanup_free_ char *hostname = NULL;
        const char *dhcpname = NULL;
        int r;

        assert(link);
        assert(link->network);

        if (!link->network->dhcp6_use_hostname)
                return 0;

        r = sd_dhcp6_lease_get_fqdn(link->dhcp6_lease, &dhcpname);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = shorten_overlong(dhcpname, &hostname);
        if (r < 0)
                return log_link_warning_errno(link, r, "Unable to shorten overlong DHCP hostname '%s': %m", dhcpname);
        if (r == 1)
                log_link_notice(link, "Overlong DHCP hostname received, shortened from '%s' to '%s'", dhcpname, hostname);

        r = manager_set_hostname(link->manager, hostname);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to set transient hostname to '%s', ignoring: %m", hostname);

        return 0;
}

static int dhcp6_lease_ip_acquired(sd_dhcp6_client *client, Link *link) {
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease_old = NULL;
        sd_dhcp6_lease *lease;
        int r;

        link_mark_addresses(link, NETWORK_CONFIG_SOURCE_DHCP6);

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DHCPv6 lease: %m");

        lease_old = TAKE_PTR(link->dhcp6_lease);
        link->dhcp6_lease = sd_dhcp6_lease_ref(lease);

        r = dhcp6_request_hostname(link);
        if (r < 0)
                return r;

        r = dhcp6_address_acquired(link);
        if (r < 0)
                return r;

        if (sd_dhcp6_lease_has_pd_prefix(lease)) {
                r = dhcp6_pd_prefix_acquired(link);
                if (r < 0)
                        return r;
        } else if (sd_dhcp6_lease_has_pd_prefix(lease_old))
                /* When we had PD prefixes but not now, we need to remove them. */
                dhcp6_pd_prefix_lost(link);

        if (link->dhcp6_messages == 0) {
                link->dhcp6_configured = true;

                r = dhcp6_remove(link, /* only_marked= */ true);
                if (r < 0)
                        return r;
        } else
                log_link_debug(link, "Setting DHCPv6 addresses and routes");

        if (!link->dhcp6_configured)
                link_set_state(link, LINK_STATE_CONFIGURING);

        link_check_ready(link);
        return 0;
}

static int dhcp6_lease_information_acquired(sd_dhcp6_client *client, Link *link) {
        sd_dhcp6_lease *lease;
        int r;

        assert(client);
        assert(link);

        r = sd_dhcp6_client_get_lease(client, &lease);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to get DHCPv6 lease: %m");

        unref_and_replace_full(link->dhcp6_lease, lease, sd_dhcp6_lease_ref, sd_dhcp6_lease_unref);

        link_dirty(link);
        return 0;
}

static int dhcp6_lease_lost(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        if (!link->dhcp6_lease)
                return 0;

        log_link_info(link, "DHCPv6 lease lost");

        if (sd_dhcp6_lease_has_pd_prefix(link->dhcp6_lease))
                dhcp6_pd_prefix_lost(link);

        link->dhcp6_lease = sd_dhcp6_lease_unref(link->dhcp6_lease);

        r = dhcp6_remove(link, /* only_marked= */ false);
        if (r < 0)
                return r;

        return 0;
}

static void dhcp6_handler(sd_dhcp6_client *client, int event, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        int r = 0;

        assert(link->network);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        switch (event) {
        case SD_DHCP6_CLIENT_EVENT_STOP:
        case SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE:
        case SD_DHCP6_CLIENT_EVENT_RETRANS_MAX:
                r = dhcp6_lease_lost(link);
                break;

        case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
                r = dhcp6_lease_ip_acquired(client, link);
                break;

        case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
                r = dhcp6_lease_information_acquired(client, link);
                break;

        default:
                if (event < 0)
                        log_link_warning_errno(link, event, "DHCPv6 error, ignoring: %m");
                else
                        log_link_warning(link, "DHCPv6 unknown event: %d", event);
        }
        if (r < 0)
                link_enter_failed(link);
}

int dhcp6_start_on_ra(Link *link, bool information_request) {
        int r;

        assert(link);
        assert(link->dhcp6_client);
        assert(link->network);
        assert(in6_addr_is_link_local(&link->ipv6ll_address));

        if (link_get_dhcp6_client_start_mode(link) != DHCP6_CLIENT_START_MODE_NO)
                /* When WithoutRA= is specified, then the DHCPv6 client should be already running in
                 * the requested mode. Hence, ignore the requests by RA. */
                return 0;

        r = sd_dhcp6_client_is_running(link->dhcp6_client);
        if (r < 0)
                return r;

        if (r > 0) {
                int inf_req;

                r = sd_dhcp6_client_get_information_request(link->dhcp6_client, &inf_req);
                if (r < 0)
                        return r;

                if (inf_req == information_request)
                        /* The client is already running in the requested mode. */
                        return 0;

                if (!inf_req) {
                        log_link_debug(link,
                                       "The DHCPv6 client is already running in the managed mode, "
                                       "refusing to start the client in the information requesting mode.");
                        return 0;
                }

                log_link_debug(link,
                               "The DHCPv6 client is running in the information requesting mode. "
                               "Restarting the client in the managed mode.");

                r = sd_dhcp6_client_stop(link->dhcp6_client);
                if (r < 0)
                        return r;
        } else {
                r = sd_dhcp6_client_set_local_address(link->dhcp6_client, &link->ipv6ll_address);
                if (r < 0)
                        return r;
        }

        r = sd_dhcp6_client_set_information_request(link->dhcp6_client, information_request);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_start(link->dhcp6_client);
        if (r < 0)
                return r;

        return 0;
}

int dhcp6_start(Link *link) {
        DHCP6ClientStartMode start_mode;
        int r;

        assert(link);
        assert(link->network);

        if (!link->dhcp6_client)
                return 0;

        if (!link_dhcp6_enabled(link))
                return 0;

        if (link_dhcp_enabled_by_bearer(link, AF_INET6) == 0)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp6_client_is_running(link->dhcp6_client) > 0)
                return 0;

        if (!in6_addr_is_link_local(&link->ipv6ll_address)) {
                log_link_debug(link, "IPv6 link-local address is not set, delaying to start DHCPv6 client.");
                return 0;
        }

        r = sd_dhcp6_client_set_local_address(link->dhcp6_client, &link->ipv6ll_address);
        if (r < 0)
                return r;

        start_mode = link_get_dhcp6_client_start_mode(link);
        if (start_mode == DHCP6_CLIENT_START_MODE_NO)
                return 0;

        r = sd_dhcp6_client_set_information_request(link->dhcp6_client,
                                                    start_mode == DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_start(link->dhcp6_client);
        if (r < 0)
                return r;

        return 1;
}

static int dhcp6_set_hostname(sd_dhcp6_client *client, Link *link) {
        _cleanup_free_ char *hostname = NULL;
        const char *hn;
        int r;

        assert(link);

        if (!link->network->dhcp6_send_hostname)
                hn = NULL;
        else if (link->network->dhcp6_hostname)
                hn = link->network->dhcp6_hostname;
        else {
                r = gethostname_strict(&hostname);
                if (r < 0 && r != -ENXIO) /* ENXIO: no hostname set or hostname is "localhost" */
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to get hostname: %m");

                hn = hostname;
        }

        r = sd_dhcp6_client_set_fqdn(client, hn);
        if (r == -EINVAL && hostname)
                /* Ignore error when the machine's hostname is not suitable to send in DHCP packet. */
                log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set hostname from kernel hostname, ignoring: %m");
        else if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set hostname: %m");

        return 0;
}

static int dhcp6_set_identifier(Link *link, sd_dhcp6_client *client) {
        const DUID *duid;
        int r;

        assert(link);
        assert(link->network);
        assert(client);

        r = sd_dhcp6_client_set_mac(client, link->hw_addr.bytes, link->hw_addr.length, link->iftype);
        if (r < 0)
                return r;

        if (link->network->dhcp6_iaid_set) {
                r = sd_dhcp6_client_set_iaid(client, link->network->dhcp6_iaid);
                if (r < 0)
                        return r;
        }

        duid = link_get_dhcp6_duid(link);

        if (duid->raw_data_len == 0)
                switch (duid->type) {
                case DUID_TYPE_LLT:
                        r = sd_dhcp6_client_set_duid_llt(client, duid->llt_time);
                        break;
                case DUID_TYPE_LL:
                        r = sd_dhcp6_client_set_duid_ll(client);
                        break;
                case DUID_TYPE_EN:
                        r = sd_dhcp6_client_set_duid_en(client);
                        break;
                case DUID_TYPE_UUID:
                        r = sd_dhcp6_client_set_duid_uuid(client);
                        break;
                default:
                        r = sd_dhcp6_client_set_duid_raw(client, duid->type, NULL, 0);
                }
        else
                r = sd_dhcp6_client_set_duid_raw(client, duid->type, duid->raw_data, duid->raw_data_len);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp6_configure(Link *link) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        sd_dhcp6_option *vendor_option;
        sd_dhcp6_option *send_option;
        void *request_options;
        int r;

        assert(link);
        assert(link->network);

        if (link->dhcp6_client)
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EBUSY), "DHCPv6 client is already configured.");

        r = sd_dhcp6_client_new(&client);
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to create DHCPv6 client: %m");

        r = sd_dhcp6_client_attach_event(client, link->manager->event, 0);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to attach event: %m");

        r = sd_dhcp6_client_attach_device(client, link->dev);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to attach device: %m");

        r = dhcp6_set_identifier(link, client);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set identifier: %m");

        ORDERED_HASHMAP_FOREACH(send_option, link->network->dhcp6_client_send_options) {
                r = sd_dhcp6_client_add_option(client, send_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set option: %m");
        }

        r = dhcp6_set_hostname(client, link);
        if (r < 0)
                return r;

        r = sd_dhcp6_client_set_ifindex(client, link->ifindex);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set ifindex: %m");

        if (link->network->dhcp6_mudurl) {
                r = sd_dhcp6_client_set_request_mud_url(client, link->network->dhcp6_mudurl);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set MUD URL: %m");
        }

        if (link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVER);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request DNS servers: %m");
        }

        if (link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP6) > 0) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DOMAIN);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request domains: %m");
        }

        if (link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_V6_DNR);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request DNR: %m");
        }

        if (link->network->dhcp6_use_captive_portal > 0) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_CAPTIVE_PORTAL);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request captive portal: %m");
        }

        if (link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NTP_SERVER);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request NTP servers: %m");

                /* If the server does not provide NTP servers, then we fallback to use SNTP servers. */
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SNTP_SERVER);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request SNTP servers: %m");
        }

        if (link->network->dhcp6_use_sip > 0) {
                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SIP_SERVER_ADDRESS);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request SIP servers: %m");

                r = sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to request SIP server domain names: %m");
        }

        SET_FOREACH(request_options, link->network->dhcp6_request_options) {
                uint32_t option = PTR_TO_UINT32(request_options);

                r = sd_dhcp6_client_set_request_option(client, option);
                if (r == -EEXIST) {
                        log_link_debug(link, "DHCPv6 CLIENT: Failed to set request flag for '%u' already exists, ignoring.", option);
                        continue;
                }
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set request flag for '%u': %m", option);
        }

        if (link->network->dhcp6_user_class) {
                r = sd_dhcp6_client_set_request_user_class(client, link->network->dhcp6_user_class);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set user class: %m");
        }

        if (link->network->dhcp6_vendor_class) {
                r = sd_dhcp6_client_set_request_vendor_class(client, link->network->dhcp6_vendor_class);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set vendor class: %m");
        }

        ORDERED_HASHMAP_FOREACH(vendor_option, link->network->dhcp6_client_send_vendor_options) {
                r = sd_dhcp6_client_add_vendor_option(client, vendor_option);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set vendor option: %m");
        }

        r = sd_dhcp6_client_set_callback(client, dhcp6_handler, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set callback: %m");

        r = dhcp6_client_set_state_callback(client, dhcp6_client_callback_bus, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set state change callback: %m");

        r = sd_dhcp6_client_set_prefix_delegation(client, link->network->dhcp6_use_pd_prefix);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to %s requesting prefixes to be delegated: %m",
                                            enable_disable(link->network->dhcp6_use_pd_prefix));

        /* Even if UseAddress=no, we need to request IA_NA, as the dhcp6 client may be started in solicit mode. */
        r = sd_dhcp6_client_set_address_request(client, link->network->dhcp6_use_pd_prefix ? link->network->dhcp6_use_address : true);
        if (r < 0)
                return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to %s requesting address: %m",
                                            enable_disable(link->network->dhcp6_use_address));

        if (link->network->dhcp6_pd_prefix_length > 0) {
                r = sd_dhcp6_client_set_prefix_delegation_hint(client,
                                                               link->network->dhcp6_pd_prefix_length,
                                                               &link->network->dhcp6_pd_prefix_hint);
                if (r < 0)
                        return log_link_debug_errno(link, r, "DHCPv6 CLIENT: Failed to set prefix delegation hint: %m");
        }

        r = sd_dhcp6_client_set_rapid_commit(client, link->network->dhcp6_use_rapid_commit);
        if (r < 0)
                return log_link_debug_errno(link, r,
                                            "DHCPv6 CLIENT: Failed to %s rapid commit: %m",
                                            enable_disable(link->network->dhcp6_use_rapid_commit));

        r = sd_dhcp6_client_set_send_release(client, link->network->dhcp6_send_release);
        if (r < 0)
                return log_link_debug_errno(link, r,
                                            "DHCPv6 CLIENT: Failed to %s sending release message on stop: %m",
                                            enable_disable(link->network->dhcp6_send_release));

        link->dhcp6_client = TAKE_PTR(client);

        return 0;
}

int dhcp6_update_mac(Link *link) {
        bool restart;
        int r;

        assert(link);

        if (!link->dhcp6_client)
                return 0;

        restart = sd_dhcp6_client_is_running(link->dhcp6_client) > 0;

        if (restart) {
                r = sd_dhcp6_client_stop(link->dhcp6_client);
                if (r < 0)
                        return r;
        }

        r = dhcp6_set_identifier(link, link->dhcp6_client);
        if (r < 0)
                return r;

        if (restart) {
                r = sd_dhcp6_client_start(link->dhcp6_client);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not restart DHCPv6 client: %m");
        }

        return 0;
}

static int dhcp6_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged= */ false))
                return 0;

        r = dhcp_configure_duid(link, link_get_dhcp6_duid(link));
        if (r <= 0)
                return r;

        r = dhcp6_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure DHCPv6 client: %m");

        r = ndisc_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start IPv6 Router Discovery: %m");

        r = dhcp6_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start DHCPv6 client: %m");

        log_link_debug(link, "DHCPv6 client is configured%s.",
                       r > 0 ? ", acquiring DHCPv6 lease" : "");
        return 1;
}

int link_request_dhcp6_client(Link *link) {
        int r;

        assert(link);

        if (!link_dhcp6_enabled(link) && !link_ndisc_enabled(link))
                return 0;

        if (link->dhcp6_client)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_DHCP6_CLIENT, dhcp6_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the DHCPv6 client: %m");

        log_link_debug(link, "Requested configuring of the DHCPv6 client.");
        return 0;
}

int link_drop_dhcp6_config(Link *link, Network *network) {
        int ret = 0;

        assert(link);
        assert(link->network);

        if (link->network == network)
                return 0; /* .network file is unchanged. It is not necessary to reconfigure the client. */

        if (!link_dhcp6_enabled(link)) {
                /* DHCPv6 client is disabled. Stop the client if it is running and drop the lease. */
                ret = sd_dhcp6_client_stop(link->dhcp6_client);

                /* Also explicitly drop DHCPv6 addresses and routes. See also link_drop_dhcp4_config(). */
                RET_GATHER(ret, dhcp6_remove(link, /* only_marked= */ false));
        }

        /* Even if the client is currently enabled and also enabled in the new .network file, detailed
         * settings for the client may be different. Let's unref() the client. But do not unref() the lease.
         * it will be unref()ed later when a new lease is acquired. */
        link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
        return ret;
}

int link_serialize_dhcp6_client(Link *link, FILE *f) {
        _cleanup_free_ char *duid = NULL;
        uint32_t iaid;
        int r;

        assert(link);

        if (!link->dhcp6_client)
                return 0;

        r = sd_dhcp6_client_get_iaid(link->dhcp6_client, &iaid);
        if (r >= 0)
                fprintf(f, "DHCP6_CLIENT_IAID=0x%x\n", iaid);

        r = sd_dhcp6_client_get_duid_as_string(link->dhcp6_client, &duid);
        if (r >= 0)
                fprintf(f, "DHCP6_CLIENT_DUID=%s\n", duid);

        return 0;
}

int config_parse_dhcp6_pd_prefix_hint(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        union in_addr_union u;
        unsigned char prefixlen;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &u, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=%s, ignoring assignment.", lvalue, rvalue);
                return 0;
        }

        if (prefixlen < 1 || prefixlen > 128) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid prefix length in %s=%s, ignoring assignment.", lvalue, rvalue);
                return 0;
        }

        network->dhcp6_pd_prefix_hint = u.in6;
        network->dhcp6_pd_prefix_length = prefixlen;

        return 0;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_dhcp6_client_start_mode, dhcp6_client_start_mode, DHCP6ClientStartMode);

static const char* const dhcp6_client_start_mode_table[_DHCP6_CLIENT_START_MODE_MAX] = {
        [DHCP6_CLIENT_START_MODE_NO]                  = "no",
        [DHCP6_CLIENT_START_MODE_INFORMATION_REQUEST] = "information-request",
        [DHCP6_CLIENT_START_MODE_SOLICIT]             = "solicit",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_client_start_mode, DHCP6ClientStartMode);

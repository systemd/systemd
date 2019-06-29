/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-dhcp-server.h"

#include "networkd-dhcp-server.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "strv.h"

static Address* link_find_dhcp_server_address(Link *link) {
        Address *address;

        assert(link);
        assert(link->network);

        /* The first statically configured address if there is any */
        LIST_FOREACH(addresses, address, link->network->static_addresses) {

                if (address->family != AF_INET)
                        continue;

                if (in_addr_is_null(address->family, &address->in_addr))
                        continue;

                return address;
        }

        /* If that didn't work, find a suitable address we got from the pool */
        LIST_FOREACH(addresses, address, link->pool_addresses) {
                if (address->family != AF_INET)
                        continue;

                return address;
        }

        return NULL;
}

static int link_push_uplink_dns_to_dhcp_server(Link *link, sd_dhcp_server *s) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;
        unsigned i;

        log_debug("Copying DNS server information from %s", link->ifname);

        if (!link->network)
                return 0;

        for (i = 0; i < link->network->n_dns; i++) {
                struct in_addr ia;

                /* Only look for IPv4 addresses */
                if (link->network->dns[i].family != AF_INET)
                        continue;

                ia = link->network->dns[i].address.in;

                /* Never propagate obviously borked data */
                if (in4_addr_is_null(&ia) || in4_addr_is_localhost(&ia))
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return log_oom();

                addresses[n_addresses++] = ia;
        }

        if (link->network->dhcp_use_dns && link->dhcp_lease) {
                const struct in_addr *da = NULL;
                int j, n;

                n = sd_dhcp_lease_get_dns(link->dhcp_lease, &da);
                if (n > 0) {

                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + n))
                                return log_oom();

                        for (j = 0; j < n; j++)
                                if (in4_addr_is_non_local(&da[j]))
                                        addresses[n_addresses++] = da[j];
                }
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_dns(s, addresses, n_addresses);
}

static int link_push_uplink_ntp_to_dhcp_server(Link *link, sd_dhcp_server *s) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;
        char **a;

        if (!link->network)
                return 0;

        log_debug("Copying NTP server information from %s", link->ifname);

        STRV_FOREACH(a, link->network->ntp) {
                union in_addr_union ia;

                /* Only look for IPv4 addresses */
                if (in_addr_from_string(AF_INET, *a, &ia) <= 0)
                        continue;

                /* Never propagate obviously borked data */
                if (in4_addr_is_null(&ia.in) || in4_addr_is_localhost(&ia.in))
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return log_oom();

                addresses[n_addresses++] = ia.in;
        }

        if (link->network->dhcp_use_ntp && link->dhcp_lease) {
                const struct in_addr *da = NULL;
                int j, n;

                n = sd_dhcp_lease_get_ntp(link->dhcp_lease, &da);
                if (n > 0) {

                        if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + n))
                                return log_oom();

                        for (j = 0; j < n; j++)
                                if (in4_addr_is_non_local(&da[j]))
                                        addresses[n_addresses++] = da[j];
                }
        }

        if (n_addresses <= 0)
                return 0;

        return sd_dhcp_server_set_ntp(s, addresses, n_addresses);
}

int dhcp4_server_configure(Link *link) {
        Address *address;
        Link *uplink = NULL;
        bool acquired_uplink = false;
        int r;

        address = link_find_dhcp_server_address(link);
        if (!address)
                return log_link_warning_errno(link, SYNTHETIC_ERRNO(EBUSY),
                                              "Failed to find suitable address for DHCPv4 server instance.");

        /* use the server address' subnet as the pool */
        r = sd_dhcp_server_configure_pool(link->dhcp_server, &address->in_addr.in, address->prefixlen,
                                          link->network->dhcp_server_pool_offset, link->network->dhcp_server_pool_size);
        if (r < 0)
                return r;

        /* TODO:
        r = sd_dhcp_server_set_router(link->dhcp_server, &main_address->in_addr.in);
        if (r < 0)
                return r;
        */

        if (link->network->dhcp_server_max_lease_time_usec > 0) {
                r = sd_dhcp_server_set_max_lease_time(link->dhcp_server,
                                                      DIV_ROUND_UP(link->network->dhcp_server_max_lease_time_usec, USEC_PER_SEC));
                if (r < 0)
                        return r;
        }

        if (link->network->dhcp_server_default_lease_time_usec > 0) {
                r = sd_dhcp_server_set_default_lease_time(link->dhcp_server,
                                                          DIV_ROUND_UP(link->network->dhcp_server_default_lease_time_usec, USEC_PER_SEC));
                if (r < 0)
                        return r;
        }

        if (link->network->dhcp_server_emit_dns) {
                if (link->network->n_dhcp_server_dns > 0)
                        r = sd_dhcp_server_set_dns(link->dhcp_server, link->network->dhcp_server_dns, link->network->n_dhcp_server_dns);
                else {
                        uplink = manager_find_uplink(link->manager, link);
                        acquired_uplink = true;

                        if (!uplink) {
                                log_link_debug(link, "Not emitting DNS server information on link, couldn't find suitable uplink.");
                                r = 0;
                        } else
                                r = link_push_uplink_dns_to_dhcp_server(uplink, link->dhcp_server);
                }
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to set DNS server for DHCP server, ignoring: %m");
        }

        if (link->network->dhcp_server_emit_ntp) {
                if (link->network->n_dhcp_server_ntp > 0)
                        r = sd_dhcp_server_set_ntp(link->dhcp_server, link->network->dhcp_server_ntp, link->network->n_dhcp_server_ntp);
                else {
                        if (!acquired_uplink)
                                uplink = manager_find_uplink(link->manager, link);

                        if (!uplink) {
                                log_link_debug(link, "Not emitting NTP server information on link, couldn't find suitable uplink.");
                                r = 0;
                        } else
                                r = link_push_uplink_ntp_to_dhcp_server(uplink, link->dhcp_server);

                }
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to set NTP server for DHCP server, ignoring: %m");
        }

        r = sd_dhcp_server_set_emit_router(link->dhcp_server, link->network->dhcp_server_emit_router);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to set router emission for DHCP server: %m");

        if (link->network->dhcp_server_emit_timezone) {
                _cleanup_free_ char *buffer = NULL;
                const char *tz;

                if (link->network->dhcp_server_timezone)
                        tz = link->network->dhcp_server_timezone;
                else {
                        r = get_timezone(&buffer);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to determine timezone: %m");

                        tz = buffer;
                }

                r = sd_dhcp_server_set_timezone(link->dhcp_server, tz);
                if (r < 0)
                        return r;
        }
        if (!sd_dhcp_server_is_running(link->dhcp_server)) {
                r = sd_dhcp_server_start(link->dhcp_server);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not start DHCPv4 server instance: %m");
        }

        return 0;
}

int config_parse_dhcp_server_dns(
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

        Network *n = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                union in_addr_union a;
                struct in_addr *m;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = in_addr_from_string(AF_INET, w, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse DNS server address '%s', ignoring assignment: %m", w);
                        continue;
                }

                m = reallocarray(n->dhcp_server_dns, n->n_dhcp_server_dns + 1, sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                m[n->n_dhcp_server_dns++] = a.in;
                n->dhcp_server_dns = m;
        }

        return 0;
}

int config_parse_dhcp_server_ntp(
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

        Network *n = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                union in_addr_union a;
                struct in_addr *m;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET, w, &a);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse NTP server address '%s', ignoring: %m", w);
                        continue;
                }

                m = reallocarray(n->dhcp_server_ntp, n->n_dhcp_server_ntp + 1, sizeof(struct in_addr));
                if (!m)
                        return log_oom();

                m[n->n_dhcp_server_ntp++] = a.in;
                n->dhcp_server_ntp = m;
        }
}

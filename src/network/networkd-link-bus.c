/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>
#include <netinet/in.h>
#include <sys/capability.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-util.h"
#include "dns-domain.h"
#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "resolve-util.h"
#include "strv.h"
#include "user-util.h"

BUS_DEFINE_PROPERTY_GET_ENUM(property_get_operational_state, link_operstate, LinkOperationalState);
BUS_DEFINE_PROPERTY_GET_ENUM(property_get_carrier_state, link_carrier_state, LinkCarrierState);
BUS_DEFINE_PROPERTY_GET_ENUM(property_get_address_state, link_address_state, LinkAddressState);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_administrative_state, link_state, LinkState);

static int property_get_bit_rates(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Link *link = userdata;
        Manager *manager;
        double interval_sec;
        uint64_t tx, rx;

        assert(bus);
        assert(reply);
        assert(userdata);

        manager = link->manager;

        if (!manager->use_speed_meter)
                return sd_bus_error_set(error, BUS_ERROR_SPEED_METER_INACTIVE, "Speed meter is disabled.");

        if (manager->speed_meter_usec_old == 0)
                return sd_bus_error_set(error, BUS_ERROR_SPEED_METER_INACTIVE, "Speed meter is not active.");

        if (!link->stats_updated)
                return sd_bus_error_set(error, BUS_ERROR_SPEED_METER_INACTIVE, "Failed to measure bit-rates.");

        assert(manager->speed_meter_usec_new > manager->speed_meter_usec_old);
        interval_sec = (manager->speed_meter_usec_new - manager->speed_meter_usec_old) / USEC_PER_SEC;

        if (link->stats_new.tx_bytes > link->stats_old.tx_bytes)
                tx = (uint64_t) ((link->stats_new.tx_bytes - link->stats_old.tx_bytes) / interval_sec);
        else
                tx = (uint64_t) ((UINT64_MAX - (link->stats_old.tx_bytes - link->stats_new.tx_bytes)) / interval_sec);

        if (link->stats_new.rx_bytes > link->stats_old.rx_bytes)
                rx = (uint64_t) ((link->stats_new.rx_bytes - link->stats_old.rx_bytes) / interval_sec);
        else
                rx = (uint64_t) ((UINT64_MAX - (link->stats_old.rx_bytes - link->stats_new.rx_bytes)) / interval_sec);

        return sd_bus_message_append(reply, "(tt)", tx, rx);
}

static int verify_managed_link(Link *l, sd_bus_error *error) {
        assert(l);

        if (l->flags & IFF_LOOPBACK)
                return sd_bus_error_setf(error, BUS_ERROR_LINK_BUSY, "Link %s is loopback device.", l->ifname);

        return 0;
}

int bus_link_method_set_ntp_servers(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **ntp = NULL;
        Link *l = userdata;
        int r;
        char **i;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &ntp);
        if (r < 0)
                return r;

        STRV_FOREACH(i, ntp) {
                r = dns_name_is_valid_or_address(*i);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid NTP server: %s", *i);
        }

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-ntp-servers",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        strv_free_and_replace(l->ntp, ntp);

        (void) link_dirty(l);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ struct in_addr_data *dns = NULL;
        size_t allocated = 0, n = 0;
        Link *l = userdata;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, 'a', "(iay)");
        if (r < 0)
                return r;

        for (;;) {
                int family;
                size_t sz;
                const void *d;

                assert_cc(sizeof(int) == sizeof(int32_t));

                r = sd_bus_message_enter_container(message, 'r', "iay");
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = sd_bus_message_read(message, "i", &family);
                if (r < 0)
                        return r;

                if (!IN_SET(family, AF_INET, AF_INET6))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

                r = sd_bus_message_read_array(message, 'y', &d, &sz);
                if (r < 0)
                        return r;
                if (sz != FAMILY_ADDRESS_SIZE(family))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address size");

                if (!dns_server_address_valid(family, d))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid DNS server address");

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(dns, allocated, n+1))
                        return -ENOMEM;

                dns[n].family = family;
                memcpy(&dns[n].address, d, sz);
                n++;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-dns-servers",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        free_and_replace(l->dns, dns);
        l->n_dns = n;

        (void) link_dirty(l);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_domains(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(ordered_set_freep) OrderedSet *search_domains = NULL, *route_domains = NULL;
        Link *l = userdata;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, 'a', "(sb)");
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *str = NULL;
                OrderedSet **domains;
                const char *name;
                int route_only;

                r = sd_bus_message_read(message, "(sb)", &name, &route_only);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = dns_name_is_valid(name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid search domain %s", name);
                if (!route_only && dns_name_is_root(name))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Root domain is not suitable as search domain");

                r = dns_name_normalize(name, 0, &str);
                if (r < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid search domain %s", name);

                domains = route_only ? &route_domains : &search_domains;
                r = ordered_set_ensure_allocated(domains, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_set_put(*domains, str);
                if (r < 0)
                        return r;

                TAKE_PTR(str);
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-domains",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        ordered_set_free_free(l->search_domains);
        ordered_set_free_free(l->route_domains);
        l->search_domains = TAKE_PTR(search_domains);
        l->route_domains = TAKE_PTR(route_domains);

        (void) link_dirty(l);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_default_route(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        int r, b;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-default-route",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        if (l->dns_default_route != b) {
                l->dns_default_route = b;
                (void) link_dirty(l);
        }

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        ResolveSupport mode;
        const char *llmnr;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &llmnr);
        if (r < 0)
                return r;

        if (isempty(llmnr))
                mode = RESOLVE_SUPPORT_YES;
        else {
                mode = resolve_support_from_string(llmnr);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid LLMNR setting: %s", llmnr);
        }

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-llmnr",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        if (l->llmnr != mode) {
                l->llmnr = mode;
                (void) link_dirty(l);
        }

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        ResolveSupport mode;
        const char *mdns;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &mdns);
        if (r < 0)
                return r;

        if (isempty(mdns))
                mode = RESOLVE_SUPPORT_NO;
        else {
                mode = resolve_support_from_string(mdns);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid MulticastDNS setting: %s", mdns);
        }

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-mdns",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        if (l->mdns != mode) {
                l->mdns = mode;
                (void) link_dirty(l);
        }

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_dns_over_tls(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        const char *dns_over_tls;
        DnsOverTlsMode mode;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &dns_over_tls);
        if (r < 0)
                return r;

        if (isempty(dns_over_tls))
                mode = _DNS_OVER_TLS_MODE_INVALID;
        else {
                mode = dns_over_tls_mode_from_string(dns_over_tls);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid DNSOverTLS setting: %s", dns_over_tls);
        }

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-dns-over-tls",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        if (l->dns_over_tls_mode != mode) {
                l->dns_over_tls_mode = mode;
                (void) link_dirty(l);
        }

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        const char *dnssec;
        DnssecMode mode;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "s", &dnssec);
        if (r < 0)
                return r;

        if (isempty(dnssec))
                mode = _DNSSEC_MODE_INVALID;
        else {
                mode = dnssec_mode_from_string(dnssec);
                if (mode < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid DNSSEC setting: %s", dnssec);
        }

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-dnssec",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        if (l->dnssec_mode != mode) {
                l->dnssec_mode = mode;
                (void) link_dirty(l);
        }

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_set_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_set_free_free_ Set *ns = NULL;
        _cleanup_strv_free_ char **ntas = NULL;
        Link *l = userdata;
        int r;
        char **i;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read_strv(message, &ntas);
        if (r < 0)
                return r;

        STRV_FOREACH(i, ntas) {
                r = dns_name_is_valid(*i);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid negative trust anchor domain: %s", *i);
        }

        ns = set_new(&dns_name_hash_ops);
        if (!ns)
                return -ENOMEM;

        STRV_FOREACH(i, ntas) {
                r = set_put_strdup(ns, *i);
                if (r < 0)
                        return r;
        }

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.set-dnssec-negative-trust-anchors",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        set_free_free(l->dnssec_negative_trust_anchors);
        l->dnssec_negative_trust_anchors = TAKE_PTR(ns);

        (void) link_dirty(l);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_revert_ntp(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.revert-ntp",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        link_ntp_settings_clear(l);
        (void) link_dirty(l);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_link_method_revert_dns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Link *l = userdata;
        int r;

        assert(message);
        assert(l);

        r = verify_managed_link(l, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.revert-dns",
                                    NULL, true, UID_INVALID,
                                    &l->manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        link_dns_settings_clear(l);
        (void) link_dirty(l);

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable link_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("OperationalState", "s", property_get_operational_state, offsetof(Link, operstate), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CarrierState", "s", property_get_carrier_state, offsetof(Link, carrier_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AddressState", "s", property_get_address_state, offsetof(Link, address_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AdministrativeState", "s", property_get_administrative_state, offsetof(Link, state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BitRates", "(tt)", property_get_bit_rates, 0, 0),

        SD_BUS_METHOD("SetNTP", "as", NULL, bus_link_method_set_ntp_servers, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDNS", "a(iay)", NULL, bus_link_method_set_dns_servers, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDomains", "a(sb)", NULL, bus_link_method_set_domains, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDefaultRoute", "b", NULL, bus_link_method_set_default_route, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLLMNR", "s", NULL, bus_link_method_set_llmnr, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetMulticastDNS", "s", NULL, bus_link_method_set_mdns, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDNSOverTLS", "s", NULL, bus_link_method_set_dns_over_tls, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDNSSEC", "s", NULL, bus_link_method_set_dnssec, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetDNSSECNegativeTrustAnchors", "as", NULL, bus_link_method_set_dnssec_negative_trust_anchors, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RevertNTP", NULL, NULL, bus_link_method_revert_ntp, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("RevertDNS", NULL, NULL, bus_link_method_revert_dns, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

char *link_bus_path(Link *link) {
        _cleanup_free_ char *ifindex = NULL;
        char *p;
        int r;

        assert(link);
        assert(link->ifindex > 0);

        if (asprintf(&ifindex, "%d", link->ifindex) < 0)
                return NULL;

        r = sd_bus_path_encode("/org/freedesktop/network1/link", ifindex, &p);
        if (r < 0)
                return NULL;

        return p;
}

int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        unsigned c = 0;
        Link *link;
        Iterator i;

        assert(bus);
        assert(path);
        assert(m);
        assert(nodes);

        l = new0(char*, hashmap_size(m->links) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(link, m->links, i) {
                char *p;

                p = link_bus_path(link);
                if (!p)
                        return -ENOMEM;

                l[c++] = p;
        }

        l[c] = NULL;
        *nodes = TAKE_PTR(l);

        return 1;
}

int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *identifier = NULL;
        Manager *m = userdata;
        Link *link;
        int ifindex, r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(m);
        assert(found);

        r = sd_bus_path_decode(path, "/org/freedesktop/network1/link", &identifier);
        if (r <= 0)
                return 0;

        r = parse_ifindex(identifier, &ifindex);
        if (r < 0)
                return 0;

        r = link_get(m, ifindex, &link);
        if (r < 0)
                return 0;

        *found = link;

        return 1;
}

int link_send_changed_strv(Link *link, char **properties) {
        _cleanup_free_ char *p = NULL;

        assert(link);
        assert(link->manager);
        assert(properties);

        if (!link->manager->bus)
                return 0;

        p = link_bus_path(link);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_properties_changed_strv(
                        link->manager->bus,
                        p,
                        "org.freedesktop.network1.Link",
                        properties);
}

int link_send_changed(Link *link, const char *property, ...) {
        char **properties;

        properties = strv_from_stdarg_alloca(property);

        return link_send_changed_strv(link, properties);
}

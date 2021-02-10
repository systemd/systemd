/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <sys/capability.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-message-util.h"
#include "bus-polkit.h"
#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-manager-bus.h"
#include "networkd-manager.h"
#include "path-util.h"
#include "socket-netlink.h"
#include "strv.h"
#include "user-util.h"

static int method_list_links(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *manager = userdata;
        Link *link;
        int r;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(iso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(link, manager->links) {
                _cleanup_free_ char *path = NULL;

                path = link_bus_path(link);
                if (!path)
                        return -ENOMEM;

                r = sd_bus_message_append(
                        reply, "(iso)",
                        link->ifindex,
                        link->ifname,
                        empty_to_root(path));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_get_link_by_name(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *path = NULL;
        Manager *manager = userdata;
        const char *name;
        int index, r;
        Link *link;

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        index = resolve_ifname(&manager->rtnl, name);
        if (index < 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_LINK, "Link %s cannot be resolved", name);

        link = hashmap_get(manager->links, INT_TO_PTR(index));
        if (!link)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_LINK, "Link %s not known", name);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        path = link_bus_path(link);
        if (!path)
                return -ENOMEM;

        r = sd_bus_message_append(reply, "io", link->ifindex, empty_to_root(path));
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_get_link_by_index(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *path = NULL;
        Manager *manager = userdata;
        int ifindex, r;
        Link *link;

        r = bus_message_read_ifindex(message, error, &ifindex);
        if (r < 0)
                return r;

        link = hashmap_get(manager->links, INT_TO_PTR(ifindex));
        if (!link)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_LINK, "Link %i not known", ifindex);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        path = link_bus_path(link);
        if (!path)
                return -ENOMEM;

        r = sd_bus_message_append(reply, "so", link->ifname, empty_to_root(path));
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int call_link_method(Manager *m, sd_bus_message *message, sd_bus_message_handler_t handler, sd_bus_error *error) {
        int ifindex, r;
        Link *l;

        assert(m);
        assert(message);
        assert(handler);

        r = bus_message_read_ifindex(message, error, &ifindex);
        if (r < 0)
                return r;

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));
        if (!l)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_LINK, "Link %i not known", ifindex);

        return handler(message, l, error);
}

static int bus_method_set_link_ntp_servers(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_ntp_servers, error);
}

static int bus_method_set_link_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dns_servers, error);
}

static int bus_method_set_link_dns_servers_ex(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dns_servers_ex, error);
}

static int bus_method_set_link_domains(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_domains, error);
}

static int bus_method_set_link_default_route(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_default_route, error);
}

static int bus_method_set_link_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_llmnr, error);
}

static int bus_method_set_link_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_mdns, error);
}

static int bus_method_set_link_dns_over_tls(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dns_over_tls, error);
}

static int bus_method_set_link_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dnssec, error);
}

static int bus_method_set_link_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_set_dnssec_negative_trust_anchors, error);
}

static int bus_method_revert_link_ntp(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_revert_ntp, error);
}

static int bus_method_revert_link_dns(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_revert_dns, error);
}

static int bus_method_renew_link(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_renew, error);
}

static int bus_method_force_renew_link(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_force_renew, error);
}

static int bus_method_reconfigure_link(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return call_link_method(userdata, message, bus_link_method_reconfigure, error);
}

static int bus_method_reload(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *manager = userdata;
        Link *link;
        int r;

        r = bus_verify_polkit_async(message, CAP_NET_ADMIN,
                                    "org.freedesktop.network1.reload",
                                    NULL, true, UID_INVALID,
                                    &manager->polkit_registry, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Polkit will call us back */

        r = netdev_load(manager, true);
        if (r < 0)
                return r;

        r = network_reload(manager);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(link, manager->links) {
                r = link_reconfigure(link, false);
                if (r < 0)
                        return r;
        }

        return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("OperationalState", "s", property_get_operational_state, offsetof(Manager, operational_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CarrierState", "s", property_get_carrier_state, offsetof(Manager, carrier_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("AddressState", "s", property_get_address_state, offsetof(Manager, address_state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD_WITH_ARGS("ListLinks",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(iso)", links),
                                method_list_links,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetLinkByName",
                                SD_BUS_ARGS("s", name),
                                SD_BUS_RESULT("i", ifindex, "o", path),
                                method_get_link_by_name,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetLinkByIndex",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_RESULT("s", name, "o", path),
                                method_get_link_by_index,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkNTP",
                                SD_BUS_ARGS("i", ifindex, "as", servers),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_ntp_servers,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNS",
                                SD_BUS_ARGS("i", ifindex, "a(iay)", addresses),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dns_servers,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSEx",
                                SD_BUS_ARGS("i", ifindex, "a(iayqs)", addresses),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dns_servers_ex,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDomains",
                                SD_BUS_ARGS("i", ifindex, "a(sb)", domains),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_domains,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDefaultRoute",
                                SD_BUS_ARGS("i", ifindex, "b", enable),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_default_route,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkLLMNR",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_llmnr,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkMulticastDNS",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_mdns,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSOverTLS",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dns_over_tls,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSSEC",
                                SD_BUS_ARGS("i", ifindex, "s", mode),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dnssec,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLinkDNSSECNegativeTrustAnchors",
                                SD_BUS_ARGS("i", ifindex, "as", names),
                                SD_BUS_NO_RESULT,
                                bus_method_set_link_dnssec_negative_trust_anchors,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RevertLinkNTP",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_NO_RESULT,
                                bus_method_revert_link_ntp,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RevertLinkDNS",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_NO_RESULT,
                                bus_method_revert_link_dns,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RenewLink",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_NO_RESULT,
                                bus_method_renew_link,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ForceRenewLink",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_NO_RESULT,
                                bus_method_force_renew_link,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReconfigureLink",
                                SD_BUS_ARGS("i", ifindex),
                                SD_BUS_NO_RESULT,
                                bus_method_reconfigure_link,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Reload",
                                SD_BUS_NO_ARGS,
                                SD_BUS_NO_RESULT,
                                bus_method_reload,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

int manager_send_changed_strv(Manager *manager, char **properties) {
        assert(manager);
        assert(properties);

        if (!manager->bus)
                return 0;

        return sd_bus_emit_properties_changed_strv(
                        manager->bus,
                        "/org/freedesktop/network1",
                        "org.freedesktop.network1.Manager",
                        properties);
}

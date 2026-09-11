/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "sd-dhcp-server.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "dns-domain.h"
#include "json-util.h"
#include "networkd-dhcp4.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-link-varlink.h"
#include "networkd-manager.h"
#include "networkd-setlink.h"
#include "networkd-state-file.h"
#include "ordered-set.h"
#include "resolve-varlink-util.h"

int dispatch_link(sd_varlink *vlink, sd_json_variant *parameters, Manager *manager, DispatchLinkFlag flags, Link **ret) {
        struct {
                int ifindex;
                const char *ifname;
        } info = {};
        Link *link = NULL;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,         voffsetof(info, ifindex), SD_JSON_RELAX },
                { "InterfaceName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(info, ifname),  0             },
                {}
        }, dispatch_polkit_table[] = {
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,         voffsetof(info, ifindex), SD_JSON_RELAX },
                { "InterfaceName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(info, ifname),  0             },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        assert(vlink);
        assert(manager);
        assert(ret);

        const char *bad_field = NULL;
        r = sd_json_dispatch_full(
                        parameters,
                        FLAGS_SET(flags, DISPATCH_LINK_POLKIT) ? dispatch_polkit_table : dispatch_table,
                        /* bad= */ NULL,
                        FLAGS_SET(flags, DISPATCH_LINK_ALLOW_EXTENSIONS) ? SD_JSON_ALLOW_EXTENSIONS : 0,
                        &info,
                        &bad_field);
        if (r < 0) {
                if (bad_field)
                        return sd_varlink_error_invalid_parameter_name(vlink, bad_field);
                return r;
        }

        if (info.ifindex < 0)
                return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));
        if (info.ifindex > 0 && link_get_by_index(manager, info.ifindex, &link) < 0)
                return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));
        if (info.ifname) {
                Link *link_by_name;

                if (link_get_by_name(manager, info.ifname, &link_by_name) < 0)
                        return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceName"));

                if (link && link_by_name != link)
                        /* If both arguments are specified, then these must be consistent. */
                        return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceName"));

                link = link_by_name;
        }

        if (!link && (flags & (DISPATCH_LINK_MANDATORY|DISPATCH_LINK_MANAGED)))
                return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));

        if (FLAGS_SET(flags, DISPATCH_LINK_MANAGED)) {
                if (FLAGS_SET(link->flags, IFF_LOOPBACK))
                        return sd_varlink_error(vlink, "io.systemd.Network.Link.InterfaceIsLoopback", NULL);

                if (link->state == LINK_STATE_UNMANAGED)
                        return sd_varlink_error(vlink, "io.systemd.Network.Link.InterfaceUnmanaged", NULL);
        }

        /* If the DISPATCH_LINK_MANDATORY or DISPATCH_LINK_MANAGED flags are
         * not set, this function may return NULL. */
        *ret = link;
        return 0;
}

int vl_method_link_describe(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(vlink);

        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_MANDATORY, &link);
        if (r != 0)
                return r;

        r = link_build_json(link, &v);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to format JSON data: %m");

        return sd_varlink_replybo(
                        vlink,
                        SD_JSON_BUILD_PAIR_VARIANT("Interface", v));
}

static int vl_method_link_up_or_down(sd_varlink *vlink, sd_json_variant *parameters, Manager *manager, bool up) {
        Link *link;
        int r;

        assert(vlink);
        assert(manager);

        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANDATORY, &link);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.manage-links",
                        (const char**) STRV_MAKE(
                                        "interface", link->ifname,
                                        "verb", up ? "up" : "down"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (!up)
                /* Stop all network engines while interface is still up to allow proper cleanup,
                 * e.g. sending IPv6 shutdown RA messages before the interface is brought down. */
                (void) link_stop_engines(link, /* may_keep_dynamic = */ false);

        return link_up_or_down_now_by_varlink(link, up, vlink);
}

int vl_method_link_up(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_link_up_or_down(vlink, parameters, userdata, /* up= */ true);
}

int vl_method_link_down(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_link_up_or_down(vlink, parameters, userdata, /* up= */ false);
}

int vl_method_link_renew(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(vlink);

        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANDATORY, &link);
        if (r != 0)
                return r;

        if (!link->network)
                return sd_varlink_error(vlink, "io.systemd.Network.Link.InterfaceUnmanaged", NULL);

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.renew",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = dhcp4_renew(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to renew DHCPv4 lease: %m");

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_force_renew(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(vlink);

        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANDATORY, &link);
        if (r != 0)
                return r;

        if (!link->network)
                return sd_varlink_error(vlink, "io.systemd.Network.Link.InterfaceUnmanaged", NULL);

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.forcerenew",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (sd_dhcp_server_is_running(link->dhcp_server)) {
                r = sd_dhcp_server_forcerenew(link->dhcp_server);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to force-renew DHCP server leases: %m");
        }

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_reconfigure(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(vlink);

        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANDATORY, &link);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.reconfigure",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        r = link_reconfigure_full(link,
                                  LINK_RECONFIGURE_UNCONDITIONALLY | LINK_RECONFIGURE_CLEANLY,
                                  /* message= */ NULL,
                                  /* varlink= */ vlink,
                                  /* counter= */ NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to reconfigure link: %m");
        if (r > 0)
                return 0; /* Reply will be sent asynchronously via vlink */

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_set_dns(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vlink);

        Link *link;
        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANAGED | DISPATCH_LINK_ALLOW_EXTENSIONS, &link);
        if (r != 0)
                return r;

        _cleanup_(link_set_dns_parameters_done) LinkSetDNSParameters p = {};
        r = dispatch_link_set_dns_parameters(NULL, parameters, SD_JSON_LOG, &p);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.set-dns-servers",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        link_set_dns(link, TAKE_PTR(p.servers), p.n_servers);
        /* The link took ownership of this array. */
        p.n_servers = 0;

        r = link_save_and_clean_full(link, /* also_save_manager= */ true);
        if (r < 0)
                return r;

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_set_domains(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vlink);

        Link *link;
        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANAGED | DISPATCH_LINK_ALLOW_EXTENSIONS, &link);
        if (r != 0)
                return r;

        _cleanup_(link_set_domains_parameters_done) LinkSetDomainsParameters p = {};
        r = dispatch_link_set_domains_parameters(NULL, parameters, SD_JSON_LOG, &p);
        if (r < 0)
                return r;

        /* The method accepts an empty strv, to override the domains set in .network.
         * Hence, we need to explicitly allocate empty sets here. */
        _cleanup_ordered_set_free_ OrderedSet *search_domains = ordered_set_new(&dns_name_hash_ops_free);
        if (!search_domains)
                return log_oom();

        _cleanup_ordered_set_free_ OrderedSet *route_domains = ordered_set_new(&dns_name_hash_ops_free);
        if (!route_domains)
                return log_oom();

        FOREACH_ARRAY(d, p.domains, p.n_domains) {
                /* dispatch_link_set_domains_parameters() validates and normalizes the name, so
                 * we can copy it as-is. */
                _cleanup_free_ char *name = strdup(d->name);
                if (!name)
                        return log_oom();

                r = ordered_set_consume(d->route_only ? route_domains : search_domains, TAKE_PTR(name));
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return r;
        }

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.set-domains",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        free_and_replace_full(link->route_domains, route_domains, ordered_set_free);
        free_and_replace_full(link->search_domains, search_domains, ordered_set_free);

        r = link_save_and_clean_full(link, /* also_save_manager= */ true);
        if (r < 0)
                return r;

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_set_dns_default_route(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vlink);

        Link *link;
        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANAGED | DISPATCH_LINK_ALLOW_EXTENSIONS, &link);
        if (r != 0)
                return r;

        struct {
                bool default_route;
        } p = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "DefaultRoute",   SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, voffsetof(p, default_route), SD_JSON_MANDATORY },
                /* Already handled by dispatch_link() */
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, NULL,                     0,                           0,                },
                { "InterfaceName",  _SD_JSON_VARIANT_TYPE_INVALID, NULL,                     0,                           0,                },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_LOG, &p);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.set-default-route",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (p.default_route != link->dns_default_route) {
                link->dns_default_route = p.default_route;

                r = link_save_and_clean_full(link, /* also_save_manager= */ true);
                if (r < 0)
                        return r;
        }

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_set_llmnr(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vlink);

        Link *link;
        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANAGED | DISPATCH_LINK_ALLOW_EXTENSIONS, &link);
        if (r != 0)
                return r;

        struct {
                const char *mode;
        } p = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Mode",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, mode), SD_JSON_MANDATORY },
                /* Already handled by dispatch_link() */
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, NULL,                          0,                  0,                },
                { "InterfaceName",  _SD_JSON_VARIANT_TYPE_INVALID, NULL,                          0,                  0,                },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_LOG, &p);
        if (r < 0)
                return r;

        ResolveSupport mode;
        if (isempty(p.mode))
                mode = RESOLVE_SUPPORT_YES;
        else {
                mode = resolve_support_from_string(p.mode);
                if (mode < 0)
                        return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("Mode"));
        }

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.set-llmnr",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (link->llmnr != mode) {
                link->llmnr = mode;

                r = link_save_and_clean_full(link, /* also_save_manager= */ true);
                if (r < 0)
                        return r;
        }

        return sd_varlink_reply(vlink, NULL);
}

int vl_method_link_set_mdns(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(vlink);

        Link *link;
        r = dispatch_link(vlink, parameters, manager, DISPATCH_LINK_POLKIT | DISPATCH_LINK_MANAGED | DISPATCH_LINK_ALLOW_EXTENSIONS, &link);
        if (r != 0)
                return r;

        struct {
                const char *mode;
        } p = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Mode",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, mode), SD_JSON_MANDATORY },
                /* Already handled by dispatch_link() */
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, NULL,                          0,                  0,                },
                { "InterfaceName",  _SD_JSON_VARIANT_TYPE_INVALID, NULL,                          0,                  0,                },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_LOG, &p);
        if (r < 0)
                return r;

        ResolveSupport mode;
        if (isempty(p.mode))
                mode = RESOLVE_SUPPORT_NO;
        else {
                mode = resolve_support_from_string(p.mode);
                if (mode < 0)
                        return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("Mode"));
        }

        r = varlink_verify_polkit_async(
                        vlink,
                        manager->bus,
                        "org.freedesktop.network1.set-mdns",
                        (const char**) STRV_MAKE("interface", link->ifname),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (link->mdns != mode) {
                link->mdns = mode;

                r = link_save_and_clean_full(link, /* also_save_manager= */ true);
                if (r < 0)
                        return r;
        }

        return sd_varlink_reply(vlink, NULL);
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "bus-polkit.h"
#include "json-util.h"
#include "networkd-link.h"
#include "networkd-link-varlink.h"
#include "networkd-manager.h"
#include "networkd-setlink.h"

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

        r = sd_varlink_dispatch(
                        vlink,
                        parameters,
                        FLAGS_SET(flags, DISPATCH_LINK_POLKIT) ? dispatch_polkit_table : dispatch_table,
                        &info);
        if (r != 0)
                return r;

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

        if (!link && FLAGS_SET(flags, DISPATCH_LINK_MANDATORY))
                return sd_varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));

        /* If the DISPATCH_LINK_MANDATORY flag is not set, this function may return NULL. */
        *ret = link;
        return 0;
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
                        /* details= */ NULL,
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

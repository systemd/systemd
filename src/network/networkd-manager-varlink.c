/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "lldp-rx-internal.h"
#include "networkd-manager-varlink.h"
#include "varlink.h"
#include "varlink-io.systemd.Network.h"

static int vl_method_get_states(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(link);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        return varlink_replyb(link,
                              JSON_BUILD_OBJECT(
                                              JSON_BUILD_PAIR_STRING("AddressState", link_address_state_to_string(m->address_state)),
                                              JSON_BUILD_PAIR_STRING("IPv4AddressState", link_address_state_to_string(m->ipv4_address_state)),
                                              JSON_BUILD_PAIR_STRING("IPv6AddressState", link_address_state_to_string(m->ipv6_address_state)),
                                              JSON_BUILD_PAIR_STRING("CarrierState", link_carrier_state_to_string(m->carrier_state)),
                                              JSON_BUILD_PAIR_CONDITION(m->online_state >= 0, "OnlineState", JSON_BUILD_STRING(link_online_state_to_string(m->online_state))),
                                              JSON_BUILD_PAIR_STRING("OperationalState", link_operstate_to_string(m->operational_state))));
}

static int vl_method_get_namespace_id(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        uint64_t inode = 0;
        uint32_t nsid = UINT32_MAX;
        int r;

        assert(link);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        /* Network namespaces have two identifiers: the inode number (which all namespace types have), and
         * the "nsid" (aka the "cookie"), which only network namespaces know as a concept, and which is not
         * assigned by default, but once it is, is fixed. Let's return both, to avoid any confusion which one
         * this is. */

        struct stat st;
        if (stat("/proc/self/ns/net", &st) < 0)
                log_warning_errno(errno, "Failed to stat network namespace, ignoring: %m");
        else
                inode = st.st_ino;

        r = netns_get_nsid(/* netnsfd= */ -EBADF, &nsid);
        if (r < 0)
                log_full_errno(r == -ENODATA ? LOG_DEBUG : LOG_WARNING, r, "Failed to query network nsid, ignoring: %m");

        return varlink_replyb(link,
                              JSON_BUILD_OBJECT(
                                              JSON_BUILD_PAIR_UNSIGNED("NamespaceId", inode),
                                              JSON_BUILD_PAIR_CONDITION(nsid == UINT32_MAX, "NamespaceNSID", JSON_BUILD_NULL),
                                              JSON_BUILD_PAIR_CONDITION(nsid != UINT32_MAX, "NamespaceNSID", JSON_BUILD_UNSIGNED(nsid))));
}

typedef struct InterfaceInfo {
        int ifindex;
        const char *ifname;
} InterfaceInfo;

static int dispatch_interface(Varlink *vlink, JsonVariant *parameters, Manager *manager, Link **ret) {
        static const JsonDispatch dispatch_table[] = {
                { "InterfaceIndex", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int,          offsetof(InterfaceInfo, ifindex), 0 },
                { "InterfaceName",  JSON_VARIANT_STRING,        json_dispatch_const_string, offsetof(InterfaceInfo, ifname),  0 },
                {}
        };

        InterfaceInfo info = {};
        Link *link = NULL;
        int r;

        assert(vlink);
        assert(manager);

        r = varlink_dispatch(vlink, parameters, dispatch_table, &info);
        if (r != 0)
                return r;

        if (info.ifindex < 0)
                return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));
        if (info.ifindex > 0 && link_get_by_index(manager, info.ifindex, &link) < 0)
                return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));
        if (info.ifname) {
                Link *link_by_name;

                if (link_get_by_name(manager, info.ifname, &link_by_name) < 0)
                        return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceName"));

                if (link && link_by_name != link)
                        /* If both arguments are specified, then these must be consistent. */
                        return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceName"));

                link = link_by_name;
        }

        /* If neither InterfaceIndex nor InterfaceName specified, this function returns NULL. */
        *ret = link;
        return 0;
}

static int link_append_lldp_neighbors(Link *link, JsonVariant *v, JsonVariant **array) {
        assert(link);
        assert(array);

        return json_variant_append_arrayb(array,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("InterfaceIndex", link->ifindex),
                                JSON_BUILD_PAIR_STRING("InterfaceName", link->ifname),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("InterfaceAlternativeNames", link->alternative_names),
                                JSON_BUILD_PAIR_CONDITION(json_variant_is_blank_array(v), "Neighbors", JSON_BUILD_EMPTY_ARRAY),
                                JSON_BUILD_PAIR_CONDITION(!json_variant_is_blank_array(v), "Neighbors", JSON_BUILD_VARIANT(v))));
}

static int vl_method_get_lldp_neighbors(Varlink *vlink, JsonVariant *parameters, VarlinkMethodFlags flags, Manager *manager) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        Link *link = NULL;
        int r;

        assert(vlink);
        assert(manager);

        r = dispatch_interface(vlink, parameters, manager, &link);
        if (r != 0)
                return r;

        if (link) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                if (link->lldp_rx) {
                        r = lldp_rx_build_neighbors_json(link->lldp_rx, &v);
                        if (r < 0)
                                return r;
                }

                r = link_append_lldp_neighbors(link, v, &array);
                if (r < 0)
                        return r;
        } else
                HASHMAP_FOREACH(link, manager->links_by_index) {
                        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                        if (!link->lldp_rx)
                                continue;

                        r = lldp_rx_build_neighbors_json(link->lldp_rx, &v);
                        if (r < 0)
                                return r;

                        if (json_variant_is_blank_array(v))
                                continue;

                        r = link_append_lldp_neighbors(link, v, &array);
                        if (r < 0)
                                return r;
                }

        return varlink_replyb(vlink,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_CONDITION(json_variant_is_blank_array(array), "Neighbors", JSON_BUILD_EMPTY_ARRAY),
                                JSON_BUILD_PAIR_CONDITION(!json_variant_is_blank_array(array), "Neighbors", JSON_BUILD_VARIANT(array))));
}

int manager_connect_varlink(Manager *m) {
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(&s, VARLINK_SERVER_ACCOUNT_UID|VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(s, m);

        r = varlink_server_add_interface(s, &vl_interface_io_systemd_Network);
        if (r < 0)
                return log_error_errno(r, "Failed to add Network interface to varlink server: %m");

        r = varlink_server_bind_method_many(
                        s,
                        "io.systemd.Network.GetStates", vl_method_get_states,
                        "io.systemd.Network.GetNamespaceId", vl_method_get_namespace_id,
                        "io.systemd.Network.GetLLDPNeighbors", vl_method_get_lldp_neighbors);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = varlink_server_listen_address(s, "/run/systemd/netif/io.systemd.Network", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);
        return 0;
}

void manager_varlink_done(Manager *m) {
        assert(m);

        m->varlink_server = varlink_server_unref(m->varlink_server);
        (void) unlink("/run/systemd/netif/io.systemd.Network");
}

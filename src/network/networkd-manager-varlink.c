/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bus-polkit.h"
#include "networkd-dhcp-server.h"
#include "networkd-manager-varlink.h"
#include "user-util.h"
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
                log_warning_errno(r, "Failed to query network nsid, ignoring: %m");

        return varlink_replyb(link,
                              JSON_BUILD_OBJECT(
                                              JSON_BUILD_PAIR_UNSIGNED("NamespaceId", inode),
                                              JSON_BUILD_PAIR_CONDITION(nsid == UINT32_MAX, "NamespaceNSID", JSON_BUILD_NULL),
                                              JSON_BUILD_PAIR_CONDITION(nsid != UINT32_MAX, "NamespaceNSID", JSON_BUILD_UNSIGNED(nsid))));
}

static int vl_method_dhcp_server_one(Link *link, bool start, JsonVariant **v) {
        int r;

        assert(link);
        assert(v);

        link->dhcp_server_can_start = start;

        if (start)
                r = link_start_dhcp_server(link);
        else
                r = sd_dhcp_server_stop(link->dhcp_server);
        if (r < 0) {
                (void) json_variant_append_arrayb(v,
                                        JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_INTEGER("InterfaceIndex", link->ifindex),
                                                JSON_BUILD_PAIR_STRING("InterfaceName", link->ifname),
                                                JSON_BUILD_PAIR_INTEGER("ErrorCode", -r)));
                return log_link_debug_errno(link, r, "Failed to %s DHCP server, ignoring: %m", start ? "start" : "stop");
        }

        return 0;
}

typedef struct InterfaceInfo {
        int ifindex;
        const char *ifname;
} InterfaceInfo;

static int vl_method_dhcp_server(Varlink *vlink, JsonVariant *parameters, VarlinkMethodFlags flags, Manager *manager, const char *method) {
        static const JsonDispatch dispatch_table[] = {
                { "InterfaceIndex", _JSON_VARIANT_TYPE_INVALID, json_dispatch_int,          offsetof(InterfaceInfo, ifindex), 0 },
                { "InterfaceName",  JSON_VARIANT_STRING,        json_dispatch_const_string, offsetof(InterfaceInfo, ifname),  0 },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        InterfaceInfo info = {};
        Link *link = NULL;
        int r, ret = 0;

        assert(vlink);
        assert(manager);
        assert(method);

        bool start = streq(method, "io.systemd.Network.StartDHCPServer");

        r = varlink_dispatch(vlink, parameters, dispatch_table, &info);
        if (r != 0)
                return r;

        if (info.ifindex < 0)
                return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));
        if (info.ifindex > 0) {
                if (info.ifname)
                        return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceName"));

                if (link_get_by_index(manager, info.ifindex, &link) < 0)
                        return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceIndex"));
        }

        if (info.ifname && link_get_by_name(manager, info.ifname, &link) < 0)
                return varlink_error_invalid_parameter(vlink, JSON_VARIANT_STRING_CONST("InterfaceName"));

        if (link && !link_dhcp4_server_enabled(link))
                return varlink_error(vlink, "io.systemd.Netowrk.NoDHCPServer", NULL);

        r = varlink_verify_polkit_async(
                                vlink,
                                manager->bus,
                                method,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (link) {
                r = vl_method_dhcp_server_one(link, start, &v);
                if (r < 0)
                        return varlink_errorb(vlink, "io.systemd.Network.DHCPServerError",
                                              JSON_BUILD_OBJECT(JSON_BUILD_PAIR_VARIANT_NON_NULL("Results", v)));

                return varlink_reply(vlink, NULL);
        }

        manager->dhcp_server_can_start = start;

        HASHMAP_FOREACH(link, manager->links_by_index)
                RET_GATHER(ret, vl_method_dhcp_server_one(link, start, &v));
        if (ret < 0)
                return varlink_errorb(vlink, "io.systemd.Network.DHCPServerError",
                                      JSON_BUILD_OBJECT(JSON_BUILD_PAIR_VARIANT_NON_NULL("Results", v)));

        return varlink_reply(vlink, NULL);
}

static int vl_method_start_dhcp_server(Varlink *vlink, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        return vl_method_dhcp_server(vlink, parameters, flags, userdata, "io.systemd.Network.StartDHCPServer");
}

static int vl_method_stop_dhcp_server(Varlink *vlink, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        return vl_method_dhcp_server(vlink, parameters, flags, userdata, "io.systemd.Network.StopDHCPServer");
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
                        "io.systemd.Network.StartDHCPServer", vl_method_start_dhcp_server,
                        "io.systemd.Network.StopDHCPServer", vl_method_stop_dhcp_server);
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

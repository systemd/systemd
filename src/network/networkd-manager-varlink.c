/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-event.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "fd-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "lldp-rx-internal.h"
#include "network-util.h"
#include "networkd-dhcp-server.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-link-varlink.h"
#include "networkd-manager.h"
#include "networkd-manager-varlink.h"
#include "stat-util.h"
#include "varlink-io.systemd.Network.h"
#include "varlink-io.systemd.Network.Link.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

static int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(parameters);
        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = manager_build_json(m, &v);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON data: %m");

        return sd_varlink_reply(link, v);
}

static int vl_method_get_states(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("AddressState", link_address_state_to_string(m->address_state)),
                        SD_JSON_BUILD_PAIR_STRING("IPv4AddressState", link_address_state_to_string(m->ipv4_address_state)),
                        SD_JSON_BUILD_PAIR_STRING("IPv6AddressState", link_address_state_to_string(m->ipv6_address_state)),
                        SD_JSON_BUILD_PAIR_STRING("CarrierState", link_carrier_state_to_string(m->carrier_state)),
                        SD_JSON_BUILD_PAIR_CONDITION(m->online_state >= 0, "OnlineState", SD_JSON_BUILD_STRING(link_online_state_to_string(m->online_state))),
                        SD_JSON_BUILD_PAIR_STRING("OperationalState", link_operstate_to_string(m->operational_state)));
}

static int vl_method_get_namespace_id(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        uint64_t inode = 0;
        uint32_t nsid = UINT32_MAX;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

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

        return sd_varlink_replybo(link,
                               SD_JSON_BUILD_PAIR_UNSIGNED("NamespaceId", inode),
                               SD_JSON_BUILD_PAIR_CONDITION(nsid == UINT32_MAX, "NamespaceNSID", SD_JSON_BUILD_NULL),
                               SD_JSON_BUILD_PAIR_CONDITION(nsid != UINT32_MAX, "NamespaceNSID", SD_JSON_BUILD_UNSIGNED(nsid)));
}

static int link_append_lldp_neighbors(Link *link, sd_json_variant *v, sd_json_variant **array) {
        assert(link);
        assert(array);

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_INTEGER("InterfaceIndex", link->ifindex),
                                              SD_JSON_BUILD_PAIR_STRING("InterfaceName", link->ifname),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("InterfaceAlternativeNames", link->alternative_names),
                        SD_JSON_BUILD_PAIR_CONDITION(sd_json_variant_is_blank_array(v), "Neighbors", SD_JSON_BUILD_EMPTY_ARRAY),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_json_variant_is_blank_array(v), "Neighbors", SD_JSON_BUILD_VARIANT(v)));
}

static int vl_method_get_lldp_neighbors(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, Manager *manager) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        Link *link = NULL;
        int r;

        assert(vlink);
        assert(manager);

        r = dispatch_interface(vlink, parameters, manager, /* polkit= */ false, &link);
        if (r != 0)
                return r;

        if (link) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

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
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                        if (!link->lldp_rx)
                                continue;

                        r = lldp_rx_build_neighbors_json(link->lldp_rx, &v);
                        if (r < 0)
                                return r;

                        if (sd_json_variant_is_blank_array(v))
                                continue;

                        r = link_append_lldp_neighbors(link, v, &array);
                        if (r < 0)
                                return r;
                }

        return sd_varlink_replybo(
                        vlink,
                        SD_JSON_BUILD_PAIR_CONDITION(sd_json_variant_is_blank_array(array), "Neighbors", SD_JSON_BUILD_EMPTY_ARRAY),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_json_variant_is_blank_array(array), "Neighbors", SD_JSON_BUILD_VARIANT(array)));
}

static int vl_method_set_persistent_storage(sd_varlink *vlink, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Ready", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, 0, 0 },
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        bool ready;
        int r;

        assert(vlink);

        r = sd_varlink_dispatch(vlink, parameters, dispatch_table, &ready);
        if (r != 0)
                return r;

        if (ready) {
                struct stat st, st_prev;
                int fd;

                fd = sd_varlink_peek_fd(vlink, 0);
                if (fd < 0)
                        return log_warning_errno(fd, "Failed to peek file descriptor of the persistent storage: %m");

                r = fd_verify_safe_flags_full(fd, O_DIRECTORY);
                if (r == -EREMOTEIO)
                        return log_warning_errno(r, "Passed persistent storage fd has unexpected flags, refusing.");
                if (r < 0)
                        return log_warning_errno(r, "Failed to verify flags of passed persistent storage fd: %m");

                r = fd_is_read_only_fs(fd);
                if (r < 0)
                        return log_warning_errno(r, "Failed to check if the persistent storage is writable: %m");
                if (r > 0) {
                        log_warning("The persistent storage is on read-only filesystem.");
                        return sd_varlink_error(vlink, "io.systemd.Network.StorageReadOnly", NULL);
                }

                if (fstat(fd, &st) < 0)
                        return log_warning_errno(errno, "Failed to stat the passed persistent storage fd: %m");

                r = stat_verify_directory(&st);
                if (r < 0)
                        return log_warning_errno(r, "The passed persistent storage fd is not a directory, refusing: %m");

                if (manager->persistent_storage_fd >= 0 &&
                    fstat(manager->persistent_storage_fd, &st_prev) >= 0 &&
                    stat_inode_same(&st, &st_prev))
                        return sd_varlink_reply(vlink, NULL);

        } else {
                if (manager->persistent_storage_fd < 0)
                        return sd_varlink_reply(vlink, NULL);
        }

        r = varlink_verify_polkit_async(
                                vlink,
                                manager->bus,
                                "org.freedesktop.network1.set-persistent-storage",
                                /* details= */ NULL,
                                &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (ready) {
                _cleanup_close_ int fd = -EBADF;

                fd = sd_varlink_take_fd(vlink, 0);
                if (fd < 0)
                        return log_warning_errno(fd, "Failed to take file descriptor of the persistent storage: %m");

                close_and_replace(manager->persistent_storage_fd, fd);
        } else
                manager->persistent_storage_fd = safe_close(manager->persistent_storage_fd);

        manager_toggle_dhcp4_server_state(manager, ready);

        return sd_varlink_reply(vlink, NULL);
}

int manager_varlink_init(Manager *m, int fd) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        _unused_ _cleanup_close_ int fd_close = fd; /* take possession */
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(
                        &s,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        (void) sd_varlink_server_set_description(s, "varlink-api-network");

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_Network,
                        &vl_interface_io_systemd_Network_Link,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Network interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Network.Describe",             vl_method_describe,
                        "io.systemd.Network.GetStates",            vl_method_get_states,
                        "io.systemd.Network.GetNamespaceId",       vl_method_get_namespace_id,
                        "io.systemd.Network.GetLLDPNeighbors",     vl_method_get_lldp_neighbors,
                        "io.systemd.Network.SetPersistentStorage", vl_method_set_persistent_storage,
                        "io.systemd.Network.Link.Up",              vl_method_link_up,
                        "io.systemd.Network.Link.Down",            vl_method_link_down,
                        "io.systemd.service.Ping",                 varlink_method_ping,
                        "io.systemd.service.SetLogLevel",          varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment",       varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        if (fd < 0)
                r = sd_varlink_server_listen_address(s, "/run/systemd/netif/io.systemd.Network", /* mode= */ 0666);
        else
                r = sd_varlink_server_listen_fd(s, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket '/run/systemd/netif/io.systemd.Network': %m");

        TAKE_FD(fd_close);

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);
        return 0;
}

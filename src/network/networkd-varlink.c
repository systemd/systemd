/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-varlink.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "json.h"
#include "varlink.h"

typedef struct LookupParameters {
        int ifindex;
} LookupParameters;

static int open_lldp_neighbors(int ifindex, FILE **ret) {
        _cleanup_free_ char *p = NULL;
        FILE *f;

        if (asprintf(&p, "/run/systemd/netif/lldp/%i", ifindex) < 0)
                return -ENOMEM;

        f = fopen(p, "re");
        if (!f)
                return -errno;

        *ret = f;
        return 0;
}

static int next_lldp_neighbor(FILE *f, sd_lldp_neighbor **ret) {
        _cleanup_free_ void *raw = NULL;
        size_t l;
        le64_t u;
        int r;

        assert(f);
        assert(ret);

        l = fread(&u, 1, sizeof(u), f);
        if (l == 0 && feof(f))
                return 0;
        if (l != sizeof(u))
                return -EBADMSG;

        /* each LLDP packet is at most MTU size, but let's allow up to 4KiB just in case */
        if (le64toh(u) >= 4096)
                return -EBADMSG;

        raw = new(uint8_t, le64toh(u));
        if (!raw)
                return -ENOMEM;

        if (fread(raw, 1, le64toh(u), f) != le64toh(u))
                return -EBADMSG;

        r = sd_lldp_neighbor_from_raw(ret, raw, le64toh(u));
        if (r < 0)
                return r;

        return 1;
}

static int dump_lldp_neighbors(int ifindex, Varlink *link) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(ifindex > 0);
        assert(link);

        r = open_lldp_neighbors(ifindex, &f);
        if (r == -ENOENT) {
                return varlink_replyb(link, JSON_BUILD_EMPTY_ARRAY);
        }
        if (r < 0)
                return r;

        for (;;) {
                const char *chassis_id = NULL, *port_id = NULL, *system_name = NULL, *port_description = NULL;
                _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;
                uint16_t cc;

                r = next_lldp_neighbor(f, &n);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read neighbor data: %m");
                        break;
                }
                if (r == 0)
                        break;

                if (v) {
                        r = varlink_notify(link, v);
                        if (r < 0)
                                return r;

                        v = json_variant_unref(v);
                }

                (void) sd_lldp_neighbor_get_chassis_id_as_string(n, &chassis_id);
                (void) sd_lldp_neighbor_get_port_id_as_string(n, &port_id);
                (void) sd_lldp_neighbor_get_system_name(n, &system_name);
                (void) sd_lldp_neighbor_get_port_description(n, &port_description);

                r = sd_lldp_neighbor_get_enabled_capabilities(n, &cc);

                r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("ChassisId", JSON_BUILD_STRING(chassis_id)),
                                JSON_BUILD_PAIR("SystemName", JSON_BUILD_STRING(system_name)),
                                JSON_BUILD_PAIR_CONDITION(r >= 0, "EnabledCapabilities", JSON_BUILD_UNSIGNED(cc)),
                                JSON_BUILD_PAIR("PortId", JSON_BUILD_STRING(port_id)),
                                JSON_BUILD_PAIR_CONDITION(port_description, "PortDescription", JSON_BUILD_STRING(port_description))));

                if (r < 0)
                        return r;
        }

        if (!v)
                return varlink_replyb(link, JSON_BUILD_EMPTY_ARRAY);

        return varlink_reply(link, v);
}

static int vl_method_network_lldp_neighbors(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "ifindex", JSON_VARIANT_INTEGER, json_dispatch_int, offsetof(LookupParameters, ifindex), JSON_MANDATORY },
                {}
        };

        int r;
        Manager *m;
        LookupParameters p;

        m = varlink_server_get_userdata(varlink_get_server(link));
        assert(m);

        assert(link);

        if (FLAGS_SET(flags, VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        if (!FLAGS_SET(flags, VARLINK_METHOD_MORE))
                return -EINVAL;

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (p.ifindex <= 0)
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("ifindex"));

        r = link_get_by_index(m, p.ifindex, NULL);
        if (r < 0) {
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("ifindex"));
        }

        return dump_lldp_neighbors(p.ifindex, link);
}

int manager_varlink_init(Manager *m) {
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(&s, VARLINK_SERVER_ACCOUNT_UID);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = varlink_server_bind_method(s, "io.systemd.Network.LLDPNeighbors", vl_method_network_lldp_neighbors);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink method: %m");

        r = varlink_server_listen_address(s, "/run/systemd/netif/io.systemd.Network", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);

        varlink_server_set_userdata(m->varlink_server, m);

        return 0;
}

void manager_varlink_done(Manager *m) {
        assert(m);

        m->varlink_server = varlink_server_unref(m->varlink_server);
}

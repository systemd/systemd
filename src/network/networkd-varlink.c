/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "json.h"
#include "networkd-varlink.h"
#include "sd-lldp.h"
#include "varlink.h"

typedef struct LookupParameters {
        int ifindex;
} LookupParameters;

static int vl_method_network_lldp_neighbors(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "ifindex", JSON_VARIANT_INTEGER, json_dispatch_int, offsetof(LookupParameters, ifindex), JSON_MANDATORY },
                {}
        };

        int r, i, n;
        Manager *m;
        Link *l;
        LookupParameters p;
        JsonVariant **neighbors;

        assert(link);

        m = varlink_server_get_userdata(varlink_get_server(link));
        assert(m);

        if (FLAGS_SET(flags, VARLINK_METHOD_ONEWAY))
                return -EINVAL;

        if (!FLAGS_SET(flags, VARLINK_METHOD_MORE))
                return -EINVAL;

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (p.ifindex <= 0)
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("ifindex"));

        r = link_get_by_index(m, p.ifindex, &l);
        if (r < 0)
                return varlink_error_invalid_parameter(link, JSON_VARIANT_STRING_CONST("ifindex"));

        r = sd_lldp_rx_get_neighbors_json(l->lldp_rx, &neighbors);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error(link, "io.systemd.Network.NoNeighborFound", NULL);

        n = r;
        for (i = 0; i < n - 1; i++) {
                r = varlink_notify(link, neighbors[i]);
                if (r < 0)
                        goto clear;
        }

        r = varlink_reply(link, neighbors[i]);
        if (r < 0)
                goto clear;

        r = 0;

clear:
        for (i = 0; i < n; i++)
                json_variant_unref(neighbors[i]);
        free(neighbors);

        return r;
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

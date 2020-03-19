/* SPDX-License-Identifier: LGPL-2.1+ */

#include "networkd-varlink.h"
#include "varlink.h"

typedef struct LookupParameters {
        int ifindex;
} LookupParameters;


static int vl_get_link(Manager *m, JsonVariant *variant, Link **ret) {
        static const JsonDispatch dispatch_table[] = {
                { "ifindex", JSON_VARIANT_INTEGER, json_dispatch_integer, offsetof(LookupParameters, ifindex), 0 },
                {}
        };
        LookupParameters p = {};
        int r;

        r = json_dispatch(variant, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (p.ifindex <= 0)
                return -EINVAL;

        return link_get(m, p.ifindex, ret);
}

static int vl_method_renew(Varlink *varlink, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m = userdata;
        Link *link;
        int r;

        assert(varlink);
        assert(m);

        r = vl_get_link(m, parameters, &link);
        if (r < 0)
                return r;

        if (link->dhcp_client) {
                r = sd_dhcp_client_send_renew(link->dhcp_client);
                if (r < 0)
                        return r;
        }

        return varlink_reply(varlink, NULL);
}

static int vl_method_force_renew(Varlink *varlink, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m = userdata;
        Link *link;
        int r;

        assert(varlink);
        assert(m);

        r = vl_get_link(m, parameters, &link);
        if (r < 0)
                return r;

        if (link->dhcp_server) {
                r = sd_dhcp_server_forcerenew(link->dhcp_server);
                if (r < 0)
                        return r;
        }

        return varlink_reply(varlink, NULL);
}

static int vl_method_reconfigure(Varlink *varlink, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m = userdata;
        Link *link;
        int r;

        assert(varlink);
        assert(m);

        r = vl_get_link(m, parameters, &link);
        if (r < 0)
                return r;

        r = link_reconfigure(link, true);
        if (r < 0)
                return r;

        link_set_state(link, LINK_STATE_INITIALIZED);
        r = link_save(link);
        if (r < 0)
                return r;
        link_clean(link);

        return varlink_reply(varlink, NULL);
}

static int vl_method_reload(Varlink *varlink, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        Manager *m = userdata;
        int r;

        assert(varlink);
        assert(m);

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(varlink, parameters);

        r = manager_reload(m);
        if (r < 0)
                return r;

        return varlink_reply(varlink, NULL);
}

int manager_open_varlink(Manager *m, const char *socket, int fd) {
        int r;

        assert(m);

        r = varlink_server_new(&m->varlink_server, VARLINK_SERVER_ROOT_ONLY);
        if (r < 0)
                return r;

        varlink_server_set_userdata(m->varlink_server, m);

        r = varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.Network.RenewLink",       vl_method_renew,
                        "io.systemd.Network.ForceRenewLink",  vl_method_force_renew,
                        "io.systemd.Network.ReconfigureLink", vl_method_reconfigure,
                        "io.systemd.Network.Reload",          vl_method_reload);
        if (r < 0)
                return r;

        if (fd < 0)
                r = varlink_server_listen_address(m->varlink_server, socket, 0600);
        else
                r = varlink_server_listen_fd(m->varlink_server, fd);
        if (r < 0)
                return r;

        r = varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}

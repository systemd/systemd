/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-manager.h"
#include "journald-sync.h"
#include "journald-varlink.h"
#include "log.h"
#include "varlink-io.systemd.Journal.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

void sync_req_varlink_reply(SyncReq *req) {
        int r;

        assert(req);

        /* This is the "second half" of the Synchronize() varlink method. This function is called when we
         * determine that no messages that were enqueued to us when the request was initiated is pending
         * anymore. */

        if (req->offline)
                manager_full_sync(req->manager, /* wait= */ true);

        log_debug("Client request to sync journal (%s offlining) completed.", req->offline ? "with" : "without");

        /* Disconnect the SyncReq from the Varlink connection object, and free it */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = TAKE_PTR(req->link);
        sd_varlink_set_userdata(vl, req->manager); /* reinstall manager object */
        req = sync_req_free(req);

        r = sd_varlink_reply(vl, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to reply to Synchronize() client, ignoring: %m");
}

static int vl_method_synchronize(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int offline = -1;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "offline", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, 0, 0},
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &offline);
        if (r != 0)
                return r;

        if (offline > 0) {
                /* Do not allow unprivileged clients to offline the journal files, since that's potentially slow */
                r = varlink_check_privileged_peer(link);
                if (r < 0)
                        return r;
        } else if (offline < 0) {
                uid_t uid = 0;

                r = sd_varlink_get_peer_uid(link, &uid);
                if (r < 0)
                        return r;

                offline = uid == 0; /* for compat, if not specified default to offlining, except for non-root */
        }

        log_full(offline ? LOG_INFO : LOG_DEBUG,
                 "Received client request to sync journal (%s offlining).", offline ? "with" : "without");

        _cleanup_(sync_req_freep) SyncReq *sr = NULL;

        r = sync_req_new(m, link, &sr);
        if (r < 0)
                return r;

        sr->offline = offline;
        sd_varlink_set_userdata(link, sr);

        sync_req_revalidate(TAKE_PTR(sr));
        return 0;
}

static int vl_method_rotate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        log_info("Received client request to rotate journal, rotating.");
        manager_full_rotate(m);
        log_debug("Client request to rotate journal completed.");

        return sd_varlink_reply(link, NULL);
}

static int vl_method_flush_to_var(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (m->namespace)
                return sd_varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to flush runtime journal.");
        manager_full_flush(m);
        log_debug("Client request to flush runtime journal completed.");

        return sd_varlink_reply(link, NULL);
}

static int vl_method_relinquish_var(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (m->namespace)
                return sd_varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to relinquish %s access.", m->system_storage.path);
        manager_relinquish_var(m);
        log_debug("Client request to relinquish %s access completed.", m->system_storage.path);

        return sd_varlink_reply(link, NULL);
}

static int vl_connect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        (void) manager_start_or_stop_idle_timer(m); /* maybe we are no longer idle */

        return 0;
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        void *u = sd_varlink_get_userdata(link);
        if (u != m) {
                /* If this is a Varlink connection that does not have the Server object as userdata, then it has a SyncReq object instead. Let's finish it. */

                SyncReq *req = u;
                sd_varlink_set_userdata(link, m); /* reinstall server object */
                sync_req_free(req);
        }

        (void) manager_start_or_stop_idle_timer(m); /* maybe we are idle now */
}

int manager_open_varlink(Manager *m, const char *socket, int fd) {
        int r;

        assert(m);

        r = varlink_server_new(
                        &m->varlink_server,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_Journal,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Journal interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.Journal.Synchronize",    vl_method_synchronize,
                        "io.systemd.Journal.Rotate",         vl_method_rotate,
                        "io.systemd.Journal.FlushToVar",     vl_method_flush_to_var,
                        "io.systemd.Journal.RelinquishVar",  vl_method_relinquish_var,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_connect(m->varlink_server, vl_connect);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_disconnect(m->varlink_server, vl_disconnect);
        if (r < 0)
                return r;

        if (fd < 0)
                r = sd_varlink_server_listen_address(m->varlink_server, socket, 0666);
        else
                r = sd_varlink_server_listen_fd(m->varlink_server, fd);
        if (r < 0)
                return r;

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}

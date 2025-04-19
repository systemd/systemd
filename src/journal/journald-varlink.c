/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-server.h"
#include "journald-varlink.h"
#include "varlink-io.systemd.Journal.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

static int synchronize_second_half(sd_event_source *event_source, void *userdata) {
        sd_varlink *link = ASSERT_PTR(userdata);
        Server *s;
        int r;

        assert_se(s = sd_varlink_get_userdata(link));

        /* This is the "second half" of the Synchronize() varlink method. This function is called as deferred
         * event source at a low priority to ensure the synchronization completes after all queued log
         * messages are processed. */
        server_full_sync(s, /* wait = */ true);

        /* Let's get rid of the event source now, by marking it as non-floating again. It then has no ref
         * anymore and is immediately destroyed after we return from this function, i.e. from this event
         * source handler at the end. */
        r = sd_event_source_set_floating(event_source, false);
        if (r < 0)
                return log_error_errno(r, "Failed to mark event source as non-floating: %m");

        return sd_varlink_reply(link, NULL);
}

static void synchronize_destroy(void *userdata) {
        sd_varlink_unref(userdata);
}

static int vl_method_synchronize(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *event_source = NULL;
        Server *s = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        log_info("Received client request to sync journal.");

        /* We don't do the main work now, but instead enqueue a deferred event loop job which will do
         * it. That job is scheduled at low priority, so that we return from this method call only after all
         * queued but not processed log messages are written to disk, so that this method call returning can
         * be used as nice synchronization point. */
        r = sd_event_add_defer(s->event, &event_source, synchronize_second_half, link);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate defer event source: %m");

        r = sd_event_source_set_destroy_callback(event_source, synchronize_destroy);
        if (r < 0)
                return log_error_errno(r, "Failed to set event source destroy callback: %m");

        sd_varlink_ref(link); /* The varlink object is now left to the destroy callback to unref */

        r = sd_event_source_set_priority(event_source, SD_EVENT_PRIORITY_NORMAL+15);
        if (r < 0)
                return log_error_errno(r, "Failed to set defer event source priority: %m");

        /* Give up ownership of this event source. It will now be destroyed along with event loop itself,
         * unless it destroys itself earlier. */
        r = sd_event_source_set_floating(event_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to mark event source as floating: %m");

        (void) sd_event_source_set_description(event_source, "deferred-sync");

        return 0;
}

static int vl_method_rotate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Server *s = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        log_info("Received client request to rotate journal, rotating.");
        server_full_rotate(s);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_flush_to_var(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Server *s = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        if (s->namespace)
                return sd_varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to flush runtime journal.");
        server_full_flush(s);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_relinquish_var(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Server *s = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table = */ NULL, /* userdata = */ NULL);
        if (r != 0)
                return r;

        if (s->namespace)
                return sd_varlink_error(link, "io.systemd.Journal.NotSupportedByNamespaces", NULL);

        log_info("Received client request to relinquish %s access.", s->system_storage.path);
        server_relinquish_var(s);

        return sd_varlink_reply(link, NULL);
}

static int vl_connect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Server *s = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        (void) server_start_or_stop_idle_timer(s); /* maybe we are no longer idle */

        return 0;
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Server *s = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        (void) server_start_or_stop_idle_timer(s); /* maybe we are idle now */
}

int server_open_varlink(Server *s, const char *socket, int fd) {
        int r;

        assert(s);

        r = varlink_server_new(
                        &s->varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_INHERIT_USERDATA,
                        s);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        s->varlink_server,
                        &vl_interface_io_systemd_Journal,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Journal interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s->varlink_server,
                        "io.systemd.Journal.Synchronize",    vl_method_synchronize,
                        "io.systemd.Journal.Rotate",         vl_method_rotate,
                        "io.systemd.Journal.FlushToVar",     vl_method_flush_to_var,
                        "io.systemd.Journal.RelinquishVar",  vl_method_relinquish_var,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_connect(s->varlink_server, vl_connect);
        if (r < 0)
                return r;

        r = sd_varlink_server_bind_disconnect(s->varlink_server, vl_disconnect);
        if (r < 0)
                return r;

        if (fd < 0)
                r = sd_varlink_server_listen_address(s->varlink_server, socket, 0600);
        else
                r = sd_varlink_server_listen_fd(s->varlink_server, fd);
        if (r < 0)
                return r;

        r = sd_varlink_server_attach_event(s->varlink_server, s->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        return 0;
}

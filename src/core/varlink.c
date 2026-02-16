/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "constants.h"
#include "errno-util.h"
#include "manager.h"
#include "metrics.h"
#include "path-util.h"
#include "pidref.h"
#include "string-util.h"
#include "unit.h"
#include "varlink.h"
#include "varlink-dynamic-user.h"
#include "varlink-io.systemd.ManagedOOM.h"
#include "varlink-io.systemd.Manager.h"
#include "varlink-io.systemd.Unit.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-io.systemd.service.h"
#include "varlink-manager.h"
#include "varlink-metrics.h"
#include "varlink-serialize.h"
#include "varlink-unit.h"
#include "varlink-util.h"

static const char* const managed_oom_mode_properties[] = {
        "ManagedOOMSwap",
        "ManagedOOMMemoryPressure",
};

static int build_managed_oom_json_array_element(Unit *u, const char *property, sd_json_variant **ret_v) {
        bool use_limit = false, use_duration = false;
        CGroupContext *c;
        const char *mode;

        assert(u);
        assert(property);
        assert(ret_v);

        if (!UNIT_VTABLE(u)->can_set_managed_oom)
                return -EOPNOTSUPP;

        c = unit_get_cgroup_context(u);
        if (!c)
                return -EINVAL;

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return -EINVAL;

        if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)))
                /* systemd-oomd should always treat inactive units as though they didn't enable any action since they
                 * should not have a valid cgroup */
                mode = managed_oom_mode_to_string(MANAGED_OOM_AUTO);
        else if (streq(property, "ManagedOOMSwap"))
                mode = managed_oom_mode_to_string(c->moom_swap);
        else if (streq(property, "ManagedOOMMemoryPressure")) {
                mode = managed_oom_mode_to_string(c->moom_mem_pressure);
                use_limit = c->moom_mem_pressure_limit > 0;
                use_duration = c->moom_mem_pressure_duration_usec != USEC_INFINITY;
        } else
                return -EINVAL;

        return sd_json_buildo(ret_v,
                              SD_JSON_BUILD_PAIR_STRING("mode", mode),
                              SD_JSON_BUILD_PAIR_STRING("path", crt->cgroup_path),
                              SD_JSON_BUILD_PAIR_STRING("property", property),
                              SD_JSON_BUILD_PAIR_CONDITION(use_limit, "limit", SD_JSON_BUILD_UNSIGNED(c->moom_mem_pressure_limit)),
                              SD_JSON_BUILD_PAIR_CONDITION(use_duration, "duration", SD_JSON_BUILD_UNSIGNED(c->moom_mem_pressure_duration_usec)));
}

static int build_managed_oom_cgroups_json(Manager *m, bool allow_empty, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL;
        int r;

        assert(m);
        assert(ret);

        if (allow_empty) {
                r = sd_json_build(&arr, SD_JSON_BUILD_EMPTY_ARRAY);
                if (r < 0)
                        return r;
        }

        for (UnitType t = 0; t < _UNIT_TYPE_MAX; t++) {

                if (!unit_vtable[t]->can_set_managed_oom)
                        continue;

                LIST_FOREACH(units_by_type, u, m->units_by_type[t]) {
                        CGroupContext *c;

                        if (UNIT_IS_INACTIVE_OR_FAILED(unit_active_state(u)))
                                continue;

                        c = unit_get_cgroup_context(u);
                        if (!c)
                                continue;

                        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
                        if (!crt || !crt->cgroup_path)
                                continue;

                        FOREACH_ELEMENT(i, managed_oom_mode_properties) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;

                                /* For the initial varlink call we only care about units that enabled (i.e. mode is not
                                 * set to "auto") oomd properties. */
                                if (!(streq(*i, "ManagedOOMSwap") && c->moom_swap == MANAGED_OOM_KILL) &&
                                    !(streq(*i, "ManagedOOMMemoryPressure") && c->moom_mem_pressure == MANAGED_OOM_KILL))
                                        continue;

                                r = build_managed_oom_json_array_element(u, *i, &e);
                                if (r < 0)
                                        return r;

                                r = sd_json_variant_append_array(&arr, e);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (!arr) {
                assert(!allow_empty);
                *ret = NULL;
                return 0;
        }

        r = sd_json_buildo(ret, SD_JSON_BUILD_PAIR_VARIANT("cgroups", arr));
        if (r < 0)
                return r;

        return 1;
}

static int manager_varlink_send_managed_oom_initial(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(m);

        if (!MANAGER_IS_USER(m))
                return 0;

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        assert(m->managed_oom_varlink);

        r = build_managed_oom_cgroups_json(m, /* allow_empty= */ false, &v);
        if (r <= 0)
                return r;

        return sd_varlink_send(m->managed_oom_varlink, "io.systemd.oom.ReportManagedOOMCGroups", v);
}

static int manager_varlink_managed_oom_connect(Manager *m);

static int managed_oom_vl_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (error_id)
                log_debug("varlink systemd-oomd client error: %s", error_id);

        if (FLAGS_SET(flags, SD_VARLINK_REPLY_ERROR|SD_VARLINK_REPLY_LOCAL)) {
                /* sd_varlink connection was closed, likely because of systemd-oomd restart. Let's try to
                 * reconnect and send the initial ManagedOOM update again. */

                m->managed_oom_varlink = sd_varlink_unref(link);

                log_debug("Reconnecting to %s", VARLINK_PATH_MANAGED_OOM_USER);

                r = manager_varlink_managed_oom_connect(m);
                if (r <= 0)
                        return r;
        }

        return 0;
}

static int manager_varlink_managed_oom_connect(Manager *m) {
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(m);

        if (m->managed_oom_varlink)
                return 1;

        if (!MANAGER_IS_USER(m))
                return -EINVAL;

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        r = sd_varlink_connect_address(&link, VARLINK_PATH_MANAGED_OOM_USER);
        if (r == -ENOENT)
                return 0;
        if (ERRNO_IS_NEG_DISCONNECT(r)) {
                log_debug_errno(r, "systemd-oomd varlink socket isn't available, skipping user manager varlink setup: %m");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to connect to '%s': %m", VARLINK_PATH_MANAGED_OOM_USER);

        sd_varlink_set_userdata(link, m);

        r = sd_varlink_bind_reply(link, managed_oom_vl_reply);
        if (r < 0)
                return r;

        r = sd_varlink_attach_event(link, m->event, EVENT_PRIORITY_IPC);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->managed_oom_varlink = TAKE_PTR(link);

        /* Queue the initial ManagedOOM update. */
        (void) manager_varlink_send_managed_oom_initial(m);

        return 1;
}

int manager_varlink_send_managed_oom_update(Unit *u) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *arr = NULL, *v = NULL;
        CGroupRuntime *crt;
        CGroupContext *c;
        int r;

        assert(u);

        if (!UNIT_VTABLE(u)->can_set_managed_oom || !u->manager)
                return 0;

        if (MANAGER_IS_TEST_RUN(u->manager))
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt || !crt->cgroup_path)
                return 0;

        if (MANAGER_IS_SYSTEM(u->manager)) {
                /* In system mode we can't send any notifications unless oomd connected back to us. In this
                 * mode oomd must initiate communication, not us. */
                if (!u->manager->managed_oom_varlink)
                        return 0;
        } else {
                /* If we are in user mode, let's connect to oomd if we aren't connected yet. In this mode we
                 * must initiate communication to oomd, not the other way round. */
                r = manager_varlink_managed_oom_connect(u->manager);
                if (r <= 0)
                        return r;
        }

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        if (MANAGER_IS_SYSTEM(u->manager)) {
                r = sd_json_build(&arr, SD_JSON_BUILD_EMPTY_ARRAY);
                if (r < 0)
                        return r;
        }

        FOREACH_ELEMENT(i, managed_oom_mode_properties) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;

                r = build_managed_oom_json_array_element(u, *i, &e);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&arr, e);
                if (r < 0)
                        return r;
        }

        if (!arr) {
                /* There is nothing updated. Skip calling method. */
                assert(!MANAGER_IS_SYSTEM(u->manager));
                return 0;
        }

        r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_VARIANT("cgroups", arr));
        if (r < 0)
                return r;

        if (MANAGER_IS_SYSTEM(u->manager))
                /* in system mode, oomd is our client, thus send out notifications as replies to the
                 * initiating method call from them. */
                r = sd_varlink_notify(u->manager->managed_oom_varlink, v);
        else
                /* in user mode, we are oomd's client, thus send out notifications as method calls that do
                 * not expect a reply. */
                r = sd_varlink_send(u->manager->managed_oom_varlink, "io.systemd.oom.ReportManagedOOMCGroups", v);

        return r;
}

static int vl_method_subscribe_managed_oom_cgroups(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        Unit *u;
        int r;

        assert(link);

        r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                return r;

        u = manager_get_unit_by_pidref(m, &pidref);
        if (!u)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        /* This is meant to be a deterrent and not actual security. The alternative is to check for the systemd-oom
         * user that this unit runs as, but NSS lookups are blocking and not allowed from PID 1. */
        if (!streq(u->id, "systemd-oomd.service"))
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        /* We only take one subscriber for this method so return an error if there's already an existing one.
         * This shouldn't happen since systemd-oomd is the only client of this method. */
        if (FLAGS_SET(flags, SD_VARLINK_METHOD_MORE) && m->managed_oom_varlink)
                return sd_varlink_error(link, "io.systemd.ManagedOOM.SubscriptionTaken", NULL);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        r = build_managed_oom_cgroups_json(m, /* allow_empty= */ true, &v);
        if (r < 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_reply(link, v);

        assert(!m->managed_oom_varlink);
        m->managed_oom_varlink = sd_varlink_ref(link);
        return sd_varlink_notify(m->managed_oom_varlink, v);
}

static void vl_disconnect(sd_varlink_server *s, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);
        assert(link);

        if (link == m->managed_oom_varlink)
                m->managed_oom_varlink = sd_varlink_unref(link);
}

int manager_setup_varlink_server(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        sd_varlink_server_flags_t flags = SD_VARLINK_SERVER_INHERIT_USERDATA;
        if (MANAGER_IS_SYSTEM(m))
                flags |= SD_VARLINK_SERVER_ACCOUNT_UID;

        r = varlink_server_new(&s, flags, m);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate Varlink server: %m");

        (void) sd_varlink_server_set_description(s, "varlink-api");

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_Manager,
                        &vl_interface_io_systemd_Unit,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_debug_errno(r, "Failed to add interfaces to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Manager.Describe", vl_method_describe_manager,
                        "io.systemd.Manager.Reexecute", vl_method_reexecute_manager,
                        "io.systemd.Manager.Reload", vl_method_reload_manager,
                        "io.systemd.Manager.EnqueueMarkedJobs", vl_method_enqueue_marked_jobs_manager,
                        "io.systemd.Unit.List", vl_method_list_units,
                        "io.systemd.service.Ping", varlink_method_ping,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_debug_errno(r, "Failed to register varlink methods: %m");

        if (MANAGER_IS_SYSTEM(m)) {
                r = sd_varlink_server_add_interface_many(
                                s,
                                &vl_interface_io_systemd_UserDatabase,
                                &vl_interface_io_systemd_ManagedOOM);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add interfaces to varlink server: %m");

                r = sd_varlink_server_bind_method_many(
                                s,
                                "io.systemd.UserDatabase.GetUserRecord",  vl_method_get_user_record,
                                "io.systemd.UserDatabase.GetGroupRecord", vl_method_get_group_record,
                                "io.systemd.UserDatabase.GetMemberships", vl_method_get_memberships,
                                "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups", vl_method_subscribe_managed_oom_cgroups);
                if (r < 0)
                        return log_debug_errno(r, "Failed to register varlink methods: %m");

                r = sd_varlink_server_bind_disconnect(s, vl_disconnect);
                if (r < 0)
                        return log_debug_errno(r, "Failed to register varlink disconnect handler: %m");
        }

        r = sd_varlink_server_attach_event(s, m->event, EVENT_PRIORITY_IPC);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);
        return 1;
}

int manager_setup_varlink_metrics_server(Manager *m) {
        assert(m);

        sd_varlink_server_flags_t flags = SD_VARLINK_SERVER_INHERIT_USERDATA;
        if (MANAGER_IS_SYSTEM(m))
                flags |= SD_VARLINK_SERVER_ACCOUNT_UID;

        return metrics_setup_varlink_server(&m->metrics_varlink_server, flags,
                                            m->event, EVENT_PRIORITY_IPC,
                                            vl_method_list_metrics, vl_method_describe_metrics,
                                            m);
}

static int varlink_server_listen_many_idempotent_sentinel(
                sd_varlink_server *s,
                bool known_fresh,
                const char *prefix,
                ...) {

        va_list ap;
        int r = 0;

        assert(s);

        va_start(ap, prefix);
        for (const char *address; (address = va_arg(ap, const char*)); ) {
                _cleanup_free_ char *p = NULL;

                if (prefix) {
                        p = path_join(prefix, address);
                        if (!p) {
                                r = log_oom();
                                break;
                        }

                        address = p;
                }

                /* We might have got sockets through deserialization. Do not bind to them twice. */
                if (!known_fresh && varlink_server_contains_socket(s, address))
                        continue;

                r = sd_varlink_server_listen_address(s, address, 0666 | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (r < 0) {
                        log_error_errno(r, "Failed to bind to varlink socket '%s': %m", address);
                        break;
                }
        }
        va_end(ap);

        return r;
}

#define varlink_server_listen_many_idempotent(s, known_fresh, prefix, ...) \
        varlink_server_listen_many_idempotent_sentinel((s), (known_fresh), (prefix), __VA_ARGS__, NULL)

static int manager_varlink_init_system_api(Manager *m) {
        int r;

        assert(m);

        r = manager_setup_varlink_server(m);
        if (r < 0)
                return log_error_errno(r, "Failed to set up varlink server: %m");
        bool fresh = r > 0;

        if (!MANAGER_IS_TEST_RUN(m)) {
                r = varlink_server_listen_many_idempotent(
                                m->varlink_server, fresh,
                                /* prefix = */ NULL,
                                "/run/systemd/io.systemd.Manager",
                                "/run/systemd/userdb/io.systemd.DynamicUser",
                                VARLINK_PATH_MANAGED_OOM_SYSTEM);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_varlink_init_user_api(Manager *m) {
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        r = manager_setup_varlink_server(m);
        if (r < 0)
                return log_error_errno(r, "Failed to set up varlink server: %m");
        bool fresh = r > 0;

        r = varlink_server_listen_many_idempotent(
                        m->varlink_server, fresh,
                        m->prefix[EXEC_DIRECTORY_RUNTIME],
                        "systemd/io.systemd.Manager");
        if (r < 0)
                return r;

        return manager_varlink_managed_oom_connect(m);
}

static int manager_varlink_init_metrics(Manager *m) {
        int r;

        assert(m);

        if (MANAGER_IS_TEST_RUN(m))
                return 0;

        r = manager_setup_varlink_metrics_server(m);
        if (r < 0)
                return log_error_errno(r, "Failed to set up metrics varlink server: %m");
        bool fresh = r > 0;

        return varlink_server_listen_many_idempotent(
                        m->metrics_varlink_server, fresh,
                        m->prefix[EXEC_DIRECTORY_RUNTIME],
                        "systemd/report/io.systemd.Manager");
}

int manager_varlink_init(Manager *m) {
        int r;

        if (MANAGER_IS_SYSTEM(m))
                r = manager_varlink_init_system_api(m);
        else
                r = manager_varlink_init_user_api(m);
        if (r < 0)
                return r;

        return manager_varlink_init_metrics(m);
}

void manager_varlink_done(Manager *m) {
        assert(m);

        /* Explicitly close the varlink connection to oomd. Note we first take the varlink connection out of
         * the manager, and only then disconnect it — in two steps – so that we don't end up accidentally
         * unreffing it twice. After all, closing the connection might cause the disconnect handler we
         * installed (vl_disconnect() above) to be called, where we will unref it too. */
        sd_varlink_close_unref(TAKE_PTR(m->managed_oom_varlink));

        m->varlink_server = sd_varlink_server_unref(m->varlink_server);
        m->managed_oom_varlink = sd_varlink_close_unref(m->managed_oom_varlink);

        m->metrics_varlink_server = sd_varlink_server_unref(m->metrics_varlink_server);
}

void manager_varlink_send_pending_reload_message(Manager *m) {
        int r;

        assert(m);

        if (!m->pending_reload_message_vl)
                return;

        r = sd_varlink_reply(m->pending_reload_message_vl, /* parameters= */ NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to send queued reload message, ignoring: %m");

        m->pending_reload_message_vl = sd_varlink_unref(m->pending_reload_message_vl);
}

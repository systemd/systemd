/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "dbus-automount.h"
#include "dbus-cgroup.h"
#include "dbus-device.h"
#include "dbus-execute.h"
#include "dbus-job.h"
#include "dbus-kill.h"
#include "dbus-manager.h"
#include "dbus-mount.h"
#include "dbus-path.h"
#include "dbus-scope.h"
#include "dbus-service.h"
#include "dbus-slice.h"
#include "dbus-socket.h"
#include "dbus-swap.h"
#include "dbus-target.h"
#include "dbus-timer.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "missing.h"
#include "mkdir.h"
#include "process-util.h"
#include "selinux-access.h"
#include "serialize.h"
#include "service.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "user-util.h"

#define CONNECTIONS_MAX 4096

static void destroy_bus(Manager *m, sd_bus **bus);

int bus_send_pending_reload_message(Manager *m) {
        int r;

        assert(m);

        if (!m->pending_reload_message)
                return 0;

        /* If we cannot get rid of this message we won't dispatch any D-Bus messages, so that we won't end up wanting
         * to queue another message. */

        r = sd_bus_send(NULL, m->pending_reload_message, NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to send queued message, ignoring: %m");

        m->pending_reload_message = sd_bus_message_unref(m->pending_reload_message);

        return 0;
}

int bus_forward_agent_released(Manager *m, const char *path) {
        int r;

        assert(m);
        assert(path);

        if (!MANAGER_IS_SYSTEM(m))
                return 0;

        if (!m->system_bus)
                return 0;

        /* If we are running a system instance we forward the agent message on the system bus, so that the user
         * instances get notified about this, too */

        r = sd_bus_emit_signal(m->system_bus,
                               "/org/freedesktop/systemd1/agent",
                               "org.freedesktop.systemd1.Agent",
                               "Released",
                               "s", path);
        if (r < 0)
                return log_debug_errno(r, "Failed to propagate agent release message: %m");

        return 1;
}

static int signal_agent_released(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Manager *m = userdata;
        const char *cgroup;
        uid_t sender_uid;
        int r;

        assert(message);
        assert(m);

        /* only accept org.freedesktop.systemd1.Agent from UID=0 */
        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0 || sender_uid != 0)
                return 0;

        /* parse 'cgroup-empty' notification */
        r = sd_bus_message_read(message, "s", &cgroup);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        manager_notify_cgroup_empty(m, cgroup);
        return 0;
}

static int signal_disconnected(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        sd_bus *bus;

        assert(message);
        assert(m);
        assert_se(bus = sd_bus_message_get_bus(message));

        if (bus == m->api_bus)
                bus_done_api(m);
        if (bus == m->system_bus)
                bus_done_system(m);

        if (set_remove(m->private_buses, bus)) {
                log_debug("Got disconnect on private connection.");
                destroy_bus(m, &bus);
        }

        return 0;
}

static int signal_activation_request(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = userdata;
        const char *name;
        Unit *u;
        int r;

        assert(message);
        assert(m);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SERVICE) ||
            manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SOCKET)) {
                r = sd_bus_error_setf(&error, BUS_ERROR_SHUTTING_DOWN, "Refusing activation, D-Bus is shutting down.");
                goto failed;
        }

        r = manager_load_unit(m, name, NULL, &error, &u);
        if (r < 0)
                goto failed;

        if (u->refuse_manual_start) {
                r = sd_bus_error_setf(&error, BUS_ERROR_ONLY_BY_DEPENDENCY, "Operation refused, %s may be requested by dependency only (it is configured to refuse manual start/stop).", u->id);
                goto failed;
        }

        r = manager_add_job(m, JOB_START, u, JOB_REPLACE, NULL, &error, NULL);
        if (r < 0)
                goto failed;

        /* Successfully queued, that's it for us */
        return 0;

failed:
        if (!sd_bus_error_is_set(&error))
                sd_bus_error_set_errno(&error, r);

        log_debug("D-Bus activation failed for %s: %s", name, bus_error_message(&error, r));

        r = sd_bus_message_new_signal(sd_bus_message_get_bus(message), &reply, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Activator", "ActivationFailure");
        if (r < 0) {
                bus_log_create_error(r);
                return 0;
        }

        r = sd_bus_message_append(reply, "sss", name, error.name, error.message);
        if (r < 0) {
                bus_log_create_error(r);
                return 0;
        }

        r = sd_bus_send_to(NULL, reply, "org.freedesktop.DBus", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to respond with to bus activation request: %m");

        return 0;
}

#if HAVE_SELINUX
static int mac_selinux_filter(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *verb, *path;
        Unit *u = NULL;
        Job *j;
        int r;

        assert(message);

        /* Our own method calls are all protected individually with
         * selinux checks, but the built-in interfaces need to be
         * protected too. */

        if (sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Set"))
                verb = "reload";
        else if (sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", NULL) ||
                 sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", NULL) ||
                 sd_bus_message_is_method_call(message, "org.freedesktop.DBus.ObjectManager", NULL) ||
                 sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Peer", NULL))
                verb = "status";
        else
                return 0;

        path = sd_bus_message_get_path(message);

        if (object_path_startswith("/org/freedesktop/systemd1", path)) {
                r = mac_selinux_access_check(message, verb, error);
                if (r < 0)
                        return r;

                return 0;
        }

        if (streq_ptr(path, "/org/freedesktop/systemd1/unit/self")) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                pid_t pid;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return 0;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return 0;

                u = manager_get_unit_by_pid(m, pid);
        } else {
                r = manager_get_job_from_dbus_path(m, path, &j);
                if (r >= 0)
                        u = j->unit;
                else
                        manager_load_unit_from_dbus_path(m, path, NULL, &u);
        }
        if (!u)
                return 0;

        r = mac_selinux_unit_access_check(u, message, verb, error);
        if (r < 0)
                return r;

        return 0;
}
#endif

static int bus_job_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Job *j;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = manager_get_job_from_dbus_path(m, path, &j);
        if (r < 0)
                return 0;

        *found = j;
        return 1;
}

static int find_unit(Manager *m, sd_bus *bus, const char *path, Unit **unit, sd_bus_error *error) {
        Unit *u = NULL;  /* just to appease gcc, initialization is not really necessary */
        int r;

        assert(m);
        assert(bus);
        assert(path);

        if (streq_ptr(path, "/org/freedesktop/systemd1/unit/self")) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                sd_bus_message *message;
                pid_t pid;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_pid(creds, &pid);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pid(m, pid);
                if (!u)
                        return 0;
        } else {
                r = manager_load_unit_from_dbus_path(m, path, error, &u);
                if (r < 0)
                        return 0;
                assert(u);
        }

        *unit = u;
        return 1;
}

static int bus_unit_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        return find_unit(m, bus, path, (Unit**) found, error);
}

static int bus_unit_interface_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        *found = u;
        return 1;
}

static int bus_unit_cgroup_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return 0;

        *found = u;
        return 1;
}

static int bus_cgroup_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        CGroupContext *c;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        *found = c;
        return 1;
}

static int bus_exec_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        ExecContext *c;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        c = unit_get_exec_context(u);
        if (!c)
                return 0;

        *found = c;
        return 1;
}

static int bus_kill_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        KillContext *c;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        c = unit_get_kill_context(u);
        if (!c)
                return 0;

        *found = c;
        return 1;
}

static int bus_job_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        unsigned k = 0;
        Iterator i;
        Job *j;

        l = new0(char*, hashmap_size(m->jobs)+1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(j, m->jobs, i) {
                l[k] = job_dbus_path(j);
                if (!l[k])
                        return -ENOMEM;

                k++;
        }

        assert(hashmap_size(m->jobs) == k);

        *nodes = TAKE_PTR(l);

        return k;
}

static int bus_unit_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        unsigned k = 0;
        Iterator i;
        Unit *u;

        l = new0(char*, hashmap_size(m->units)+1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(u, m->units, i) {
                l[k] = unit_dbus_path(u);
                if (!l[k])
                        return -ENOMEM;

                k++;
        }

        *nodes = TAKE_PTR(l);

        return k;
}

static int bus_setup_api_vtables(Manager *m, sd_bus *bus) {
        UnitType t;
        int r;

        assert(m);
        assert(bus);

#if HAVE_SELINUX
        r = sd_bus_add_filter(bus, NULL, mac_selinux_filter, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add SELinux access filter: %m");
#endif

        r = sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", bus_manager_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register Manager vtable: %m");

        r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/job", "org.freedesktop.systemd1.Job", bus_job_vtable, bus_job_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register Job vtable: %m");

        r = sd_bus_add_node_enumerator(bus, NULL, "/org/freedesktop/systemd1/job", bus_job_enumerate, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add job enumerator: %m");

        r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/unit", "org.freedesktop.systemd1.Unit", bus_unit_vtable, bus_unit_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register Unit vtable: %m");

        r = sd_bus_add_node_enumerator(bus, NULL, "/org/freedesktop/systemd1/unit", bus_unit_enumerate, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add job enumerator: %m");

        for (t = 0; t < _UNIT_TYPE_MAX; t++) {
                const char *interface;

                assert_se(interface = unit_dbus_interface_from_type(t));

                r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/unit", interface, unit_vtable[t]->bus_vtable, bus_unit_interface_find, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to register type specific vtable for %s: %m", interface);

                if (unit_vtable[t]->cgroup_context_offset > 0) {
                        r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/unit", interface, bus_unit_cgroup_vtable, bus_unit_cgroup_find, m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to register control group unit vtable for %s: %m", interface);

                        r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/unit", interface, bus_cgroup_vtable, bus_cgroup_context_find, m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to register control group vtable for %s: %m", interface);
                }

                if (unit_vtable[t]->exec_context_offset > 0) {
                        r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/unit", interface, bus_exec_vtable, bus_exec_context_find, m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to register execute vtable for %s: %m", interface);
                }

                if (unit_vtable[t]->kill_context_offset > 0) {
                        r = sd_bus_add_fallback_vtable(bus, NULL, "/org/freedesktop/systemd1/unit", interface, bus_kill_vtable, bus_kill_context_find, m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to register kill vtable for %s: %m", interface);
                }
        }

        return 0;
}

static int bus_setup_disconnected_match(Manager *m, sd_bus *bus) {
        int r;

        assert(m);
        assert(bus);

        r = sd_bus_match_signal_async(
                        bus,
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "/org/freedesktop/DBus/Local",
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        signal_disconnected, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for Disconnected message: %m");

        return 0;
}

static int bus_on_connection(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int nfd = -1;
        Manager *m = userdata;
        sd_id128_t id;
        int r;

        assert(s);
        assert(m);

        nfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (nfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                log_warning_errno(errno, "Failed to accept private connection, ignoring: %m");
                return 0;
        }

        if (set_size(m->private_buses) >= CONNECTIONS_MAX) {
                log_warning("Too many concurrent connections, refusing");
                return 0;
        }

        r = set_ensure_allocated(&m->private_buses, NULL);
        if (r < 0) {
                log_oom();
                return 0;
        }

        r = sd_bus_new(&bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to allocate new private connection bus: %m");
                return 0;
        }

        (void) sd_bus_set_description(bus, "private-bus-connection");

        r = sd_bus_set_fd(bus, nfd, nfd);
        if (r < 0) {
                log_warning_errno(r, "Failed to set fd on new connection bus: %m");
                return 0;
        }

        nfd = -1;

        r = bus_check_peercred(bus);
        if (r < 0) {
                log_warning_errno(r, "Incoming private connection from unprivileged client, refusing: %m");
                return 0;
        }

        assert_se(sd_id128_randomize(&id) >= 0);

        r = sd_bus_set_server(bus, 1, id);
        if (r < 0) {
                log_warning_errno(r, "Failed to enable server support for new connection bus: %m");
                return 0;
        }

        r = sd_bus_negotiate_creds(bus, 1,
                                   SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|
                                   SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS|
                                   SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0) {
                log_warning_errno(r, "Failed to enable credentials for new connection: %m");
                return 0;
        }

        r = sd_bus_set_sender(bus, "org.freedesktop.systemd1");
        if (r < 0) {
                log_warning_errno(r, "Failed to set direct connection sender: %m");
                return 0;
        }

        r = sd_bus_start(bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to start new connection bus: %m");
                return 0;
        }

        r = sd_bus_attach_event(bus, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0) {
                log_warning_errno(r, "Failed to attach new connection bus to event loop: %m");
                return 0;
        }

        r = bus_setup_disconnected_match(m, bus);
        if (r < 0)
                return 0;

        r = bus_setup_api_vtables(m, bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to set up API vtables on new connection bus: %m");
                return 0;
        }

        r = set_put(m->private_buses, bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to add new connection bus to set: %m");
                return 0;
        }

        bus = NULL;

        log_debug("Accepted new private connection.");

        return 0;
}

static int manager_dispatch_sync_bus_names(sd_event_source *es, void *userdata) {
        _cleanup_strv_free_ char **names = NULL;
        Manager *m = userdata;
        const char *name;
        Iterator i;
        Unit *u;
        int r;

        assert(es);
        assert(m);
        assert(m->sync_bus_names_event_source == es);

        /* First things first, destroy the defer event so that we aren't triggered again */
        m->sync_bus_names_event_source = sd_event_source_unref(m->sync_bus_names_event_source);

        /* Let's see if there's anything to do still? */
        if (!m->api_bus)
                return 0;
        if (hashmap_isempty(m->watch_bus))
                return 0;

        /* OK, let's sync up the names. Let's see which names are currently on the bus. */
        r = sd_bus_list_names(m->api_bus, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to get initial list of names: %m");

        /* We have to synchronize the current bus names with the
         * list of active services. To do this, walk the list of
         * all units with bus names. */
        HASHMAP_FOREACH_KEY(u, name, m->watch_bus, i) {
                Service *s = SERVICE(u);

                assert(s);

                if (!streq_ptr(s->bus_name, name)) {
                        log_unit_warning(u, "Bus name has changed from %s → %s, ignoring.", s->bus_name, name);
                        continue;
                }

                /* Check if a service's bus name is in the list of currently
                 * active names */
                if (strv_contains(names, name)) {
                        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                        const char *unique;

                        /* If it is, determine its current owner */
                        r = sd_bus_get_name_creds(m->api_bus, name, SD_BUS_CREDS_UNIQUE_NAME, &creds);
                        if (r < 0) {
                                log_full_errno(r == -ENXIO ? LOG_DEBUG : LOG_ERR, r, "Failed to get bus name owner %s: %m", name);
                                continue;
                        }

                        r = sd_bus_creds_get_unique_name(creds, &unique);
                        if (r < 0) {
                                log_full_errno(r == -ENXIO ? LOG_DEBUG : LOG_ERR, r, "Failed to get unique name for %s: %m", name);
                                continue;
                        }

                        /* Now, let's compare that to the previous bus owner, and
                         * if it's still the same, all is fine, so just don't
                         * bother the service. Otherwise, the name has apparently
                         * changed, so synthesize a name owner changed signal. */

                        if (!streq_ptr(unique, s->bus_name_owner))
                                UNIT_VTABLE(u)->bus_name_owner_change(u, s->bus_name_owner, unique);
                } else {
                        /* So, the name we're watching is not on the bus.
                         * This either means it simply hasn't appeared yet,
                         * or it was lost during the daemon reload.
                         * Check if the service has a stored name owner,
                         * and synthesize a name loss signal in this case. */

                        if (s->bus_name_owner)
                                UNIT_VTABLE(u)->bus_name_owner_change(u, s->bus_name_owner, NULL);
                }
        }

        return 0;
}

int manager_enqueue_sync_bus_names(Manager *m) {
        int r;

        assert(m);

        /* Enqueues a request to synchronize the bus names in a later event loop iteration. The callers generally don't
         * want us to invoke ->bus_name_owner_change() unit calls from their stack frames as this might result in event
         * dispatching on its own creating loops, hence we simply create a defer event for the event loop and exit. */

        if (m->sync_bus_names_event_source)
                return 0;

        r = sd_event_add_defer(m->event, &m->sync_bus_names_event_source, manager_dispatch_sync_bus_names, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus name synchronization event: %m");

        r = sd_event_source_set_priority(m->sync_bus_names_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "Failed to set event priority: %m");

        r = sd_event_source_set_enabled(m->sync_bus_names_event_source, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to set even to oneshot: %m");

        (void) sd_event_source_set_description(m->sync_bus_names_event_source, "manager-sync-bus-names");
        return 0;
}

static int bus_setup_api(Manager *m, sd_bus *bus) {
        Iterator i;
        char *name;
        Unit *u;
        int r;

        assert(m);
        assert(bus);

        /* Let's make sure we have enough credential bits so that we can make security and selinux decisions */
        r = sd_bus_negotiate_creds(bus, 1,
                                   SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|
                                   SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS|
                                   SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0)
                log_warning_errno(r, "Failed to enable credential passing, ignoring: %m");

        r = bus_setup_api_vtables(m, bus);
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, name, m->watch_bus, i) {
                r = unit_install_bus_match(u, bus, name);
                if (r < 0)
                        log_error_errno(r, "Failed to subscribe to NameOwnerChanged signal for '%s': %m", name);
        }

        r = sd_bus_match_signal_async(
                        bus,
                        NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.systemd1.Activator",
                        "ActivationRequest",
                        signal_activation_request, NULL, m);
        if (r < 0)
                log_warning_errno(r, "Failed to subscribe to activation signal: %m");

        /* Allow replacing of our name, to ease implementation of reexecution, where we keep the old connection open
         * until after the new connection is set up and the name installed to allow clients to synchronously wait for
         * reexecution to finish */
        r = sd_bus_request_name_async(bus, NULL, "org.freedesktop.systemd1", SD_BUS_NAME_REPLACE_EXISTING|SD_BUS_NAME_ALLOW_REPLACEMENT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        log_debug("Successfully connected to API bus.");

        return 0;
}

int bus_init_api(Manager *m) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (m->api_bus)
                return 0;

        /* The API and system bus is the same if we are running in system mode */
        if (MANAGER_IS_SYSTEM(m) && m->system_bus)
                bus = sd_bus_ref(m->system_bus);
        else {
                if (MANAGER_IS_SYSTEM(m))
                        r = sd_bus_open_system_with_description(&bus, "bus-api-system");
                else
                        r = sd_bus_open_user_with_description(&bus, "bus-api-user");
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to API bus: %m");

                r = sd_bus_attach_event(bus, m->event, SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach API bus to event loop: %m");

                r = bus_setup_disconnected_match(m, bus);
                if (r < 0)
                        return r;
        }

        r = bus_setup_api(m, bus);
        if (r < 0)
                return log_error_errno(r, "Failed to set up API bus: %m");

        m->api_bus = TAKE_PTR(bus);

        r = manager_enqueue_sync_bus_names(m);
        if (r < 0)
                return r;

        return 0;
}

static int bus_setup_system(Manager *m, sd_bus *bus) {
        int r;

        assert(m);
        assert(bus);

        /* if we are a user instance we get the Released message via the system bus */
        if (MANAGER_IS_USER(m)) {
                r = sd_bus_match_signal_async(
                                bus,
                                NULL,
                                NULL,
                                "/org/freedesktop/systemd1/agent",
                                "org.freedesktop.systemd1.Agent",
                                "Released",
                                signal_agent_released, NULL, m);
                if (r < 0)
                        log_warning_errno(r, "Failed to request Released match on system bus: %m");
        }

        log_debug("Successfully connected to system bus.");
        return 0;
}

int bus_init_system(Manager *m) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (m->system_bus)
                return 0;

        /* The API and system bus is the same if we are running in system mode */
        if (MANAGER_IS_SYSTEM(m) && m->api_bus)
                bus = sd_bus_ref(m->api_bus);
        else {
                r = sd_bus_open_system_with_description(&bus, "bus-system");
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to system bus: %m");

                r = sd_bus_attach_event(bus, m->event, SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach system bus to event loop: %m");

                r = bus_setup_disconnected_match(m, bus);
                if (r < 0)
                        return r;
        }

        r = bus_setup_system(m, bus);
        if (r < 0)
                return log_error_errno(r, "Failed to set up system bus: %m");

        m->system_bus = TAKE_PTR(bus);

        return 0;
}

int bus_init_private(Manager *m) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa = {};
        sd_event_source *s;
        int r, salen;

        assert(m);

        if (m->private_listen_fd >= 0)
                return 0;

        if (MANAGER_IS_SYSTEM(m)) {

                /* We want the private bus only when running as init */
                if (getpid_cached() != 1)
                        return 0;

                salen = sockaddr_un_set_path(&sa.un, "/run/systemd/private");
        } else {
                const char *e, *joined;

                e = secure_getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                               "XDG_RUNTIME_DIR is not set, refusing.");

                joined = strjoina(e, "/systemd/private");
                salen = sockaddr_un_set_path(&sa.un, joined);
        }
        if (salen < 0)
                return log_error_errno(salen, "Can't set path for AF_UNIX socket to bind to: %m");

        (void) mkdir_parents_label(sa.un.sun_path, 0755);
        (void) sockaddr_un_unlink(&sa.un);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate private socket: %m");

        r = bind(fd, &sa.sa, salen);
        if (r < 0)
                return log_error_errno(errno, "Failed to bind private socket: %m");

        r = listen(fd, SOMAXCONN);
        if (r < 0)
                return log_error_errno(errno, "Failed to make private socket listening: %m");

        /* Generate an inotify event in case somebody waits for this socket to appear using inotify() */
        (void) touch(sa.un.sun_path);

        r = sd_event_add_io(m->event, &s, fd, EPOLLIN, bus_on_connection, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event source: %m");

        (void) sd_event_source_set_description(s, "bus-connection");

        m->private_listen_fd = TAKE_FD(fd);
        m->private_listen_event_source = s;

        log_debug("Successfully created private D-Bus server.");

        return 0;
}

static void destroy_bus(Manager *m, sd_bus **bus) {
        Iterator i;
        Unit *u;
        Job *j;

        assert(m);
        assert(bus);

        if (!*bus)
                return;

        /* Make sure all bus slots watching names are released. */
        HASHMAP_FOREACH(u, m->watch_bus, i) {
                if (!u->match_bus_slot)
                        continue;

                if (sd_bus_slot_get_bus(u->match_bus_slot) != *bus)
                        continue;

                u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
        }

        /* Get rid of tracked clients on this bus */
        if (m->subscribed && sd_bus_track_get_bus(m->subscribed) == *bus)
                m->subscribed = sd_bus_track_unref(m->subscribed);

        HASHMAP_FOREACH(j, m->jobs, i)
                if (j->bus_track && sd_bus_track_get_bus(j->bus_track) == *bus)
                        j->bus_track = sd_bus_track_unref(j->bus_track);

        HASHMAP_FOREACH(u, m->units, i)
                if (u->bus_track && sd_bus_track_get_bus(u->bus_track) == *bus)
                        u->bus_track = sd_bus_track_unref(u->bus_track);

        /* Get rid of queued message on this bus */
        if (m->pending_reload_message && sd_bus_message_get_bus(m->pending_reload_message) == *bus)
                m->pending_reload_message = sd_bus_message_unref(m->pending_reload_message);

        /* Possibly flush unwritten data, but only if we are
         * unprivileged, since we don't want to sync here */
        if (!MANAGER_IS_SYSTEM(m))
                sd_bus_flush(*bus);

        /* And destroy the object */
        *bus = sd_bus_close_unref(*bus);
}

void bus_done_api(Manager *m) {
        destroy_bus(m, &m->api_bus);
}

void bus_done_system(Manager *m) {
        destroy_bus(m, &m->system_bus);
}

void bus_done_private(Manager *m) {
        sd_bus *b;

        assert(m);

        while ((b = set_steal_first(m->private_buses)))
                destroy_bus(m, &b);

        m->private_buses = set_free(m->private_buses);

        m->private_listen_event_source = sd_event_source_unref(m->private_listen_event_source);
        m->private_listen_fd = safe_close(m->private_listen_fd);
}

void bus_done(Manager *m) {
        assert(m);

        bus_done_api(m);
        bus_done_system(m);
        bus_done_private(m);

        assert(!m->subscribed);

        m->deserialized_subscribed = strv_free(m->deserialized_subscribed);
        bus_verify_polkit_async_registry_free(m->polkit_registry);
}

int bus_fdset_add_all(Manager *m, FDSet *fds) {
        Iterator i;
        sd_bus *b;
        int fd;

        assert(m);
        assert(fds);

        /* When we are about to reexecute we add all D-Bus fds to the
         * set to pass over to the newly executed systemd. They won't
         * be used there however, except thatt they are closed at the
         * very end of deserialization, those making it possible for
         * clients to synchronously wait for systemd to reexec by
         * simply waiting for disconnection */

        if (m->api_bus) {
                fd = sd_bus_get_fd(m->api_bus);
                if (fd >= 0) {
                        fd = fdset_put_dup(fds, fd);
                        if (fd < 0)
                                return fd;
                }
        }

        SET_FOREACH(b, m->private_buses, i) {
                fd = sd_bus_get_fd(b);
                if (fd >= 0) {
                        fd = fdset_put_dup(fds, fd);
                        if (fd < 0)
                                return fd;
                }
        }

        /* We don't offer any APIs on the system bus (well, unless it
         * is the same as the API bus) hence we don't bother with it
         * here */

        return 0;
}

int bus_foreach_bus(
                Manager *m,
                sd_bus_track *subscribed2,
                int (*send_message)(sd_bus *bus, void *userdata),
                void *userdata) {

        Iterator i;
        sd_bus *b;
        int r, ret = 0;

        /* Send to all direct buses, unconditionally */
        SET_FOREACH(b, m->private_buses, i) {

                /* Don't bother with enqueing these messages to clients that haven't started yet */
                if (sd_bus_is_ready(b) <= 0)
                        continue;

                r = send_message(b, userdata);
                if (r < 0)
                        ret = r;
        }

        /* Send to API bus, but only if somebody is subscribed */
        if (m->api_bus &&
            (sd_bus_track_count(m->subscribed) > 0 ||
             sd_bus_track_count(subscribed2) > 0)) {
                r = send_message(m->api_bus, userdata);
                if (r < 0)
                        ret = r;
        }

        return ret;
}

void bus_track_serialize(sd_bus_track *t, FILE *f, const char *prefix) {
        const char *n;

        assert(f);
        assert(prefix);

        for (n = sd_bus_track_first(t); n; n = sd_bus_track_next(t)) {
                int c, j;

                c = sd_bus_track_count_name(t, n);
                for (j = 0; j < c; j++)
                        (void) serialize_item(f, prefix, n);
        }
}

int bus_track_coldplug(Manager *m, sd_bus_track **t, bool recursive, char **l) {
        int r = 0;

        assert(m);
        assert(t);

        if (strv_isempty(l))
                return 0;

        if (!m->api_bus)
                return 0;

        if (!*t) {
                r = sd_bus_track_new(m->api_bus, t, NULL, NULL);
                if (r < 0)
                        return r;
        }

        r = sd_bus_track_set_recursive(*t, recursive);
        if (r < 0)
                return r;

        return bus_track_add_name_many(*t, l);
}

int bus_verify_manage_units_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(call, CAP_SYS_ADMIN, "org.freedesktop.systemd1.manage-units", NULL, false, UID_INVALID, &m->polkit_registry, error);
}

int bus_verify_manage_unit_files_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(call, CAP_SYS_ADMIN, "org.freedesktop.systemd1.manage-unit-files", NULL, false, UID_INVALID, &m->polkit_registry, error);
}

int bus_verify_reload_daemon_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(call, CAP_SYS_ADMIN, "org.freedesktop.systemd1.reload-daemon", NULL, false, UID_INVALID, &m->polkit_registry, error);
}

int bus_verify_set_environment_async(Manager *m, sd_bus_message *call, sd_bus_error *error) {
        return bus_verify_polkit_async(call, CAP_SYS_ADMIN, "org.freedesktop.systemd1.set-environment", NULL, false, UID_INVALID, &m->polkit_registry, error);
}

uint64_t manager_bus_n_queued_write(Manager *m) {
        uint64_t c = 0;
        Iterator i;
        sd_bus *b;
        int r;

        /* Returns the total number of messages queued for writing on all our direct and API buses. */

        SET_FOREACH(b, m->private_buses, i) {
                uint64_t k;

                r = sd_bus_get_n_queued_write(b, &k);
                if (r < 0)
                        log_debug_errno(r, "Failed to query queued messages for private bus: %m");
                else
                        c += k;
        }

        if (m->api_bus) {
                uint64_t k;

                r = sd_bus_get_n_queued_write(m->api_bus, &k);
                if (r < 0)
                        log_debug_errno(r, "Failed to query queued messages for API bus: %m");
                else
                        c += k;
        }

        return c;
}

static void vtable_dump_bus_properties(FILE *f, const sd_bus_vtable *table) {
        const sd_bus_vtable *i;

        for (i = table; i->type != _SD_BUS_VTABLE_END; i++) {
                if (!IN_SET(i->type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY) ||
                    (i->flags & (SD_BUS_VTABLE_DEPRECATED | SD_BUS_VTABLE_HIDDEN)) != 0)
                        continue;

                fprintf(f, "%s\n", i->x.property.member);
        }
}

void dump_bus_properties(FILE *f) {
        assert(f);

        vtable_dump_bus_properties(f, bus_automount_vtable);
        vtable_dump_bus_properties(f, bus_cgroup_vtable);
        vtable_dump_bus_properties(f, bus_device_vtable);
        vtable_dump_bus_properties(f, bus_exec_vtable);
        vtable_dump_bus_properties(f, bus_job_vtable);
        vtable_dump_bus_properties(f, bus_kill_vtable);
        vtable_dump_bus_properties(f, bus_manager_vtable);
        vtable_dump_bus_properties(f, bus_mount_vtable);
        vtable_dump_bus_properties(f, bus_path_vtable);
        vtable_dump_bus_properties(f, bus_scope_vtable);
        vtable_dump_bus_properties(f, bus_service_vtable);
        vtable_dump_bus_properties(f, bus_slice_vtable);
        vtable_dump_bus_properties(f, bus_socket_vtable);
        vtable_dump_bus_properties(f, bus_swap_vtable);
        vtable_dump_bus_properties(f, bus_target_vtable);
        vtable_dump_bus_properties(f, bus_timer_vtable);
        vtable_dump_bus_properties(f, bus_unit_vtable);
        vtable_dump_bus_properties(f, bus_unit_cgroup_vtable);
}

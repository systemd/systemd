/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/stat.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "bus-util.h"
#include "common-signal.h"
#include "constants.h"
#include "daemon-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "machine.h"
#include "machined.h"
#include "machined-varlink.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "operation.h"
#include "path-lookup.h"
#include "service-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "string-util.h"

static Manager* manager_unref(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(machine_hash_ops, char, string_hash_func, string_compare_func, Machine, machine_free);

static int manager_new(RuntimeScope scope, Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .runtime_scope = scope,
        };

        r = runtime_directory_generic(scope, "systemd/machines", &m->state_dir);
        if (r < 0)
                return r;

        m->machines = hashmap_new(&machine_hash_ops);
        if (!m->machines)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || r == -EHOSTDOWN ? LOG_DEBUG : LOG_NOTICE, r,
                               "Unable to create memory pressure event source, ignoring: %m");

        (void) sd_event_set_watchdog(m->event, true);

        *ret = TAKE_PTR(m);
        return 0;
}

static Manager* manager_unref(Manager *m) {
        if (!m)
                return NULL;

        while (m->operations)
                operation_free(m->operations);

        assert(m->n_operations == 0);

        hashmap_free(m->machines); /* This will free all machines, thus the by_unit/by_leader hashmaps shall be empty */

        assert(hashmap_isempty(m->machines_by_unit));
        hashmap_free(m->machines_by_unit);
        assert(hashmap_isempty(m->machines_by_leader));
        hashmap_free(m->machines_by_leader);

        hashmap_free(m->image_cache);

        sd_event_source_unref(m->image_cache_defer_event);

        sd_event_source_disable_unref(m->deferred_gc_event_source);

        hashmap_free(m->polkit_registry);

        manager_varlink_done(m);

        m->query_filter_subscriptions = set_free(m->query_filter_subscriptions);

        sd_bus_flush_close_unref(m->api_bus);
        sd_bus_flush_close_unref(m->system_bus);
        sd_event_unref(m->event);

        free(m->state_dir);

        return mfree(m);
}

static int manager_add_host_machine(Manager *m) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *rd = NULL, *unit = NULL;
        sd_id128_t mid;
        Machine *t;
        int r;

        if (m->runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return 0;
        if (m->host_machine)
                return 0;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine ID: %m");

        rd = strdup("/");
        if (!rd)
                return log_oom();

        unit = strdup(SPECIAL_ROOT_SLICE);
        if (!unit)
                return log_oom();

        r = pidref_set_pid(&pidref, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to open reference to PID 1: %m");

        r = machine_new(MACHINE_HOST, ".host", &t);
        if (r < 0)
                return log_error_errno(r, "Failed to create machine: %m");

        r = machine_link(m, t);
        if (r < 0)
                return log_error_errno(r, "Failed to link machine to manager: %m");

        t->leader = TAKE_PIDREF(pidref);
        t->id = mid;

        /* If vsock is available, let's expose the loopback CID for the local host (and not the actual local
         * CID, in order to return a ideally constant record for the host) */
        if (vsock_get_local_cid(/* ret= */ NULL) >= 0)
                t->vsock_cid = VMADDR_CID_LOCAL;

        t->root_directory = TAKE_PTR(rd);
        t->unit = TAKE_PTR(unit);

        dual_timestamp_from_boottime(&t->timestamp, 0);

        m->host_machine = t;

        return 0;
}

static int manager_enumerate_machines(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        r = manager_add_host_machine(m);
        if (r < 0)
                return r;

        /* Read in machine data stored on disk */
        d = opendir(m->state_dir);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open '%s': %m", m->state_dir);
        }

        FOREACH_DIRENT(de, d, return -errno) {
                struct Machine *machine;
                int k;

                if (!dirent_is_file(de))
                        continue;

                /* Ignore symlinks that map the unit name to the machine */
                if (startswith(de->d_name, "unit:"))
                        continue;

                if (!hostname_is_valid(de->d_name, 0))
                        continue;

                k = manager_add_machine(m, de->d_name, &machine);
                if (k < 0) {
                        RET_GATHER(r, log_error_errno(k, "Failed to add machine by file name %s: %m", de->d_name));
                        continue;
                }

                machine_add_to_gc_queue(machine);

                RET_GATHER(r, machine_load(machine));
        }

        return r;
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->system_bus);
        assert(!m->api_bus);

        r = sd_bus_default_system(&m->system_bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_attach_event(m->system_bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach system bus to event loop: %m");

        if (m->runtime_scope == RUNTIME_SCOPE_SYSTEM)
                m->api_bus = sd_bus_ref(m->system_bus);
        else {
                assert(m->runtime_scope == RUNTIME_SCOPE_USER);

                r = sd_bus_default_user(&m->api_bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to user bus: %m");

                r = sd_bus_attach_event(m->api_bus, m->event, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach user bus to event loop: %m");
        }

        r = bus_add_implementation(m->api_bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_match_signal_async(m->api_bus, NULL, bus_systemd_mgr, "JobRemoved", match_job_removed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add match for JobRemoved: %m");

        r = bus_match_signal_async(m->api_bus, NULL, bus_systemd_mgr, "UnitRemoved", match_unit_removed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for UnitRemoved: %m");

        r = sd_bus_match_signal_async(
                        m->api_bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        NULL,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        match_properties_changed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged: %m");

        r = bus_match_signal_async(m->api_bus, NULL, bus_systemd_mgr, "Reloading", match_reloading, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for Reloading: %m");

        r = bus_call_method_async(m->api_bus, NULL, bus_systemd_mgr, "Subscribe", NULL, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to enable subscription: %m");

        r = bus_log_control_api_register(m->api_bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->api_bus, NULL, "org.freedesktop.machine1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        return 0;
}

static int manager_startup(Manager *m) {
        Machine *machine;
        int r;

        assert(m);

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        /* Set up Varlink service */
        r = manager_varlink_init(m);
        if (r < 0)
                return r;

        /* Deserialize state */
        manager_enumerate_machines(m);

        /* Remove stale objects before we start them */
        manager_gc(m, false);

        /* And start everything */
        HASHMAP_FOREACH(machine, m->machines)
                machine_start(machine, NULL, NULL);

        return 0;
}

static bool check_idle(void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        if (m->operations)
                return false;

        if (sd_varlink_server_current_connections(m->varlink_userdb_server) > 0)
                return false;

        if (sd_varlink_server_current_connections(m->varlink_machine_server) > 0)
                return false;

        if (!hashmap_isempty(m->polkit_registry))
                return false;

        return hashmap_isempty(m->machines);
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        RuntimeScope scope = RUNTIME_SCOPE_SYSTEM;
        int r;

        log_set_facility(LOG_AUTH);
        log_setup();

        r = service_parse_argv("systemd-machined.service",
                               "Manage registrations of local VMs and containers.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               &scope,
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        /* Always create the directories people can create inotify watches in. Note that some applications might check
         * for the existence of /run/systemd/machines/ to determine whether machined is available, so please always
         * make sure this check stays in. */
        if (scope == RUNTIME_SCOPE_SYSTEM)
                (void) mkdir_label("/run/systemd/machines", 0755);

        r = manager_new(scope, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to fully start up daemon: %m");

        r = sd_notify(false, NOTIFY_READY_MESSAGE);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(
                        m->event,
                        m->api_bus,
                        "org.freedesktop.machine1",
                        DEFAULT_EXIT_USEC,
                        check_idle, m);
        if (r < 0)
                return log_error_errno(r, "Failed to run main loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

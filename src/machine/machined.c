/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hostname-util.h"
#include "label.h"
#include "machine-image.h"
#include "machined.h"
#include "main-func.h"
#include "process-util.h"
#include "signal-util.h"
#include "special.h"

static Manager* manager_unref(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(machine_hash_ops, char, string_hash_func, string_compare_func, Machine, machine_free);

static int manager_new(Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->machines = hashmap_new(&machine_hash_ops);
        m->machine_units = hashmap_new(&string_hash_ops);
        m->machine_leaders = hashmap_new(NULL);

        if (!m->machines || !m->machine_units || !m->machine_leaders)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

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

        hashmap_free(m->machines); /* This will free all machines, so that the machine_units/machine_leaders is empty */
        hashmap_free(m->machine_units);
        hashmap_free(m->machine_leaders);
        hashmap_free(m->image_cache);

        sd_event_source_unref(m->image_cache_defer_event);
        sd_event_source_unref(m->nscd_cache_flush_event);

        bus_verify_polkit_async_registry_free(m->polkit_registry);

        sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        return mfree(m);
}

static int manager_add_host_machine(Manager *m) {
        _cleanup_free_ char *rd = NULL, *unit = NULL;
        sd_id128_t mid;
        Machine *t;
        int r;

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

        t = machine_new(m, MACHINE_HOST, ".host");
        if (!t)
                return log_oom();

        t->leader = 1;
        t->id = mid;

        t->root_directory = TAKE_PTR(rd);
        t->unit = TAKE_PTR(unit);

        dual_timestamp_from_boottime_or_monotonic(&t->timestamp, 0);

        m->host_machine = t;

        return 0;
}

static int manager_enumerate_machines(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        assert(m);

        r = manager_add_host_machine(m);
        if (r < 0)
                return r;

        /* Read in machine data stored on disk */
        d = opendir("/run/systemd/machines");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open /run/systemd/machines: %m");
        }

        FOREACH_DIRENT(de, d, return -errno) {
                struct Machine *machine;
                int k;

                if (!dirent_is_file(de))
                        continue;

                /* Ignore symlinks that map the unit name to the machine */
                if (startswith(de->d_name, "unit:"))
                        continue;

                if (!machine_name_is_valid(de->d_name))
                        continue;

                k = manager_add_machine(m, de->d_name, &machine);
                if (k < 0) {
                        r = log_error_errno(k, "Failed to add machine by file name %s: %m", de->d_name);
                        continue;
                }

                machine_add_to_gc_queue(machine);

                k = machine_load(machine);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->bus);

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/machine1", "org.freedesktop.machine1.Manager", manager_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add manager object vtable: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/machine1/machine", "org.freedesktop.machine1.Machine", machine_vtable, machine_object_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add machine object vtable: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/machine1/machine", machine_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add machine enumerator: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/machine1/image", "org.freedesktop.machine1.Image", image_vtable, image_object_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add image object vtable: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/machine1/image", image_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add image enumerator: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "JobRemoved",
                        match_job_removed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add match for JobRemoved: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "UnitRemoved",
                        match_unit_removed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for UnitRemoved: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        NULL,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        match_properties_changed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Reloading",
                        match_reloading, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for Reloading: %m");

        r = sd_bus_call_method_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Subscribe",
                        NULL, NULL,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to enable subscription: %m");

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.machine1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static void manager_gc(Manager *m, bool drop_not_started) {
        Machine *machine;

        assert(m);

        while ((machine = m->machine_gc_queue)) {
                LIST_REMOVE(gc_queue, m->machine_gc_queue, machine);
                machine->in_gc_queue = false;

                /* First, if we are not closing yet, initiate stopping */
                if (machine_may_gc(machine, drop_not_started) &&
                    machine_get_state(machine) != MACHINE_CLOSING)
                        machine_stop(machine);

                /* Now, the stop probably made this referenced
                 * again, but if it didn't, then it's time to let it
                 * go entirely. */
                if (machine_may_gc(machine, drop_not_started)) {
                        machine_finalize(machine);
                        machine_free(machine);
                }
        }
}

static int manager_startup(Manager *m) {
        Machine *machine;
        Iterator i;
        int r;

        assert(m);

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        /* Deserialize state */
        manager_enumerate_machines(m);

        /* Remove stale objects before we start them */
        manager_gc(m, false);

        /* And start everything */
        HASHMAP_FOREACH(machine, m->machines, i)
                machine_start(machine, NULL, NULL);

        return 0;
}

static bool check_idle(void *userdata) {
        Manager *m = userdata;

        if (m->operations)
                return false;

        manager_gc(m, true);

        return hashmap_isempty(m->machines);
}

static int manager_run(Manager *m) {
        assert(m);

        return bus_event_loop_with_idle(
                        m->event,
                        m->bus,
                        "org.freedesktop.machine1",
                        DEFAULT_EXIT_USEC,
                        check_idle, m);
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        log_set_facility(LOG_AUTH);
        log_setup_service();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                return -EINVAL;
        }

        /* Always create the directories people can create inotify watches in. Note that some applications might check
         * for the existence of /run/systemd/machines/ to determine whether machined is available, so please always
         * make sure this check stays in. */
        (void) mkdir_label("/run/systemd/machines", 0755);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGTERM, SIGINT, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to fully start up daemon: %m");

        log_debug("systemd-machined running as pid "PID_FMT, getpid_cached());
        (void) sd_notify(false,
                         "READY=1\n"
                         "STATUS=Processing requests...");

        r = manager_run(m);

        log_debug("systemd-machined stopped as pid "PID_FMT, getpid_cached());
        (void) sd_notify(false,
                         "STOPPING=1\n"
                         "STATUS=Shutting down...");

        return r;
}

DEFINE_MAIN_FUNCTION(run);

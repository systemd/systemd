/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-get-properties.h"
#include "bus-object.h"
#include "bus-util.h"
#include "dbus.h"
#include "dbus-job.h"
#include "dbus-unit.h"
#include "dbus-util.h"
#include "hashmap.h"
#include "job.h"
#include "log.h"
#include "manager.h"
#include "selinux-access.h"
#include "strv.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, job_type, JobType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_state, job_state, JobState);

static int property_get_unit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        Job *j = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        p = unit_dbus_path(j->unit);
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", j->unit->id, p);
}

int bus_job_method_cancel(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Job *j = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(j->unit, message, "stop", error);
        if (r < 0)
                return r;

        /* Access is granted to the job owner */
        if (!sd_bus_track_contains(j->bus_track, sd_bus_message_get_sender(message))) {

                /* And for everybody else consult polkit */
                r = bus_verify_manage_units_async(j->manager, message, error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        job_finish_and_invalidate(j, JOB_CANCELED, true, false);

        return sd_bus_reply_method_return(message, NULL);
}

int bus_job_method_get_waiting_jobs(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ Job **list = NULL;
        Job *j = userdata;
        int r, n;

        if (strstr(sd_bus_message_get_member(message), "After"))
                n = job_get_after(j, &list);
        else
                n = job_get_before(j, &list);
        if (n < 0)
                return n;

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssoo)");
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, list, n) {
                _cleanup_free_ char *unit_path = NULL, *job_path = NULL;
                Job *job = *i;

                job_path = job_dbus_path(job);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(job->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(usssoo)",
                                          job->id,
                                          job->unit->id,
                                          job_type_to_string(job->type),
                                          job_state_to_string(job->state),
                                          job_path,
                                          unit_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

const sd_bus_vtable bus_job_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("Cancel", NULL, NULL, bus_job_method_cancel, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetAfter",
                                 SD_BUS_NO_ARGS,
                                 SD_BUS_RESULT("a(usssoo)", jobs),
                                 bus_job_method_get_waiting_jobs,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetBefore",
                                 SD_BUS_NO_ARGS,
                                 SD_BUS_RESULT("a(usssoo)", jobs),
                                 bus_job_method_get_waiting_jobs,
                                 SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_PROPERTY("Id", "u", NULL, offsetof(Job, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Unit", "(so)", property_get_unit, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobType", "s", property_get_type, offsetof(Job, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("State", "s", property_get_state, offsetof(Job, state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("ActivationDetails", "a(ss)", bus_property_get_activation_details, offsetof(Job, activation_details), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int bus_job_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = manager_get_job_from_dbus_path(m, path, &j);
        if (r < 0)
                return 0;

        *found = j;
        return 1;
}

static int bus_job_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        unsigned k = 0;
        Job *j;

        l = new0(char*, hashmap_size(m->jobs)+1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(j, m->jobs) {
                l[k] = job_dbus_path(j);
                if (!l[k])
                        return -ENOMEM;

                k++;
        }

        assert(hashmap_size(m->jobs) == k);

        *nodes = TAKE_PTR(l);

        return k;
}

const BusObjectImplementation job_object = {
        "/org/freedesktop/systemd1/job",
        "org.freedesktop.systemd1.Job",
        .fallback_vtables = BUS_FALLBACK_VTABLES({bus_job_vtable, bus_job_find}),
        .node_enumerator = bus_job_enumerate,
};

static int send_new_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Job *j = ASSERT_PTR(userdata);
        int r;

        assert(bus);

        p = job_dbus_path(j);
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "JobNew");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "uos", j->id, p, j->unit->id);
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

static int send_changed_signal(sd_bus *bus, void *userdata) {
        _cleanup_free_ char *p = NULL;
        Job *j = ASSERT_PTR(userdata);

        assert(bus);

        p = job_dbus_path(j);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_properties_changed(bus, p, "org.freedesktop.systemd1.Job", "State", NULL);
}

void bus_job_send_change_signal(Job *j) {
        int r;

        assert(j);

        /* Make sure that any change signal on the unit is reflected before we send out the change signal on the job */
        bus_unit_send_pending_change_signal(j->unit, true);

        if (j->in_dbus_queue) {
                LIST_REMOVE(dbus_queue, j->manager->dbus_job_queue, j);
                j->in_dbus_queue = false;

                /* The job might be good to be GC once its pending signals have been sent */
                job_add_to_gc_queue(j);
        }

        r = bus_foreach_bus(j->manager, j->bus_track, j->sent_dbus_new_signal ? send_changed_signal : send_new_signal, j);
        if (r < 0)
                log_debug_errno(r, "Failed to send job change signal for %u: %m", j->id);

        j->sent_dbus_new_signal = true;
}

void bus_job_send_pending_change_signal(Job *j, bool including_new) {
        assert(j);

        if (!j->in_dbus_queue)
                return;

        if (!j->sent_dbus_new_signal && !including_new)
                return;

        if (MANAGER_IS_RELOADING(j->manager))
                return;

        bus_job_send_change_signal(j);
}

static int send_removed_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Job *j = ASSERT_PTR(userdata);
        int r;

        assert(bus);

        p = job_dbus_path(j);
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "JobRemoved");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "uoss", j->id, p, j->unit->id, job_result_to_string(j->result));
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, NULL);
}

void bus_job_send_removed_signal(Job *j) {
        int r;

        assert(j);

        if (!j->sent_dbus_new_signal)
                bus_job_send_change_signal(j);

        /* Make sure that any change signal on the unit is reflected before we send out the change signal on the job */
        bus_unit_send_pending_change_signal(j->unit, true);

        r = bus_foreach_bus(j->manager, j->bus_track, send_removed_signal, j);
        if (r < 0)
                log_debug_errno(r, "Failed to send job remove signal for %u: %m", j->id);
}

static int bus_job_track_handler(sd_bus_track *t, void *userdata) {
        Job *j = ASSERT_PTR(userdata);

        assert(t);

        j->bus_track = sd_bus_track_unref(j->bus_track); /* make sure we aren't called again */

        /* Last client dropped off the bus, maybe we should GC this now? */
        job_add_to_gc_queue(j);
        return 0;
}

static int bus_job_allocate_bus_track(Job *j) {

        assert(j);

        if (j->bus_track)
                return 0;

        return sd_bus_track_new(j->manager->api_bus, &j->bus_track, bus_job_track_handler, j);
}

int bus_job_coldplug_bus_track(Job *j) {
        _cleanup_strv_free_ char **deserialized_clients = NULL;
        int r;

        assert(j);

        deserialized_clients = TAKE_PTR(j->deserialized_clients);

        if (strv_isempty(deserialized_clients))
                return 0;

        if (!j->manager->api_bus)
                return 0;

        r = bus_job_allocate_bus_track(j);
        if (r < 0)
                return r;

        return bus_track_add_name_many(j->bus_track, deserialized_clients);
}

int bus_job_track_sender(Job *j, sd_bus_message *m) {
        int r;

        assert(j);
        assert(m);

        if (sd_bus_message_get_bus(m) != j->manager->api_bus) {
                j->ref_by_private_bus = true;
                return 0;
        }

        r = bus_job_allocate_bus_track(j);
        if (r < 0)
                return r;

        return sd_bus_track_add_sender(j->bus_track, m);
}

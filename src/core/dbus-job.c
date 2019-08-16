/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-bus.h"

#include "alloc-util.h"
#include "dbus-job.h"
#include "dbus-unit.h"
#include "dbus.h"
#include "job.h"
#include "log.h"
#include "selinux-access.h"
#include "string-util.h"
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
        Job *j = userdata;

        assert(bus);
        assert(reply);
        assert(j);

        p = unit_dbus_path(j->unit);
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", j->unit->id, p);
}

int bus_job_method_cancel(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Job *j = userdata;
        int r;

        assert(message);
        assert(j);

        r = mac_selinux_unit_access_check(j->unit, message, "stop", error);
        if (r < 0)
                return r;

        /* Access is granted to the job owner */
        if (!sd_bus_track_contains(j->bus_track, sd_bus_message_get_sender(message))) {

                /* And for everybody else consult polkit */
                r = bus_verify_manage_units_async(j->unit->manager, message, error);
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
        int r, i, n;

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

        for (i = 0; i < n; i ++) {
                _cleanup_free_ char *unit_path = NULL, *job_path = NULL;

                job_path = job_dbus_path(list[i]);
                if (!job_path)
                        return -ENOMEM;

                unit_path = unit_dbus_path(list[i]->unit);
                if (!unit_path)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(usssoo)",
                                          list[i]->id,
                                          list[i]->unit->id,
                                          job_type_to_string(list[i]->type),
                                          job_state_to_string(list[i]->state),
                                          job_path,
                                          unit_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

const sd_bus_vtable bus_job_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Cancel", NULL, NULL, bus_job_method_cancel, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetAfter", NULL, "a(usssoo)", bus_job_method_get_waiting_jobs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetBefore", NULL, "a(usssoo)", bus_job_method_get_waiting_jobs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("Id", "u", NULL, offsetof(Job, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Unit", "(so)", property_get_unit, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("JobType", "s", property_get_type, offsetof(Job, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("State", "s", property_get_state, offsetof(Job, state), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};

static int send_new_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Job *j = userdata;
        int r;

        assert(bus);
        assert(j);

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
        Job *j = userdata;

        assert(bus);
        assert(j);

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

        if (MANAGER_IS_RELOADING(j->unit->manager))
                return;

        bus_job_send_change_signal(j);
}

static int send_removed_signal(sd_bus *bus, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        Job *j = userdata;
        int r;

        assert(bus);
        assert(j);

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
        Job *j = userdata;

        assert(t);
        assert(j);

        j->bus_track = sd_bus_track_unref(j->bus_track); /* make sure we aren't called again */

        /* Last client dropped off the bus, maybe we should GC this now? */
        job_add_to_gc_queue(j);
        return 0;
}

static int bus_job_allocate_bus_track(Job *j) {

        assert(j);

        if (j->bus_track)
                return 0;

        return sd_bus_track_new(j->unit->manager->api_bus, &j->bus_track, bus_job_track_handler, j);
}

int bus_job_coldplug_bus_track(Job *j) {
        int r = 0;
        _cleanup_strv_free_ char **deserialized_clients = NULL;

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

        if (sd_bus_message_get_bus(m) != j->unit->manager->api_bus) {
                j->ref_by_private_bus = true;
                return 0;
        }

        r = bus_job_allocate_bus_track(j);
        if (r < 0)
                return r;

        return sd_bus_track_add_sender(j->bus_track, m);
}

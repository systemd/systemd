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
#include "extract-word.h"
#include "hashmap.h"
#include "job.h"
#include "log.h"
#include "manager.h"
#include "parse-util.h"
#include "selinux-access.h"
#include "serialize.h"
#include "strv.h"
#include "unit-name.h"
#include "varlink-unit.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, job_type, JobType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_state, job_state, JobState);

static int property_get_unit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        _cleanup_free_ char *p = NULL;
        Job *j = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        p = unit_dbus_path(j->unit);
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", j->unit->id, p);
}

int bus_job_method_cancel(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Job *j = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(j->unit, message, "stop", reterr_error);
        if (r < 0)
                return r;

        /* Access is granted to the job owner. Only clients on the API bus are tracked, messages on the
         * private bus have no sender. */
        if (sd_bus_message_get_bus(message) != j->manager->api_bus ||
            !sd_bus_track_contains(j->bus_track, sd_bus_message_get_sender(message))) {

                /* And for everybody else consult polkit */
                r = bus_verify_manage_units_async(j->manager, message, reterr_error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        job_finish_and_invalidate(j, JOB_CANCELED, /* recursive= */ true, /* already= */ false);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

int bus_job_method_get_waiting_jobs(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
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

static int bus_job_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *reterr_error) {
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

static int bus_job_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *reterr_error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        unsigned k = 0;
        Job *j;

        assert(nodes);

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

        return sd_bus_send(bus, m, /* ret_cookie= */ NULL);
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
        bus_unit_send_pending_change_signal(j->unit, /* including_new= */ true);

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

static int send_removed_signal_full(sd_bus *bus, uint32_t id, const char *unit, JobResult result) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(bus);
        assert(unit);

        if (asprintf(&p, "/org/freedesktop/systemd1/job/%" PRIu32, id) < 0)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "JobRemoved");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "uoss", id, p, unit, job_result_to_string(result));
        if (r < 0)
                return r;

        return sd_bus_send(bus, m, /* ret_cookie= */ NULL);
}

static int send_removed_signal(sd_bus *bus, void *userdata) {
        Job *j = ASSERT_PTR(userdata);

        return send_removed_signal_full(bus, j->id, j->unit->id, j->result);
}

static int held_job_removed_add(Manager *m, uint32_t id, const char *unit, JobResult result) {
        _cleanup_free_ char *u = NULL;

        assert(m);
        assert(unit);

        u = strdup(unit);
        if (!u)
                return -ENOMEM;

        if (!GREEDY_REALLOC(m->held_job_removed, m->n_held_job_removed + 1))
                return -ENOMEM;

        m->held_job_removed[m->n_held_job_removed++] = (HeldJobRemoved) {
                .id = id,
                .unit = TAKE_PTR(u),
                .result = result,
        };

        return 0;
}

static int hold_removed_signal(Job *j) {
        assert(j);

        /* bus_foreach_bus() doesn't send anything on the API bus until it's set up, so keep the signal until
         * then if anybody might want it by then: the clients of the job, whether tracked already or not yet,
         * or the subscribers that we're yet to track again. */
        if (!j->manager->api_bus || j->manager->api_bus_ready)
                return 0;
        if (sd_bus_track_count(j->bus_track) <= 0 &&
            strv_isempty(j->deserialized_clients) &&
            strv_isempty(j->manager->subscribed_as_strv))
                return 0;

        return held_job_removed_add(j->manager, j->id, j->unit->id, j->result);
}

void bus_job_send_held_removed_signals(Manager *m, sd_bus *bus) {
        int r;

        assert(m);
        assert(bus);
        assert(m->api_bus_ready);

        FOREACH_ARRAY(h, m->held_job_removed, m->n_held_job_removed) {
                Unit *u;

                /* The change signals of the unit didn't go out on the API bus either. If the unit is still
                 * queued for one, take it from the queue first, as manager_dispatch_dbus_queue() does, so
                 * that clients on the API bus see the change of the unit before JobRemoved, as everybody
                 * else did. */
                u = manager_get_unit(m, h->unit);
                if (u && u->in_dbus_queue && !MANAGER_IS_RELOADING(m)) {
                        bus_unit_send_change_signal(u);
                        varlink_unit_send_change_signal(u);
                }

                r = send_removed_signal_full(bus, h->id, h->unit, h->result);
                if (r < 0)
                        log_debug_errno(r, "Failed to send held back job remove signal for %u, ignoring: %m",
                                        h->id);
        }

        bus_job_free_held_removed_signals(m);
}

void bus_job_free_held_removed_signals(Manager *m) {
        assert(m);

        FOREACH_ARRAY(h, m->held_job_removed, m->n_held_job_removed)
                free(h->unit);

        m->held_job_removed = mfree(m->held_job_removed);
        m->n_held_job_removed = 0;
}

void bus_job_serialize_held_removed_signals(Manager *m, FILE *f) {
        assert(m);
        assert(f);

        FOREACH_ARRAY(h, m->held_job_removed, m->n_held_job_removed)
                (void) serialize_item_format(f, "held-job-removed", "%" PRIu32 " %s %s",
                                             h->id, job_result_to_string(h->result), h->unit);
}

int bus_job_deserialize_held_removed_signal(Manager *m, const char *value) {
        _cleanup_free_ char *id_str = NULL, *result_str = NULL;
        const char *p = ASSERT_PTR(value);
        JobResult result;
        uint32_t id;
        int r;

        assert(m);

        r = extract_many_words(&p, /* separators= */ NULL, /* flags= */ 0, &id_str, &result_str);
        if (r < 0)
                return r;
        if (r != 2 || !unit_name_is_valid(p, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return -EINVAL;

        r = safe_atou32(id_str, &id);
        if (r < 0)
                return r;

        result = job_result_from_string(result_str);
        if (result < 0)
                return result;

        return held_job_removed_add(m, id, p, result);
}

void bus_job_send_removed_signal(Job *j) {
        int r;

        assert(j);

        if (!j->sent_dbus_new_signal)
                bus_job_send_change_signal(j);

        /* Make sure that any change signal on the unit is reflected before we send out the change signal on the job */
        bus_unit_send_pending_change_signal(j->unit, /* including_new= */ true);

        r = bus_foreach_bus(j->manager, j->bus_track, send_removed_signal, j);
        if (r < 0)
                log_debug_errno(r, "Failed to send job remove signal for %u: %m", j->id);

        r = hold_removed_signal(j);
        if (r < 0)
                log_debug_errno(r, "Failed to hold back job remove signal for %u, ignoring: %m", j->id);
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

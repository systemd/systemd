/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-wait-for-jobs.h"
#include "set.h"
#include "bus-util.h"
#include "bus-internal.h"
#include "unit-def.h"
#include "escape.h"
#include "strv.h"

typedef struct BusWaitForJobs {
        sd_bus *bus;

        /* The set of jobs to wait for, as bus object paths */
        Set *jobs;

        /* The unit name and job result of the last Job message */
        char *name;
        char *result;

        sd_bus_slot *slot_job_removed;
        sd_bus_slot *slot_disconnected;
} BusWaitForJobs;

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        assert(m);

        log_error("Warning! D-Bus connection terminated.");
        sd_bus_close(sd_bus_message_get_bus(m));

        return 0;
}

static int match_job_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *path, *unit, *result;
        BusWaitForJobs *d = ASSERT_PTR(userdata);
        uint32_t id;
        char *found;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        found = set_remove(d->jobs, (char*) path);
        if (!found)
                return 0;

        free(found);

        (void) free_and_strdup(&d->result, empty_to_null(result));

        (void) free_and_strdup(&d->name, empty_to_null(unit));

        return 0;
}

BusWaitForJobs* bus_wait_for_jobs_free(BusWaitForJobs *d) {
        if (!d)
                return NULL;

        set_free(d->jobs);

        sd_bus_slot_unref(d->slot_disconnected);
        sd_bus_slot_unref(d->slot_job_removed);

        sd_bus_unref(d->bus);

        free(d->name);
        free(d->result);

        return mfree(d);
}

int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *d = NULL;
        int r;

        assert(bus);
        assert(ret);

        d = new(BusWaitForJobs, 1);
        if (!d)
                return -ENOMEM;

        *d = (BusWaitForJobs) {
                .bus = sd_bus_ref(bus),
        };

        /* When we are a bus client we match by sender. Direct
         * connections OTOH have no initialized sender field, and
         * hence we ignore the sender then */
        r = sd_bus_match_signal_async(
                        bus,
                        &d->slot_job_removed,
                        bus->bus_client ? "org.freedesktop.systemd1" : NULL,
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "JobRemoved",
                        match_job_removed, NULL, d);
        if (r < 0)
                return r;

        r = sd_bus_match_signal_async(
                        bus,
                        &d->slot_disconnected,
                        "org.freedesktop.DBus.Local",
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        match_disconnected, NULL, d);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(d);

        return 0;
}

static int bus_process_wait(sd_bus *bus) {
        int r;

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                r = sd_bus_wait(bus, UINT64_MAX);
                if (r < 0)
                        return r;
        }
}

static int bus_job_get_service_result(BusWaitForJobs *d, char **result) {
        _cleanup_free_ char *dbus_path = NULL;

        assert(d);
        assert(d->name);
        assert(result);

        if (!endswith(d->name, ".service"))
                return -EINVAL;

        dbus_path = unit_dbus_path_from_name(d->name);
        if (!dbus_path)
                return -ENOMEM;

        return sd_bus_get_property_string(d->bus,
                                          "org.freedesktop.systemd1",
                                          dbus_path,
                                          "org.freedesktop.systemd1.Service",
                                          "Result",
                                          NULL,
                                          result);
}

static void log_job_error_with_service_result(const char* service, const char *result, const char* const* extra_args) {
        _cleanup_free_ char *service_shell_quoted = NULL;
        const char *systemctl = "systemctl", *journalctl = "journalctl";

        static const struct {
                const char *result, *explanation;
        } explanations[] = {
                { "resources",   "of unavailable resources or another system error" },
                { "protocol",    "the service did not take the steps required by its unit configuration" },
                { "timeout",     "a timeout was exceeded" },
                { "exit-code",   "the control process exited with error code" },
                { "signal",      "a fatal signal was delivered to the control process" },
                { "core-dump",   "a fatal signal was delivered causing the control process to dump core" },
                { "watchdog",    "the service failed to send watchdog ping" },
                { "start-limit", "start of the service was attempted too often" }
        };

        assert(service);

        service_shell_quoted = shell_maybe_quote(service, 0);

        if (!strv_isempty((char**) extra_args)) {
                _cleanup_free_ char *t = NULL;

                t = strv_join((char**) extra_args, " ");
                systemctl = strjoina("systemctl ", t ?: "<args>");
                journalctl = strjoina("journalctl ", t ?: "<args>");
        }

        if (!isempty(result)) {
                size_t i;

                for (i = 0; i < ELEMENTSOF(explanations); ++i)
                        if (streq(result, explanations[i].result))
                                break;

                if (i < ELEMENTSOF(explanations)) {
                        log_error("Job for %s failed because %s.\n"
                                  "See \"%s status %s\" and \"%s -xeu %s\" for details.\n",
                                  service,
                                  explanations[i].explanation,
                                  systemctl,
                                  service_shell_quoted ?: "<service>",
                                  journalctl,
                                  service_shell_quoted ?: "<service>");
                        goto finish;
                }
        }

        log_error("Job for %s failed.\n"
                  "See \"%s status %s\" and \"%s -xeu %s\" for details.\n",
                  service,
                  systemctl,
                  service_shell_quoted ?: "<service>",
                  journalctl,
                  service_shell_quoted ?: "<service>");

finish:
        /* For some results maybe additional explanation is required */
        if (streq_ptr(result, "start-limit"))
                log_info("To force a start use \"%1$s reset-failed %2$s\"\n"
                         "followed by \"%1$s start %2$s\" again.",
                         systemctl,
                         service_shell_quoted ?: "<service>");
}

static int check_wait_response(BusWaitForJobs *d, WaitJobsFlags flags, const char* const* extra_args) {
        assert(d);
        assert(d->name);
        assert(d->result);

        if (FLAGS_SET(flags, BUS_WAIT_JOBS_LOG_ERROR)) {
                if (streq(d->result, "canceled"))
                        log_error("Job for %s canceled.", strna(d->name));
                else if (streq(d->result, "timeout"))
                        log_error("Job for %s timed out.", strna(d->name));
                else if (streq(d->result, "dependency"))
                        log_error("A dependency job for %s failed. See 'journalctl -xe' for details.", strna(d->name));
                else if (streq(d->result, "invalid"))
                        log_error("%s is not active, cannot reload.", strna(d->name));
                else if (streq(d->result, "assert"))
                        log_error("Assertion failed on job for %s.", strna(d->name));
                else if (streq(d->result, "unsupported"))
                        log_error("Operation on or unit type of %s not supported on this system.", strna(d->name));
                else if (streq(d->result, "collected"))
                        log_error("Queued job for %s was garbage collected.", strna(d->name));
                else if (streq(d->result, "once"))
                        log_error("Unit %s was started already once and can't be started again.", strna(d->name));
                else if (!STR_IN_SET(d->result, "done", "skipped")) {

                        if (d->name && endswith(d->name, ".service")) {
                                _cleanup_free_ char *result = NULL;
                                int q;

                                q = bus_job_get_service_result(d, &result);
                                if (q < 0)
                                        log_debug_errno(q, "Failed to get Result property of unit %s: %m", d->name);

                                log_job_error_with_service_result(d->name, result, extra_args);
                        } else
                                log_error("Job failed. See \"journalctl -xe\" for details.");
                }
        }

        if (STR_IN_SET(d->result, "canceled", "collected"))
                return -ECANCELED;
        else if (streq(d->result, "timeout"))
                return -ETIME;
        else if (streq(d->result, "dependency"))
                return -EIO;
        else if (streq(d->result, "invalid"))
                return -ENOEXEC;
        else if (streq(d->result, "assert"))
                return -EPROTO;
        else if (streq(d->result, "unsupported"))
                return -EOPNOTSUPP;
        else if (streq(d->result, "once"))
                return -ESTALE;
        else if (STR_IN_SET(d->result, "done", "skipped"))
                return 0;

        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                               "Unexpected job result, assuming server side newer than us: %s", d->result);
}

int bus_wait_for_jobs(BusWaitForJobs *d, WaitJobsFlags flags, const char* const* extra_args) {
        int r = 0;

        assert(d);

        while (!set_isempty(d->jobs)) {
                int q;

                q = bus_process_wait(d->bus);
                if (q < 0)
                        return log_error_errno(q, "Failed to wait for response: %m");

                if (d->name && d->result) {
                        q = check_wait_response(d, flags, extra_args);
                        /* Return the first error as it is most likely to be
                         * meaningful. */
                        if (q < 0 && r == 0)
                                r = q;

                        log_full_errno_zerook(LOG_DEBUG, q,
                                              "Got result %s/%m for job %s", d->result, d->name);
                }

                d->name = mfree(d->name);
                d->result = mfree(d->result);
        }

        return r;
}

int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path) {
        assert(d);

        return set_put_strdup(&d->jobs, path);
}

int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, WaitJobsFlags flags, const char* const* extra_args) {
        int r;

        r = bus_wait_for_jobs_add(d, path);
        if (r < 0)
                return log_oom();

        return bus_wait_for_jobs(d, flags, extra_args);
}

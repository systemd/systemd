/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "errno-util.h"
#include "escape.h"
#include "log.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "unit-def.h"

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

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        assert(m);

        log_warning("D-Bus connection terminated while waiting for jobs.");
        sd_bus_close(sd_bus_message_get_bus(m));

        return 0;
}

static int match_job_removed(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        BusWaitForJobs *d = ASSERT_PTR(userdata);
        _cleanup_free_ char *job_found = NULL;
        const char *path, *unit, *result;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "uoss", /* id = */ NULL, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        job_found = set_remove(d->jobs, (char*) path);
        if (!job_found)
                return 0;

        (void) free_and_strdup(&d->name, empty_to_null(unit));
        (void) free_and_strdup(&d->result, empty_to_null(result));

        return 0;
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

        /* When we are a bus client we match by sender. Direct connections OTOH have no initialized sender
         * field, and hence we ignore the sender then */
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

static int bus_job_get_service_result(BusWaitForJobs *d, char **ret) {
        _cleanup_free_ char *dbus_path = NULL;

        assert(d);
        assert(d->name);
        assert(ret);

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
                                          ret);
}

static void log_job_error_with_service_result(const char* service, const char *result, const char* const* extra_args) {

        static const struct {
                const char *result, *explanation;
        } explanations[] = {
                { "resources",       "of unavailable resources or another system error"                      },
                { "protocol",        "the service did not take the steps required by its unit configuration" },
                { "timeout",         "a timeout was exceeded"                                                },
                { "exit-code",       "the control process exited with error code"                            },
                { "signal",          "a fatal signal was delivered to the control process"                   },
                { "core-dump",       "a fatal signal was delivered causing the control process to dump core" },
                { "watchdog",        "the service failed to send watchdog ping"                              },
                { "start-limit-hit", "start of the service was attempted too often"                          },
                { "oom-kill",        "of an out-of-memory (OOM) siutation"                                   },
        };

        _cleanup_free_ char *service_shell_quoted = NULL;
        const char *systemctl = "systemctl", *journalctl = "journalctl";

        assert(service);

        service_shell_quoted = shell_maybe_quote(service, 0);

        if (!strv_isempty((char* const*) extra_args)) {
                _cleanup_free_ char *t = NULL;

                t = strv_join((char* const*) extra_args, " ");
                systemctl = strjoina("systemctl ", t ?: "<args>");
                journalctl = strjoina("journalctl ", t ?: "<args>");
        }

        if (!isempty(result))
                FOREACH_ELEMENT(i, explanations)
                        if (streq(result, i->result)) {
                                log_error("Job for %s failed because %s.\n"
                                          "See \"%s status %s\" and \"%s -xeu %s\" for details.\n",
                                          service, i->explanation,
                                          systemctl, service_shell_quoted ?: "<service>",
                                          journalctl, service_shell_quoted ?: "<service>");
                                goto extra;
                        }

        log_error("Job for %s failed.\n"
                  "See \"%s status %s\" and \"%s -xeu %s\" for details.\n",
                  service,
                  systemctl, service_shell_quoted ?: "<service>",
                  journalctl, service_shell_quoted ?: "<service>");

extra:
        /* For some results maybe additional explanation is required */
        if (streq_ptr(result, "start-limit-hit"))
                log_info("To force a start use \"%1$s reset-failed %2$s\"\n"
                         "followed by \"%1$s start %2$s\" again.",
                         systemctl,
                         service_shell_quoted ?: "<service>");
}

static int check_wait_response(BusWaitForJobs *d, WaitJobsFlags flags, const char* const* extra_args) {
        int r;

        assert(d);
        assert(d->name);
        assert(d->result);

        if (streq(d->result, "done")) {
                if (FLAGS_SET(flags, BUS_WAIT_JOBS_LOG_SUCCESS))
                        log_info("Job for %s finished.", d->name);

                return 0;
        } else if (streq(d->result, "skipped")) {
                if (FLAGS_SET(flags, BUS_WAIT_JOBS_LOG_SUCCESS))
                        log_info("Job for %s was skipped.", d->name);

                return 0;
        }

        if (FLAGS_SET(flags, BUS_WAIT_JOBS_LOG_ERROR)) {
                if (streq(d->result, "canceled"))
                        log_error("Job for %s canceled.", d->name);
                else if (streq(d->result, "timeout"))
                        log_error("Job for %s timed out.", d->name);
                else if (streq(d->result, "dependency"))
                        log_error("A dependency job for %s failed. See 'journalctl -xe' for details.", d->name);
                else if (streq(d->result, "invalid"))
                        log_error("%s is not active, cannot reload.", d->name);
                else if (streq(d->result, "assert"))
                        log_error("Assertion failed on job for %s.", d->name);
                else if (streq(d->result, "unsupported"))
                        log_error("Operation on or unit type of %s not supported on this system.", d->name);
                else if (streq(d->result, "collected"))
                        log_error("Queued job for %s was garbage collected.", d->name);
                else if (streq(d->result, "once"))
                        log_error("Unit %s was started already once and can't be started again.", d->name);
                else if (streq(d->result, "frozen"))
                        log_error("Cannot perform operation on frozen unit %s.", d->name);
                else if (streq(d->result, "concurrency"))
                        log_error("Concurrency limit of a slice unit %s is contained in has been reached.", d->name);
                else if (endswith(d->name, ".service")) {
                        /* Job result is unknown. For services, let's also try Result property. */
                        _cleanup_free_ char *result = NULL;

                        r = bus_job_get_service_result(d, &result);
                        if (r < 0)
                                log_debug_errno(r, "Failed to get Result property of unit %s, ignoring: %m",
                                                d->name);

                        log_job_error_with_service_result(d->name, result, extra_args);
                } else /* Otherwise we just show a generic message. */
                        log_error("Job failed. See \"journalctl -xe\" for details.");
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
        else if (streq(d->result, "frozen"))
                return -EDEADLK;
        else if (streq(d->result, "concurrency"))
                return -ETOOMANYREFS;

        return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                               "Unexpected job result '%s' for unit '%s', assuming server side newer than us.",
                               d->result, d->name);
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
                        /* Return the first error as it is most likely to be meaningful. */
                        RET_GATHER(r, q);

                        log_full_errno_zerook(LOG_DEBUG, q,
                                              "Got result %s/%m for job %s.", d->result, d->name);
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

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "sd-event.h"

#include "bus-error.h"
#include "bus-message.h"
#include "bus-wait-for-jobs.h"
#include "fd-util.h"
#include "log.h"
#include "missing_syscall.h"
#include "process-util.h"
#include "tests.h"

static const size_t NCHILDREN=10;

static int on_sigusr1(sd_event_source *s, const struct signalfd_siginfo *ssi, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        PidRef *pids = (PidRef *) userdata;
        const char *job;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire bus: %m");

        r = sd_bus_message_new_method_call(bus, &message,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartAuxiliaryScope");
        if (r < 0)
                return log_error_errno(r, "Failed to create bus message: %m");

        r = sd_bus_message_append_basic(message, 's', "test-aux-scope.scope");
        if (r < 0)
                return log_error_errno(r, "Failed to attach scope name: %m");

        r = sd_bus_message_open_container(message, 'a', "h");
        if (r < 0)
                return log_error_errno(r, "Failed to create array of FDs: %m");

        for (size_t i = 0; i < NCHILDREN; i++) {
                r = sd_bus_message_append_basic(message, 'h', &pids[i].fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to append PIDFD to message: %m");
        }

        r = sd_bus_message_close_container(message);
        if (r < 0)
                return log_error_errno(r, "Failed to close container: %m");

        r = sd_bus_message_append(message, "t", UINT64_C(0));
        if (r < 0)
                return log_error_errno(r, "Failed to attach flags: %m");

        r = sd_bus_message_open_container(message, 'a', "(sv)");
        if (r < 0)
                return log_error_errno(r, "Failed to create property array: %m");

        r = sd_bus_message_append(message, "(sv)", "Description", "s", "Test auxiliary scope");
        if (r < 0)
                return log_error_errno(r, "Failed to append property: %m");

        r = sd_bus_message_close_container(message);
        if (r < 0)
                return log_error_errno(r, "Failed to close container: %m");

        r = sd_bus_call(bus, message, -1, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start auxiliary scope: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &job);
        if (r < 0)
                return log_error_errno(r, "Failed to read reply: %m");

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        r = bus_wait_for_jobs_one(w, job, false, NULL);
        if (r < 0)
                return r;

        return 0;
}

static void destroy_pidrefs(PidRef *pids, size_t n_pids) {
        size_t i;

        assert(pids || n_pids == 0);

        for (i = 0; i < n_pids; i++)
                pidref_done(&pids[i]);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        PidRef pids[NCHILDREN] = {};
        int r, fd;

        CLEANUP_ARRAY(pids, NCHILDREN, destroy_pidrefs);

        test_setup_logging(LOG_INFO);

        fd = pidfd_open(getpid_cached(), 0);
        if (fd < 0 && (ERRNO_IS_NOT_SUPPORTED(errno) || ERRNO_IS_PRIVILEGE(errno)))
                return log_tests_skipped("pidfds are not available");
        else if (fd < 0) {
                log_error_errno(errno, "pidfd_open() failed: %m");
                return EXIT_FAILURE;
        }
        safe_close(fd);

        r = sd_event_new(&event);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate event loop: %m");
                return EXIT_FAILURE;
        }

        r = sd_event_add_signal(event, NULL, SIGUSR1|SD_EVENT_SIGNAL_PROCMASK, on_sigusr1, pids);
        if (r < 0) {
                log_error_errno(r, "Failed to setup SIGUSR1 signal handling: %m");
                return EXIT_FAILURE;
        }

        for (size_t i = 0; i < NCHILDREN; i++) {
                PidRef pidref = PIDREF_NULL;
                pid_t pid;

                r = safe_fork("(worker)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_CLOSE_ALL_FDS, &pid);
                if (r < 0) {
                        log_error_errno(r, "Failed to fork(): %m");
                        return EXIT_FAILURE;
                }

                if (r == 0) {
                        /* Worker */
                        sleep(3600);
                        _exit(EXIT_SUCCESS);
                }

                r = pidref_set_pid(&pidref, pid);
                if (r < 0) {
                        log_error_errno(r, "Failed to initialize PID ref: %m");
                        return EXIT_FAILURE;
                }

                assert_se(pidref.pid == pid);
                assert_se(pidref.fd != -EBADF);

                pids[i] = TAKE_PIDREF(pidref);
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

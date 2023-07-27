/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "sd-event.h"

#include "bus-error.h"
#include "bus-message.h"
#include "log.h"
#include "missing_syscall.h"
#include "process-util.h"
#include "tests.h"

#define NCHILDREN 10

static int on_sigchld(sd_event_source *s, const struct signalfd_siginfo *ssi, void *userdata) {
        while (wait(NULL) > 0);
        return 0;
}

static int on_sigusr1(sd_event_source *s, const struct signalfd_siginfo *ssi, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int *pidfds = (int *) userdata;
        const char *job;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire bus");

        r = sd_bus_message_new_method_call(bus, &message,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartAuxiliaryScope");
        if (r < 0)
                return log_error_errno(r, "Failed to create bus message");

        r = sd_bus_message_append_basic(message, 's', "test-aux-scope.scope");
        if (r < 0)
                return log_error_errno(r, "Failed to attach scope name");

        r = sd_bus_message_open_container(message, 'a', "h");
        if (r < 0)
                return log_error_errno(r, "Failed to create array of FDs");

        for (int i = 0; i < NCHILDREN; i++) {
                r = sd_bus_message_append_basic(message, 'h', &pidfds[i]);
                if (r < 0)
                        return log_error_errno(r, "Failed to append PIDFD to message");
        }

        r = sd_bus_message_close_container(message);
        if (r < 0)
                return log_error_errno(r, "Failed to close container: %m");

        r = sd_bus_message_append_basic(message, 't', 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach flags");

        r = sd_bus_call(bus, message, -1, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start auxiliary scope: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &job);
        if (r < 0)
                return log_error_errno(r, "Failed to read reply");

        printf("aux scope job: %s\n", job);
        return 0;
}

int main(int argc, char *argv[]) {
        sd_event *event;
        int r;
        int pidfds[NCHILDREN] = {};

        test_setup_logging(LOG_INFO);

        r = pidfd_open(getpid_cached(), 0);
        if (r < 0) {
                if (errno == ENOSYS)
                        return log_tests_skipped("pidfds are not available");
                else {
                        log_error("pidfd_open() failed");
                        return EXIT_FAILURE;
                }
        }
        close(r);

        r = sd_event_new(&event);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate event loop: %m");
                return EXIT_FAILURE;
        }

        r = sd_event_add_signal(event, NULL, SIGCHLD | SD_EVENT_SIGNAL_PROCMASK, on_sigchld, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to setup SIGCHLD handling: %m");
                return EXIT_FAILURE;
        }

        r = sd_event_add_signal(event, NULL, SIGUSR1 | SD_EVENT_SIGNAL_PROCMASK, on_sigusr1, pidfds);
        if (r < 0) {
                log_error_errno(r, "Failed to setup SIGUSR1 handling: %m");
                return EXIT_FAILURE;
        }

        for (int i = 0; i < NCHILDREN; i++) {
                pid_t p;

                p = fork();
                if (p < 0) {
                        log_error("fork() failed: %m");
                        return EXIT_FAILURE;
                }

                if (p == 0) {
                        const char *args[3] = { "/usr/bin/sleep", "infinity", NULL };
                        (void) execv(args[0], (char * const *) args);

                        return EXIT_FAILURE;
                } else {
                        int fd;

                        fd = pidfd_open(p, 0);
                        if (fd < 0) {
                                log_error("pidfd_open() failed");
                                return EXIT_FAILURE;
                        }

                        pidfds[i] = fd;
                }
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

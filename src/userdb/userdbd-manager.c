/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>

#include "sd-daemon.h"

#include "common-signal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "umask-util.h"
#include "userdbd-manager.h"

#define LISTEN_TIMEOUT_USEC (25 * USEC_PER_SEC)

static int start_workers(Manager *m, bool explicit_request);

static int on_worker_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        assert_se(!set_remove(m->workers_dynamic, s) != !set_remove(m->workers_fixed, s));
        sd_event_source_disable_unref(s);

        if (si->si_code == CLD_EXITED) {
                if (si->si_status == EXIT_SUCCESS)
                        log_debug("Worker " PID_FMT " exited successfully.", si->si_pid);
                else
                        log_warning("Worker " PID_FMT " died with a failure exit status %i, ignoring.", si->si_pid, si->si_status);
        } else if (si->si_code == CLD_KILLED)
                log_warning("Worker " PID_FMT " was killed by signal %s, ignoring.", si->si_pid, signal_to_string(si->si_status));
        else if (si->si_code == CLD_DUMPED)
                log_warning("Worker " PID_FMT " dumped core by signal %s, ignoring.", si->si_pid, signal_to_string(si->si_status));
        else
                log_warning("Can't handle SIGCHLD of this type");

        (void) start_workers(m, /* explicit_request= */ false); /* Fill up workers again if we fell below the low watermark */
        return 0;
}

static int on_sigusr2(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        (void) start_workers(m, /* explicit_request=*/ true); /* Workers told us there's more work, let's add one more worker as long as we are below the high watermark */
        return 0;
}

static int on_deferred_start_worker(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        m->deferred_start_worker_event_source = sd_event_source_unref(m->deferred_start_worker_event_source);

        (void) start_workers(m, /* explicit_request=*/ false);
        return 0;
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                event_source_hash_ops,
                sd_event_source,
                (void (*)(const sd_event_source*, struct siphash*)) trivial_hash_func,
                (int (*)(const sd_event_source*, const sd_event_source*)) trivial_compare_func,
                sd_event_source_disable_unref);

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .listen_fd = -EBADF,
                .worker_ratelimit = {
                        .interval = 2 * USEC_PER_SEC,
                        .burst = 2500,
                },
        };

        r = sd_event_new(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed allocate memory pressure event source, ignoring: %m");

        r = sd_event_set_watchdog(m->event, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable watchdog handling, ignoring: %m");

        r = sd_event_add_signal(m->event, NULL, SIGUSR2|SD_EVENT_SIGNAL_PROCMASK, on_sigusr2, m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        set_free(m->workers_fixed);
        set_free(m->workers_dynamic);

        m->deferred_start_worker_event_source = sd_event_source_unref(m->deferred_start_worker_event_source);

        safe_close(m->listen_fd);

        sd_event_unref(m->event);

        return mfree(m);
}

static size_t manager_current_workers(Manager *m) {
        assert(m);

        return set_size(m->workers_fixed) + set_size(m->workers_dynamic);
}

static int start_one_worker(Manager *m) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *source = NULL;
        bool fixed;
        pid_t pid;
        int r;

        assert(m);

        fixed = set_size(m->workers_fixed) < USERDB_WORKERS_MIN;

        r = safe_fork_full(
                        "(sd-worker)",
                        /* stdio_fds= */ NULL,
                        &m->listen_fd, 1,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_CLOSE_ALL_FDS,
                        &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to fork new worker child: %m");
        if (r == 0) {
                char pids[DECIMAL_STR_MAX(pid_t)];
                /* Child */

                if (m->listen_fd == 3) {
                        r = fd_cloexec(3, false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to turn off O_CLOEXEC for fd 3: %m");
                                _exit(EXIT_FAILURE);
                        }
                } else {
                        if (dup2(m->listen_fd, 3) < 0) { /* dup2() creates with O_CLOEXEC off */
                                log_error_errno(errno, "Failed to move listen fd to 3: %m");
                                _exit(EXIT_FAILURE);
                        }

                        safe_close(m->listen_fd);
                }

                xsprintf(pids, PID_FMT, pid);
                if (setenv("LISTEN_PID", pids, 1) < 0) {
                        log_error_errno(errno, "Failed to set $LISTEN_PID: %m");
                        _exit(EXIT_FAILURE);
                }

                if (setenv("LISTEN_FDS", "1", 1) < 0) {
                        log_error_errno(errno, "Failed to set $LISTEN_FDS: %m");
                        _exit(EXIT_FAILURE);
                }


                if (setenv("USERDB_FIXED_WORKER", one_zero(fixed), 1) < 0) {
                        log_error_errno(errno, "Failed to set $USERDB_FIXED_WORKER: %m");
                        _exit(EXIT_FAILURE);
                }

                /* execl("/home/lennart/projects/systemd/build/systemd-userwork", "systemd-userwork", "xxxxxxxxxxxxxxxx", NULL); /\* With some extra space rename_process() can make use of *\/ */
                /* execl("/usr/bin/valgrind", "valgrind", "/home/lennart/projects/systemd/build/systemd-userwork", "systemd-userwork", "xxxxxxxxxxxxxxxx", NULL); /\* With some extra space rename_process() can make use of *\/ */

                execl(SYSTEMD_USERWORK_PATH, "systemd-userwork", "xxxxxxxxxxxxxxxx", NULL); /* With some extra space rename_process() can make use of */
                log_error_errno(errno, "Failed start worker process: %m");
                _exit(EXIT_FAILURE);
        }

        r = sd_event_add_child(m->event, &source, pid, WEXITED, on_worker_exit, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch child " PID_FMT ": %m", pid);

        r = set_ensure_put(
                        fixed ? &m->workers_fixed : &m->workers_dynamic,
                        &event_source_hash_ops,
                        source);
        if (r < 0)
                return log_error_errno(r, "Failed to add child process to set: %m");

        TAKE_PTR(source);

        return 0;
}

static int start_workers(Manager *m, bool explicit_request) {
        int r;

        assert(m);

        for (;;)  {
                size_t n;

                n = manager_current_workers(m);
                if (n >= USERDB_WORKERS_MIN && (!explicit_request || n >= USERDB_WORKERS_MAX))
                        break;

                if (!ratelimit_below(&m->worker_ratelimit)) {

                        /* If we keep starting workers too often but none sticks, let's fail the whole
                         * daemon, something is wrong */
                        if (n == 0) {
                                sd_event_exit(m->event, EXIT_FAILURE);
                                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Worker threads requested too frequently, but worker count is zero, something is wrong.");
                        }

                        /* Otherwise, let's stop spawning more for a while. */
                        log_warning("Worker threads requested too frequently, not starting new ones for a while.");

                        if (!m->deferred_start_worker_event_source) {
                                r = sd_event_add_time(
                                                m->event,
                                                &m->deferred_start_worker_event_source,
                                                CLOCK_MONOTONIC,
                                                ratelimit_end(&m->worker_ratelimit),
                                                /* accuracy_usec= */ 0,
                                                on_deferred_start_worker,
                                                m);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to allocate deferred start worker event source: %m");
                        }

                        break;
                }

                r = start_one_worker(m);
                if (r < 0)
                        return r;

                explicit_request = false;
        }

        return 0;
}

int manager_startup(Manager *m) {
        int n, r;

        assert(m);
        assert(m->listen_fd < 0);

        n = sd_listen_fds(false);
        if (n < 0)
                return log_error_errno(n, "Failed to determine number of passed file descriptors: %m");
        if (n > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected one listening fd, got %i.", n);
        if (n == 1)
                m->listen_fd = SD_LISTEN_FDS_START;
        else {
                static const union sockaddr_union sockaddr = {
                        .un.sun_family = AF_UNIX,
                        .un.sun_path = "/run/systemd/userdb/io.systemd.Multiplexer",
                };

                r = mkdir_p("/run/systemd/userdb", 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create /run/systemd/userdb: %m");

                m->listen_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
                if (m->listen_fd < 0)
                        return log_error_errno(errno, "Failed to bind on socket: %m");

                (void) sockaddr_un_unlink(&sockaddr.un);

                WITH_UMASK(0000)
                        if (bind(m->listen_fd, &sockaddr.sa, SOCKADDR_UN_LEN(sockaddr.un)) < 0)
                                return log_error_errno(errno, "Failed to bind socket: %m");

                r = symlink_idempotent("io.systemd.Multiplexer",
                                       "/run/systemd/userdb/io.systemd.NameServiceSwitch", false);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind io.systemd.Multiplexer: %m");

                r = symlink_idempotent("io.systemd.Multiplexer",
                                       "/run/systemd/userdb/io.systemd.DropIn", false);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind io.systemd.Multiplexer: %m");

                if (listen(m->listen_fd, SOMAXCONN_DELUXE) < 0)
                        return log_error_errno(errno, "Failed to listen on socket: %m");
        }

        /* Let's make sure every accept() call on this socket times out after 25s. This allows workers to be
         * GC'ed on idle */
        if (setsockopt(m->listen_fd, SOL_SOCKET, SO_RCVTIMEO, TIMEVAL_STORE(LISTEN_TIMEOUT_USEC), sizeof(struct timeval)) < 0)
                return log_error_errno(errno, "Failed to se SO_RCVTIMEO: %m");

        return start_workers(m, /* explicit_request= */ false);
}

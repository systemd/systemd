/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "coredump-config.h"
#include "coredump-manager.h"
#include "coredump-util.h"
#include "coredump-worker.h"
#include "daemon-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "namespace-util.h"
#include "notify-recv.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

#define COREDUMP_SOCKET_PATH           "/run/systemd/coredump-kernel"
#define COREDUMP_SOCKET_MAX_CONNECTION 16u

#define WORKER_TIMEOUT_USEC (5 * USEC_PER_MINUTE)

enum {
        /* This should have the highest priority than others, to prevent accepting newer connections. */
        EVENT_PRIORITY_SIGTERM_SIGINT  = SD_EVENT_PRIORITY_NORMAL - 5,
        /* This must have a higher priority than the worker SIGCHLD event, to make notifications about completions of
         * processing events received before SIGCHLD. */
        EVENT_PRIORITY_WORKER_NOTIFY   = SD_EVENT_PRIORITY_NORMAL - 4,
        /* This should have a higher priority than timer events about killing long running or idle worker processes. */
        EVENT_PRIORITY_WORKER_SIGCHLD  = SD_EVENT_PRIORITY_NORMAL - 3,
        /* As said in the above, this should have a lower proority than the SIGCHLD event source. */
        EVENT_PRIORITY_WORKER_TIMER    = SD_EVENT_PRIORITY_NORMAL - 2,
        /* This should have a lower priority than the events for workers. */
        EVENT_PRIORITY_COREDUMP_SOCKET = SD_EVENT_PRIORITY_NORMAL - 1,
        /* This should have a lower priority than other event sources. */
        EVENT_PRIORITY_SIGHUP          = SD_EVENT_PRIORITY_NORMAL + 1,
};

typedef struct Manager Manager;

typedef struct WorkerInfo {
        Manager *manager;
        sd_event_source *timer_event_source;
        sd_event_source *child_event_source;
        PidRef pidref;
} WorkerInfo;

struct Manager {
        CoredumpConfig config;
        sd_event *event;
        sd_event_source *coredump_socket_event_source;
        int coredump_socket;
        char *worker_notify_socket_path;
        Hashmap *workers_by_pidref;
        bool exit;
};

static WorkerInfo* worker_info_free(WorkerInfo *worker) {
        if (!worker)
                return NULL;

        if (pidref_is_set(&worker->pidref)) {
                if (worker->manager)
                        hashmap_remove(worker->manager->workers_by_pidref, &worker->pidref);

                (void) pidref_done_sigkill_wait(&worker->pidref);
        }

        sd_event_source_unref(worker->child_event_source);
        sd_event_source_unref(worker->timer_event_source);

        return mfree(worker);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WorkerInfo*, worker_info_free);

static WorkerInfo* worker_info_new(void) {
        WorkerInfo *worker = new(WorkerInfo, 1);
        if (!worker)
                return NULL;

        *worker = (WorkerInfo) {
                .pidref = PIDREF_NULL,
        };

        return worker;
}

static Manager* manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        sd_event_source_unref(manager->coredump_socket_event_source);
        sd_event_unref(manager->event);
        safe_close(manager->coredump_socket);
        free(manager->worker_notify_socket_path);
        hashmap_free(manager->workers_by_pidref);

        return mfree(manager);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

static Manager* manager_new(void) {
        Manager *manager = new(Manager, 1);
        if (!manager)
                return NULL;

        *manager = (Manager) {
                .config = COREDUMP_CONFIG_NULL,
                .coredump_socket = -EBADF,
        };

        return TAKE_PTR(manager);
}

static int on_worker_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _unused_ _cleanup_(worker_info_freep) WorkerInfo *worker = ASSERT_PTR(userdata);

        assert(si);

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0) {
                        log_debug("Worker ["PID_FMT"] exited.", si->si_pid);
                        return 0;
                }

                log_warning("Worker ["PID_FMT"] exited with return code %i.", si->si_pid, si->si_status);
                break;

        case CLD_KILLED:
        case CLD_DUMPED:
                log_warning("Worker ["PID_FMT"] terminated by signal %i (%s).",
                            si->si_pid, si->si_status, signal_to_string(si->si_status));
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int on_worker_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        WorkerInfo *worker = ASSERT_PTR(userdata);

        log_warning("Worker ["PID_FMT"] is running longer than %s, killing the worker.",
                    worker->pidref.pid, FORMAT_TIMESPAN(WORKER_TIMEOUT_USEC, USEC_PER_SEC));
        (void) pidref_kill(&worker->pidref, SIGKILL);
        return 0;
}

static int manager_spawn_worker(Manager *manager, int coredump_fd) {
        int r;

        assert(manager);
        assert(coredump_fd >= 0);

        _cleanup_(worker_info_freep) WorkerInfo *worker = worker_info_new();
        if (!worker)
                return -ENOMEM;

        /* On socket mode, the kernel does not provide any timestamp of the crash. Let's use the timestamp
         * that the socket accept the connection. */
        usec_t timestamp;
        r = sd_event_now(manager->event, CLOCK_REALTIME, &timestamp);
        if (r < 0)
                return r;

        r = pidref_safe_fork_full(
                        "(coredump-worker)",
                        /* stdio_fds= */ NULL,
                        (int[]) { coredump_fd }, 1,
                        FORK_DEATHSIG_SIGTERM | FORK_CLOSE_ALL_FDS | FORK_REOPEN_LOG | FORK_LOG,
                        &worker->pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Worker process */

                if (setenv("NOTIFY_SOCKET", manager->worker_notify_socket_path, /* overwrite= */ true) < 0) {
                        log_error_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_FAILURE);
                }

                r = coredump_worker(&manager->config, TAKE_FD(coredump_fd), timestamp);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        r = event_add_child_pidref(manager->event, &worker->child_event_source, &worker->pidref, WEXITED, on_worker_sigchld, worker);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(worker->child_event_source, EVENT_PRIORITY_WORKER_SIGCHLD);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(worker->child_event_source, "worker-child-event");

        r = sd_event_add_time_relative(manager->event, &worker->timer_event_source,
                                       CLOCK_MONOTONIC, WORKER_TIMEOUT_USEC, USEC_PER_SEC,
                                       on_worker_timeout, worker);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(worker->timer_event_source, EVENT_PRIORITY_WORKER_TIMER);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(worker->timer_event_source, "worker-timeout");

        r = hashmap_ensure_put(&manager->workers_by_pidref, &pidref_hash_ops, &worker->pidref, worker);
        if (r < 0)
                return r;

        worker->manager = manager;

        TAKE_PTR(worker);
        return 0;
}

static int on_connect(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        _cleanup_close_ int coredump_fd = accept4(fd, /* addr= */ NULL, /* addrlen= */ NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (coredump_fd < 0) {
                if (!ERRNO_IS_ACCEPT_AGAIN(errno))
                        log_warning_errno(errno, "Failed to accept coredump socket connection, ignoring: %m");

                return 0;
        }

        r = manager_spawn_worker(manager, coredump_fd);
        if (r < 0)
                log_warning_errno(r, "Failed to spawn worker process, ignoring: %m");

        return 0;
}

static int on_worker_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        _cleanup_(pidref_done) PidRef sender = PIDREF_NULL;
        _cleanup_strv_free_ char **l = NULL;
        r = notify_recv_strv(fd, &l, /* ret_ucred= */ NULL, &sender);
        if (r < 0) {
                if (r != -EAGAIN)
                        log_warning_errno(r, "Failed to receive worker notification, ignoring: %m");
                return 0;
        }

        /* lookup worker who sent the signal */
        WorkerInfo *worker = hashmap_get(manager->workers_by_pidref, &sender);
        if (!worker) {
                log_warning("Received notification from unknown process ["PID_FMT"], ignoring.", sender.pid);
                return 0;
        }

        if (strv_contains(l, "READY=1")) {
                log_debug("Received ready notification from worker process ["PID_FMT"].", sender.pid);
                return 0;
        }

        if (strv_contains(l, "STOPPING=1")) {
                log_debug("Received stopping notification from worker process ["PID_FMT"].", sender.pid);
                return 0;
        }

        _cleanup_free_ char *joined = strv_join(l, ", ");
        log_warning("Received unexpected notification from worker process ["PID_FMT"], ignoring: %s", sender.pid, strna(joined));
        return 0;
}

static int on_post(sd_event_source *s, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        if (!manager->exit)
                return 0;

        if (!hashmap_isempty(manager->workers_by_pidref))
                return 0; /* There still exist workers. */

        return sd_event_exit(manager->event, 0);
}

static int on_sigterm(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        manager->exit = true;

        (void) sd_notify(/* unset_environment= */ false, NOTIFY_STOPPING_MESSAGE);

        /* Do not accept any new connections. */
        manager->coredump_socket_event_source = sd_event_source_disable_unref(manager->coredump_socket_event_source);

        return 0;
}

static int on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        (void) notify_reloading();

        manager->config = COREDUMP_CONFIG_NULL;
        (void) coredump_parse_config(&manager->config);

        r = sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        return 0;
}

static int manager_setup_signal(
                Manager *manager,
                sd_event *event,
                int signal,
                sd_event_signal_handler_t handler,
                int64_t priority,
                const char *description) {

        int r;

        assert(manager);
        assert(event);

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_signal(event, &s, signal | SD_EVENT_SIGNAL_PROCMASK, handler, manager);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, priority);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, description);

        r = sd_event_source_set_floating(s, true);
        if (r < 0)
                return r;

        return 0;
}

static int manager_init_event(Manager *manager) {
        int r;

        assert(manager);

        /* block SIGCHLD for listening child events. */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD) >= 0);

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_set_watchdog(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable watchdog: %m");

        r = manager_setup_signal(manager, event, SIGINT, on_sigterm, EVENT_PRIORITY_SIGTERM_SIGINT, "sigint-event-source");
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGINT event source: %m");

        r = manager_setup_signal(manager, event, SIGTERM, on_sigterm, EVENT_PRIORITY_SIGTERM_SIGINT, "sigterm-event-source");
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGTERM event source: %m");

        r = manager_setup_signal(manager, event, SIGHUP, on_sighup, EVENT_PRIORITY_SIGHUP, "sighup-event-source");
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGHUP event source: %m");

        r = sd_event_add_post(event, /* ret= */ NULL, on_post, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create post event source: %m");

        r = notify_socket_prepare(
                        event,
                        EVENT_PRIORITY_WORKER_NOTIFY,
                        on_worker_notify,
                        manager,
                        &manager->worker_notify_socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare notify socket: %m");

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(event, &s, manager->coredump_socket, EPOLLIN, on_connect, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate IO event source: %m");

        (void) sd_event_source_set_description(s, "coredump-socket-event");

        r = sd_event_source_set_priority(s, EVENT_PRIORITY_COREDUMP_SOCKET);
        if (r < 0)
                return log_error_errno(r, "Failed to set priority of IO event source: %m");

        manager->coredump_socket_event_source = TAKE_PTR(s);
        manager->event = TAKE_PTR(event);
        return 0;
}

static int manager_open_coredump_socket(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->coredump_socket < 0);

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create AF_UNIX socket(): %m");

        union sockaddr_union sa;
        r = sockaddr_un_set_path(&sa.un, COREDUMP_SOCKET_PATH);
        if (r < 0)
                return log_error_errno(r, "Failed to set path for AF_UNIX socket: %m");
        socklen_t sa_len = r;

        (void) sockaddr_un_unlink(&sa.un);

        if (bind(fd, &sa.sa, sa_len) < 0)
                return log_error_errno(errno, "Failed to bind AF_UNIX socket at %s: %m", sa.un.sun_path);

        (void) chmod(sa.un.sun_path, 0600);

        if (listen(fd, COREDUMP_SOCKET_MAX_CONNECTION) < 0)
                return log_error_errno(errno, "Failed to listen AF_UNIX socket at %s: %m", sa.un.sun_path);

        manager->coredump_socket = TAKE_FD(fd);
        return 0;
}

static int manager_push_coredump_socket(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->coredump_socket >= 0);

        r = notify_push_fd(manager->coredump_socket, "coredump-socket");
        if (r < 0)
                return log_warning_errno(r, "Failed to push coredump socket to service manager, ignoring: %m");

        log_debug("Pushed coredump socket to service manager.");
        return 0;
}

static int manager_set_coredump_socket(Manager *manager, int fd) {
        int r;

        assert(manager);
        assert(fd >= 0);

        /* This takes passed fd on success. */

        if (manager->coredump_socket >= 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EALREADY),
                                         "Received multiple coredump socket (%i), ignoring.", fd);

        r = sd_is_socket_unix(fd, SOCK_STREAM, /* listening= */ true, COREDUMP_SOCKET_PATH, /* length= */ 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to check if fd (%i) is a valid unix socket, ignoring: %m", fd);
        if (r == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "Received invalid coredump socket (%i), ignoring.", fd);

        (void) fd_nonblock(fd, true);

        manager->coredump_socket = fd;
        return 0;
}

static int manager_listen_fds(Manager *manager) {
        int r;

        assert(manager);

        _cleanup_strv_free_ char **names = NULL;
        int n = sd_listen_fds_with_names(/* unset_environment= */ false, &names);
        if (n < 0)
                return log_error_errno(n, "Failed to determine the number of file descriptors: %m");

        for (int i = 0; i < n; i++) {
                int fd = SD_LISTEN_FDS_START + i;

                if (streq_ptr(names[i], "coredump-socket"))
                        r = manager_set_coredump_socket(manager, fd);
                else
                        r = log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Received unexpected fd (%i: %s), ignoring.", fd, names[i]);
                if (r < 0)
                        close_and_notify_warn(fd, names[i]);
        }

        return 0;
}

static int register_coredump_socket(void) {
        int r;

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Coredump.Register");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to /run/systemd/io.systemd.Coredump.Register: %m");

        (void) sd_varlink_set_description(vl, "varlink-coredump-register");

        /* The "@@" prefix means the path is a AF_UNIX socket and it accepts the request mode protocol. The
         * protocol is supported since kernel v6.17. We have already checked if PIDFD_INFO_COREDUMP_SIGNAL
         * flag (since v6.19) is supported in check_requirements(). Hence, the prefix should be supported. */
        sd_json_variant *reply;
        const char *error_id;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Coredump.Register.SetCorePattern",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("pattern", "@@" COREDUMP_SOCKET_PATH));
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.Coredump.Register.SetCorePattern() varlink call: %m");
        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return log_error_errno(r, "Failed to issue io.systemd.Coredump.Register.SetCorePattern() varlink call: %m");

                return log_error_errno(r, "Failed to issue io.systemd.Coredump.Register.SetCorePattern() varlink call: %s", error_id);
        }

        return 0;
}

static int check_requirements(void) {
        int r;

        /* The request mode coredump socket pattern is supported since kernel v6.17. Old kernels do not
         * refuse the new core patterns (moreover, any strings are accepted), hence we need to check kernel
         * version in some ways other than reading/writing core patterns. Here, we use if
         * ioctl(PIDFD_GET_INFO) supportes necessary flags.
         *
         * The following flags are required for supporting kernel coredump socket feature:
         * PIDFD_INFO_COREDUMP        : 1d8db6fd698de1f73b1a7d72aea578fdd18d9a87 (v6.16),
         * PIDFD_INFO_COREDUMP_SIGNAL : 036375522be8425874e9e0f907c7127e315c7a52 (v6.19). */
        r = pidfd_info_mask_is_supported(PIDFD_INFO_COREDUMP | PIDFD_INFO_COREDUMP_SIGNAL);
        if (r == 0 || ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_debug("ioctl(PIDFD_GET_INFO) does not support PIDFD_INFO_COREDUMP and/or PIDFD_INFO_COREDUMP_SIGNAL.");
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to check if PIDFD_INFO_COREDUMP and PIDFD_INFO_COREDUMP_SIGNAL flags are supported by ioctl(PIDFD_GET_INFO): %m");

        /* Let's check if we are in the initial PID, USER, TIME namespace. */
        r = namespace_is_init(NAMESPACE_PID);
        if (r < 0)
                return log_error_errno(r, "Failed to check if we are in the initial PID namespace: %m");
        if (r == 0) {
                log_debug("Running in a non-initial PID namespace.");
                return false;
        }

        r = namespace_is_init(NAMESPACE_USER);
        if (r < 0)
                return log_error_errno(r, "Failed to check if we are in the initial USER namespace: %m");
        if (r == 0) {
                log_debug("Running in a non-initial USER namespace.");
                return false;
        }

        r = namespace_is_init(NAMESPACE_TIME);
        if (r < 0)
                return log_error_errno(r, "Failed to check if we are in the initial TIME namespace: %m");
        if (r == 0) {
                log_debug("Running in a non-initial TIME namespace.");
                return false;
        }

        return true;
}

int coredump_manager(int argc, char *argv[]) {
        int r;

        log_setup();

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message =
                notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        /* Make sure we never enter a loop. */
        (void) set_dumpable(SUID_DUMP_DISABLE);

        r = check_requirements();
        if (r <= 0)
                return r;

        _cleanup_(manager_freep) Manager *manager = manager_new();
        if (!manager)
                return log_oom();

        /* Ignore all parse errors. */
        (void) coredump_parse_config(&manager->config);

        r = manager_listen_fds(manager);
        if (r < 0)
                return r;

        if (manager->coredump_socket < 0) {
                r = manager_open_coredump_socket(manager);
                if (r < 0)
                        return r;

                (void) manager_push_coredump_socket(manager);
        }

        r = register_coredump_socket();
        if (r < 0)
                return r;

        r = manager_init_event(manager);
        if (r < 0)
                return r;

        r = sd_event_loop(manager->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

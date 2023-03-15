/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
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
#include "stat-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "umask-util.h"
#include "userdbd-manager.h"
#include "recurse-dir.h"

#define LISTEN_TIMEOUT_USEC (25 * USEC_PER_SEC)

static int start_workers(Manager *m, bool explicit_request);

static int manager_registry_scan(Manager *m);

static int on_sigchld(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        for (;;) {
                siginfo_t siginfo = {};
                bool removed = false;

                if (waitid(P_ALL, 0, &siginfo, WNOHANG|WEXITED) < 0) {
                        if (errno == ECHILD)
                                break;

                        log_warning_errno(errno, "Failed to invoke waitid(): %m");
                        break;
                }
                if (siginfo.si_pid == 0)
                        break;

                if (set_remove(m->workers_dynamic, PID_TO_PTR(siginfo.si_pid)))
                        removed = true;
                if (set_remove(m->workers_fixed, PID_TO_PTR(siginfo.si_pid)))
                        removed = true;

                if (!removed) {
                        log_warning("Weird, got SIGCHLD for unknown child " PID_FMT ", ignoring.", siginfo.si_pid);
                        continue;
                }

                if (siginfo.si_code == CLD_EXITED) {
                        if (siginfo.si_status == EXIT_SUCCESS)
                                log_debug("Worker " PID_FMT " exited successfully.", siginfo.si_pid);
                        else
                                log_warning("Worker " PID_FMT " died with a failure exit status %i, ignoring.", siginfo.si_pid, siginfo.si_status);
                } else if (siginfo.si_code == CLD_KILLED)
                        log_warning("Worker " PID_FMT " was killed by signal %s, ignoring.", siginfo.si_pid, signal_to_string(siginfo.si_status));
                else if (siginfo.si_code == CLD_DUMPED)
                        log_warning("Worker " PID_FMT " dumped core by signal %s, ignoring.", siginfo.si_pid, signal_to_string(siginfo.si_status));
                else
                        log_warning("Can't handle SIGCHLD of this type");
        }

        (void) start_workers(m, false); /* Fill up workers again if we fell below the low watermark */
        return 0;
}

static int on_sigusr2(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        (void) start_workers(m, true); /* Workers told us there's more work, let's add one more worker as long as we are below the high watermark */
        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .listen_fd = -EBADF,
                .worker_ratelimit = {
                        .interval = 5 * USEC_PER_SEC,
                        .burst = 50,
                },
        };

        r = sd_event_new(&m->event);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGRTMIN+18, sigrtmin18_handler, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed allocate memory pressure event source, ignoring: %m");

        (void) sd_event_set_watchdog(m->event, true);

        m->workers_fixed = set_new(NULL);
        m->workers_dynamic = set_new(NULL);

        if (!m->workers_fixed || !m->workers_dynamic)
                return -ENOMEM;

        r = sd_event_add_signal(m->event, &m->sigusr2_event_source, SIGUSR2, on_sigusr2, m);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, &m->sigchld_event_source, SIGCHLD, on_sigchld, m);
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

        sd_event_source_disable_unref(m->sigusr2_event_source);
        sd_event_source_disable_unref(m->sigchld_event_source);

        hashmap_free(m->registry_pidfds);

        sd_event_unref(m->event);

        return mfree(m);
}

static size_t manager_current_workers(Manager *m) {
        assert(m);

        return set_size(m->workers_fixed) + set_size(m->workers_dynamic);
}

static int start_one_worker(Manager *m) {
        bool fixed;
        pid_t pid;
        int r;

        assert(m);

        fixed = set_size(m->workers_fixed) < USERDB_WORKERS_MIN;

        r = safe_fork("(sd-worker)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to fork new worker child: %m");
        if (r == 0) {
                char pids[DECIMAL_STR_MAX(pid_t)];
                /* Child */

                log_close();

                r = close_all_fds(&m->listen_fd, 1);
                if (r < 0) {
                        log_error_errno(r, "Failed to close fds in child: %m");
                        _exit(EXIT_FAILURE);
                }

                log_open();

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

                execl("/home/lennart/projects/systemd/build/systemd-userwork", "systemd-userwork", "xxxxxxxxxxxxxxxx", NULL); /* With some extra space rename_process() can make use of */
                /* execl("/usr/bin/valgrind", "valgrind", "/home/lennart/projects/systemd/build/systemd-userwork", "systemd-userwork", "xxxxxxxxxxxxxxxx", NULL); /\* With some extra space rename_process() can make use of *\/ */

                /* execl(SYSTEMD_USERWORK_PATH, "systemd-userwork", "xxxxxxxxxxxxxxxx", NULL); /\* With some extra space rename_process() can make use of *\/ */
                log_error_errno(errno, "Failed start worker process: %m");
                _exit(EXIT_FAILURE);
        }

        if (fixed)
                r = set_put(m->workers_fixed, PID_TO_PTR(pid));
        else
                r = set_put(m->workers_dynamic, PID_TO_PTR(pid));
        if (r < 0)
                return log_error_errno(r, "Failed to add child process to set: %m");

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
                        /* If we keep starting workers too often, let's fail the whole daemon, something is wrong */
                        sd_event_exit(m->event, EXIT_FAILURE);

                        return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Worker threads requested too frequently, something is wrong.");
                }

                r = start_one_worker(m);
                if (r < 0)
                        return r;

                explicit_request = false;
        }

        return 0;
}

static int on_pid_dead(sd_event_source *s, int fd, uint32_t events, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) manager_registry_scan(m);
        return 0;
}

static int on_registry_inotify(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) manager_registry_scan(m);
        return 0;
}

DEFINE_PRIVATE_HASH_OPS_FULL(stat_event_source_hash_ops, struct stat, inode_hash_func, inode_compare_func, free, sd_event_source, sd_event_source_disable_unref);

typedef enum WatchResult {
        WATCH_RESULT_ALREADY,
        WATCH_RESULT_DEAD,
        WATCH_RESULT_NOT_MOUNTED,
        WATCH_RESULT_ADDED,
        _WATCH_RESULT_MAX,
        _WATCH_RESULT_INVALID = -EINVAL,
        _WATCH_RESULT_ERRNO_MAX = -ERRNO_MAX,
} WatchResult;

static WatchResult manager_watch_process(Manager *m, int proc_dir_fd, const struct stat *st) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *s = NULL;
        _cleanup_free_ struct stat *cst = NULL;
        _cleanup_close_ int pid_fd = -EBADF;
        int r;

        assert(m);
        assert(proc_dir_fd >= 0);
        assert(st);

        if (hashmap_contains(m->registry_pidfds, st)) {
                log_debug("Process already tracked, skipping.");
                return WATCH_RESULT_ALREADY;
        }

        pid_fd = pidfd_from_procfs(proc_dir_fd);
        if (pid_fd == -ESRCH)
                return WATCH_RESULT_DEAD;
        if (pid_fd == -ENOTTY)
                return WATCH_RESULT_NOT_MOUNTED;
        if (pid_fd < 0)
                return log_error_errno(pid_fd, "Failed to convert procfs directory fd to pidfd: %m");

        r = sd_event_add_io(m->event, &s, pid_fd, EPOLLIN, on_pid_dead, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate IO event for pidfd: %m");

        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return log_error_errno(r, "Unable ot pass child fd ownership to event source: %m");

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to set event source to oneshot mode: %m");

        TAKE_FD(pid_fd);

        cst = newdup(struct stat, st, 1);
        if (!cst)
                return log_oom();

        if (hashmap_ensure_put(&m->registry_pidfds, &stat_event_source_hash_ops, cst, s) < 0)
                return log_oom();

        TAKE_PTR(cst);
        TAKE_PTR(s);

        return WATCH_RESULT_ADDED;
}

static void manager_unwatch_process(Manager *m, const struct stat *st) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_free_ struct stat *cst = NULL;

        assert(m);
        assert(st);

        s = hashmap_remove2(m->registry_pidfds, st, (void**) &cst);
}

static int manager_registry_scan(Manager *m) {
        _cleanup_close_ int registry_fd = -EBADF;
        _cleanup_free_ DirectoryEntries *de = NULL;
        int r;

        registry_fd = open("/run/systemd/userdbd/registry", O_DIRECTORY|O_CLOEXEC);
        if (registry_fd < 0)
                return log_error_errno(errno, "Failed to open registry fd: %m");

        r = readdir_all(registry_fd, RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate registry.");

        for (size_t i = 0; i < de->n_entries; i++) {
                struct dirent *entry = de->entries[i];
                _cleanup_close_ int inode_fd = -EBADF;
                _cleanup_free_ char *p = NULL, *f = NULL;
                bool valid_procfs;
                struct stat st;
                const char *e;

                e = endswith(entry->d_name, ".process");
                if (!e)
                        continue;

                /* We open as O_PATH which will work even if the process is dead */
                inode_fd = openat(registry_fd, entry->d_name, O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY);
                if (inode_fd < 0) {
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to open inode /run/systemd/userdbd/registry/%s, skipping: %m", entry->d_name);
                        continue;
                }

                if (fstatat(inode_fd, ".", &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno != ESRCH) {
                                log_warning_errno(errno, "Unable to validate /run/systemd/userdbd/registry/%s, skipping: %m", entry->d_name);
                                continue;
                        }

                        /* Failed with ESRCH? Then the proc mount points to a dead process, clean it up */
                        valid_procfs = true;
                } else {
                        WatchResult wr;

                        wr = manager_watch_process(m, inode_fd, &st);
                        if (wr < 0)
                                return wr;
                        if (IN_SET(wr, WATCH_RESULT_ALREADY, WATCH_RESULT_ADDED))
                                continue;

                        /* Watching the process failed because the process is not there anymore, clean it up */
                        valid_procfs = wr == WATCH_RESULT_DEAD;
                }

                /* It's dead, Jim! */

                if (valid_procfs) {
                        manager_unwatch_process(m, &st);

                        if (umount2(FORMAT_PROC_FD_PATH(inode_fd), MNT_DETACH) < 0) {
                                log_warning_errno(errno, "Failed to unmount '/run/systemd/userdbd/registry/%s', skipping: %m", entry->d_name);
                                continue;
                        }
                }

                if (unlinkat(registry_fd, entry->d_name, AT_REMOVEDIR) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to remove directory '/run/systemd/userdbd/registry/%s', ignoring: %m", entry->d_name);

                f = strndup(entry->d_name, e - entry->d_name);
                if (!f)
                        return log_oom();

                if (!strextend(&f, ".uidrange"))
                        return log_oom();

                if (unlinkat(registry_fd, f, 0) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to remove directory '/run/systemd/userdbd/registry/%s', ignoring: %m", f);

                log_debug("Cleaned up mapping '%s'", f);
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
                union sockaddr_union sockaddr = {
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

                FOREACH_STRING(alias,
                               "/run/systemd/userdb/io.systemd.NameServiceSwitch",
                               "/run/systemd/userdb/io.systemd.DropIn",
                               "/run/systemd/userdb/io.systemd.Registry") {

                        r = symlink_idempotent("io.systemd.Multiplexer", alias, false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to symlink '%s': %m", alias);
                }

                if (listen(m->listen_fd, SOMAXCONN) < 0)
                        return log_error_errno(errno, "Failed to listen on socket: %m");
        }

        /* Let's make sure every accept() call on this socket times out after 25s. This allows workers to be
         * GC'ed on idle */
        if (setsockopt(m->listen_fd, SOL_SOCKET, SO_RCVTIMEO, TIMEVAL_STORE(LISTEN_TIMEOUT_USEC), sizeof(struct timeval)) < 0)
                return log_error_errno(errno, "Failed to se SO_RCVTIMEO: %m");

        r = mkdir_p("/run/systemd/userdbd/registry", 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/userdb/registry: %m");

        /* We watch the registry directory so that we pick new allocations whose owning processes we want to watch */
        r = sd_event_add_inotify(m->event, NULL, "/run/systemd/userdbd/registry", IN_CLOSE_WRITE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_ONLYDIR, on_registry_inotify, m);
        if (r < 0)
                return log_error_errno(r, "Failed to create inotify watch for registry directory: %m");

        r = start_workers(m, /* explicit_request= */ false);
        if (r < 0)
                return r;

        (void) manager_registry_scan(m);
        return 0;
}

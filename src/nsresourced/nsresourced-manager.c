/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <sys/wait.h>

#include "sd-daemon.h"

#include "bpf-dlopen.h"
#include "common-signal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "nsresourced-manager.h"
#include "parse-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "umask-util.h"
#include "unaligned.h"
#include "user-util.h"
#include "userns-registry.h"
#include "userns-restrict.h"

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
                        .burst = 250,
                },
                .registry_fd = -EBADF,
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

        sd_event_source_disable_unref(m->userns_restrict_bpf_ring_buffer_event_source);
        if (m->userns_restrict_bpf_ring_buffer)
                sym_ring_buffer__free(m->userns_restrict_bpf_ring_buffer);
        userns_restrict_bpf_free(m->userns_restrict_bpf);

        safe_close(m->registry_fd);

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

        fixed = set_size(m->workers_fixed) < NSRESOURCE_WORKERS_MIN;

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

                if (setenv("NSRESOURCE_FIXED_WORKER", one_zero(fixed), 1) < 0) {
                        log_error_errno(errno, "Failed to set $NSRESOURCE_FIXED_WORKER: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Tell the workers whether to enable the userns API */
                if (setenv("NSRESOURCE_API", one_zero(m->userns_restrict_bpf), 1) < 0) {
                        log_error_errno(errno, "Failed to set $NSRESOURCE_API: %m");
                        _exit(EXIT_FAILURE);
                }

                // FIXME
                execl("/home/lennart/projects/systemd/build/systemd-nsresourcework", "systemd-nsresourcework", "xxxxxxxxxxxxxxxx", NULL); /* With some extra space rename_process() can make use of */
                /* execl("/usr/bin/valgrind", "valgrind", "/home/lennart/projects/systemd/build/systemd-nsresourcework", "systemd-nsresourcework", "xxxxxxxxxxxxxxxx", NULL); /\* With some extra space rename_process() can make use of *\/ */

                execl(SYSTEMD_NSRESOURCEWORK_PATH, "systemd-nsresourcework", "xxxxxxxxxxxxxxxx", NULL); /* With some extra space rename_process() can make use of */
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
                if (n >= NSRESOURCE_WORKERS_MIN && (!explicit_request || n >= NSRESOURCE_WORKERS_MAX))
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

static void manager_release_userns_bpf(Manager *m, uint64_t inode) {
        int r;

        assert(m);

        if (inode == 0)
                return;

        assert(m->userns_restrict_bpf);

        r = userns_restrict_reset_by_inode(m->userns_restrict_bpf, inode);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to remove namespace inode from BPF map, ignoring: %m");
}

static void manager_release_userns_fds(Manager *m, uint64_t inode) {
        int r;

        assert(m);
        assert(inode != 0);

        r = sd_notifyf(/* unset_environment= */ false,
                       "FDSTOREREMOVE=1\n"
                       "FDNAME=userns-%" PRIu64 "\n", inode);
        if (r < 0)
                log_warning_errno(r, "Failed to send fd store removal message, ignoring: %m");
}

static void manager_release_userns_by_inode(Manager *m, uint64_t inode) {
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_close_ int lock_fd = -EBADF;
        int r;

        assert(m);
        assert(inode != 0);

        lock_fd = userns_registry_lock(m->registry_fd);
        if (lock_fd < 0)
                return (void) log_error_errno(lock_fd, "Failed to lock registry: %m");

        r = userns_registry_load_by_userns_inode(m->registry_fd, inode, &userns_info);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to find userns for inode %" PRIu64 ", ignoring: %m", inode);

        if (userns_info && uid_is_valid(userns_info->start))
                log_debug("Removing user namespace mapping %" PRIu64 " for UID " UID_FMT ".", inode, userns_info->start);
        else
                log_debug("Removing user namespace mapping %" PRIu64 ".", inode);

        /* Remove the BPF rules */
        manager_release_userns_bpf(m, inode);

        /* Remove the resources from the fdstore */
        manager_release_userns_fds(m, inode);

        /* And finally remove the resources file from disk */
        if (userns_info) {
                /* Remove the cgroups of this userns */
                r = userns_info_remove_cgroups(userns_info);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove cgroups of user namespace: %m");

                r = userns_registry_remove(m->registry_fd, userns_info);
                if (r < 0)
                        log_warning_errno(r, "Failed to remove user namespace '%s', ignoring.", userns_info->name);
        }
}

static int manager_scan_registry(Manager *m, Set **registry_inodes) {
        _cleanup_free_ DirectoryEntries *de = NULL;
        int r;

        assert(m);
        assert(registry_inodes);
        assert(m->registry_fd >= 0);

        r = readdir_all(m->registry_fd, RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate registry.");

        for (size_t i = 0; i < de->n_entries; i++) {
                struct dirent *dentry = de->entries[i];
                _cleanup_free_ char *u = NULL;
                const char *e, *p;
                uint64_t inode;

                p = startswith(dentry->d_name, "i");
                if (!p)
                        continue;

                e = endswith(p, ".userns");
                if (!e)
                        continue;

                u = strndup(p, e - p);
                if (!u)
                        return log_oom();

                r = safe_atou64(u, &inode);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse userns inode number from '%s', skipping: %m", dentry->d_name);
                        continue;
                }

                if (inode > UINT32_MAX) { /* namespace inode numbers are 23bit only right now */
                        log_warning("userns inode number outside of 32bit range, skipping.");
                        continue;
                }

                if (set_ensure_put(registry_inodes, NULL, UINT32_TO_PTR(inode)) < 0)
                        return log_oom();

                log_debug("Found user namespace %" PRIu64 " in registry directory", inode);
        }

        return 0;
}

static int manager_make_listen_socket(Manager *m) {
        static const union sockaddr_union sockaddr = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/io.systemd.NamespaceResource",
        };
        int r;

        assert(m);

        if (m->listen_fd >= 0)
                return 0;

        m->listen_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (m->listen_fd < 0)
                return log_error_errno(errno, "Failed to bind on socket: %m");

        (void) sockaddr_un_unlink(&sockaddr.un);

        WITH_UMASK(0000)
                if (bind(m->listen_fd, &sockaddr.sa, SOCKADDR_UN_LEN(sockaddr.un)) < 0)
                        return log_error_errno(errno, "Failed to bind socket: %m");

        r = mkdir_p("/run/systemd/userdb", 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/userdb: %m");

        r = symlink_idempotent("../io.systemd.NamespaceResource", "/run/systemd/userdb/io.systemd.NamespaceResource", /* make_relative= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to symlink userdb socket: %m");

        if (listen(m->listen_fd, SOMAXCONN) < 0)
                return log_error_errno(errno, "Failed to listen on socket: %m");

        return 1;
}

static int manager_scan_listen_fds(Manager *m, Set **fdstore_inodes) {
        _cleanup_strv_free_ char **names = NULL;
        int n, r;

        assert(m);
        assert(fdstore_inodes);

        n = sd_listen_fds_with_names(/* unset_environment= */ true, &names);
        if (n < 0)
                return log_error_errno(n, "Failed to determine number of passed file descriptors: %m");

        for (int i = 0; i < n; i++) {
                _cleanup_close_ int fd = SD_LISTEN_FDS_START + i; /* Take possession */
                const char *e;

                /* If this is a BPF allowlist related fd, just close it, but remember which start UIDs this covers */
                e = startswith(names[i], "userns-");
                if (e) {
                        uint64_t inode;

                        r = safe_atou64(e, &inode);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to parse UID from fd name '%s', ignoring: %m", e);
                                continue;
                        }

                        if (inode > UINT32_MAX) {
                                log_warning("Inode number outside of 32bit range, ignoring");
                                continue;
                        }

                        if (set_ensure_put(fdstore_inodes, NULL, UINT32_TO_PTR(inode)) < 0)
                                return log_oom();

                        continue;
                }

                /* We don't check the name for the stream socket, for compatibility with older versions */
                r = sd_is_socket(fd, AF_UNIX, SOCK_STREAM, 1);
                if (r < 0)
                        return log_error_errno(r, "Failed to detect if passed file descriptor is a socket: %m");
                if (r > 0) {
                        if (m->listen_fd >= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Passed more than one AF_UNIX/SOCK_STREAM socket, refusing.");

                        m->listen_fd = TAKE_FD(fd);
                        continue;
                }

                log_warning("Closing passed file descriptor %i (%s) we don't recognize.", fd, names[i]);
        }

        return 0;
}

#if BPF_FRAMEWORK
static int ringbuf_event(void *userdata, void *data, size_t size) {
        Manager *m = ASSERT_PTR(userdata);
        size_t n;

        if ((size % sizeof(unsigned int)) != 0) /* Not multiples of "unsigned int"? */
                return -EIO;

        n = size / sizeof(unsigned int);
        for (size_t i = 0; i < n; i++) {
                const void *d;
                uint64_t inode;

                d = (const uint8_t*) data + i * sizeof(unsigned int);
                inode = unaligned_read_ne32(d);

                log_debug("Got BPF ring buffer notification that user namespace %" PRIu64 " is now dead.", inode);
                manager_release_userns_by_inode(m, inode);
        }

        return 0;
}

static int on_ringbuf_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = sym_ring_buffer__poll(m->userns_restrict_bpf_ring_buffer, 0);
        if (r < 0)
                return log_error_errno(r, "Got failure reading from BPF ring buffer: %m");

        return 0;
}

static int manager_setup_bpf(Manager *m) {
        int rb_fd = -EBADF, poll_fd = -EBADF, r;

        assert(m);
        assert(!m->userns_restrict_bpf);
        assert(!m->userns_restrict_bpf_ring_buffer);
        assert(!m->userns_restrict_bpf_ring_buffer_event_source);

        r = userns_restrict_install(/* pin= */ true, &m->userns_restrict_bpf);
        if (r < 0) {
                log_notice_errno(r, "Proceeding with user namespace interfaces disabled.");
                return 0;
        }

        rb_fd = sym_bpf_map__fd(m->userns_restrict_bpf->maps.userns_ringbuf);
        if (rb_fd < 0)
                return log_error_errno(rb_fd, "Failed to get fd of ring buffer: %m");

        m->userns_restrict_bpf_ring_buffer = sym_ring_buffer__new(rb_fd, ringbuf_event, m, NULL);
        if (!m->userns_restrict_bpf_ring_buffer)
                return log_error_errno(errno, "Failed to allocate BPF ring buffer object: %m");

        poll_fd = sym_ring_buffer__epoll_fd(m->userns_restrict_bpf_ring_buffer);
        if (poll_fd < 0)
                return log_error_errno(poll_fd, "Failed to get poll fd of ring buffer: %m");

        r = sd_event_add_io(
                        m->event,
                        &m->userns_restrict_bpf_ring_buffer_event_source,
                        poll_fd,
                        EPOLLIN,
                        on_ringbuf_io,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event source for BPF ring buffer: %m");

        return 0;
}
#else
static int manager_setup_bpf(Manager *m) {
        log_notice("Not setting up BPF subsystem, as functionality has been disabled at compile time.");
        return 0;
}
#endif

int manager_startup(Manager *m) {
        _cleanup_(set_freep) Set *fdstore_inodes = NULL, *registry_inodes = NULL;
        void *p;
        int r;

        assert(m);
        assert(m->registry_fd < 0);
        assert(!m->userns_restrict_bpf);
        assert(m->listen_fd < 0);

        m->registry_fd = userns_registry_open_fd();
        if (m->registry_fd < 0)
                return log_error_errno(m->registry_fd, "Failed to open registry directory: %m");

        r = manager_setup_bpf(m);
        if (r < 0)
                return r;

        r = manager_scan_listen_fds(m, &fdstore_inodes);
        if (r < 0)
                return r;

        r = manager_scan_registry(m, &registry_inodes);
        if (r < 0)
                return r;

        /* If there are resources tied to UIDs not found in the registry, then release them */
        SET_FOREACH(p, fdstore_inodes)  {
                uint64_t inode;

                if (set_contains(registry_inodes, p))
                        continue;

                inode = PTR_TO_UINT32(p);

                log_debug("Found stale fd store entry for user namespace %" PRIu64 ", removing.", inode);
                manager_release_userns_by_inode(m, inode);
        }

        r = manager_make_listen_socket(m);
        if (r < 0)
                return r;

        /* Let's make sure every accept() call on this socket times out after 25s. This allows workers to be
         * GC'ed on idle */
        if (setsockopt(m->listen_fd, SOL_SOCKET, SO_RCVTIMEO, TIMEVAL_STORE(LISTEN_TIMEOUT_USEC), sizeof(struct timeval)) < 0)
                return log_error_errno(errno, "Failed to se SO_RCVTIMEO: %m");

        r = start_workers(m, /* explicit_request= */ false);
        if (r < 0)
                return r;

        return 0;
}

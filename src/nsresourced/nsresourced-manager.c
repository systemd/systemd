/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "bpf-util.h"
#if HAVE_VMLINUX_H
#include "bpf-link.h"
#include "userns-restrict-skel.h"
#endif
#include "build-path.h"
#include "common-signal.h"
#include "env-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "nsresourced-manager.h"
#include "parse-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "umask-util.h"
#include "unaligned.h"
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
                log_warning("Got unexpected exit code from child, ignoring.");

        (void) start_workers(m, /* explicit_request= */ false); /* Fill up workers again if we fell below the low watermark */
        return 0;
}

static int on_sigusr2(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        (void) start_workers(m, /* explicit_request= */ true); /* Workers told us there's more work, let's add one more worker as long as we are below the high watermark */
        return 0;
}

static int on_deferred_start_worker(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        m->deferred_start_worker_event_source = sd_event_source_unref(m->deferred_start_worker_event_source);

        (void) start_workers(m, /* explicit_request= */ false);
        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

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
                log_debug_errno(r, "Failed to allocate memory pressure event source, ignoring: %m");

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

#if HAVE_VMLINUX_H
        sd_event_source_disable_unref(m->userns_restrict_bpf_ring_buffer_event_source);
        sd_event_source_disable_unref(m->userns_restrict_bpf_ring_buffer_retry_event_source);
        bpf_ring_buffer_free(m->userns_restrict_bpf_ring_buffer);
        userns_restrict_bpf_free(m->userns_restrict_bpf);
#endif

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
        int r;

        assert(m);

        fixed = set_size(m->workers_fixed) < NSRESOURCE_WORKERS_MIN;

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(sd-worker)",
                        /* stdio_fds= */ NULL,
                        &m->listen_fd, 1,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_CLOSE_ALL_FDS,
                        &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to fork new worker child: %m");
        if (r == 0) {
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

                r = setenvf("LISTEN_PID", /* overwrite= */ true, PID_FMT, pidref.pid);
                if (r < 0) {
                        log_error_errno(r, "Failed to set $LISTEN_PID: %m");
                        _exit(EXIT_FAILURE);
                }

                uint64_t pidfdid;
                if (pidfd_get_inode_id_self_cached(&pidfdid) >= 0) {
                        r = setenvf("LISTEN_PIDFDID", /* overwrite= */ true, "%" PRIu64, pidfdid);
                        if (r < 0) {
                                log_error_errno(r, "Failed to set $LISTEN_PIDFDID: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                if (setenv("LISTEN_FDS", "1", 1) < 0) {
                        log_error_errno(errno, "Failed to set $LISTEN_FDS: %m");
                        _exit(EXIT_FAILURE);
                }

                if (setenv("NSRESOURCE_FIXED_WORKER", one_zero(fixed), 1) < 0) {
                        log_error_errno(errno, "Failed to set $NSRESOURCE_FIXED_WORKER: %m");
                        _exit(EXIT_FAILURE);
                }

#if HAVE_VMLINUX_H
                bool supported = m->userns_restrict_bpf;
#else
                bool supported = false;
#endif

                /* Tell the workers whether to enable the userns API */
                if (setenv("NSRESOURCE_API", one_zero(supported), 1) < 0) {
                        log_error_errno(errno, "Failed to set $NSRESOURCE_API: %m");
                        _exit(EXIT_FAILURE);
                }

                r = setenv_systemd_log_level();
                if (r < 0) {
                        log_error_errno(r, "Failed to set $SYSTEMD_LOG_LEVEL: %m");
                        _exit(EXIT_FAILURE);
                }

                r = invoke_callout_binary(SYSTEMD_NSRESOURCEWORK_PATH, STRV_MAKE("systemd-nsresourcework", "xxxxxxxxxxxxxxxx")); /* With some extra space rename_process() can make use of */
                log_error_errno(r, "Failed to start worker process: %m");
                _exit(EXIT_FAILURE);
        }

        r = event_add_child_pidref(m->event, &source, &pidref, WEXITED, on_worker_exit, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch child " PID_FMT ": %m", pidref.pid);

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
                                                /* accuracy= */ 0,
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

static struct userns_restrict_bpf *manager_bpf(Manager *m) {
        assert(m);

#if HAVE_VMLINUX_H
        return m->userns_restrict_bpf;
#else
        return NULL;
#endif
}

/* Releases the resources tied to a user namespace described by info. The caller must hold the
 * registry lock if there is any chance of a concurrent writer (i.e. workers — true once the listen
 * socket is open; not true during manager_startup() before that point). */
static void manager_release_userns_by_info(Manager *m, UserNamespaceInfo *info) {
        assert(m);
        assert(info);
        assert(info->userns_inode != 0);

        /* Before tearing anything down, confirm by namespace id that the namespace we're releasing is
         * actually dead. The kernel may have recycled this inode for a freshly created live namespace
         * (e.g. between a BPF death event firing and us getting here); proceeding in that case would
         * clobber the new namespace's BPF allowlist, fdstore fd and registry entry. */
        if (info->userns_id != 0) {
                _cleanup_close_ int probe_fd = namespace_open_by_id(info->userns_id);
                if (probe_fd >= 0) {
                        log_warning("Refusing to release user namespace %" PRIu64 " (id %" PRIu64 "): the namespace is still alive.",
                                    info->userns_inode, info->userns_id);
                        return;
                }
                if (probe_fd != -ESTALE &&
                    !ERRNO_IS_NEG_PRIVILEGE(probe_fd) &&
                    !ERRNO_IS_NEG_NOT_SUPPORTED(probe_fd))
                        log_warning_errno(probe_fd,
                                          "Failed to probe liveness of user namespace %" PRIu64 " (id %" PRIu64 "), proceeding with release: %m",
                                          info->userns_inode, info->userns_id);
        }

        userns_registry_release_by_info(manager_bpf(m), m->registry_fd, info);
}

static void manager_release_userns_by_inode(Manager *m, uint64_t inode) {
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        int r;

        assert(m);
        assert(inode != 0);

        r = userns_registry_load_by_userns_inode(m->registry_fd, inode, &userns_info);
        if (r >= 0)
                return manager_release_userns_by_info(m, userns_info);

        /* No registry entry to consult — fall through to inode-only cleanup of kernel resources. */
        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                       "Failed to load registry entry for user namespace %" PRIu64 ", proceeding with inode-only cleanup: %m", inode);
        userns_registry_release_by_userns_inode(manager_bpf(m), m->registry_fd, inode);
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
                if (bind(m->listen_fd, &sockaddr.sa, sockaddr_un_len(&sockaddr.un)) < 0)
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

#if HAVE_VMLINUX_H
static int ringbuf_event(void *userdata, void *data, size_t size) {
        Manager *m = ASSERT_PTR(userdata);
        size_t n;

        if ((size % sizeof(unsigned)) != 0) /* Not multiples of "unsigned"? */
                return -EIO;

        /* The registry lock is held by our caller, manager_drain_ringbuf(), so that we don't have to
         * block the event loop acquiring it here. (The startup-time release callers run before any
         * worker exists and don't need the lock either.) */

        n = size / sizeof(unsigned);
        for (size_t i = 0; i < n; i++) {
                const void *d;
                uint64_t inode;

                d = (const uint8_t*) data + i * sizeof(unsigned);
                inode = unaligned_read_ne32(d);

                log_debug("Got BPF ring buffer notification that user namespace %" PRIu64 " is now dead.", inode);
                manager_release_userns_by_inode(m, inode);
        }

        return 0;
}

/* How long to wait before retrying to drain the BPF ring buffer when a worker currently holds the
 * registry lock. */
#define NSRESOURCE_RINGBUF_RETRY_USEC (250 * USEC_PER_MSEC)

static int on_ringbuf_retry(sd_event_source *s, uint64_t usec, void *userdata);

static int manager_drain_ringbuf(Manager *m) {
        int r;

        assert(m);

        /* Serialize registry mutations against the workers, but never block the event loop while doing
         * so: a worker may hold the registry lock across fork()s, procfs writes and BPF map operations,
         * and blocking here would stall watchdog pings, SIGTERM and SIGCHLD handling. If the lock is
         * contended, leave the pending notifications queued in the ring buffer, stop our IO source from
         * busy-looping on the (still readable) ring buffer fd, and retry a little later. */
        _cleanup_close_ int lock_fd = userns_registry_lock_full(m->registry_fd, LOCK_EX|LOCK_NB);
        if (lock_fd == -EAGAIN) {
                r = sd_event_source_set_enabled(m->userns_restrict_bpf_ring_buffer_event_source, SD_EVENT_OFF);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable BPF ring buffer event source: %m");

                r = event_reset_time_relative(
                                m->event,
                                &m->userns_restrict_bpf_ring_buffer_retry_event_source,
                                CLOCK_MONOTONIC,
                                NSRESOURCE_RINGBUF_RETRY_USEC,
                                /* accuracy= */ 0,
                                on_ringbuf_retry,
                                m,
                                /* priority= */ 0,
                                "nsresource-ringbuf-retry",
                                /* force_reset= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to arm BPF ring buffer retry timer: %m");

                return 0;
        }
        if (lock_fd < 0)
                return log_error_errno(lock_fd, "Failed to lock registry: %m");

        r = sym_ring_buffer__poll(m->userns_restrict_bpf_ring_buffer, 0);
        if (r < 0)
                return log_error_errno(r, "Got failure reading from BPF ring buffer: %m");

        /* We drained the ring buffer under the lock, make sure the IO source is enabled again, in case a
         * previous contention had disabled it. */
        r = sd_event_source_set_enabled(m->userns_restrict_bpf_ring_buffer_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable BPF ring buffer event source: %m");

        return 0;
}

static int on_ringbuf_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        return manager_drain_ringbuf(ASSERT_PTR(userdata));
}

static int on_ringbuf_retry(sd_event_source *s, uint64_t usec, void *userdata) {
        return manager_drain_ringbuf(ASSERT_PTR(userdata));
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
        _cleanup_set_free_ Set *fdstore_inodes = NULL, *registry_inodes = NULL;
        void *p;
        int r;

        assert(m);
        assert(m->registry_fd < 0);
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

        /* Look for registry entries whose user namespace has died without us getting a BPF
         * notification — e.g. because the BPF ring buffer overflowed, the kprobe is missing, or
         * something else dropped the fd store entry without going through our cleanup path. Each
         * registry entry stores the kernel's unique namespace identifier; ask the kernel to open
         * the namespace by that identifier and release the entry if the lookup fails. Entries
         * written by older versions don't carry the identifier, and old kernels (or running
         * outside the initial user namespace) don't support lookup by it — in those cases we leave
         * the entry alone. */

        SET_FOREACH(p, registry_inodes) {
                uint64_t inode = PTR_TO_UINT32(p);

                r = userns_registry_reap_if_dead(manager_bpf(m), m->registry_fd, inode);
                if (r < 0) {
                        log_debug_errno(r, "Failed to probe liveness of user namespace %" PRIu64 ", ignoring: %m", inode);
                        continue;
                }
                if (r == USERNS_REAP_UNSUPPORTED) {
                        /* Can't look namespaces up by id at all here (old kernel, or not in the
                         * initial user namespace) — no entry is probeable, so stop rather than
                         * continuing to probe (and log) once per entry. */
                        log_debug("Cannot detect stale registry entries, skipping the rest.");
                        break;
                }
                /* USERNS_REAP_RELEASED, _ALIVE, or _INDETERMINATE — nothing more to do for this entry. */
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

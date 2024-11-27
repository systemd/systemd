/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "copy.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "machined.h"
#include "namespace-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "strv.h"
#include "user-util.h"

int manager_get_machine_by_pidref(Manager *m, const PidRef *pidref, Machine **ret) {
        Machine *mm;
        int r;

        assert(m);
        assert(pidref_is_set(pidref));
        assert(ret);

        mm = hashmap_get(m->machines_by_leader, pidref);
        if (!mm) {
                _cleanup_free_ char *unit = NULL;

                r = cg_pidref_get_unit(pidref, &unit);
                if (r >= 0)
                        mm = hashmap_get(m->machines_by_unit, unit);
        }
        if (!mm) {
                *ret = NULL;
                return 0;
        }

        *ret = mm;
        return 1;
}

int manager_add_machine(Manager *m, const char *name, Machine **ret) {
        Machine *machine;
        int r;

        assert(m);
        assert(name);

        machine = hashmap_get(m->machines, name);
        if (!machine) {
                r = machine_new(_MACHINE_CLASS_INVALID, name, &machine);
                if (r < 0)
                        return r;

                r = machine_link(m, machine);
                if (r < 0) {
                        machine_free(machine);
                        return r;
                }
        }

        if (ret)
                *ret = machine;

        return 0;
}

int manager_find_machine_for_uid(Manager *m, uid_t uid, Machine **ret_machine, uid_t *ret_internal_uid) {
        Machine *machine;
        int r;

        assert(m);
        assert(uid_is_valid(uid));

        /* Finds the machine for the specified host UID and returns it along with the UID translated into the
         * internal UID inside the machine */

        HASHMAP_FOREACH(machine, m->machines) {
                uid_t converted;

                r = machine_owns_uid(machine, uid, &converted);
                if (r < 0)
                        return r;
                if (r) {
                        if (ret_machine)
                                *ret_machine = machine;

                        if (ret_internal_uid)
                                *ret_internal_uid = converted;

                        return true;
                }
        }

        if (ret_machine)
                *ret_machine = NULL;
        if (ret_internal_uid)
                *ret_internal_uid = UID_INVALID;

        return false;
}

int manager_find_machine_for_gid(Manager *m, gid_t gid, Machine **ret_machine, gid_t *ret_internal_gid) {
        Machine *machine;
        int r;

        assert(m);
        assert(gid_is_valid(gid));

        HASHMAP_FOREACH(machine, m->machines) {
                gid_t converted;

                r = machine_owns_gid(machine, gid, &converted);
                if (r < 0)
                        return r;
                if (r) {
                        if (ret_machine)
                                *ret_machine = machine;

                        if (ret_internal_gid)
                                *ret_internal_gid = converted;

                        return true;
                }
        }

        if (ret_machine)
                *ret_machine = NULL;
        if (ret_internal_gid)
                *ret_internal_gid = GID_INVALID;

        return false;
}

void manager_gc(Manager *m, bool drop_not_started) {
        Machine *machine;

        assert(m);

        while ((machine = LIST_POP(gc_queue, m->machine_gc_queue))) {
                machine->in_gc_queue = false;

                /* First, if we are not closing yet, initiate stopping */
                if (machine_may_gc(machine, drop_not_started) &&
                    machine_get_state(machine) != MACHINE_CLOSING)
                        machine_stop(machine);

                /* Now, the stop probably made this referenced
                 * again, but if it didn't, then it's time to let it
                 * go entirely. */
                if (machine_may_gc(machine, drop_not_started)) {
                        machine_finalize(machine);
                        machine_free(machine);
                }
        }
}

static int on_deferred_gc(sd_event_source *s, void *userdata) {
        manager_gc(userdata, /* drop_not_started= */ true);
        return 0;
}

void manager_enqueue_gc(Manager *m) {
        int r;

        assert(m);

        if (m->deferred_gc_event_source) {
                r = sd_event_source_set_enabled(m->deferred_gc_event_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        log_warning_errno(r, "Failed to enable GC event source, ignoring: %m");

                return;
        }

        r = sd_event_add_defer(m->event, &m->deferred_gc_event_source, on_deferred_gc, m);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to allocate GC event source, ignoring: %m");

        r = sd_event_source_set_priority(m->deferred_gc_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                log_warning_errno(r, "Failed to tweak priority of event source, ignoring: %m");

        (void) sd_event_source_set_description(m->deferred_gc_event_source, "deferred-gc");
}

int machine_get_addresses(Machine *machine, struct local_address **ret_addresses) {
        assert(machine);
        assert(ret_addresses);

        switch (machine->class) {

        case MACHINE_HOST: {
                _cleanup_free_ struct local_address *addresses = NULL;
                int n;

                n = local_addresses(/* rtnl = */ NULL, /* ifindex = */ 0, AF_UNSPEC, &addresses);
                if (n < 0)
                        return log_debug_errno(n, "Failed to get local addresses: %m");

                *ret_addresses = TAKE_PTR(addresses);
                return n;
        }

        case MACHINE_CONTAINER: {
                _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
                _cleanup_close_ int netns_fd = -EBADF;
                pid_t child;
                int r;

                r = pidref_in_same_namespace(/* pid1 = */ NULL, &machine->leader, NAMESPACE_NET);
                if (r < 0)
                        return log_debug_errno(r, "Failed to check if container has private network: %m");
                if (r > 0)
                        return -ENONET;

                r = pidref_namespace_open(&machine->leader,
                                          /* ret_pidns_fd = */ NULL,
                                          /* ret_mntns_fd = */ NULL,
                                          &netns_fd,
                                          /* ret_userns_fd = */ NULL,
                                          /* ret_root_fd = */ NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to open namespace: %m");

                if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0)
                        return log_debug_errno(errno, "Failed to call socketpair(): %m");

                r = namespace_fork("(sd-addrns)",
                                   "(sd-addr)",
                                   /* except_fds = */ NULL,
                                   /* n_except_fds = */ 0,
                                   FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                                   /* pidns_fd = */ -1,
                                   /* mntns_fd = */ -1,
                                   netns_fd,
                                   /* userns_fd = */ -1,
                                   /* root_fd = */ -1,
                                   &child);
                if (r < 0)
                        return log_debug_errno(r, "Failed to fork(): %m");
                if (r == 0) {
                        _cleanup_free_ struct local_address *addresses = NULL;

                        pair[0] = safe_close(pair[0]);

                        int n = local_addresses(/* rtnl = */ NULL, /* ifindex = */ 0, AF_UNSPEC, &addresses);
                        if (n < 0) {
                                log_debug_errno(n, "Failed to get local addresses: %m");
                                _exit(EXIT_FAILURE);
                        }

                        FOREACH_ARRAY(a, addresses, n) {
                                r = write(pair[1], a, sizeof(*a));
                                if (r < 0) {
                                        log_debug_errno(errno, "Failed to write to socket: %m");
                                        _exit(EXIT_FAILURE);
                                }
                        }

                        pair[1] = safe_close(pair[1]);

                        _exit(EXIT_SUCCESS);
                }

                pair[1] = safe_close(pair[1]);

                _cleanup_free_ struct local_address *list = NULL;
                size_t n_list = 0;

                for (;;) {
                        ssize_t n;
                        struct local_address la;

                        n = read(pair[0], &la, sizeof(la));
                        if (n < 0)
                                return log_debug_errno(errno, "Failed to read from socket(): %m");
                        if (n == 0)
                                break;
                        if ((size_t) n < sizeof(la))
                                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Received unexpectedly short message");

                        r = add_local_address(&list,
                                              &n_list,
                                              la.ifindex,
                                              la.scope,
                                              la.family,
                                              &la.address);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add local address: %m");
                }

                r = wait_for_terminate_and_check("(sd-addrns)", child, /* flags = */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to wait for child: %m");
                if (r != EXIT_SUCCESS)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESHUTDOWN), "Child died abnormally");

                *ret_addresses = TAKE_PTR(list);
                return (int) n_list;
        }

        default:
                return -EOPNOTSUPP;
        }
}

#define EXIT_NOT_FOUND 2

int machine_get_os_release(Machine *machine, char ***ret_os_release) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(machine);
        assert(ret_os_release);

        switch (machine->class) {

        case MACHINE_HOST:
                r = load_os_release_pairs(/* root = */ NULL, &l);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load OS release information: %m");

                break;

        case MACHINE_CONTAINER: {
                _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF;
                _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
                _cleanup_fclose_ FILE *f = NULL;
                pid_t child;

                r = pidref_namespace_open(&machine->leader,
                                          &pidns_fd,
                                          &mntns_fd,
                                          /* ret_netns_fd = */ NULL,
                                          /* ret_userns_fd = */ NULL,
                                          &root_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to open namespace: %m");

                if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0)
                        return log_debug_errno(errno, "Failed to call socketpair(): %m");

                r = namespace_fork("(sd-osrelns)",
                                   "(sd-osrel)",
                                   /* except_fds = */ NULL,
                                   /* n_except_fds = */ 0,
                                   FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                                   pidns_fd,
                                   mntns_fd,
                                   /* netns_fd = */ -1,
                                   /* userns_fd = */ -1,
                                   root_fd,
                                   &child);
                if (r < 0)
                        return log_debug_errno(r, "Failed to fork(): %m");
                if (r == 0) {
                        _cleanup_close_ int fd = -EBADF;

                        pair[0] = safe_close(pair[0]);

                        r = open_os_release(/* root = */ NULL, /* ret_path = */ NULL, &fd);
                        if (r == -ENOENT)
                                _exit(EXIT_NOT_FOUND);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to read OS release: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = copy_bytes(fd, pair[1], UINT64_MAX, /* copy_flags = */ 0);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to write to fd: %m");
                                _exit(EXIT_FAILURE);
                        }

                        _exit(EXIT_SUCCESS);
                }

                pair[1] = safe_close(pair[1]);

                f = take_fdopen(&pair[0], "r");
                if (!f)
                        return log_debug_errno(errno, "Failed to fdopen(): %m");

                r = load_env_file_pairs(f, "/etc/os-release", &l);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load OS release information: %m");

                r = wait_for_terminate_and_check("(sd-osrelns)", child, /* flags = */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to wait for child: %m");
                if (r == EXIT_NOT_FOUND)
                        return -ENOENT;
                if (r != EXIT_SUCCESS)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESHUTDOWN), "Child died abnormally");

                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        *ret_os_release = TAKE_PTR(l);
        return 0;
}

static int image_flush_cache(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        hashmap_clear(m->image_cache);
        return 0;
}

int manager_acquire_image(Manager *m, const char *name, Image **ret) {
        int r;

        assert(m);
        assert(name);

        Image *existing = hashmap_get(m->image_cache, name);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        if (!m->image_cache_defer_event) {
                r = sd_event_add_defer(m->event, &m->image_cache_defer_event, image_flush_cache, m);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add deferred event: %m");

                r = sd_event_source_set_priority(m->image_cache_defer_event, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return log_debug_errno(r, "Failed to set source priority for event: %m");
        }

        r = sd_event_source_set_enabled(m->image_cache_defer_event, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable source: %m") ;

        _cleanup_(image_unrefp) Image *image = NULL;
        r = image_find(m->runtime_scope, IMAGE_MACHINE, name, NULL, &image);
        if (r < 0)
                return log_debug_errno(r, "Failed to find image: %m");

        image->userdata = m;

        r = hashmap_ensure_put(&m->image_cache, &image_hash_ops, image->name, image);
        if (r < 0)
                return r;

        if (ret)
                *ret = image;

        TAKE_PTR(image);
        return 0;
}

int rename_image_and_update_cache(Manager *m, Image *image, const char* new_name) {
        int r;

        assert(m);
        assert(image);
        assert(new_name);

        /* The image is cached with its name, hence it is necessary to remove from the cache before renaming. */
        assert_se(hashmap_remove_value(m->image_cache, image->name, image));

        r = image_rename(image, new_name, m->runtime_scope);
        if (r < 0) {
                image = image_unref(image);
                return r;
        }

        /* Then save the object again in the cache. */
        r = hashmap_put(m->image_cache, image->name, image);
        if (r < 0) {
                image = image_unref(image);
                log_debug_errno(r, "Failed to put renamed image into cache, ignoring: %m");
        }

        return 0;
}

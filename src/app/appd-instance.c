/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "appd-instance.h"
#include "appd-instance-varlink.h"
#include "appd-manager.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "log.h"
#include "pidref.h"
#include "stat-util.h"
#include "string-util.h"
#include "xattr-util.h"

static AppInstance* app_instance_free(AppInstance *a) {
        if (!a)
                return NULL;

        a->cg_path = mfree(a->cg_path);
        a->cg_fd = safe_close(a->cg_fd);
        a->cg_inotify = sd_event_source_disable_unref(a->cg_inotify);

        a->app_id = mfree(a->app_id);
        a->collection = mfree(a->collection);
        a->sandbox = mfree(a->sandbox);

        a->permissions = sd_json_variant_unref(a->permissions);
        a->entitlements = sd_json_variant_unref(a->entitlements);

        return mfree(a);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(AppInstance, app_instance, app_instance_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(instance_hash_ops,
                                              char, string_hash_func, string_compare_func,
                                              AppInstance, app_instance_unref);

static void app_instance_unmanage(AppInstance *instance) {
        log_debug("App %s (cg_path: %s) disappeared", instance->app_id, instance->cg_path);

        _cleanup_(app_instance_unrefp) AppInstance *owned_instance = NULL;
        owned_instance = hashmap_remove(instance->manager->instances, instance->cg_path);
        assert(owned_instance == instance);

        instance->cg_inotify = sd_event_source_disable_unref(instance->cg_inotify);

        (void) app_instance_notify(instance, APP_INSTANCE_DISAPPEARED, NULL, NULL);
}

static int app_instance_inotify(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        AppInstance *instance = ASSERT_PTR(userdata);
        int r;

        r = cg_is_empty(instance->cg_path);
        if (r < 0)
                log_debug_errno(r, "Failed to check if cgroup %s is empty, assuming it is: %m", instance->cg_path);
        if (r == 0) {
                /* The cgroup isn't empty, but that's not yet conclusive because we check by path. The path
                 * might have been recycled (i.e. if the app restarts), and we'd incorrectly apply old
                 * permissions to a new app instance. */
                r = fd_verify_linked(instance->cg_fd);
                if (r >= 0)
                        return 0; /* still linked + not empty => app still alive => keep watching */
                if (r != -EIDRM)
                        log_debug_errno(r, "Failed to check if cgroup %s still linked, assuming not: %m", instance->cg_path);
        }

        app_instance_unmanage(instance);
        return 0;
}

static int attempt_find_cgroup(Manager *manager, const PidRef *process, AppInstance **ret) {
        int r;

        assert(manager);
        assert(process);
        assert(ret);

        _cleanup_free_ char *path = NULL;
        r = cg_pidref_get_user_unit_path(process, &path);
        if (r < 0)
                return log_debug_errno(r, "Failed to query cgroup for PID " PID_FMT ": %m", process->pid);

        AppInstance *cached = hashmap_get(manager->instances, path);
        if (cached) {
                r = fd_verify_linked(cached->cg_fd);
                if (r >= 0) {
                        log_debug("PID " PID_FMT " is cached app: %s (cg_path: %s, sandbox: %s)",
                                  process->pid, cached->app_id, cached->cg_path, cached->sandbox ?: "none");
                        *ret = app_instance_ref(cached);
                        return 0;
                }
                if (r != -EIDRM)
                        return log_debug_errno(r, "Failed to verify cached %s still linked: %m", cached->cg_path);

                /* The cached instance points at a cgroup that has been recycled. This can happen if an app
                 * restarts, and we look up the new instance before the kernel notifies us of the old instance's
                 * disappearance. */
                app_instance_unmanage(cached);
        }

        /* We now try to open the cgroup to pin it. There's a race condition here: the app might move to a
         * different cgroup before we get the chance to open it. This would invalidate whatever result we
         * have from the open(). We can close the race by checking that the app hasn't moved */
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *verification_path = NULL;
        fd = cg_path_open(path);
        r = cg_pidref_get_user_unit_path(process, &verification_path);
        if (r < 0)
                return log_debug_errno(r, "Failed to re-query cgroup for PID " PID_FMT ": %m", process->pid);
        if (!streq(verification_path, path))
                return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                       "PID " PID_FMT " moved cgroup hierarchies, retrying: %s -> %s",
                                       process->pid, path, verification_path);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open %s: %m", path);

        _cleanup_free_ char *app_id = NULL;
        r = fgetxattr_malloc(fd, "user.app_id", &app_id, NULL);
        if (r == -ENODATA)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "PID " PID_FMT " is member of unmanaged cgroup: %s",
                                       process->pid, path);
        if (r < 0)
                return log_debug_errno(r, "Failed to read user.app_id xattr on %s: %m", path);

        log_debug("PID " PID_FMT " is new app: %s (cg_path: %s)",
                  process->pid, app_id, path);

        _cleanup_(app_instance_unrefp) AppInstance *app = new(AppInstance, 1);
        if (!app)
                return log_oom_debug();
        *app = (AppInstance) {
                .n_ref = 1,
                .manager = manager,
                .cg_path = TAKE_PTR(path),
                .cg_fd = TAKE_FD(fd),
                .app_id = TAKE_PTR(app_id),
        };

        _cleanup_close_ int events_fd = RET_NERRNO(openat(app->cg_fd, "cgroup.events", O_RDONLY|O_CLOEXEC));
        if (events_fd < 0)
                return log_debug_errno(events_fd, "Failed to open cgroup.events for %s: %m", app->cg_path);
        r = sd_event_add_inotify_fd(manager->event, &app->cg_inotify, events_fd, IN_MODIFY,
                                    app_instance_inotify, app);
        if (r < 0)
                return log_debug_errno(r, "Failed to watch cgroup.events for instance %s: %m", app->cg_path);

        r = hashmap_ensure_put(&manager->instances, &instance_hash_ops, app->cg_path, app);
        if (r < 0)
                return log_debug_errno(r, "Failed to add instance to hashmap %s: %m", app->cg_path);
        app_instance_ref(app);

        *ret = TAKE_PTR(app);
        return 0;
}

int app_instance_get(Manager *manager, const PidRef *process, AppInstance **ret) {
        int attempts = 0;
        int r;

        assert(manager);
        assert(process);
        assert(ret);

        for (;;) {
                r = attempt_find_cgroup(manager, process, ret);
                if (r >= 0)
                        return 0;

                if (r != -EAGAIN)
                        return r;

                if (attempts++ >= 3)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "PID " PID_FMT " ran out of attempts, giving up.",
                                               process->pid);
        }
}

int app_instance_commit(AppInstance *instance) {
        assert(instance);

        instance->generation++;
        log_debug("Committing instance: %s (cg_path: %s), new generation: %" PRIu64,
                  instance->app_id, instance->cg_path, instance->generation);

        return 0;
}

bool app_instance_same_app(AppInstance *a, AppInstance *b) {
        assert(a);
        assert(b);

        return streq(a->app_id, b->app_id) &&
                streq_ptr(a->collection, b->collection) &&
                streq_ptr(a->sandbox, b->sandbox);
}

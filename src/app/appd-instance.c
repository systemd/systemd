/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "appd-instance.h"
#include "appd-instance-varlink.h"
#include "appd-manager.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "log.h"
#include "pidref.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "unit-name.h"
#include "xattr-util.h"

static AppInstance* app_instance_free(AppInstance *a) {
        if (!a)
                return NULL;

        a->cg_path = mfree(a->cg_path);
        a->cg_fd = safe_close(a->cg_fd);
        a->cg_inotify = sd_event_source_disable_unref(a->cg_inotify);
        a->unit = mfree(a->unit);

        a->app_id = mfree(a->app_id);
        a->collection = mfree(a->collection);
        a->sandbox = mfree(a->sandbox);

        a->permissions = sd_json_variant_unref(a->permissions);
        a->entitlements = sd_json_variant_unref(a->entitlements);

        a->last_notify = sd_future_unref(a->last_notify);

        return mfree(a);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(AppInstance, app_instance, app_instance_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(instance_hash_ops,
                                              char, string_hash_func, string_compare_func,
                                              AppInstance, app_instance_unref);

static void app_instance_unmanage(AppInstance *instance) {
        assert(instance);

        log_full(instance->published ? LOG_INFO : LOG_DEBUG, "App instance %s disappeared", instance->unit);
        if (instance->published)
                app_instance_notify_async(instance, APP_INSTANCE_DISAPPEARED);
        instance->published = false;

        _cleanup_(app_instance_unrefp) AppInstance *owned_instance = NULL;
        owned_instance = hashmap_remove(instance->manager->instances, instance->cg_path);
        assert(owned_instance == instance);

        instance->cg_inotify = sd_event_source_disable_unref(instance->cg_inotify);
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
                        /* Still linked + not empty => app still alive => keep watching */
                        return 0;
                if (r != -EIDRM) {
                        /* If the check failed somehow, we still want to fail closed: better to use a recycled
                         * cgroup than to unmanage a still-running sandboxed app, forget that it is
                         * sandboxed, and then allow it to change its own permissions */
                        log_debug_errno(r, "Failed to check if cgroup %s still linked: %m", instance->cg_path);
                        return 0;
                }
        }

        app_instance_unmanage(instance);
        return 0;
}

static int attempt_find_cgroup(Manager *manager, const char *in_path, const PidRef *process, AppInstance **ret) {
        int r;

        assert(manager);
        assert(!in_path != !process); /* Exactly one should be NULL */
        assert(ret);

        _cleanup_free_ char *path = NULL;
        if (process) {
                r = cg_pidref_get_user_unit_path(process, &path);
                if (r == -ENXIO)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "PID " PID_FMT " not in a user unit",
                                               process->pid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to query cgroup for PID " PID_FMT ": %m",
                                               process->pid);

                log_debug("PID " PID_FMT " belongs to cgroup: %s", process->pid, path);
        } else {
                r = cg_path_get_user_unit_path(in_path, &path);
                if (r == -ENXIO)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "CGroup '%s' not in a user unit",
                                               in_path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to normalize cgroup '%s': %m", in_path);

                if (!streq(path, in_path))
                        log_debug("CGroup '%s' normalized to '%s'", in_path, path);
        }

        AppInstance *cached = hashmap_get(manager->instances, path);
        if (cached) {
                r = fd_verify_linked(cached->cg_fd);
                if (r >= 0) {
                        log_debug("Found app in cache: %s", cached->unit);
                        *ret = app_instance_ref(cached);
                        return 0;
                }
                if (r != -EIDRM)
                        return log_debug_errno(r, "Failed to verify cached %s still linked: %m", cached->unit);

                /* The cached instance points at a cgroup that has been recycled. This can happen if an app
                 * restarts, and we look up the new instance before the kernel notifies us of the old instance's
                 * disappearance. */
                app_instance_unmanage(cached);
        }

        /* We now try to open the cgroup to pin it */
        _cleanup_close_ int fd = cg_path_open(path);
        if (process) {
                /* If we're looking up by PID, there's a race condition here: the app might move to a different
                 * cgroup between us looking up its cgroup and pinning an fd. This would invalidate whatever
                 * result we have from the open(). Close the race by checking that the app hasn't moved */
                _cleanup_free_ char *verification_path = NULL;
                r = cg_pidref_get_user_unit_path(process, &verification_path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to re-query cgroup for PID " PID_FMT ": %m", process->pid);
                if (!streq(verification_path, path))
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN),
                                               "PID " PID_FMT " moved cgroup hierarchies, retrying: %s -> %s",
                                               process->pid, path, verification_path);
        }
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open %s: %m", path);

        _cleanup_free_ char *unit_name = NULL;
        r = cg_path_get_user_unit(path, &unit_name);
        if (r < 0)
                return log_debug_errno(r, "Failed to get unit name from %s: %m", path);

        _cleanup_free_ char *app_id = NULL;
        r = unit_name_to_app_id(unit_name, &app_id);
        if (r == -EINVAL)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Unit '%s' is not an app", unit_name);
        if (r < 0)
                return log_debug_errno(r, "Failed to get app ID from unit name '%s': %m", unit_name);

        log_debug("Unit '%s' is an un-cached app: %s", unit_name, app_id);

        _cleanup_(app_instance_unrefp) AppInstance *app = new(AppInstance, 1);
        if (!app)
                return log_oom_debug();
        *app = (AppInstance) {
                .n_ref = 1,
                .manager = manager,
                .cg_path = TAKE_PTR(path),
                .cg_fd = TAKE_FD(fd),
                .unit = TAKE_PTR(unit_name),
                .app_id = TAKE_PTR(app_id),
        };

        _cleanup_close_ int events_fd = xopenat(app->cg_fd, "cgroup.events", O_RDONLY);
        if (events_fd < 0)
                return log_debug_errno(events_fd, "Failed to open cgroup.events for %s: %m", app->cg_path);
        r = sd_event_add_inotify_fd(manager->event, &app->cg_inotify, events_fd, IN_MODIFY,
                                    app_instance_inotify, app);
        if (r < 0)
                return log_debug_errno(r, "Failed to watch cgroup.events for instance %s: %m", app->unit);

        r = hashmap_ensure_put(&manager->instances, &instance_hash_ops, app->cg_path, app);
        if (r < 0)
                return log_debug_errno(r, "Failed to add instance %s to hashmap: %m", app->unit);
        app_instance_ref(app);

        *ret = TAKE_PTR(app);
        return 0;
}

int app_instance_from_pidref(Manager *manager, const PidRef *process, AppInstance **ret) {
        int attempts = 0;
        int r;

        assert(manager);
        assert(process);
        assert(ret);

        for (;;) {
                r = attempt_find_cgroup(manager, NULL, process, ret);
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

int app_instance_from_path(Manager *manager, const char *path, AppInstance **ret) {
        return attempt_find_cgroup(manager, path, NULL, ret);
}

int app_instance_commit(AppInstance *instance) {
        assert(instance);

        instance->generation++;
        log_debug("Committing instance %s, new generation: %" PRIu64, instance->unit, instance->generation);

        return 0;
}

bool app_instance_same_app(AppInstance *a, AppInstance *b) {
        assert(a);
        assert(b);

        return streq(a->app_id, b->app_id) &&
                streq_ptr(a->collection, b->collection) &&
                streq_ptr(a->sandbox, b->sandbox);
}

static const char* const app_instance_event_table[_APP_INSTANCE_EVENT_MAX] = {
        [APP_INSTANCE_APPEARED] = "appeared",
        [APP_INSTANCE_CHANGED] = "changed",
        [APP_INSTANCE_DISAPPEARED] = "disappeared",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(app_instance_event, AppInstanceEvent);

typedef struct NotifyFiberContext {
        AppInstance *instance;
        AppInstanceEvent event;
        sd_future *previous_notify;
} NotifyFiberContext;

static NotifyFiberContext* notify_fiber_context_free(NotifyFiberContext *context) {
        if (!context)
                return NULL;

        context->instance = app_instance_unref(context->instance);
        context->previous_notify = sd_future_unref(context->previous_notify);
        return mfree(context);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(NotifyFiberContext*, notify_fiber_context_free);

static int notify_fiber(void *userdata) {
        _cleanup_(notify_fiber_context_freep) NotifyFiberContext *ctx = ASSERT_PTR(userdata);

        /* Wait for all previous notifications to be delivered, before we send this one */
        if (ctx->previous_notify)
                (void) sd_fiber_await(ctx->previous_notify);

        return app_instance_varlink_notify(ctx->instance, ctx->event);
}

static int app_instance_notify_impl(AppInstance *instance, AppInstanceEvent event, sd_future **ret) {
        int r;

        assert(instance);

        log_debug("Starting fiber to notify that app instance %s %s",
                  instance->unit, app_instance_event_to_string(event));

        _cleanup_free_ char *description = NULL;
        r = asprintf(&description, "vl-instance-notify-%s-%s", instance->app_id,
                     app_instance_event_to_string(event));
        if (r < 0)
                return log_oom_debug();

        _cleanup_(notify_fiber_context_freep) NotifyFiberContext *ctx = new(NotifyFiberContext, 1);
        if (!ctx)
                return log_oom_debug();

        *ctx = (NotifyFiberContext) {
                .instance = app_instance_ref(instance),
                .event = event,
                .previous_notify = sd_future_ref(instance->last_notify),
        };

        _cleanup_(sd_future_cancel_unrefp) sd_future *fiber = NULL;
        r = sd_fiber_new(instance->manager->event, description, notify_fiber, ctx, &fiber);
        if (r < 0)
                return log_debug_errno(r, "Failed to spawn fiber: %m");
        TAKE_PTR(ctx);

        /* Ensure that this fiber holds a reference on itself, until it resolves. This way we don't have to
         * worry about freeing the fiber before it's done: in all cases the fiber will be driven to completion
         * before being free'd. */
        r = sd_fiber_set_floating(fiber, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to make fiber floating: %m");

        if (ret)
                *ret = sd_future_ref(fiber);
        free_and_replace_full(instance->last_notify, fiber, sd_future_unref);
        return 0;
}

void app_instance_notify_async(AppInstance *instance, AppInstanceEvent event) {
        return (void) app_instance_notify_impl(instance, event, /* ret= */ NULL);
}

int app_instance_notify(AppInstance *instance, AppInstanceEvent event) {
        int r;

        assert(instance);

        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        r = app_instance_notify_impl(instance, event, &fiber);
        if (r < 0)
                return r;

        return sd_fiber_await(fiber);
}

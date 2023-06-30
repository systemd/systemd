/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-polkit.h"
#include "main-func.h"
#include "service-util.h"
#include "signal-util.h"
#include "socket-util.h"

typedef struct Job Job;
typedef struct Target Target;
typedef struct Manager Manager;

typedef int (*JobComplete)(sd_bus_message *, const Job *, const JsonVariant *, sd_bus_error *);

struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *targets;

        uint32_t current_job_id;
        Hashmap *jobs;

        Hashmap *polkit_registry;

        int notify_fd;
        sd_event_source *notify_event_source;
}

typedef enum TargetClass {
        /* These should try to match ImageClass from src/basic/os-util.h */
        TARGET_MACHINE = IMAGE_MACHINE,
        TARGET_PORTABLE = IMAGE_PORTABLE,
        TARGET_EXTENSION = IMAGE_EXTENSION,
        TARGET_CONFEXT = IMAGE_CONFEXT,

        /* sysupdate-specific classes */
        TARGET_HOST,
        TARGET_COMPONENT,

        _TARGET_CLASS_MAX,
        _TARGET_CLASS_INVALID = -EINVAL,
}

struct Target {
        Manager *manager;

        TargetClass class;
        char *name;
        char *path;

        char *id;
        ImageType image_type;

        Job *active_job;
}

typedef enum JobType {
        JOB_LIST,
        JOB_DESCRIBE,
        JOB_CHECK_NEW,
        JOB_UPDATE,
        JOB_VACUUM,
        _JOB_TYPE_MAX,
        _JOB_TYPE_INVALID = -EINVAL,
} JobType;

struct Job {
        Manager *manager;
        Target *target;

        uint32_t id;
        char *object_path;

        JobType type;
        bool offline;
        char *version; /* Passed into sysupdate for JOB_DESCRIBE and JOB_UPDATE */

        unsigned progress_percent;

        pid_t pid;
        int stdout_fd;
        sd_event_source *pid_event_source;
        unsigned n_cancelled;

        JsonVariant *json;

        JobComplete complete_cb;
        sd_bus_message *dbus_msg;
}

static const char* const target_class_table[_TARGET_CLASS_MAX] = {
        [TARGET_MACHINE] = "machine",
        [TARGET_PORTABLE] = "portable",
        [TARGET_EXTENSION] = "extension",
        [TARGET_CONFEXT] = "confext",
        [TARGET_COMPONENT] = "component",
        [TARGET_HOST] = "host",
}

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(target_class, TargetClass);

static const char* const job_type_table[_JOB_TYPE_MAX] = {
        [JOB_LIST] = "list",
        [JOB_DESCRIBE] = "describe",
        [JOB_CHECK_NEW] = "check-new",
        [JOB_UPDATE] = "update",
        [JOB_VACUUM] = "vacuum",
}

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(job_type, JobType);

static Job *job_unref(Job *j) {
        if (!j)
                return NULL;

        if (j->manager)
                hashmap_remove(j->manager->jobs, UINT32_TO_PTR(j->id));

        free(j->object_path);
        free(j->version);

        json_variant_unref(j->json);

        sd_event_source_unref(j->pid_event_source);
        if (j->pid > 1)
                sigkill_wait(j->pid);
        safe_close(j->stdout_fd);

        return mfree(j);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Job*, job_unref);

static int job_new(JobType type, Target *t, sd_bus_message *msg, JobComplete cb, Job **ret) {
        _cleanup_(job_unrefp) Job *j = NULL;

        assert(m);
        assert(t);
        assert(ret);

        j = new0(Job, 1);
        if (!j)
                return -ENOMEM;

        j->type = type;
        j->target = t;
        j->manager = t->manager;
        j->id = m->current_job_id + 1;
        j->stdout_fd = -EBADF;
        j->complete_cb = cb;
        j->dbus_msg = msg;

        if (asprintf(&j->object_path, "/org/freedesktop/sysupdate1/job/_%" PRIu32, j->id) < 0)
                return -ENOMEM;

        r = hashmap_put(&m->jobs, UINT32_TO_PTR(j->id), j);
        if (r < 0)
                return r;

        m->current_job_id = j->id;

        *ret = TAKE_PTR(j);
        return 0;
}

static int job_parse_stdout(int _fd, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_close_ int fd = _fd;
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        int r;

        assert(j);
        assert(ret);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat stdout fd: %m");

        assert(S_ISREG(st.st_mode));

        if (st.st_size == 0)
                return 0;

        if (lseek(fd, SEEK_SET, 0) == (off_t) -1)
                return log_error_errno(errno, "Failed to seek to beginning of memfd: %m");

        f = take_fdopen(&fd, "r");
        if (!f)
                return log_error_errno(errno, "Failed to reopen memfd: %m");

        r = json_parse_file(f, "stdout", 0, &v, NULL, NULL)
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        *ret = TAKE_PTR(v);
        return 0;
}

static int job_on_pid(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Job *j = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *json = NULL;
        int r, code;

        assert(s);
        assert(si);

        j->pid = 0;

        assert(j->target->active_job = j);
        j->target->active_job = NULL;

        if (si->si_code != CLD_EXITED) {
                assert(IN_SET(si->si_code, CLD_KILLED, CLD_DUMPED));
                sd_bus_error_setf(error, SD_BUS_ERROR_FAILED,
                                  "Job terminated abnormally with signal %s.",
                                  signal_to_string(si->si_status));
        } else if (si->si_status != EXIT_SUCCESS)
                sd_bus_error_setf(error, SD_BUS_ERROR_FAILED,
                                  "Job failed with exit code %i.",
                                  si->si_status);
        else {
                r = job_parse_stdout(TAKE_FD(j->stdout_fd), &json);
                if (r < 0)
                        sd_bus_error_set_errnof(error, r, "Failed to parse JSON: %m");
        }

        r = sd_bus_emit_signal(
                        j->manager->bus,
                        "/org/freedesktop/sysupdate1",
                        "org.freedesktop.sysupdate1.Manager",
                        "JobRemoved",
                        "uoi",
                        j->id,
                        j->object_path,
                        si->si_status);
        if (r < 0)
                log_error_errno(r, "Cannot emit JobRemoved message, ignoring: %m");

        if (j->dbus_msg && j->complete_cb) {
                if (sd_bus_error_is_set(error))
                        sd_bus_reply_method_error(j->dbus_msg, error);
                else {
                        r = j->complete_cb(j->dbus_msg, j, json, &error);
                        if (r < 0 || sd_bus_error_is_set(error))
                                sd_bus_reply_method_errno(m, r, error);
                }
        }

        job_unref(j);
        return 0;
}

static int job_start(Job *j) {
        _cleanup_close_ int stdout_fd = -EBADF;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        int r;

        assert(j);

        if (j->target->active_job)
                return -EBUSY;

        stdout_fd = memfd_create_wrapper("sysupdate-stdout", MFD_CLOEXEC | MFD_NOEXEC_SEAL);
        if (stdout_fd < 0)
                return stdout_fd;

        r = safe_fork_full("(sd-sysupdate)",
                           (int[]) { -EBADF, stdout_fd, STDERR_FILENO }, NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_REARRANGE_STDIO|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                _cleanup_free_ char *target_arg = NULL;
                const char *cmd[] = {
                        ROOTLIBEXECDIR "/systemd-sysupdate",
                        "--json=short",
                        NULL, /* maybe --component=, --root=, or --image= */
                        NULL, /* maybe --offline */
                        NULL, /* list, check-new, update, vacuum */
                        NULL, /* maybe version (for list, update) */
                        NULL
                }
                unsigned k = 1;

                if (setenv("NOTIFY_SOCKET", "/run/systemd/sysupdate/notify", 1) < 0) {
                        log_error_errno(errno, "setenv() failed: %m");
                        _exit(EXIT_FAILURE);
                }

                r = setenv_systemd_exec_pid(true);
                if (r < 0)
                        log_warning_errno(r, "Failed to update $SYSTEMD_EXEC_PID, ignoring: %m");

                if (j->target->class == TARGET_HOST)
                        r = 0; /* Host doesn't need any argument */
                else if (j->target->class == TARGET_COMPONENT)
                        r = asprintf(&target_arg, "--component=%s", j->target->path);
                else if (IN_SET(j->target->image_type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME))
                        r = asprintf(&target_arg, "--root=%s", j->target->path);
                else
                        r = asprintf(&target_arg, "--image=%s", j->target->path);
                if (r < 0) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }
                if (target_arg)
                        cmd[k++] = target_arg;

                if (j->offline)
                        cmd[k++] = "--offline";

                switch (j->type) {
                case JOB_LIST:
                        cmd[k++] = "list";
                        break;

                case JOB_DESCRIBE:
                        cmd[k++] = "list";
                        assert(!isempty(j->version));
                        cmd[k++] = j->version;
                        break;

                case JOB_CHECK_NEW:
                        cmd[k++] = "check-new";
                        break;

                case JOB_UPDATE:
                        cmd[k++] = "update";
                        cmd[k++] = empty_to_null(j->version);
                        break;

                case JOB_VACUUM:
                        cmd[k++] = "vacuum";
                        break;

                default:
                        assert_not_reached();
                }

                execv(cmd[0], (char * const *) cmd);
                log_error_errno(errno, "Failed to execute systemd-sysupdate: %m");
                _exit(EXIT_FAILURE);
        }

        r = sd_event_add_child(j->manager->event, &j->pid_event_source, j->pid,
                               WEXITED, job_on_pid, j);
        if (r < 0)
                return r;

        j->stdout_fd = TAKE_FD(stdout_fd);
        j->pid = TAKE_PID(pid);
        j->target->active_job = j;

        return 0;
}

static int job_cancel(Job *j) {
        int r;

        assert(j);

        r = kill_and_sigcont(j->pid, j->n_canceled < 3 ? SIGTERM : SIGKILL);
        if (r < 0)
                return r;

        j->n_canceled++;
        return 0;
}

static int job_method_cancel(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Job *j = ASSERT_PTR(userdata);
        char *action;
        int r;

        assert(msg);

        switch (j->type) {
        case JOB_LIST:
        case JOB_DESCRIBE:
        case JOB_CHECK_NEW:
                action = "org.freedesktop.sysupdate1.check";
                break;

        case JOB_UPDATE:
                action = "org.freedesktop.sysupdate1.update";
                break;

        case JOB_VACUUM:
                action = "org.freedesktop.sysupdate1.vacuum";
                break;

        default:
                assert_not_reached();
        }

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        action,
                        NULL,
                        false,
                        UID_INVALID,
                        &j->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_cancel(j);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(msg, NULL);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(job_property_get_type, job_type, JobType);

static int job_object_find(
                sd_bus *bus,
                const char *path,
                const char *iface,
                void *userdata,
                void **found
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        const char *p;
        uint32_t id;
        int r;

        assert(bus);
        assert(path);
        assert(found);

        p = startswith(path, "/org/freedesktop/syspdate1/job/_");
        if (!p)
                return 0;

        r = safe_atou32(p, &id);
        if (r < 0 || id == 0)
                return 0;

        j = hashmap_get(m->jobs, UINT32_TO_PTR(id));
        if (!j)
                return 0;

        *found = j;
        return 1;
}

static int job_node_enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***nodes,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        unsigned k = 0;

        l = new0(char*, hashmap_size(j->jobs) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(j, m->jobs) {
                l[k] = strdup(j->object_path);
                if (!l[k])
                        return -ENOMEM;
                k++;
        }

        *nodes = TAKE_PTR(l);
        return 1;
}

static const sd_bus_vtable job_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "u", NULL, offsetof(Job, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Type", "u", job_property_get_type, offsetof(Job, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Offline", "b", NULL, offsetof(Job, offline), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Progress", "u", NULL, offsetof(Job, progress_percent), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD("Cancel", NULL, NULL, job_method_cancel, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
}

static const BusObjectImplementation job_object = {
        "/org/freedesktop/sysupdate1/job",
        "org.freedesktop.sysupdate1.Job",
        .fallback_vtables = BUS_FALLBACK_VTABLES({job_vtable, job_object_find}),
        .node_enumerator = job_node_enumerator,
};

static Target *target_unref(Target *t) {
        if (!t)
                return NULL;

        if (t->manager)
                hashmap_remove(t->manager->targets, t->id);

        free(t->name);
        free(t->path);
        free(t->version);
        free(t->id);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Target*, target_unref);

static int target_new(TargetClass class, const char *name, Manager *m, Target **ret) {
        _cleanup_(target_unrefp) Target *t = NULL;

        assert(m);
        assert(ret);

        t = new0(Target, 1);
        if (!t)
                return -ENOMEM;

        t->image_type = _IMAGE_TYPE_INVALID;
        t->class = class;

        t->name = strdup(name);
        if (!t->name)
                return -ENOMEM;

        if (class == TARGET_HOST) {
                t->id = strdup("host");
                if (!t->id)
                        return -ENOMEM;
        } else if (asprintf(&t->id, "%s/%s", target_class_to_string(class), name) < 0)
                return -ENOMEM;

        r = hashmap_put(&m->targets, t->id, t);
        if (r < 0)
                return r;

        *ref = TAKE_PTR(t);
        return 0;
}

static int target_cache_version_from_json(Target *t, JsonVariant *json) {
        JsonVariant *v;
        const char *version;

        v = json_variant_by_key(json, "current");
        if (!v)
                return -EINVAL;

        version = json_variant_string(v);
        if (!version)
                return -EINVAL;

        t->version = strdup(version);
        if (!t->version)
                return -ENOMEM;

        return 0;
}

static int target_property_get_version_finish(
                sd_bus_message *reply,
                const Job *j,
                const JsonVariant *json,
                sd_bus_error *error) {
        int r;

        r = target_cache_version_from_json(j->target, json);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "s", j->target->version);
}

static int target_property_get_version(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_unrefp) Job *j = NULL;
        int r;

        assert(bus);
        assert(reply);

        if (t->version)
                return sd_bus_message_append(reply, "s", t->version);

        r = job_new(JOB_LIST, t, reply, target_property_get_version_finish, &j);
        if (r < 0)
                return r;

        j->offline = true;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");

        j = NULL; /* Avoid job from being killed & freed */
        return 1;
}


static int target_method_list_finish(sd_bus_message *msg, const Job *j, const JsonVariant *json, sd_bus_error *error) {
        JsonVariant *v;
        _cleanup_strv_free_ char **versions = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        /* Try our best since we have the data anyway, but isn't fatal if it fails */
        (void) target_cache_version_from_json(j->target, json);

        v = json_variant_by_key(json, "all");
        if (!v)
                return -EINVAL;

        r = json_variant_strv(v, &versions);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, versions);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int target_method_list(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_unrefp) Job *j = NULL;
        bool offline;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "b", &offline);
        if (r < 0)
                return r;

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", target->name,
                "offline", true_false(offline),
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                CAP_SYS_ADMIN,
                "org.freedesktop.sysupdate1.check",
                details,
                false,
                UID_INVALID,
                &m->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_LIST, t, msg, target_method_list_finish, &j);
        if (r < 0)
                return r;

        j->offline = offline;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");

        j = NULL; /* Avoid job from being killed & freed */
        return 1;
}

static int target_method_describe_finish(sd_bus_message *msg, const Job *j, const JsonVariant *json, sd_bus_error *error) {
        // TODO: Figure out what the output format even looks like
        // TODO: Convert the JSON to the output format
        // json_variant_dispatch may be very useful here
        return 0;
}

static int target_method_describe(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_unrefp) Job *j = NULL;
        const char *version;
        bool offline;
        int r;

        assert(msg);

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", target->name,
                "version", version,
                "offline", true_false(offline),
                NULL
        };

        r = sd_bus_message_read(msg, "sb", &version, &offline);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                msg,
                CAP_SYS_ADMIN,
                "org.freedesktop.sysupdate1.check",
                details,
                false,
                UID_INVALID,
                &m->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_DESCRIBE, t, msg, target_method_describe_finish, &j);
        if (r < 0)
                return r;

        j->version = strdup(version);
        if (!j->version)
                return log_oom();
        j->offline = offline;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");

        j = NULL; /* Avoid job from being killed & freed */
        return 1;
}

static int target_method_check_finish(sd_bus_message *msg, const Job *j, const JsonVariant *json, sd_bus_error *error) {
        char *result = json_variant_string(json);
        if (!result)
                return -EINVAL;
        return sd_bus_reply_method_return(msg, "s", result);
}

static int target_method_check(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_unrefp) Job *j = NULL;
        int r;

        assert(msg);

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", target->name,
                "offline", "false",
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                CAP_SYS_ADMIN,
                "org.freedesktop.sysupdate1.check",
                details,
                false,
                UID_INVALID,
                &m->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_CHECK_NEW, t, msg, target_method_check_finish, &j);
        if (r < 0)
                return r;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");

        j = NULL; /* Avoid job from being killed & freed */
        return 1;
}

static int target_method_update(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_unrefp) Job *j = NULL;
        const char *version;
        bool interactive;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "sb", &version, &interactive);
        if (r < 0)
                return r;

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", target->name,
                "version", version,
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                CAP_SYS_ADMIN,
                "org.freedesktop.sysupdate1.update",
                details,
                interactive,
                UID_INVALID,
                &m->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_UPDATE, t, /* msg= */ NULL, /* cb= */ NULL, &j);
        if (r < 0)
                return r;

        j->version = strdup(version);
        if (!j->version)
                return log_oom();

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");

        r = sd_bus_reply_method_return(msg, "o", j->object_path);
        j = NULL; /* Avoid job from being killed & freed */
        return r;
}

static int target_method_vacuum_finish(sd_bus_message *msg, const Job *j, const JsonVariant *json, sd_bus_error *error) {
        return sd_bus_reply_method_return(msg, "u", json_variant_unsigned(json));
}

static int target_method_vacuum(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_unrefp) Job *j = NULL;
        bool interactive;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "b", &interactive);
        if (r < 0)
                return r;

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", target->name,
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                CAP_SYS_ADMIN,
                "org.freedesktop.sysupdate1.vacuum",
                details,
                interactive,
                UID_INVALID,
                &m->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_VACUUM, t, msg, &j, target_method_vacuum_finish);
        if (r < 0)
                return r;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");

        j = NULL; /* Avoid job from being killed & freed */
        return 1;
}

static int target_object_find(
                sd_bus *bus,
                const char *path,
                const char *iface,
                void *userdata,
                void **found
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Target *t;
        _cleanup_free_ char *e;
        const char *p, class, name;
        uint32_t id;
        int r;

        assert(bus);
        assert(path);
        assert(found);

        p = startswith(path, "/org/freedesktop/syspdate1/target/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        t = hashmap_get(m->targets, e);
        if (!t)
                return 0;

        *found = t;
        return 1;
}

static char *target_bus_path(Target *t) {
        _cleanup_free_ char *e = NULL;

        assert(t);

        e = bus_label_escape(t->id);
        if (!e)
                return NULL;

        return strjoin("/org/freedesktop/sysupdate1/target/", e);
}

static int target_node_enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***nodes,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Target *t;
        char *key;
        unsigned k = 0;

        l = new0(char*, hashmap_size(j->targets) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(t, m->targets) {
                l[k] = target_bus_path(t);
                if (!l[k])
                        return -ENOMEM;
                k++;
        }

        *nodes = TAKE_PTR(l);
        return 1;
}


static const sd_bus_vtable target_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Class", "s", property_target_get_class, offsetof(Target, class), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(Target, name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Path", "s", NULL, offsetof(Target, path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Version", "s", property_target_get_version, 0, 0),

        SD_BUS_METHOD_WITH_ARGS("List",
                                SD_BUS_ARGS("b", offline),
                                SD_BUS_RESULT("as", versions),
                                target_method_list,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("Describe",
                                SD_BUS_ARGS("s", version, "b", offline),
                                SD_BUS_RESULT("TODO", todo, "TODO", todo),
                                target_method_describe,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("CheckNew",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", new_version)
                                target_method_check_new,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("Update",
                                SD_BUS_ARGS("s", new_version, "b", interactive),
                                SD_BUS_RESULT("o", job),
                                target_method_update,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("Vacuum",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_RESULT("u", count),
                                target_method_vacuum,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
}

static const BusObjectImplementation target_object = {
        "/org/freedesktop/sysupdate1/target",
        "org.freedesktop.sysupdate1.Target",
        .fallback_vtables = BUS_FALLBACK_VTABLES({target_vtable, target_object_find}),
        .node_enumerator = target_node_enumerator,
};

static Manager *manager_unref(Manager *m) {
        Target *target;
        Job *job;

        if (!m)
                return NULL;

        sd_event_source_unref(m->notify_event_source);
        safe_close(m->notify_fd);

        while ((target = hashmap_first(m->targets)))
                target_unref(target);
        hashmap_free(m->tragets);

        while ((job = hashmap_first(m->jobs)))
                job_free(job);
        hashmap_free(m->jobs);

        bus_verify_polkit_async_registry_free(m->polkit_registry);

        m->bus = sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager *, manager_unref);

static int manager_on_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        char buf[NOTIFY_BUFFER_MAX+1];
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf)-1,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)) control;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct ucred *ucred;
        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        ssize_t n;
        unsigned progress;
        char *p;
        int r;

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(n))
                        return 0;
                return (int) n;
        }

        cmsg_close_all(&msghdr);

        if (msghdr.msg_flags & MSG_TRUNC) {
                log_warning("Got overly long notification datagram, ignoring.");
                return 0;
        }

        ucred = CMSG_FIND_DATA(&msghdr, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
        if (!ucred || ucred->pid <= 0) {
                log_warning("Got notification datagram lacking credential information, ignoring.");
                return 0;
        }

        HASHMAP_FOREACH(j, m->jobs)
                if (ucred->pid == j->pid)
                        break;

        if (!t) {
                log_warning("Got notification datagram from unexpected peer, ignoring.");
                return 0;
        }

        buf[n] = 0;

        p = find_line_startswith(buf, "X_IMPORT_PROGRESS=");
        if (!p)
                return 0;

        truncate_nl(p);

        r = safe_atou(p, &progress);
        if (r < 0 || progress > 100) {
                log_warning("Got invalid percent value, ignoring.");
                return 0;
        }

        t->progress_percent = progress;
        (void) sd_bus_emit_properties_changed(t->manager->bus, t->object_path,
                                              "org.freedesktop.sysupdate1.Job",
                                              "Progress", NULL);

        log_debug("Got percentage from worker " PID_FMT ": %u%%", t->pid, t->progress_percent);
        return 0;
}

static int manager_new(Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/sysupdate/notify",
        };
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->targets = hashmap_new(&string_hash_ops);
        if (!m->tragets)
                return -ENOMEM;

        m->jobs = hashmap_new(&trivial_hash_ops);
        if (!m->jobs)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

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

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return r;

        m->notify_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->notify_fd < 0)
                return -errno;

        (void) mkdir_parents_label(sa.un.sun_path, 0755);
        (void) sockaddr_un_unlink(&sa.un);

        if (bind(m->notify_fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return -errno;

        r = setsockopt_int(m->notify_fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return r;

        r = sd_event_add_io(m->event, &m->notify_event_source, m->notify_fd, EPOOLIN,
                            manager_on_notify, m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int manager_discover_images(Manager *m, ImageClass class) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        Target *t;
        Image *image;
        int r;

        images = hashmap_new(&image_hash_ops);
        if (!images)
                return log_oom();

        r = image_discover(class, NULL, images);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate images: %m");

        HASHMAP_FOREACH(image, images) {
                r = target_new(class, image->name, m, &t);
                if (r < 0)
                        return r;

                t->path = strdup(image->path);
                if (!t->path)
                        return log_oom();

                t->image_type = image->type;
        }

        return 0;
}

static int manager_enumerate_components(Manager *m) {
        _cleanup_close_pair_ int pipe[2] = PIPE_EBADF;
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        _cleanup_fclose_ FILE *f = NULL;
        Target *t;
        int r;

        r = safe_fork_full("(sd-sysupdate)",
                           (int[]) { -EBADF, pipe[1], -EBADF }, NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_REARRANGE_STDIO|FORK_LOG,
                           &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                const char *cmd[] = {
                        ROOTLIBEXECDIR "/systemd-sysupdate",
                        "components",
                };
                execv(cmd[0], (char * const * ) cmd);
                log_error_errno(errno, "Failed to execute systemd-sysupdate: %m");
                _exit(EXIT_FAILURE);
        }

        pipe[0] = safe_close(pipe[0]);
        f = take_fdopen(&pipe[1], "r");
        if (!f)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *component = NULL;

                r = read_line(f, LONG_LINE_MAX, &component);
                if (r < 0)
                        return log_error_errno(r, "Failed to read component names: %m");
                if (r == 0)
                        break;

                if (streq(component, "<default>"))
                        continue;

                r = target_new(TARGET_COMPONENT, component, m, &t);
                if (r < 0)
                        return r;
                if (asprintf(&t->path, "sysupdate.%s.d", component) < 0)
                        return log_oom();
        }
}

static int manager_enumerate_targets(Manager *m) {
        static const ImageClass classes[] = { IMAGE_MACHINE, IMAGE_PORTABLE, IMAGE_EXTENSION, IMAGE_CONFEXT };
        ImageClass class;
        Target *t;
        int r;

        assert(m);

        r = target_new(TARGET_HOST, "host", m, &t);
        if (r < 0)
                return r;
        t->path = strdup("sysupdate.d");
        if (!t->path)
                return log_oom();

        FOREACH_ARRAY(class, classes, ELEMENTSOF(classes)) {
                r = manager_discover_images(m, class);
                if (r < 0)
                        return r;
        }

        return manager_enumerate_components(m);
}

static int method_list_targets(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Target *t;

        assert(msg);
        assert(m);

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(sso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(t, m->targets) {
                _cleanup_free_ char *bus_path = NULL;

                bus_path = target_bus_path(t);
                if (!bus_path)
                        return log_oom();

                r = sd_bus_message_append(reply, "(sso)",
                                          target_class_to_string(t->class),
                                          t->name,
                                          bus_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD_WITH_ARGS("ListTargets",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(sso)", targets),
                                method_list_targets,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_ARGS("JobRemoved",
                                SD_BUS_ARGS("u", job_id, "o", job_path, "i", exit_code),
                                0),

        SD_BUS_VTABLE_END,
}

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/sysupdate1",
        "org.freedesktop.sysupdate1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS(&job_object, &target_object),
}

static int manager_add_bus_objects(Manager *m) {
        int r;

        assert(m);

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.sysupdate1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bust to event loop: %m");

        return 0;
}

static bool manager_check_idle(void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        return hashmap_isempty(m->jobs);
}

static int manager_run(Manager *m) {
        assert(m);

        return bus_event_loop_with_idle(m->event,
                                        m->bus,
                                        "org.freedesktop.sysupdate1",
                                        DEFAULT_EXIT_USEC,
                                        manager_check_idle,
                                        m);
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        log_setup();

        r = service_parse_argv("systemd-sysupdated.service",
                               "System update management service.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHILD, SIGRTMIN+18, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        r = manager_add_bus_objects(m);
        if (r < 0)
                return r;

        r = manager_enumerate_targets(m);
        if (r < 0)
                return r;

        r = manager_run(m);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

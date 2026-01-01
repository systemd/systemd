/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-json.h"

#include "build-path.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-get-properties.h"
#include "bus-label.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "common-signal.h"
#include "constants.h"
#include "discover-image.h"
#include "dropin.h"
#include "env-util.h"
#include "escape.h"
#include "event-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "memfd-util.h"
#include "notify-recv.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "service-util.h"
#include "signal-util.h"
#include "string-table.h"
#include "strv.h"
#include "sysupdate-util.h"
#include "utf8.h"

#define FEATURES_DROPIN_NAME "systemd-sysupdate-enabled"

typedef struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *targets;

        uint64_t last_job_id;
        Hashmap *jobs;

        Hashmap *polkit_registry;

        char *notify_socket_path;

        RuntimeScope runtime_scope; /* For now only RUNTIME_SCOPE_SYSTEM */
} Manager;

/* Forward declare so that jobs can call it on exit */
static void manager_check_idle(Manager *m);

typedef enum TargetClass {
        /* These should try to match ImageClass from src/basic/os-util.h */
        TARGET_MACHINE  = IMAGE_MACHINE,
        TARGET_PORTABLE = IMAGE_PORTABLE,
        TARGET_SYSEXT   = IMAGE_SYSEXT,
        TARGET_CONFEXT  = IMAGE_CONFEXT,
        _TARGET_CLASS_IS_IMAGE_CLASS_MAX,

        /* sysupdate-specific classes */
        TARGET_HOST = _TARGET_CLASS_IS_IMAGE_CLASS_MAX,
        TARGET_COMPONENT,

        _TARGET_CLASS_MAX,
        _TARGET_CLASS_INVALID = -EINVAL,
} TargetClass;

/* Let's ensure when the number of classes is updated things are updated here too */
assert_cc((int) _IMAGE_CLASS_MAX == (int) _TARGET_CLASS_IS_IMAGE_CLASS_MAX);

typedef struct Target {
        Manager *manager;

        TargetClass class;
        char *name;
        char *path;

        char *id;
        ImageType image_type;
        bool busy;
} Target;

typedef enum JobType {
        JOB_LIST,
        JOB_DESCRIBE,
        JOB_CHECK_NEW,
        JOB_UPDATE,
        JOB_VACUUM,
        JOB_DESCRIBE_FEATURE,
        _JOB_TYPE_MAX,
        _JOB_TYPE_INVALID = -EINVAL,
} JobType;

typedef struct Job Job;

typedef int (*JobReady)(sd_bus_message *msg, const Job *job);
typedef int (*JobComplete)(sd_bus_message *msg, const Job *job, sd_json_variant *response, sd_bus_error *error);

struct Job {
        Manager *manager;
        Target *target;

        uint64_t id;
        char *object_path;

        JobType type;
        bool offline;
        char *version; /* Passed into sysupdate for JOB_DESCRIBE and JOB_UPDATE */
        char *feature; /* Passed into sysupdate for JOB_DESCRIBE_FEATURE */

        unsigned progress_percent;

        sd_event_source *child;
        int stdout_fd;
        int status_errno;
        unsigned n_cancelled;

        sd_json_variant *json;

        JobComplete complete_cb; /* Callback called on job exit */
        sd_bus_message *dbus_msg;
        JobReady detach_cb; /* Callback called when job has started.  Detaches the job to run in the background */
};

static const char* const target_class_table[_TARGET_CLASS_MAX] = {
        [TARGET_MACHINE]   = "machine",
        [TARGET_PORTABLE]  = "portable",
        [TARGET_SYSEXT]    = "sysext",
        [TARGET_CONFEXT]   = "confext",
        [TARGET_COMPONENT] = "component",
        [TARGET_HOST]      = "host",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(target_class, TargetClass);

static const char* const job_type_table[_JOB_TYPE_MAX] = {
        [JOB_LIST]             = "list",
        [JOB_DESCRIBE]         = "describe",
        [JOB_CHECK_NEW]        = "check-new",
        [JOB_UPDATE]           = "update",
        [JOB_VACUUM]           = "vacuum",
        [JOB_DESCRIBE_FEATURE] = "describe-feature",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(job_type, JobType);

static Job *job_free(Job *j) {
        if (!j)
                return NULL;

        if (j->manager)
                assert_se(hashmap_remove(j->manager->jobs, &j->id) == j);

        free(j->object_path);
        free(j->version);
        free(j->feature);

        sd_json_variant_unref(j->json);

        sd_bus_message_unref(j->dbus_msg);

        sd_event_source_disable_unref(j->child);
        safe_close(j->stdout_fd);

        return mfree(j);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Job*, job_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(job_hash_ops, uint64_t, uint64_hash_func, uint64_compare_func,
                                      Job, job_free);

static int job_new(JobType type, Target *t, sd_bus_message *msg, JobComplete complete_cb, Job **ret) {
        _cleanup_(job_freep) Job *j = NULL;
        int r;

        assert(t);
        assert(ret);

        j = new(Job, 1);
        if (!j)
                return -ENOMEM;

        *j = (Job) {
                .type = type,
                .target = t,
                .id = t->manager->last_job_id + 1,
                .stdout_fd = -EBADF,
                .complete_cb = complete_cb,
                .dbus_msg = sd_bus_message_ref(msg),
        };

        if (asprintf(&j->object_path, "/org/freedesktop/sysupdate1/job/_%" PRIu64, j->id) < 0)
                return -ENOMEM;

        r = hashmap_ensure_put(&t->manager->jobs, &job_hash_ops, &j->id, j);
        if (r < 0)
                return r;

        j->manager = t->manager;

        t->manager->last_job_id = j->id;

        *ret = TAKE_PTR(j);
        return 0;
}

static int job_parse_child_output(int _fd, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        /* Take ownership of the passed fd */
        _cleanup_close_ int fd = _fd;
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        int r;

        assert(ret);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat stdout fd: %m");

        assert(S_ISREG(st.st_mode));

        if (st.st_size == 0) {
                log_warning("No output from child job, ignoring");
                return 0;
        }

        if (lseek(fd, SEEK_SET, 0) == (off_t) -1)
                return log_debug_errno(errno, "Failed to seek to beginning of memfd: %m");

        f = take_fdopen(&fd, "r");
        if (!f)
                return log_debug_errno(errno, "Failed to reopen memfd: %m");

        r = sd_json_parse_file(f, "stdout", 0, &v, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse JSON: %m");

        *ret = TAKE_PTR(v);
        return 0;
}

static void job_on_ready(Job *j) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *msg = NULL;
        int r;

        assert(j);

        /* Some jobs run in the background as we return the job ID to the dbus caller (i.e. for the Update
         * method). However, the worker will perform some sanity-checks on startup which would be valuable
         * as dbus errors. So, we wait for the worker to signal via READY=1 that it has completed its sanity
         * checks and we should continue the job in the background. */

        if (!j->detach_cb)
                return;

        log_debug("Got READY=1 from job %" PRIu64", detaching.", j->id);

        assert(j->dbus_msg);
        msg = TAKE_PTR(j->dbus_msg);

        j->complete_cb = NULL;

        r = j->detach_cb(msg, j);
        if (r < 0)
                log_warning_errno(r, "Failed to detach job %" PRIu64 ", ignoring: %m", j->id);
}

static void job_on_errno(Job *j, const char *buf) {
        int r;

        assert(j);
        assert(buf);

        r = parse_errno(buf);
        if (r < 0) {
                log_warning_errno(r, "Got invalid errno value from job %" PRIu64 ", ignoring: %m", j->id);
                return;
        }

        j->status_errno = r;

        log_debug_errno(r, "Got errno from job %" PRIu64 ": %i (%m)", j->id, r);
}

static void job_on_progress(Job *j, const char *buf) {
        unsigned progress;
        int r;

        assert(j);
        assert(buf);

        r = safe_atou(buf, &progress);
        if (r < 0 || progress > 100) {
                log_warning("Got invalid percent value, ignoring.");
                return;
        }

        j->progress_percent = progress;
        (void) sd_bus_emit_properties_changed(j->manager->bus, j->object_path,
                                              "org.freedesktop.sysupdate1.Job",
                                              "Progress", NULL);

        log_debug("Got percentage from job %" PRIu64 ": %u%%", j->id, j->progress_percent);
}

static void job_on_version(Job *j, const char *version) {
        assert(j);
        assert(version);

        if (free_and_strdup_warn(&j->version, version) < 0)
                return;

        log_debug("Got version from job %" PRIu64 ": %s ", j->id, j->version);
}

static int job_on_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Job *j = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        Manager *manager = j->manager;
        int r;

        assert(j);
        assert(s);
        assert(si);

        if (IN_SET(j->type, JOB_UPDATE, JOB_VACUUM)) {
                assert(j->target->busy);
                j->target->busy = false;
        }

        if (si->si_code != CLD_EXITED) {
                assert(IN_SET(si->si_code, CLD_KILLED, CLD_DUMPED));
                sd_bus_error_setf(&error, SD_BUS_ERROR_FAILED,
                                  "Job terminated abnormally with signal %s.",
                                  signal_to_string(si->si_status));
        } else if (si->si_status != EXIT_SUCCESS)
                if (j->status_errno != 0)
                        sd_bus_error_set_errno(&error, j->status_errno);
                else
                        sd_bus_error_setf(&error, SD_BUS_ERROR_FAILED,
                                          "Job failed with exit code %i.", si->si_status);
        else {
                r = job_parse_child_output(TAKE_FD(j->stdout_fd), &json);
                if (r < 0)
                        sd_bus_error_set_errnof(&error, r, "Failed to parse job worker output: %m");
        }

        /* Only send notification of exit if the job was actually detached */
        if (j->detach_cb) {
                r = sd_bus_emit_signal(
                                j->manager->bus,
                                "/org/freedesktop/sysupdate1",
                                "org.freedesktop.sysupdate1.Manager",
                                "JobRemoved",
                                "toi",
                                j->id,
                                j->object_path,
                                j->status_errno != 0 ? -j->status_errno : si->si_status);
                if (r < 0)
                        log_warning_errno(r,
                                          "Cannot emit JobRemoved message for job %" PRIu64 ", ignoring: %m",
                                          j->id);
        }

        if (j->dbus_msg && j->complete_cb) {
                if (sd_bus_error_is_set(&error)) {
                        log_warning("Job %" PRIu64 " failed with bus error, ignoring callback: %s",
                                    j->id, error.message);
                        sd_bus_reply_method_error(j->dbus_msg, &error);
                } else {
                        r = j->complete_cb(j->dbus_msg, j, json, &error);
                        if (r < 0) {
                                log_warning_errno(r,
                                                  "Error during execution of job callback for job %" PRIu64 ": %s",
                                                  j->id,
                                                  bus_error_message(&error, r));
                                sd_bus_reply_method_errno(j->dbus_msg, r, &error);
                        }
                }
        }

        job_free(j);

        if (manager)
                manager_check_idle(manager);

        return 0;
}

static inline const char* sysupdate_binary_path(void) {
        return secure_getenv("SYSTEMD_SYSUPDATE_PATH") ?: SYSTEMD_SYSUPDATE_PATH;
}

static int target_get_argument(Target *t, char **ret) {
        _cleanup_free_ char *target_arg = NULL;

        assert(t);
        assert(ret);

        if (t->class != TARGET_HOST) {
                if (t->class == TARGET_COMPONENT)
                        target_arg = strjoin("--component=", t->name);
                else if (IN_SET(t->image_type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME))
                        target_arg = strjoin("--root=", t->path);
                else if (IN_SET(t->image_type, IMAGE_RAW, IMAGE_BLOCK))
                        target_arg = strjoin("--image=", t->path);
                else
                        assert_not_reached();
                if (!target_arg)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(target_arg);
        return 0;
}

static int job_start(Job *j) {
        _cleanup_close_ int stdout_fd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        int r;

        assert(j);

        if (IN_SET(j->type, JOB_UPDATE, JOB_VACUUM) && j->target->busy)
                return log_notice_errno(SYNTHETIC_ERRNO(EBUSY), "Target %s busy, ignoring job.", j->target->name);

        stdout_fd = memfd_new("sysupdate-stdout");
        if (stdout_fd < 0)
                return log_error_errno(stdout_fd, "Failed to create memfd: %m");

        r = pidref_safe_fork_full("(sd-sysupdate)",
                                  (int[]) { -EBADF, stdout_fd, STDERR_FILENO }, NULL, 0,
                                  FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|
                                  FORK_REARRANGE_STDIO|FORK_LOG|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r; /* FORK_LOG means pidref_safe_fork_full will handle the logging */
        if (r == 0) {
                /* Child */

                _cleanup_free_ char *target_arg = NULL;
                const char *cmd[] = {
                        "systemd-sysupdate",
                        "--json=short",
                        NULL, /* maybe --verify=no */
                        NULL, /* maybe --component=, --root=, or --image= */
                        NULL, /* maybe --offline */
                        NULL, /* list, check-new, update, vacuum, features */
                        NULL, /* maybe version (for list, update), maybe feature (features) */
                        NULL
                };
                size_t k = 2;

                if (setenv("NOTIFY_SOCKET", j->manager->notify_socket_path, /* overwrite= */ 1) < 0) {
                        log_error_errno(errno, "setenv() failed: %m");
                        _exit(EXIT_FAILURE);
                }

                if (getenv_bool("SYSTEMD_SYSUPDATE_NO_VERIFY") > 0)
                        cmd[k++] = "--verify=no"; /* For testing */

                r = setenv_systemd_exec_pid(true);
                if (r < 0)
                        log_warning_errno(r, "Failed to update $SYSTEMD_EXEC_PID, ignoring: %m");

                r = target_get_argument(j->target, &target_arg);
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

                case JOB_DESCRIBE_FEATURE:
                        cmd[k++] = "features";
                        assert(!isempty(j->feature));
                        cmd[k++] = j->feature;
                        break;

                default:
                        assert_not_reached();
                }

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *s = NULL;

                        s = quote_command_line((char**) cmd, SHELL_ESCAPE_EMPTY);
                        if (!s) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        log_debug("Spawning worker for job %" PRIu64 ": %s", j->id, s);
                }

                r = invoke_callout_binary(sysupdate_binary_path(), (char *const *) cmd);
                log_error_errno(r, "Failed to execute systemd-sysupdate: %m");
                _exit(EXIT_FAILURE);
        }

        log_info("Started job %" PRIu64 " with worker PID " PID_FMT,
                 j->id, pid.pid);

        r = event_add_child_pidref(j->manager->event, &j->child, &pid, WEXITED, job_on_exit, j);
        if (r < 0)
                return log_error_errno(r, "Failed to add child process to event loop: %m");

        r = sd_event_source_set_child_process_own(j->child, true);
        if (r < 0)
                return log_error_errno(r, "Event loop failed to take ownership of child process: %m");
        pidref_done(&pid); /* disarm sigkill_wait */

        j->stdout_fd = TAKE_FD(stdout_fd);

        if (IN_SET(j->type, JOB_UPDATE, JOB_VACUUM))
                j->target->busy = true;

        return 0;
}

static int job_cancel(Job *j) {
        int r;

        assert(j);

        r = sd_event_source_send_child_signal(j->child, j->n_cancelled < 3 ? SIGTERM : SIGKILL,
                                              NULL, 0);
        if (r < 0)
                return r;

        j->n_cancelled++;
        return 0;
}

static int job_method_cancel(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Job *j = ASSERT_PTR(userdata);
        const char *action;
        int r;

        assert(msg);

        switch (j->type) {
        case JOB_LIST:
        case JOB_DESCRIBE:
        case JOB_CHECK_NEW:
                action = "org.freedesktop.sysupdate1.check";
                break;

        case JOB_UPDATE:
                if (j->version)
                        action = "org.freedesktop.sysupdate1.update-to-version";
                else
                        action = "org.freedesktop.sysupdate1.update";
                break;

        case JOB_VACUUM:
                action = "org.freedesktop.sysupdate1.vacuum";
                break;

        case JOB_DESCRIBE_FEATURE:
                action = NULL;
                break;

        default:
                assert_not_reached();
        }

        if (action) {
                r = bus_verify_polkit_async(
                                msg,
                                action,
                                /* details= */ NULL,
                                &j->manager->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

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
                void **ret,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        const char *p;
        uint64_t id;
        int r;

        assert(bus);
        assert(path);
        assert(ret);

        p = startswith(path, "/org/freedesktop/sysupdate1/job/_");
        if (!p)
                return 0;

        r = safe_atou64(p, &id);
        if (r < 0 || id == 0)
                return 0;

        j = hashmap_get(m->jobs, &id);
        if (!j)
                return 0;

        *ret = j;
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

        l = new0(char*, hashmap_size(m->jobs) + 1);
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

        SD_BUS_PROPERTY("Id", "t", NULL, offsetof(Job, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Type", "s", job_property_get_type, offsetof(Job, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Offline", "b", bus_property_get_bool, offsetof(Job, offline), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Progress", "u", bus_property_get_unsigned, offsetof(Job, progress_percent), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD("Cancel", NULL, NULL, job_method_cancel, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

static const BusObjectImplementation job_object = {
        "/org/freedesktop/sysupdate1/job",
        "org.freedesktop.sysupdate1.Job",
        .fallback_vtables = BUS_FALLBACK_VTABLES({job_vtable, job_object_find}),
        .node_enumerator = job_node_enumerator,
};

static Target *target_free(Target *t) {
        if (!t)
                return NULL;

        free(t->name);
        free(t->path);
        free(t->id);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Target*, target_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(target_hash_ops, char, string_hash_func, string_compare_func,
                                      Target, target_free);

static int target_new(Manager *m, TargetClass class, const char *name, const char *path, Target **ret) {
        _cleanup_(target_freep) Target *t = NULL;

        assert(m);
        assert(ret);

        t = new(Target, 1);
        if (!t)
                return -ENOMEM;

        *t = (Target) {
                .manager = m,
                .class = class,
                .image_type = _IMAGE_TYPE_INVALID,
        };

        t->name = strdup(name);
        if (!t->name)
                return -ENOMEM;

        t->path = strdup(path);
        if (!t->path)
                return -ENOMEM;

        if (class == TARGET_HOST)
                t->id = strdup("host"); /* This is what appears in the object path */
        else
                t->id = strjoin(target_class_to_string(class), ":", name);
        if (!t->id)
                return -ENOMEM;

        *ret = TAKE_PTR(t);
        return 0;
}

static int sysupdate_run_simple(sd_json_variant **ret, Target *t, ...) {
        _cleanup_close_pair_ int pipe[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *target_arg = NULL;
        int r;

        if (t) {
                r = target_get_argument(t, &target_arg);
                if (r < 0)
                        return r;
        }

        r = pipe2(pipe, O_CLOEXEC);
        if (r < 0)
                return -errno;

        r = pidref_safe_fork_full("(sd-sysupdate)",
                                  (int[]) { -EBADF, pipe[1], STDERR_FILENO },
                                  NULL, 0,
                                  FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|
                                  FORK_REARRANGE_STDIO|FORK_LOG|FORK_REOPEN_LOG,
                                  &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                va_list ap;
                char *arg;
                _cleanup_strv_free_ char **args = NULL;

                if (strv_extend(&args, "systemd-sysupdate") < 0) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }

                if (strv_extend(&args, "--json=short") < 0) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }

                if (target_arg && strv_extend(&args, target_arg) < 0) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }

                va_start(ap, t);
                while ((arg = va_arg(ap, char*))) {
                        r = strv_extend(&args, arg);
                        if (r < 0)
                                break;
                }
                va_end(ap);
                if (r < 0) {
                        log_oom();
                        _exit(EXIT_FAILURE);
                }

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *s = NULL;

                        s = quote_command_line((char**) args, SHELL_ESCAPE_EMPTY);
                        if (!s) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        log_debug("Spawning sysupdate: %s", s);
                }

                r = invoke_callout_binary(sysupdate_binary_path(), args);
                log_error_errno(r, "Failed to execute systemd-sysupdate: %m");
                _exit(EXIT_FAILURE);
        }

        pipe[1] = safe_close(pipe[1]);
        f = take_fdopen(&pipe[0], "r");
        if (!f)
                return -errno;

        r = sd_json_parse_file(f, "stdout", 0, &v, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse JSON: %m");

        *ret = TAKE_PTR(v);
        return 0;
}

static BUS_DEFINE_PROPERTY_GET_ENUM(target_property_get_class, target_class, TargetClass);

#define log_sysupdate_bad_json_full(lvl, r, verb, msg) \
        log_full_errno((lvl), (r), "Invalid JSON response from 'systemd-sysupdate %s': %s", (verb), (msg))
#define log_sysupdate_bad_json(r, verb, msg) \
        log_sysupdate_bad_json_full(LOG_ERR, (r), (verb), (msg))
#define log_sysupdate_bad_json_debug(r, verb, msg) \
        log_sysupdate_bad_json_full(LOG_DEBUG, (r), (verb), (msg))

static int target_method_list_finish(
                sd_bus_message *msg,
                const Job *j,
                sd_json_variant *json,
                sd_bus_error *error) {

        sd_json_variant *v;
        _cleanup_strv_free_ char **versions = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(json);

        v = sd_json_variant_by_key(json, "all");
        if (!v)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "list", "Missing key 'all'");

        r = sd_json_variant_strv(v, &versions);
        if (r < 0)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "list", "Key 'all' should be strv");

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, versions);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int target_method_list(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_freep) Job *j = NULL;
        uint64_t flags;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "t", &flags);
        if (r < 0)
                return r;

        if ((flags & ~SD_SYSUPDATE_FLAGS_ALL) != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid flags specified");

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", t->name,
                "offline", one_zero(FLAGS_SET(flags, SD_SYSUPDATE_OFFLINE)),
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                "org.freedesktop.sysupdate1.check",
                details,
                &t->manager->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_LIST, t, msg, target_method_list_finish, &j);
        if (r < 0)
                return r;

        j->offline = FLAGS_SET(flags, SD_SYSUPDATE_OFFLINE);

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");
        TAKE_PTR(j); /* Avoid job from being killed & freed */

        return 1;
}

static int target_method_describe_finish(
                sd_bus_message *msg,
                const Job *j,
                sd_json_variant *json,
                sd_bus_error *error) {
        _cleanup_free_ char *text = NULL;
        int r;

        /* NOTE: This is also reused by target_method_describe_feature */

        assert(json);

        r = sd_json_variant_format(json, 0, &text);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(msg, "s", text);
}

static int target_method_describe(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_freep) Job *j = NULL;
        const char *version;
        uint64_t flags;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "st", &version, &flags);
        if (r < 0)
                return r;

        if (isempty(version))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Version must be specified");

        if ((flags & ~SD_SYSUPDATE_FLAGS_ALL) != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid flags specified");

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", t->name,
                "version", version,
                "offline", one_zero(FLAGS_SET(flags, SD_SYSUPDATE_OFFLINE)),
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                "org.freedesktop.sysupdate1.check",
                details,
                &t->manager->polkit_registry,
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

        j->offline = FLAGS_SET(flags, SD_SYSUPDATE_OFFLINE);

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");
        TAKE_PTR(j); /* Avoid job from being killed & freed */

        return 1;
}

static int target_method_check_new_finish(
                sd_bus_message *msg,
                const Job *j,
                sd_json_variant *json,
                sd_bus_error *error) {
        const char *reply;

        assert(json);

        sd_json_variant *v = sd_json_variant_by_key(json, "available");
        if (!v)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "check-new", "Missing key 'available'");

        if (sd_json_variant_is_null(v))
                reply = "";
        else
                reply = sd_json_variant_string(v);
        if (!reply)
                return -EINVAL;

        return sd_bus_reply_method_return(msg, "s", reply);
}

static int target_method_check_new(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_freep) Job *j = NULL;
        int r;

        assert(msg);

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", t->name,
                "offline", "0",
                NULL
        };

        r = bus_verify_polkit_async(
                        msg,
                        "org.freedesktop.sysupdate1.check",
                        details,
                        &t->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_CHECK_NEW, t, msg, target_method_check_new_finish, &j);
        if (r < 0)
                return r;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");
        TAKE_PTR(j); /* Avoid job from being killed & freed */

        return 1;
}

static int target_method_update_finished_early(
                sd_bus_message *msg,
                const Job *j,
                sd_json_variant *json,
                sd_bus_error *error) {

        /* Called when job finishes w/ a successful exit code, but before any work begins.
         * This happens when there is no candidate (i.e. we're already up-to-date), or
         * specified update is already installed. */
        return sd_bus_error_setf(error, BUS_ERROR_NO_UPDATE_CANDIDATE,
                                 "Job exited successfully with no work to do, assume already updated");
}

static int target_method_update_detach(sd_bus_message *msg, const Job *j) {
        int r;

        assert(msg);
        assert(j);

        r = sd_bus_reply_method_return(msg, "sto", j->version, j->id, j->object_path);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int target_method_update(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_freep) Job *j = NULL;
        const char *version, *action;
        uint64_t flags;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "st", &version, &flags);
        if (r < 0)
                return r;

        if (flags != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Flags must be 0");

        if (isempty(version))
                action = "org.freedesktop.sysupdate1.update";
        else
                action = "org.freedesktop.sysupdate1.update-to-version";

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", t->name,
                "version", version,
                NULL
        };

        r = bus_verify_polkit_async(
                        msg,
                        action,
                        details,
                        &t->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_UPDATE, t, msg, target_method_update_finished_early, &j);
        if (r < 0)
                return r;
        j->detach_cb = target_method_update_detach;

        j->version = strdup(version);
        if (!j->version)
                return -ENOMEM;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");
        TAKE_PTR(j);

        return 1;
}

static int target_method_vacuum_finish(
                sd_bus_message *msg,
                const Job *j,
                sd_json_variant *json,
                sd_bus_error *error) {

        sd_json_variant *v;
        uint64_t instances, disabled;

        assert(json);

        v = sd_json_variant_by_key(json, "removed");
        if (!v)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "vacuum", "Missing key 'removed'");
        if (!sd_json_variant_is_unsigned(v))
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "vacuum", "Key 'removed' should be an unsigned int");
        instances = sd_json_variant_unsigned(v);
        assert(instances <= UINT32_MAX);

        v = sd_json_variant_by_key(json, "disabledTransfers");
        if (!v)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "vacuum", "Missing key 'disabledTransfers'");
        if (!sd_json_variant_is_unsigned(v))
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "vacuum", "Key 'disabledTransfers' should be an unsigned int");
        disabled = sd_json_variant_unsigned(v);
        assert(disabled <= UINT32_MAX);

        return sd_bus_reply_method_return(msg, "uu", (uint32_t) instances, (uint32_t) disabled);
}

static int target_method_vacuum(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_freep) Job *j = NULL;
        int r;

        assert(msg);

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", t->name,
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                "org.freedesktop.sysupdate1.vacuum",
                details,
                &t->manager->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = job_new(JOB_VACUUM, t, msg, target_method_vacuum_finish, &j);
        if (r < 0)
                return r;

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");
        TAKE_PTR(j); /* Avoid job from being killed & freed */

        return 1;
}

static int target_method_get_version(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        sd_json_variant *version_json;
        int r;

        r = sysupdate_run_simple(&v, t, "--offline", "list", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run 'systemd-sysupdate list': %m");

        version_json = sd_json_variant_by_key(v, "current");
        if (!version_json)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "list", "Missing key 'current'");

        if (sd_json_variant_is_null(version_json))
                return sd_bus_reply_method_return(msg, "s", "");

        if (!sd_json_variant_is_string(version_json))
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "list", "Key 'current' should be a string");

        return sd_bus_reply_method_return(msg, "s", sd_json_variant_string(version_json));
}

static int target_get_appstream(Target *t, char ***ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        sd_json_variant *appstream_url_json;
        int r;

        r = sysupdate_run_simple(&v, t, "--offline", "list", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run 'systemd-sysupdate list': %m");

        appstream_url_json = sd_json_variant_by_key(v, "appstreamUrls");
        if (!appstream_url_json)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "list", "Missing key 'appstreamUrls'");

        r = sd_json_variant_strv(appstream_url_json, ret);
        if (r < 0)
                return log_sysupdate_bad_json(SYNTHETIC_ERRNO(EPROTO), "list", "Key 'appstreamUrls' should be strv");

        return 0;
}

static int target_method_get_appstream(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **appstream_urls = NULL;
        int r;

        r = target_get_appstream(t, &appstream_urls);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, appstream_urls);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int target_method_list_features(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        _cleanup_strv_free_ char **features = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Target *t = ASSERT_PTR(userdata);
        sd_json_variant *v;
        uint64_t flags;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "t", &flags);
        if (r < 0)
                return r;
        if (flags != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Flags must be 0");

        r = sysupdate_run_simple(&json, t, "features", NULL);
        if (r < 0)
                return r;

        v = sd_json_variant_by_key(json, "features");
        if (!v)
                return -EINVAL;
        r = sd_json_variant_strv(v, &features);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, features);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int target_method_describe_feature(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Target *t = ASSERT_PTR(userdata);
        _cleanup_(job_freep) Job *j = NULL;
        const char *feature;
        uint64_t flags;
        int r;

        assert(msg);

        r = sd_bus_message_read(msg, "st", &feature, &flags);
        if (r < 0)
                return r;

        if (isempty(feature))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Feature must be specified");

        if (flags != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Flags must be 0");

        r = job_new(JOB_DESCRIBE_FEATURE, t, msg, target_method_describe_finish, &j);
        if (r < 0)
                return r;

        j->feature = strdup(feature);
        if (!j->feature)
                return log_oom();

        r = job_start(j);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to start job: %m");
        TAKE_PTR(j); /* Avoid job from being killed & freed */

        return 1;
}

static bool feature_name_is_valid(const char *name) {
        if (isempty(name))
                return false;

        if (!ascii_is_valid(name))
                return false;

        if (!filename_is_valid(strjoina(name, ".feature.d")))
                return false;

        return true;
}

static int target_method_set_feature_enabled(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *feature_ext = NULL;
        Target *t = ASSERT_PTR(userdata);
        const char *feature;
        uint64_t flags;
        int32_t enabled;
        int r;

        assert(msg);

        if (t->class != TARGET_HOST)
                return sd_bus_reply_method_errorf(msg,
                                                  SD_BUS_ERROR_NOT_SUPPORTED,
                                                  "For now, features can only be managed on the host system.");

        r = sd_bus_message_read(msg, "sit", &feature, &enabled, &flags);
        if (r < 0)
                return r;
        if (!feature_name_is_valid(feature))
                return sd_bus_reply_method_errorf(msg,
                                                  SD_BUS_ERROR_INVALID_ARGS,
                                                  "The specified feature is invalid");
        if (flags != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Flags must be 0");

        if (!endswith(feature, ".feature")) {
                feature_ext = strjoin(feature, ".feature");
                if (!feature_ext)
                        return -ENOMEM;
                feature = feature_ext;
        }

        const char *details[] = {
                "class", target_class_to_string(t->class),
                "name", t->name,
                "feature", feature,
                "enabled", enabled >= 0 ? true_false(enabled) : "unset",
                NULL
        };

        r = bus_verify_polkit_async(
                msg,
                "org.freedesktop.sysupdate1.manage-features",
                details,
                &t->manager->polkit_registry,
                error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        /* We assume that no sysadmin will name their config 50-systemd-sysupdate-enabled.conf */
        if (enabled < 0) { /* Reset -> delete the drop-in file */
                _cleanup_free_ char *path = NULL;

                r = drop_in_file(SYSCONF_DIR "/sysupdate.d", feature, 50, FEATURES_DROPIN_NAME, NULL, &path);
                if (r < 0)
                        return r;

                if (unlink(path) < 0)
                        return -errno;
        } else { /* otherwise, create the drop-in with the right settings */
                r = write_drop_in_format(SYSCONF_DIR "/sysupdate.d", feature, 50, FEATURES_DROPIN_NAME,
                                         "# Generated via org.freedesktop.sysupdate1 D-Bus interface\n\n"
                                         "[Feature]\n"
                                         "Enabled=%s\n",
                                         yes_no(enabled));
                if (r < 0)
                        return r;
        }

        return sd_bus_reply_method_return(msg, NULL);
}

static int target_list_components(Target *t, char ***ret_components, bool *ret_have_default) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        _cleanup_strv_free_ char **components = NULL;
        sd_json_variant *v;
        bool have_default;
        int r;

        r = sysupdate_run_simple(&json, t, "components", NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to run 'systemd-sysupdate components': %m");

        v = sd_json_variant_by_key(json, "default");
        if (!v)
                return log_sysupdate_bad_json_debug(SYNTHETIC_ERRNO(EPROTO), "components", "Missing key 'default'");
        have_default = sd_json_variant_boolean(v);

        v = sd_json_variant_by_key(json, "components");
        if (!v)
                return log_sysupdate_bad_json_debug(SYNTHETIC_ERRNO(EPROTO), "components", "Missing key 'components'");
        r = sd_json_variant_strv(v, &components);
        if (r < 0)
                return log_sysupdate_bad_json_debug(SYNTHETIC_ERRNO(EPROTO), "components", "Key 'components' should be a strv");

        if (ret_components)
                *ret_components = TAKE_PTR(components);
        if (ret_have_default)
                *ret_have_default = have_default;
        return 0;
}

static int manager_ensure_targets(Manager *m);

static int target_object_find(
                sd_bus *bus,
                const char *path,
                const char *iface,
                void *userdata,
                void **found,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Target *t;
        _cleanup_free_ char *e = NULL;
        const char *p;
        int r;

        assert(bus);
        assert(path);
        assert(found);

        p = startswith(path, "/org/freedesktop/sysupdate1/target/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        r = manager_ensure_targets(m);
        if (r < 0)
                return r;

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
        unsigned k = 0;
        int r;

        r = manager_ensure_targets(m);
        if (r < 0)
                return r;

        l = new0(char*, hashmap_size(m->targets) + 1);
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

        SD_BUS_PROPERTY("Class", "s", target_property_get_class,
                        offsetof(Target, class), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Name", "s", NULL, offsetof(Target, name),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Path", "s", NULL, offsetof(Target, path),
                        SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD_WITH_ARGS("List",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_RESULT("as", versions),
                                target_method_list,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("Describe",
                                SD_BUS_ARGS("s", version, "t", flags),
                                SD_BUS_RESULT("s", json),
                                target_method_describe,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("CheckNew",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", new_version),
                                target_method_check_new,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("Update",
                                SD_BUS_ARGS("s", new_version, "t", flags),
                                SD_BUS_RESULT("s", new_version, "t", job_id, "o", job_path),
                                target_method_update,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("Vacuum",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("u", instances, "u", disabled_transfers),
                                target_method_vacuum,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("GetAppStream",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("as", appstream),
                                target_method_get_appstream,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("GetVersion",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", version),
                                target_method_get_version,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("ListFeatures",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_RESULT("as", features),
                                target_method_list_features,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("DescribeFeature",
                                SD_BUS_ARGS("s", feature, "t", flags),
                                SD_BUS_RESULT("s", json),
                                target_method_describe_feature,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("SetFeatureEnabled",
                                SD_BUS_ARGS("s", feature, "i", enabled, "t", flags),
                                SD_BUS_NO_RESULT,
                                target_method_set_feature_enabled,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

static const BusObjectImplementation target_object = {
        "/org/freedesktop/sysupdate1/target",
        "org.freedesktop.sysupdate1.Target",
        .fallback_vtables = BUS_FALLBACK_VTABLES({target_vtable, target_object_find}),
        .node_enumerator = target_node_enumerator,
};

static Manager *manager_free(Manager *m) {
        if (!m)
                return NULL;

        hashmap_free(m->targets);
        hashmap_free(m->jobs);

        m->bus = sd_bus_flush_close_unref(m->bus);
        free(m->notify_socket_path);
        sd_event_unref(m->event);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager *, manager_free);

static int manager_on_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        _cleanup_(pidref_done) PidRef sender_pidref = PIDREF_NULL;
        _cleanup_free_ char *buf = NULL;
        r = notify_recv(fd, &buf, /* ret_ucred= */ NULL, &sender_pidref);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        Job *j;
        HASHMAP_FOREACH(j, m->jobs) {
                PidRef child_pidref = PIDREF_NULL;

                r = event_source_get_child_pidref(j->child, &child_pidref);
                if (r < 0)
                        return log_warning_errno(r, "Failed to get child pidref: %m");

                if (pidref_equal(&sender_pidref, &child_pidref))
                        break;
        }
        if (!j) {
                log_warning("Got notification datagram from unexpected peer, ignoring.");
                return 0;
        }

        char *version = find_line_startswith(buf, "X_SYSUPDATE_VERSION=");
        char *progress = find_line_startswith(buf, "X_SYSUPDATE_PROGRESS=");
        char *errno_str = find_line_startswith(buf, "ERRNO=");
        const char *ready = find_line_startswith(buf, "READY=1");

        if (version)
                job_on_version(j, truncate_nl(version));

        if (progress)
                job_on_progress(j, truncate_nl(progress));

        if (errno_str)
                job_on_errno(j, truncate_nl(errno_str));

        /* Should come last, since this might actually detach the job */
        if (ready)
                job_on_ready(j);

        return 0;
}

static int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
        };

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, (SIGRTMIN+18) | SD_EVENT_SIGNAL_PROCMASK,
                                sigrtmin18_handler, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to allocate memory pressure event source, ignoring: %m");

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return r;

        r = notify_socket_prepare(
                        m->event,
                        SD_EVENT_PRIORITY_NORMAL - 1, /* Make this processed before SIGCHLD. */
                        manager_on_notify,
                        m,
                        &m->notify_socket_path);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int manager_enumerate_image_class(Manager *m, TargetClass class) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        Image *image;
        int r;

        r = image_discover(m->runtime_scope, (ImageClass) class, NULL, &images);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images) {
                _cleanup_(target_freep) Target *t = NULL;
                bool have = false;

                if (image_is_host(image))
                        continue; /* We already enroll the host ourselves */

                r = target_new(m, class, image->name, image->path, &t);
                if (r < 0)
                        return r;
                t->image_type = image->type;

                r = target_list_components(t, NULL, &have);
                if (r < 0)
                        return r;
                if (!have) {
                        log_debug("Skipping %s because it has no default component", image->path);
                        continue;
                }

                r = hashmap_ensure_put(&m->targets, &target_hash_ops, t->id, t);
                if (r < 0)
                        return r;
                TAKE_PTR(t);
        }

        return 0;
}

static int manager_enumerate_components(Manager *m) {
        _cleanup_strv_free_ char **components = NULL;
        bool have_default;
        int r;

        r = target_list_components(NULL, &components, &have_default);
        if (r < 0)
                return r;

        if (have_default) {
                _cleanup_(target_freep) Target *t = NULL;

                r = target_new(m, TARGET_HOST, "host", "sysupdate.d", &t);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&m->targets, &target_hash_ops, t->id, t);
                if (r < 0)
                        return r;
                TAKE_PTR(t);
        }

        STRV_FOREACH(component, components) {
                _cleanup_free_ char *path = NULL;
                _cleanup_(target_freep) Target *t = NULL;

                path = strjoin("sysupdate.", *component, ".d");
                if (!path)
                        return -ENOMEM;

                r = target_new(m, TARGET_COMPONENT, *component, path, &t);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&m->targets, &target_hash_ops, t->id, t);
                if (r < 0)
                        return r;
                TAKE_PTR(t);
        }

        return 0;
}

static int manager_enumerate_targets(Manager *m) {
        static const TargetClass discoverable_classes[] = {
                TARGET_MACHINE,
                TARGET_PORTABLE,
                TARGET_SYSEXT,
                TARGET_CONFEXT,
        };
        int r;

        assert(m);

        FOREACH_ARRAY(class, discoverable_classes, ELEMENTSOF(discoverable_classes)) {
                r = manager_enumerate_image_class(m, *class);
                if (r < 0)
                        log_warning_errno(r, "Failed to enumerate %ss, ignoring: %m",
                                          target_class_to_string(*class));
        }

        r = manager_enumerate_components(m);
        if (r < 0)
                log_warning_errno(r, "Failed to enumerate components, ignoring: %m");

        return 0;
}

static int manager_ensure_targets(Manager *m) {
        assert(m);

        if (!hashmap_isempty(m->targets))
                return 0;

        return manager_enumerate_targets(m);
}

static int method_list_targets(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Target *t;
        int r;

        assert(msg);

        r = manager_ensure_targets(m);
        if (r < 0)
                return r;

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
                        return -ENOMEM;

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

        return sd_bus_message_send(reply);
}

static int method_list_jobs(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Job *j;
        int r;

        assert(msg);

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(tsuo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(j, m->jobs) {
                r = sd_bus_message_append(reply, "(tsuo)",
                                          j->id,
                                          job_type_to_string(j->type),
                                          j->progress_percent,
                                          j->object_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_appstream(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_strv_free_ char **urls = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Target *t;
        int r;

        assert(msg);

        r = manager_ensure_targets(m);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(t, m->targets) {
                char **target_appstream;

                r = target_get_appstream(t, &target_appstream);
                if (r < 0)
                        return r;

                r = strv_extend_strv_consume(&urls, target_appstream, /* filter_duplicates = */ true);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, urls);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD_WITH_ARGS("ListTargets",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(sso)", targets),
                                method_list_targets,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("ListJobs",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(tsuo)", jobs),
                                method_list_jobs,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_METHOD_WITH_ARGS("ListAppStream",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("as", urls),
                                method_list_appstream,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_ARGS("JobRemoved",
                                SD_BUS_ARGS("t", id, "o", path, "i", status),
                                0),

        SD_BUS_VTABLE_END
};

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/sysupdate1",
        "org.freedesktop.sysupdate1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS(&job_object, &target_object),
};

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
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static bool manager_is_idle(void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

	return hashmap_isempty(m->jobs);
}

static void manager_check_idle(Manager *m) {
	assert(m);

	if (!hashmap_isempty(m->jobs))
		return;

        hashmap_clear(m->targets);
        log_debug("Cleared target cache");
}

static int manager_run(Manager *m) {
        assert(m);

        return bus_event_loop_with_idle(m->event,
                                        m->bus,
                                        "org.freedesktop.sysupdate1",
                                        DEFAULT_EXIT_USEC,
                                        manager_is_idle,
                                        m);
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
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

        /* SIGCHLD signal must be blocked for sd_event_add_child to work */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        r = manager_add_bus_objects(m);
        if (r < 0)
                return log_error_errno(r, "Failed to add bus objects: %m");

        r = manager_run(m);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

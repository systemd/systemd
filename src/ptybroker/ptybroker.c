/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <paths.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "env-util.h"
#include "escape.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pidref.h"
#include "ptybroker.h"                       /* IWYU pragma: keep */
#include "ptybroker-monitor.h"
#include "ptybroker-pty.h"
#include "runtime-scope.h"
#include "service-util.h"
#include "set.h"
#include "special.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "user-util.h"
#include "varlink-io.systemd.PTYBroker.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

COMMAND(
        "systemd-ptybrokerd\0",
        "Broker access to pseudo terminals",
        .man_pages = "systemd-ptybrokerd.service(8)\0",
        .option_namespace = "service",
        .option_groups =
                "Options\0"
                "Runtime scope\0");

#define PSEUDO_TTY_MAX 1024U
#define MONITOR_MAX 16U
#define UNIT_REFERENCE_MAX 1024U

struct UnitReference {
        Manager *manager;
        char *unit;
        PseudoTTY *pty;
        sd_bus_slot *slot;
        sd_event_source *event_source;
        bool acquired;
};

static void manager_schedule_idle_check(Manager *m);
static int manager_connect_bus(Manager *m);
static int manager_schedule_bus_retry(Manager *m);
static int unit_reference_acquire(UnitReference *ref);
static int invoke_start_shell(PseudoTTY *pty);

static int on_unit_unref_reply(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        const sd_bus_error *error = sd_bus_message_get_error(message);

        if (!error)
                return 0;

        /* A cancelled Ref() or a disconnected manager may already have dropped the reference. */
        if (sd_bus_error_has_name(error, BUS_ERROR_NOT_REFERENCED) ||
            sd_bus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT) ||
            bus_error_is_connection(error) ||
            bus_error_is_unknown_service(error))
                log_debug("Unit reference already gone: %s", error->message);
        else
                log_warning("Failed to release unit reference: %s", error->message);

        return 0;
}

UnitReference* unit_reference_free(UnitReference *ref) {
        int r;

        if (!ref)
                return NULL;

        if (ref->pty) {
                assert(ref->pty->unit_reference == ref);
                ref->pty->unit_reference = NULL;
        }

        if (ref->manager) {
                set_remove(ref->manager->unit_references, ref);

                /* Also undo an in-flight Ref(): both calls use the same connection and stay ordered. */
                if (ref->manager->bus && (ref->acquired || ref->slot)) {
                        r = bus_call_method_async(
                                        ref->manager->bus,
                                        /* ret_slot= */ NULL,
                                        bus_systemd_mgr,
                                        "UnrefUnit",
                                        on_unit_unref_reply,
                                        /* userdata= */ NULL,
                                        "s", ref->unit);
                        if (r < 0)
                                log_warning_errno(r, "Failed to enqueue release of unit reference for '%s': %m", ref->unit);
                }
        }

        sd_bus_slot_unref(ref->slot);
        sd_event_source_disable_unref(ref->event_source);
        free(ref->unit);
        return mfree(ref);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitReference*, unit_reference_free);

static void unit_reference_fail(UnitReference *ref, int error) {
        Manager *m = ASSERT_PTR(ref->manager);

        assert(error < 0);

        if (ref->pty) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
                int r;

                r = sd_json_buildo(
                                &parameters,
                                SD_JSON_BUILD_PAIR_STRING("origin", "linux"),
                                SD_JSON_BUILD_PAIR_INTEGER("errno", -error));
                if (r < 0) {
                        log_oom();
                        pseudo_tty_fail_acquire(ref->pty, /* error_id= */ NULL, /* parameters= */ NULL);
                } else
                        pseudo_tty_fail_acquire(ref->pty, SD_VARLINK_ERROR_SYSTEM, parameters);

                pseudo_tty_add_to_free_queue(ref->pty);
        }

        unit_reference_free(ref);
        manager_schedule_idle_check(m);
}

static void manager_disconnect_bus(Manager *m) {
        assert(m);

        UnitReference *ref;
        SET_FOREACH(ref, m->unit_references) {
                ref->slot = sd_bus_slot_unref(ref->slot);
                ref->acquired = false;
        }

        m->bus_disconnected_slot = sd_bus_slot_unref(m->bus_disconnected_slot);
        if (m->bus)
                (void) sd_bus_detach_event(m->bus);
        m->bus = sd_bus_close_unref(m->bus);
}

static int on_bus_retry(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        m->bus_retry_event_source = sd_event_source_disable_unref(m->bus_retry_event_source);
        if (set_isempty(m->unit_references))
                return 0;

        r = manager_connect_bus(m);
        if (r < 0) {
                log_warning_errno(r, "Failed to reconnect to bus, retrying: %m");
                return manager_schedule_bus_retry(m);
        }

        UnitReference *ref;
        SET_FOREACH(ref, m->unit_references) {
                if (ref->acquired || ref->slot)
                        continue;

                r = unit_reference_acquire(ref);
                if (r < 0) {
                        log_warning_errno(r, "Failed to request reference for unit '%s': %m", ref->unit);
                        unit_reference_fail(ref, r);
                }
        }

        return 0;
}

static int manager_schedule_bus_retry(Manager *m) {
        int r;

        assert(m);

        r = event_reset_time_relative(
                        m->event,
                        &m->bus_retry_event_source,
                        CLOCK_MONOTONIC,
                        USEC_PER_SEC, /* accuracy= */ 0,
                        on_bus_retry, m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "bus-retry",
                        /* force_reset= */ false);
        if (r < 0) {
                (void) sd_event_exit(m->event, EXIT_FAILURE);
                return log_error_errno(r, "Failed to schedule bus reconnection: %m");
        }

        return 0;
}

static int on_bus_disconnected(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);

        log_debug("Disconnected from bus, reconnecting to restore unit references.");
        manager_disconnect_bus(m);
        return manager_schedule_bus_retry(m);
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);

        if (m->bus)
                return 0;

        if (m->scope == RUNTIME_SCOPE_SYSTEM)
                r = sd_bus_open_system(&m->bus);
        else
                r = sd_bus_open_user(&m->bus);
        if (r < 0)
                return r;

        r = sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                goto fail;

        r = sd_bus_match_signal_async(
                        m->bus,
                        &m->bus_disconnected_slot,
                        "org.freedesktop.DBus.Local",
                        /* path= */ NULL,
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        on_bus_disconnected,
                        /* install_callback= */ NULL,
                        m);
        if (r < 0)
                goto fail;

        return 0;

fail:
        manager_disconnect_bus(m);
        return r;
}

static int on_unit_ref_reply(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        UnitReference *ref = ASSERT_PTR(userdata);
        const sd_bus_error *error = sd_bus_message_get_error(message);
        int r;

        ref->slot = sd_bus_slot_unref(ref->slot);
        if (error) {
                if (bus_error_is_connection(error)) {
                        Manager *m = ref->manager;

                        log_debug("Bus connection lost while referencing unit '%s': %s", ref->unit, error->message);
                        manager_disconnect_bus(m);
                        return manager_schedule_bus_retry(m);
                }
                if (bus_error_is_unknown_service(error)) {
                        log_debug("Service manager unavailable while referencing unit '%s', retrying: %s", ref->unit, error->message);
                        return manager_schedule_bus_retry(ref->manager);
                }

                log_error("Failed to reference unit '%s': %s", ref->unit, error->message);
                unit_reference_fail(ref, -sd_bus_message_get_errno(message));
                return 0;
        }

        ref->acquired = true;
        if (ref->pty) {
                if (!ref->pty->acquire_link || sd_varlink_is_connected(ref->pty->acquire_link) <= 0) {
                        log_debug("Client disconnected before starting shell for unit '%s'.", ref->unit);
                        unit_reference_fail(ref, -ECONNRESET);
                        return 0;
                }

                r = invoke_start_shell(ref->pty);
                if (r < 0) {
                        unit_reference_fail(ref, r);
                        return 0;
                }

                ref->pty->unit_reference = NULL;
                ref->pty = NULL;
        }

        return 0;
}

static int unit_reference_acquire(UnitReference *ref) {
        assert(ref);
        assert(ref->manager);
        assert(ref->manager->bus);
        assert(!ref->slot);
        assert(!ref->acquired);

        if (ref->pty) {
                _cleanup_free_ char *path = unit_dbus_path_from_name(ref->unit);
                if (!path)
                        return -ENOMEM;

                /* Pin the pristine stub before StartTransient(), including for immediately exiting shells. */
                return sd_bus_call_method_async(
                                ref->manager->bus,
                                &ref->slot,
                                "org.freedesktop.systemd1",
                                path,
                                "org.freedesktop.systemd1.Unit",
                                "Ref",
                                on_unit_ref_reply,
                                ref,
                                /* types= */ NULL);
        }

        /* After reconnection, require the existing unit rather than pinning a fresh stub whose exit status
         * has already been lost. RefUnit() validates that the unit is loaded, unlike Unit.Ref(). */
        return bus_call_method_async(
                        ref->manager->bus,
                        &ref->slot,
                        bus_systemd_mgr,
                        "RefUnit",
                        on_unit_ref_reply,
                        ref,
                        "s", ref->unit);
}

static int on_unit_reference_closed(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        UnitReference *ref = ASSERT_PTR(userdata);
        Manager *m = ref->manager;

        assert(s);
        assert(fd >= 0);

        if (ref->pty) {
                unit_reference_fail(ref, -ECONNRESET);
                return 0;
        }

        unit_reference_free(ref);
        manager_schedule_idle_check(m);
        return 0;
}

static int acquire_unit_reference(Manager *m, PseudoTTY *pty, int *ret_fd) {
        _cleanup_(unit_reference_freep) UnitReference *ref = NULL;
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        int r;

        assert(m);
        assert(pty);
        assert(pty->unit);
        assert(!pty->unit_reference);
        assert(ret_fd);

        ref = new0(UnitReference, 1);
        if (!ref)
                return log_oom();

        ref->unit = strdup(pty->unit);
        if (!ref->unit)
                return log_oom();

        if (pipe2(pipe_fds, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate unit reference pipe: %m");

        r = sd_event_add_io(m->event, &ref->event_source, pipe_fds[0], EPOLLHUP, on_unit_reference_closed, ref);
        if (r < 0)
                return log_error_errno(r, "Failed to watch unit reference pipe: %m");

        r = sd_event_source_set_io_fd_own(ref->event_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to take ownership of unit reference pipe: %m");
        TAKE_FD(pipe_fds[0]);

        r = set_ensure_put(&m->unit_references, &trivial_hash_ops, ref);
        if (r < 0)
                return log_error_errno(r, "Failed to register unit reference: %m");
        ref->manager = m;
        ref->pty = pty;
        pty->unit_reference = ref;

        r = manager_connect_bus(m);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bus to reference shell unit: %m");

        r = unit_reference_acquire(ref);
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue reference request for unit '%s': %m", ref->unit);

        *ret_fd = TAKE_FD(pipe_fds[1]);
        TAKE_PTR(ref);
        return 0;
}

static Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        hashmap_free(m->ptys);
        assert(!m->ptys_free_queue);

        UnitReference *ref;
        while ((ref = set_first(m->unit_references)))
                unit_reference_free(ref);
        m->unit_references = set_free(m->unit_references);

        manager_disconnect_bus(m);
        sd_event_source_disable_unref(m->bus_retry_event_source);

        sd_varlink_server_unref(m->varlink_server);
        hashmap_free(m->polkit_registry);

        sd_event_source_disable_unref(m->ptys_free_queue_event_source);
        sd_event_source_disable_unref(m->exit_on_idle_event_source);
        sd_event_unref(m->event);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

static int invoke_start_shell(PseudoTTY *pty) {
        int r;

        assert(pty);
        assert(pty->start_shell_link);
        assert(pty->start_shell_parameters);

        r = sd_varlink_invoke(pty->start_shell_link, "io.systemd.Unit.StartTransient", pty->start_shell_parameters);
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue io.systemd.Unit.StartTransient() call: %m");

        pty->start_shell_parameters = sd_json_variant_unref(pty->start_shell_parameters);
        return 0;
}

static int pseudo_tty_send_acquire_reply(PseudoTTY *pty) {
        int r;

        assert(pty);

        /* Sends the prepared AcquirePty() reply to the client. Called either right away (if no shell needs
         * to be started), or delayed from the StartTransient() reply callback (if one does). On failure the
         * connection is left in place, so that the caller may still fail it properly. */

        if (!pty->acquire_link)
                return 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = TAKE_PTR(pty->acquire_reply);

        if (pty->acquire_monitor)
                r = sd_varlink_respond_and_upgrade(pty->acquire_link, reply);
        else
                r = sd_varlink_reply(pty->acquire_link, reply);
        if (r < 0)
                return r;

        pty->acquire_link = sd_varlink_unref(pty->acquire_link);
        return 0;
}

static int start_shell_reply_callback(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        PseudoTTY *pty = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(link == pty->start_shell_link);

        /* The call is complete, we don't need the connection to the service manager anymore.
         * sd_varlink_process() pins the connection for the duration of this callback, hence dropping our
         * reference here is safe. */
        pty->start_shell_link = sd_varlink_close_unref(pty->start_shell_link);

        if (error_id) {
                log_error_errno(sd_varlink_error_to_errno(error_id, parameters),
                                "io.systemd.Unit.StartTransient failed for PTY '%s': %s", strna(pty->name), error_id);

                /* Propagate the failure to the client still waiting for the AcquirePty() reply */
                pseudo_tty_fail_acquire(pty, error_id, parameters);

                /* No shell will ever show up on the backend, hence dispose of the PTY */
                pseudo_tty_add_to_free_queue(pty);
                return 0;
        }

        log_debug("Transient unit '%s' for PTY '%s' started.", strna(pty->unit), strna(pty->name));

        r = pseudo_tty_send_acquire_reply(pty);
        if (r < 0) {
                log_warning_errno(r, "Failed to send AcquirePty() reply to client, disposing of PTY: %m");

                /* We couldn't answer the client, hence nobody will ever service this connection anymore,
                 * close it. And since the client will never learn of the PTY, dispose of it (and the shell we
                 * just started on it), too. */
                pty->acquire_link = sd_varlink_close_unref(pty->acquire_link);
                pseudo_tty_add_to_free_queue(pty);
        }

        return 0;
}

static int make_shell_unit_name(const char *name, char **ret) {
        assert(name);
        assert(ret);

        /* The PTY name is client-supplied and may contain characters that are not valid in unit names, hence
         * escape it. */
        _cleanup_free_ char *escaped = unit_name_escape(name);
        if (!escaped)
                return -ENOMEM;

        _cleanup_free_ char *unit = strjoin("shell-", escaped, ".service");
        if (!unit)
                return -ENOMEM;

        /* Escaping can expand each character fourfold, hence the result may exceed the unit name length
         * limit even though the PTY name itself passed validation. */
        if (!unit_name_is_valid(unit, UNIT_NAME_PLAIN))
                return -EINVAL;

        *ret = TAKE_PTR(unit);
        return 0;
}

typedef struct WorkingDirectory {
        const char *path;
        bool home;
        bool missing_ok;
} WorkingDirectory;

static bool working_directory_is_set(const WorkingDirectory *wd) {
        assert(wd);
        return wd->path || wd->home;
}

static int start_shell(
                Manager *m,
                PseudoTTY *pty,
                const char *user,
                const char *group,
                const WorkingDirectory *working_directory,
                char **environment,
                char **command_line,
                const char *executable,
                bool via_shell,
                int lightweight,
                bool reference_unit,
                int *ret_unit_reference_fd) {

        int r;

        assert(m);
        assert(pty);
        assert(working_directory);
        assert(pty->backend_fd >= 0);
        assert(pty->backend_path);
        assert(!pty->unit);
        assert(!pty->start_shell_link);
        assert(ret_unit_reference_fd);

        const char *d;
        _cleanup_free_ char *description = NULL;
        if (user) {
                description = strjoin("Shell of '", user, "'");
                if (!description)
                        return log_oom();

                d = description;
        } else
                d = "Shell";

        _cleanup_free_ char *unit = NULL;
        r = make_shell_unit_name(pty->name, &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate shell unit name from PTY name '%s': %m", pty->name);

        _cleanup_strv_free_ char **patched_environment = strv_copy(environment);
        if (!patched_environment)
                return log_oom();

        if (!strv_env_get(patched_environment, "XDG_SESSION_CLASS") && lightweight >= 0) {
                bool is_root = STRPTR_IN_SET(user, "root", "0") || (!user && m->scope == RUNTIME_SCOPE_SYSTEM);

                const char *class = lightweight ?
                        (is_root ? "user-early-light" : "user-light") :
                        (is_root ? "user-early" : "user");

                log_debug("Setting XDG_SESSION_CLASS to '%s'.", class);

                r = strv_env_assign(&patched_environment, "XDG_SESSION_CLASS", class);
                if (r < 0)
                        return log_error_errno(r, "Failed to set $XDG_SESSION_CLASS environment variable: %m");
        }

        /* Propagate the (settled) terminal settings to the shell, unless the client explicitly set the
         * variables otherwise */
        const TerminalSettings *ts = &pty->terminal_settings;
        if (ts->env_term && !strv_env_get(patched_environment, "TERM")) {
                r = strv_env_assign(&patched_environment, "TERM", ts->env_term);
                if (r < 0)
                        return log_error_errno(r, "Failed to set $TERM environment variable: %m");
        }
        if (ts->env_colorterm && !strv_env_get(patched_environment, "COLORTERM")) {
                r = strv_env_assign(&patched_environment, "COLORTERM", ts->env_colorterm);
                if (r < 0)
                        return log_error_errno(r, "Failed to set $COLORTERM environment variable: %m");
        }
        if (ts->env_no_color > 0 && !strv_env_get(patched_environment, "NO_COLOR")) {
                r = strv_env_assign(&patched_environment, "NO_COLOR", "1");
                if (r < 0)
                        return log_error_errno(r, "Failed to set $NO_COLOR environment variable: %m");
        }

        environment = patched_environment;

        /* Compose the ExecStart command. By default we go via the target user's native shell (the
         * equivalent of ExecStart=|): as an interactive login shell if no command line was specified,
         * otherwise running the specified command line through 'sh -c'. Only if the client explicitly opted
         * out of shell invocation the command line is executed directly, optionally with a binary path
         * that differs from argv[0]. */
        _cleanup_strv_free_ char **argv = NULL;
        const char *path;
        if (via_shell) {
                path = _PATH_BSHELL; /* Placeholder only — the service manager substitutes the target user's actual shell */

                argv = strv_new(strv_isempty(command_line) ? "-sh" : "sh");
                if (!argv)
                        return log_oom();

                r = strv_extend_strv(&argv, command_line, /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        } else {
                assert(!strv_isempty(command_line));

                path = executable ?: command_line[0];

                argv = strv_copy(command_line);
                if (!argv)
                        return log_oom();
        }

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(m->scope, "systemd/io.systemd.Manager", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine service manager socket path: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to service manager Varlink socket: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing to Varlink socket: %m");

        int fd_stdin_idx = sd_varlink_push_dup_fd(vl, pty->backend_fd);
        if (fd_stdin_idx < 0)
                return log_error_errno(fd_stdin_idx, "Failed to push file descriptor into Varlink connection: %m");

        int fd_stdout_idx = sd_varlink_push_dup_fd(vl, pty->backend_fd);
        if (fd_stdout_idx < 0)
                return log_error_errno(fd_stdout_idx, "Failed to push file descriptor into Varlink connection: %m");

        int fd_stderr_idx = sd_varlink_push_fd(vl, pty->backend_fd);
        if (fd_stderr_idx < 0)
                return log_error_errno(fd_stderr_idx, "Failed to push file descriptor into Varlink connection: %m");

        TAKE_FD(pty->backend_fd);

        r = sd_varlink_attach_event(vl, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink connection to event loop: %m");

        sd_varlink_set_userdata(vl, pty);

        r = sd_varlink_bind_reply(vl, start_shell_reply_callback);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback: %m");

        r = sd_json_buildo(
                        &pty->start_shell_parameters,
                        SD_JSON_BUILD_PAIR("context", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("ID", unit),
                                        SD_JSON_BUILD_PAIR_STRING("Description", d),
                                        SD_JSON_BUILD_PAIR_STRING("CollectMode", "inactive_or_failed"),
                                        SD_JSON_BUILD_PAIR("Kill", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGHUP", true))),
                                        /* Shells are user workloads, hence place them in user.slice (only
                                         * on the system manager, the per-user manager has no such slice) */
                                        SD_JSON_BUILD_PAIR_CONDITION(m->scope == RUNTIME_SCOPE_SYSTEM, "CGroup", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_STRING("Slice", SPECIAL_USER_SLICE))),
                                        SD_JSON_BUILD_PAIR("Service", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_STRING("Type", "exec"),
                                                                           SD_JSON_BUILD_PAIR_INTEGER("StandardInputFileDescriptor", fd_stdin_idx),
                                                                           SD_JSON_BUILD_PAIR_INTEGER("StandardOutputFileDescriptor", fd_stdout_idx),
                                                                           SD_JSON_BUILD_PAIR_INTEGER("StandardErrorFileDescriptor", fd_stderr_idx),
                                                                           SD_JSON_BUILD_PAIR("ExecStart", SD_JSON_BUILD_ARRAY(
                                                                                                              SD_JSON_BUILD_OBJECT(
                                                                                                                              SD_JSON_BUILD_PAIR_STRING("path", path),
                                                                                                                              SD_JSON_BUILD_PAIR_STRV("arguments", argv),
                                                                                                                              SD_JSON_BUILD_PAIR_BOOLEAN("viaShell", via_shell),
                                                                                                                              /* Don't let the service manager expand $VARIABLES via
                                                                                                                               * the client-supplied environment: what we execute
                                                                                                                               * must be exactly what polkit authorized. */
                                                                                                                              SD_JSON_BUILD_PAIR_BOOLEAN("noEnvExpand", true)))))),
                                        SD_JSON_BUILD_PAIR("Exec", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_STRING("TTYPath", pty->backend_path),
                                                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("User", user),
                                                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("Group", group),
                                                                           /* Open a PAM session for the shell, the same way run0 does it,
                                                                            * but via our own PAM stack. Only on the system manager, the
                                                                            * per-user manager lacks the privileges for that. */
                                                                           SD_JSON_BUILD_PAIR_CONDITION(m->scope == RUNTIME_SCOPE_SYSTEM, "PAMName", SD_JSON_BUILD_STRING("systemd-ptybroker-shell")),
                                                                           SD_JSON_BUILD_PAIR_CONDITION(working_directory_is_set(working_directory), "WorkingDirectory",
                                                                                                        SD_JSON_BUILD_OBJECT(
                                                                                                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("path", working_directory->path),
                                                                                                                        SD_JSON_BUILD_PAIR_CONDITION(working_directory->home, "home", SD_JSON_BUILD_BOOLEAN(true)),
                                                                                                                        SD_JSON_BUILD_PAIR_CONDITION(working_directory->missing_ok, "missingOK", SD_JSON_BUILD_BOOLEAN(true)))),
                                                                           JSON_BUILD_PAIR_STRV_NON_EMPTY("Environment", environment),
                                                                           SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreSIGPIPE", false))))),
                        SD_JSON_BUILD_PAIR_STRING("mode", "replace"));
        if (r < 0)
                return log_error_errno(r, "Failed to build io.systemd.Unit.StartTransient() parameters: %m");

        pty->start_shell_link = TAKE_PTR(vl);
        pty->unit = TAKE_PTR(unit);

        _cleanup_close_ int unit_reference_fd = -EBADF;
        if (reference_unit)
                r = acquire_unit_reference(m, pty, &unit_reference_fd);
        else
                r = invoke_start_shell(pty);
        if (r < 0)
                return r;

        *ret_unit_reference_fd = TAKE_FD(unit_reference_fd);

        return 0;
}

typedef struct AcquirePtyParameters {
        FrontendType frontend_type;
        BackendType backend_type;
        char *name;
        char *description;
        char *tag;
        const char *user;
        const char *group;
        WorkingDirectory working_directory;
        char **environment;
        char **command_line;
        const char *executable;
        int via_shell;
        int lightweight;
        bool monitor;
        bool hang_up_on_disconnect;
        bool ignore_hangup;
        bool osc2811;
        bool reference_unit;
        sd_json_variant *terminal_settings; /* no reference */
} AcquirePtyParameters;

static void acquire_pty_parameters_done(AcquirePtyParameters *p) {
        assert(p);

        free(p->name);
        free(p->description);
        free(p->tag);
        strv_free(p->environment);
        strv_free(p->command_line);
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_frontend_type, FrontendType, frontend_type_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_backend_type, BackendType, backend_type_from_string);

static int dispatch_working_directory(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        WorkingDirectory *wd = ASSERT_PTR(userdata);
        int r;

        /* Mirrors the WorkingDirectory structure of io.systemd.Unit.StartTransient() */
        static const sd_json_dispatch_field dispatch_table[] = {
                { "path",      SD_JSON_VARIANT_STRING,  json_dispatch_const_path, offsetof(WorkingDirectory, path),       0 },
                { "home",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(WorkingDirectory, home),       0 },
                { "missingOK", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(WorkingDirectory, missing_ok), 0 },
                {}
        };

        if (sd_json_variant_is_null(variant)) {
                *wd = (WorkingDirectory) {};
                return 0;
        }

        WorkingDirectory t = {};
        r = sd_json_dispatch(variant, dispatch_table, flags, &t);
        if (r < 0)
                return r;

        if (!!t.path == t.home)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "JSON field '%s' must specify exactly one of 'path' or 'home'.", strna(name));

        *wd = t;
        return 0;
}

static const char* polkit_action_from_backend_type(BackendType type) {

        switch (type) {

        case BACKEND_SHELL:
                return "io.systemd.PTYBroker.acquire-pty-with-shell";

        default:
                return "io.systemd.PTYBroker.acquire-pty";
        }
}

static int vl_method_acquire_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        _cleanup_(acquire_pty_parameters_done) AcquirePtyParameters p = {
                .frontend_type = _FRONTEND_TYPE_INVALID,
                .backend_type = _BACKEND_TYPE_INVALID,
                .via_shell = -1,
                .lightweight = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "frontendType",       _SD_JSON_VARIANT_TYPE_INVALID, dispatch_frontend_type,              voffsetof(p, frontend_type),         SD_JSON_MANDATORY },
                { "backendType",        _SD_JSON_VARIANT_TYPE_INVALID, dispatch_backend_type,               voffsetof(p, backend_type),          SD_JSON_MANDATORY },
                { "name",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, name),                  0                 },
                { "description",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, description),           0                 },
                { "tag",                SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, tag),                   0                 },
                { "user",               SD_JSON_VARIANT_STRING,        json_dispatch_const_user_group_name, voffsetof(p, user),                  0                 },
                { "group",              SD_JSON_VARIANT_STRING,        json_dispatch_const_user_group_name, voffsetof(p, group),                 0                 },
                { "workingDirectory",   SD_JSON_VARIANT_OBJECT,        dispatch_working_directory,          voffsetof(p, working_directory),     0                 },
                { "environment",        _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_strv_environment,      voffsetof(p, environment),           0                 },
                { "commandLine",        SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,               voffsetof(p, command_line),          0                 },
                { "executable",         SD_JSON_VARIANT_STRING,        json_dispatch_const_path,            voffsetof(p, executable),            0                 },
                { "viaShell",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,           voffsetof(p, via_shell),             0                 },
                { "lightweight",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,           voffsetof(p, lightweight),           0                 },
                { "monitor",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, monitor),               0                 },
                { "hangUpOnDisconnect", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, hang_up_on_disconnect), 0                 },
                { "ignoreHangup",       SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, ignore_hangup),         0                 },
                { "osc2811",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, osc2811),               0                 },
                { "referenceUnit",      SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, reference_unit),        0                 },
                { "terminalSettings",   SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref,      voffsetof(p, terminal_settings),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* Validate all parameters before we hand any of them to polkit as details: they end up in the
         * authentication prompt a human is supposed to make a decision on, hence must be well-formed. */

        if (p.name) {
                if (!pseudo_tty_name_valid(p.name))
                        return sd_varlink_error_invalid_parameter_name(link, "name");

                /* For the shell backend the name is embedded (in escaped form) in the transient unit's name,
                 * hence also verify early that the result stays within the unit name length limit, so that
                 * the client gets a clean error rather than whatever the service manager returns later. */
                if (p.backend_type == BACKEND_SHELL) {
                        _cleanup_free_ char *unit = NULL;
                        r = make_shell_unit_name(p.name, &unit);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return sd_varlink_error_invalid_parameter_name(link, "name");
                }
        }

        if (p.description && !pseudo_tty_description_valid(p.description))
                return sd_varlink_error_invalid_parameter_name(link, "description");

        if (p.tag && !pseudo_tty_tag_valid(p.tag))
                return sd_varlink_error_invalid_parameter_name(link, "tag");

        if (p.monitor) {
                if (p.frontend_type == FRONTEND_TAKE)
                        return sd_varlink_error_invalid_parameter_name(link, "monitor");
                if (!FLAGS_SET(flags, SD_VARLINK_METHOD_UPGRADE))
                        return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_UPGRADE, NULL);
        }

        if (p.osc2811 && !p.monitor)
                return sd_varlink_error_invalid_parameter_name(link, "osc2811");

        /* If backend hangups are ignored, the monitor connection going away is what ends the pty's lifetime */
        if (p.ignore_hangup && (!p.monitor || !p.hang_up_on_disconnect))
                return sd_varlink_error_invalid_parameter_name(link, "ignoreHangup");

        if (p.backend_type != BACKEND_SHELL) {
                if (p.user)
                        return sd_varlink_error_invalid_parameter_name(link, "user");
                if (p.group)
                        return sd_varlink_error_invalid_parameter_name(link, "group");
                if (working_directory_is_set(&p.working_directory))
                        return sd_varlink_error_invalid_parameter_name(link, "workingDirectory");
                if (!strv_isempty(p.environment))
                        return sd_varlink_error_invalid_parameter_name(link, "environment");
                if (!strv_isempty(p.command_line))
                        return sd_varlink_error_invalid_parameter_name(link, "commandLine");
                if (p.executable)
                        return sd_varlink_error_invalid_parameter_name(link, "executable");
                if (p.via_shell >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "viaShell");
                if (p.lightweight >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "lightweight");
                if (p.reference_unit)
                        return sd_varlink_error_invalid_parameter_name(link, "referenceUnit");
        }

        /* Direct invocation without a command line would leave nothing to execute */
        if (p.via_shell == 0 && strv_isempty(p.command_line))
                return sd_varlink_error_invalid_parameter_name(link, "viaShell");

        /* A separate binary path only makes sense if we invoke the command line directly */
        if (p.executable && p.via_shell != 0)
                return sd_varlink_error_invalid_parameter_name(link, "executable");

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        _cleanup_strv_free_ char **details = strv_new(
                        "frontendType", frontend_type_to_string(p.frontend_type),
                        "backendType", backend_type_to_string(p.backend_type));
        if (!details)
                return -ENOMEM;
        if (p.name) {
                r = strv_extend_many(&details, "name", p.name);
                if (r < 0)
                        return r;
        }
        _cleanup_free_ char *our_user = NULL, *joined_command_line = NULL, *escaped_working_directory = NULL, *joined_environment = NULL;
        if (p.backend_type == BACKEND_SHELL) {
                /* For the shell backend always include the user the shell will run as and the command line
                 * it will execute in the polkit details, so that the authentication question can show
                 * them. If no user was specified the shell runs as the service manager's user, i.e. root in
                 * system scope, ourselves in user scope. */
                const char *shell_user = p.user;
                if (!shell_user) {
                        if (m->scope == RUNTIME_SCOPE_SYSTEM)
                                shell_user = "root";
                        else {
                                our_user = getusername_malloc();
                                if (!our_user)
                                        return log_oom();

                                shell_user = our_user;
                        }
                }

                /* The command line is arbitrary client input. Show it exactly the way it is going to be
                 * executed, but make sure that control characters — in particular newlines, which could be
                 * used to forge additional lines in the authentication prompt, and which act as command
                 * separators for 'sh -c' — as well as backslashes are rendered as escape sequences rather
                 * than passed through verbatim. */
                if (strv_isempty(p.command_line))
                        joined_command_line = strdup("(login shell)");
                else if (p.via_shell != 0) {
                        /* When going via the shell, the service manager joins the arguments with spaces and
                         * passes the result to 'sh -c'. Hence show exactly that string, rather than quoting
                         * the individual arguments, which would suggest a different command. */
                        _cleanup_free_ char *j = strv_join(p.command_line, " ");
                        if (!j)
                                return log_oom();

                        joined_command_line = cescape(j);
                } else if (p.executable) {
                        /* If a separate binary is specified, show that rather than argv[0], since that's
                         * what is actually executed. */
                        _cleanup_strv_free_ char **l = strv_new(p.executable);
                        if (!l)
                                return log_oom();

                        r = strv_extend_strv(&l, strv_skip(p.command_line, 1), /* filter_duplicates= */ false);
                        if (r < 0)
                                return log_oom();

                        joined_command_line = quote_command_line(l, SHELL_ESCAPE_EMPTY);
                } else
                        /* For direct invocation quote the arguments the way we'd quote them for a shell (as
                         * the service manager does for its logs, too) */
                        joined_command_line = quote_command_line(p.command_line, SHELL_ESCAPE_EMPTY);
                if (!joined_command_line)
                        return log_oom();

                r = strv_extend_many(&details,
                                     "user", shell_user,
                                     "command_line", joined_command_line);
                if (r < 0)
                        return r;

                if (p.group) {
                        r = strv_extend_many(&details, "group", p.group);
                        if (r < 0)
                                return r;
                }

                /* The working directory and the environment affect what is executed too (think $PATH,
                 * $LD_PRELOAD, $BASH_ENV), hence include them, so that polkit rules can take them into
                 * account. */
                if (working_directory_is_set(&p.working_directory)) {
                        if (p.working_directory.home)
                                r = strv_extend_many(&details, "working_directory_home", "yes");
                        else {
                                escaped_working_directory = cescape(p.working_directory.path);
                                if (!escaped_working_directory)
                                        return log_oom();

                                r = strv_extend_many(&details, "working_directory", escaped_working_directory);
                        }
                        if (r < 0)
                                return r;

                        r = strv_extend_many(&details, "working_directory_missing_ok", yes_no(p.working_directory.missing_ok));
                        if (r < 0)
                                return r;
                }

                if (!strv_isempty(p.environment)) {
                        joined_environment = quote_command_line(p.environment, SHELL_ESCAPE_EMPTY);
                        if (!joined_environment)
                                return log_oom();

                        r = strv_extend_many(&details, "environment", joined_environment);
                        if (r < 0)
                                return r;
                }
        }

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        polkit_action_from_backend_type(p.backend_type),
                        (const char**) details,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        gid_t gid;
        r = sd_varlink_get_peer_gid(link, &gid);
        if (r < 0)
                return r;

        _cleanup_(pidref_done) PidRef peer_pidref = PIDREF_NULL;
        r = varlink_get_peer_pidref(link, &peer_pidref);
        if (r < 0)
                return r;

        /* Also acquire the pidfd inode number, so that the PID remains unambiguous even after the client
         * exited. Might not be available on old kernels, ignore that. */
        (void) pidref_acquire_pidfd_id(&peer_pidref);

        if (p.name) {
                if (hashmap_contains(m->ptys, p.name))
                        return sd_varlink_error(link, "io.systemd.PTYBroker.PtyExists", NULL);
        } else {
                sd_id128_t id;

                r = sd_id128_randomize(&id);
                if (r < 0)
                        return r;

                p.name = strdup(SD_ID128_TO_STRING(id));
                if (!p.name)
                        return log_oom();
        }

        r = terminal_settings_settle(&ts);
        if (r < 0)
                return r;

        if (hashmap_size(m->ptys) >= PSEUDO_TTY_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyPtys", NULL);

        if (p.reference_unit && set_size(m->unit_references) >= UNIT_REFERENCE_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyUnitReferences", NULL);

        _cleanup_(pseudo_tty_freep) PseudoTTY *pty = NULL;
        r = pseudo_tty_new(&pty);
        if (r < 0)
                return r;

        pty->frontend_fd = openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC, &pty->backend_path);
        if (pty->frontend_fd < 0)
                return log_error_errno(pty->frontend_fd, "Failed to allocate PTY: %m");

        pty->backend_fd = pty_open_peer(pty->frontend_fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (pty->backend_fd < 0)
                return log_error_errno(pty->backend_fd, "Failed to open PTY backend: %m");

        pty->pin_fd = fd_reopen(pty->backend_fd, O_PATH|O_CLOEXEC);
        if (pty->pin_fd < 0)
                return log_error_errno(pty->pin_fd, "Failed to open O_PATH fd on backend: %m");

        r = terminal_settings_sync_size_fd(&ts, pty->frontend_fd, pty->backend_path);
        if (r < 0)
                return log_error_errno(r, "Failed to set PTY dimensions: %m");

        pty->name = TAKE_PTR(p.name);
        pty->description = TAKE_PTR(p.description);
        pty->tag = TAKE_PTR(p.tag);
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(ts);
        pty->frontend_type = p.frontend_type;
        pty->backend_type = p.backend_type;
        pty->ignore_hangup = p.ignore_hangup;
        pty->owner_pidref = TAKE_PIDREF(peer_pidref);
        pty->owner_uid = uid;
        pty->owner_gid = gid;

        /* Read back the settled terminal settings while the frontend fd is still open — for the
         * FRONTEND_TAKE case we close it below before handing it to the client, and would then no longer be
         * able to query the dimensions. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return r;

        int frontend_idx = -EINVAL;
        if (pty->frontend_type == FRONTEND_TAKE) {
                assert(pty->frontend_fd >= 0);

                frontend_idx = sd_varlink_push_fd(link, pty->frontend_fd);
                if (frontend_idx < 0)
                        return log_error_errno(frontend_idx, "Failed to push PTY frontend fd to client: %m");

                TAKE_FD(pty->frontend_fd);
        }

        _cleanup_close_ int unit_reference_fd = -EBADF;
        int backend_idx = -1;
        switch (pty->backend_type) {

        case BACKEND_TAKE:
                assert(pty->backend_fd >= 0);

                if (fchmod(pty->backend_fd, 0600) < 0)
                        return log_error_errno(errno, "Failed to adjust mode of PTY backend: %m");

                if (fchown(pty->backend_fd, uid, gid) < 0)
                        return log_error_errno(errno, "Failed to adjust ownership of PTY backend to client's UID/GID: %m");

                backend_idx = sd_varlink_push_fd(link, pty->backend_fd);
                if (backend_idx < 0)
                        return log_error_errno(backend_idx, "Failed to push PTY backend fd to client: %m");

                TAKE_FD(pty->backend_fd);
                break;

        case BACKEND_SHELL:
                assert(pty->backend_fd >= 0);

                r = start_shell(m,
                                pty,
                                p.user,
                                p.group,
                                &p.working_directory,
                                p.environment,
                                p.command_line,
                                p.executable,
                                p.via_shell != 0,
                                p.lightweight,
                                p.reference_unit,
                                &unit_reference_fd);
                if (r < 0)
                        return r;

                break;

        default:
                assert_not_reached();
        }

        r = pseudo_tty_watch_frontend_fd(pty, m->event);
        if (r < 0)
                return r;

        /* Also watch the backend device node for removal. For FRONTEND_TAKE we handed the frontend fd to the
         * client and no longer hold one to watch for EPOLLHUP, so this is how we learn the PTY is gone. */
        r = pseudo_tty_watch_backend_node(pty, m->event);
        if (r < 0)
                return r;

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = NULL;
        if (p.monitor) {
                assert(pty->frontend_fd >= 0);

                r = pseudo_tty_monitor_new(link, p.osc2811, &monitor);
                if (r < 0)
                        return r;

                monitor->hang_up_on_disconnect = p.hang_up_on_disconnect;
        }

        /* Link everything into the manager *before* sending the (upgrade) response: once the upgrade reply
         * is enqueued the upgrade callback may fire, and it requires the monitor to be fully wired up (in
         * particular its connection userdata pointer). Doing all fallible linking up front also ensures we
         * never leave a connection half-upgraded if e.g. the hashmap insertion runs out of memory. */
        r = pseudo_tty_link(pty, m);
        if (r < 0)
                return r;

        if (monitor) {
                pseudo_tty_monitor_link(monitor, pty);

                r = pseudo_tty_monitor_push_pending(monitor);
                if (r < 0)
                        return log_error_errno(r, "Failed to enqueue pending output for monitor: %m");
        }

        int unit_reference_idx = -1;
        if (unit_reference_fd >= 0) {
                unit_reference_idx = sd_varlink_push_fd(link, unit_reference_fd);
                if (unit_reference_idx < 0)
                        return log_error_errno(unit_reference_idx, "Failed to push unit reference fd to client: %m");
                TAKE_FD(unit_reference_fd);
        }

        /* Assemble the reply up-front. Note that the monitor and non-monitor cases need no separate variants
         * here: monitoring is refused for the 'take' frontend type above, hence frontend_idx is never set in
         * the monitor case, and the conditional pair simply remains absent. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        r = sd_json_buildo(
                        &reply,
                        SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", pty->description),
                        JSON_BUILD_PAIR_ENUM("frontendType", frontend_type_to_string(pty->frontend_type)),
                        JSON_BUILD_PAIR_ENUM("backendType", backend_type_to_string(pty->backend_type)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tag", pty->tag),
                        SD_JSON_BUILD_PAIR_CONDITION(frontend_idx >= 0, "frontendFileDescriptor", SD_JSON_BUILD_INTEGER(frontend_idx)),
                        SD_JSON_BUILD_PAIR_CONDITION(backend_idx >= 0, "backendFileDescriptor", SD_JSON_BUILD_INTEGER(backend_idx)),
                        SD_JSON_BUILD_PAIR_STRING("backendPath", pty->backend_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("unit", pty->unit),
                        SD_JSON_BUILD_PAIR_CONDITION(unit_reference_idx >= 0, "unitReferenceFileDescriptor", SD_JSON_BUILD_INTEGER(unit_reference_idx)),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        if (r < 0)
                return r;

        pty->acquire_link = sd_varlink_ref(link);
        pty->acquire_reply = TAKE_PTR(reply);
        pty->acquire_monitor = p.monitor;

        /* If a shell unit start is in flight, hold the reply back until StartTransient() completed, so that
         * a failure to start the shell is propagated to the client as an error. Otherwise send it right
         * away. */
        if (!pty->start_shell_link) {
                r = pseudo_tty_send_acquire_reply(pty);
                if (r < 0)
                        return r;
        }

        TAKE_PTR(pty);
        TAKE_PTR(monitor);

        return 0;
}

static int validate_pty_master_fd(int fd, int *ret_pin_fd) {
        assert(fd >= 0);
        assert(ret_pin_fd);

        /* Vet a caller-provided pty frontend ('master') fd before we start operating on it. As a privileged
         * service we must not let a client trick us into acting on an fd it couldn't use itself: reject
         * anything with unexpected open flags (in particular O_PATH, which would smuggle in a reference to an
         * fd the client cannot actually read from or write to), insist on O_RDWR, and require that it's an
         * actual TTY. */
        int fl = fd_verify_safe_flags_full(fd, O_NONBLOCK);
        if (fl < 0)
                return fl;
        if ((fl & O_ACCMODE_STRICT) != O_RDWR)
                return -EACCES;

        if (!isatty_safe(fd))
                return -ENOTTY;

        /* Open the backend ('slave') side through the frontend fd. This confirms it really is the frontend
         * side, and gives us an fd we can pin for later hang-up requests. We keep only an O_PATH reference
         * around: a proper open would keep the backend busy and prevent hang-up detection. */
        _cleanup_close_ int peer_fd = pty_open_peer(fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (peer_fd < 0)
                return peer_fd;

        int pin_fd = fd_reopen(peer_fd, O_PATH|O_CLOEXEC);
        if (pin_fd < 0)
                return pin_fd;

        *ret_pin_fd = pin_fd;
        return 0;
}

typedef struct EnrollPtyParameters {
        int frontend_fd_idx;
        FrontendType frontend_type;
        char *name;
        char *description;
        char *tag;
        char *backend_path;
        bool monitor;
        bool hang_up_on_disconnect;
        bool ignore_hangup;
        bool osc2811;
        sd_json_variant *terminal_settings; /* no reference */
} EnrollPtyParameters;

static void enroll_pty_parameters_done(EnrollPtyParameters *p) {
        assert(p);

        free(p->name);
        free(p->description);
        free(p->tag);
        free(p->backend_path);
}

static int vl_method_enroll_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        _cleanup_(enroll_pty_parameters_done) EnrollPtyParameters p = {
                .frontend_fd_idx = -1,
                .frontend_type = _FRONTEND_TYPE_INVALID,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "frontendFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,           voffsetof(p, frontend_fd_idx),       SD_JSON_MANDATORY },
                { "frontendType",           _SD_JSON_VARIANT_TYPE_INVALID, dispatch_frontend_type,         voffsetof(p, frontend_type),         SD_JSON_MANDATORY },
                { "backendPath",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, backend_path),          0                 },
                { "name",                   SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, name),                  0                 },
                { "description",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, description),           0                 },
                { "tag",                    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, tag),                   0                 },
                { "monitor",                SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, monitor),               0                 },
                { "hangUpOnDisconnect",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, hang_up_on_disconnect), 0                 },
                { "ignoreHangup",           SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, ignore_hangup),         0                 },
                { "osc2811",                SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, osc2811),               0                 },
                { "terminalSettings",       SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref, voffsetof(p, terminal_settings),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* Taking over a caller-provided fd only makes sense if the broker keeps a copy of the frontend, i.e.
         * for the 'null' and 'log' frontend types. Handing the fd straight back to the caller ('take') would
         * be a no-op since the caller already holds it. */
        if (p.frontend_type == FRONTEND_TAKE)
                return sd_varlink_error_invalid_parameter_name(link, "frontendType");

        if (p.osc2811 && !p.monitor)
                return sd_varlink_error_invalid_parameter_name(link, "osc2811");

        /* If backend hangups are ignored, the monitor connection going away is what ends the pty's lifetime */
        if (p.ignore_hangup && (!p.monitor || !p.hang_up_on_disconnect))
                return sd_varlink_error_invalid_parameter_name(link, "ignoreHangup");

        if (p.monitor && !FLAGS_SET(flags, SD_VARLINK_METHOD_UPGRADE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_UPGRADE, NULL);

        if (p.name && !pseudo_tty_name_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (p.description && !pseudo_tty_description_valid(p.description))
                return sd_varlink_error_invalid_parameter_name(link, "description");

        if (p.tag && !pseudo_tty_tag_valid(p.tag))
                return sd_varlink_error_invalid_parameter_name(link, "tag");

        if (p.backend_path && (!path_is_absolute(p.backend_path) || !path_is_normalized(p.backend_path)))
                return sd_varlink_error_invalid_parameter_name(link, "backendPath");

        _cleanup_strv_free_ char **details = strv_new(
                        "frontendType", frontend_type_to_string(p.frontend_type));
        if (!details)
                return -ENOMEM;
        if (p.name) {
                r = strv_extend_many(&details, "name", p.name);
                if (r < 0)
                        return r;
        }

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.enroll-pty",
                        (const char**) details,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        gid_t gid;
        r = sd_varlink_get_peer_gid(link, &gid);
        if (r < 0)
                return r;

        _cleanup_(pidref_done) PidRef peer_pidref = PIDREF_NULL;
        r = varlink_get_peer_pidref(link, &peer_pidref);
        if (r < 0)
                return r;

        /* Also acquire the pidfd inode number, so that the PID remains unambiguous even after the client
         * exited. Might not be available on old kernels, ignore that. */
        (void) pidref_acquire_pidfd_id(&peer_pidref);

        if (p.name) {
                if (hashmap_contains(m->ptys, p.name))
                        return sd_varlink_error(link, "io.systemd.PTYBroker.PtyExists", NULL);
        } else {
                sd_id128_t id;

                r = sd_id128_randomize(&id);
                if (r < 0)
                        return r;

                p.name = strdup(SD_ID128_TO_STRING(id));
                if (!p.name)
                        return log_oom();
        }

        /* Unlike AcquirePty() we do not settle the terminal settings to the broker's defaults: the pty is
         * already set up by the caller, so we leave the existing configuration in place and only merge the
         * IPC-provided settings on top of it. */
        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        if (hashmap_size(m->ptys) >= PSEUDO_TTY_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyPtys", NULL);

        _cleanup_close_ int frontend_fd = sd_varlink_take_fd(link, p.frontend_fd_idx);
        if (frontend_fd < 0)
                return sd_varlink_error_invalid_parameter_name(link, "frontendFileDescriptor");

        _cleanup_close_ int pin_fd = -EBADF;
        r = validate_pty_master_fd(frontend_fd, &pin_fd);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "frontendFileDescriptor");

        _cleanup_(pseudo_tty_freep) PseudoTTY *pty = NULL;
        r = pseudo_tty_new(&pty);
        if (r < 0)
                return r;

        pty->frontend_fd = TAKE_FD(frontend_fd);
        pty->pin_fd = TAKE_FD(pin_fd);

        pty->name = TAKE_PTR(p.name);
        pty->description = TAKE_PTR(p.description);
        pty->tag = TAKE_PTR(p.tag);
        pty->backend_path = TAKE_PTR(p.backend_path);
        pty->frontend_type = p.frontend_type;
        pty->backend_type = BACKEND_TAKE; /* The backend (i.e. 'slave') stays under the caller's control. */
        pty->ignore_hangup = p.ignore_hangup;
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(ts);
        pty->owner_pidref = TAKE_PIDREF(peer_pidref);
        pty->owner_uid = uid;
        pty->owner_gid = gid;

        /* Apply any IPC-provided dimensions to the pty (merging them onto whatever is already in effect) and
         * read back the settled size. */
        (void) terminal_settings_sync_size_fd(&pty->terminal_settings, pty->frontend_fd, pty->backend_path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return r;

        r = pseudo_tty_watch_frontend_fd(pty, m->event);
        if (r < 0)
                return r;

        /* Also watch the backend device node for removal. For FRONTEND_TAKE we handed the frontend fd to the
         * client and no longer hold one to watch for EPOLLHUP, so this is how we learn the PTY is gone. */
        r = pseudo_tty_watch_backend_node(pty, m->event);
        if (r < 0)
                return r;

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = NULL;
        if (p.monitor) {
                assert(pty->frontend_fd >= 0);

                r = pseudo_tty_monitor_new(link, p.osc2811, &monitor);
                if (r < 0)
                        return r;

                monitor->hang_up_on_disconnect = p.hang_up_on_disconnect;
        }

        /* Link everything into the manager *before* sending the (upgrade) response — see the matching comment
         * in vl_method_acquire_pty() for the rationale. */
        r = pseudo_tty_link(pty, m);
        if (r < 0)
                return r;

        if (monitor) {
                pseudo_tty_monitor_link(monitor, pty);

                r = pseudo_tty_monitor_push_pending(monitor);
                if (r < 0)
                        return log_error_errno(r, "Failed to enqueue pending output for monitor: %m");
        }

        if (p.monitor)
                r = sd_varlink_respond_and_upgradebo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("description", pty->description),
                                JSON_BUILD_PAIR_ENUM("frontendType", frontend_type_to_string(pty->frontend_type)),
                                JSON_BUILD_PAIR_ENUM("backendType", backend_type_to_string(pty->backend_type)),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("tag", pty->tag),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        else
                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("description", pty->description),
                                JSON_BUILD_PAIR_ENUM("frontendType", frontend_type_to_string(pty->frontend_type)),
                                JSON_BUILD_PAIR_ENUM("backendType", backend_type_to_string(pty->backend_type)),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("tag", pty->tag),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        if (r < 0)
                return r;

        TAKE_PTR(pty);
        TAKE_PTR(monitor);

        return 0;
}

static PseudoTTY* manager_get_alive_pty(Manager *m, const char *name) {
        assert(m);
        assert(name);

        PseudoTTY *pty = hashmap_get(m->ptys, name);
        if (!pty || pty->in_free_queue) /* A pty queued for removal is as good as gone, report it as such
                                         * rather than hooking up to it and then dropping the client on the
                                         * floor when the deferred free runs. */
                return NULL;

        return pty;
}

static int vl_method_monitor_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_UPGRADE));

        struct {
                const char *name;
                size_t track_buffer_lines;
                bool hang_up_on_disconnect;
                bool osc2811;
                sd_json_variant *terminal_settings; /* no reference */
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  voffsetof(p, name),                  SD_JSON_MANDATORY },
                { "trackBufferLines",   _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_size,             voffsetof(p, track_buffer_lines),    0                 },
                { "hangUpOnDisconnect", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, hang_up_on_disconnect), 0                 },
                { "osc2811",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, osc2811),               0                 },
                { "terminalSettings",   SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref, voffsetof(p, terminal_settings),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        if (!pseudo_tty_name_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        PseudoTTY *pty = manager_get_alive_pty(m, p.name);
        if (!pty)
                return sd_varlink_error(link, "io.systemd.PTYBroker.NoSuchPty", NULL);

        /* The owner of the pty may monitor it without further authentication. (Note that once the
         * asynchronous polkit check completed the method call is dispatched again, and hence the lookup
         * above is repeated.) */
        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.monitor-pty",
                        (const char**) STRV_MAKE("name", p.name),
                        /* good_user= */ pty->owner_uid,
                        /* flags= */ 0,
                        &m->polkit_registry,
                        /* ret_admin= */ NULL);
        if (r <= 0)
                return r;

        if (pty->frontend_fd < 0)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TrackingNotEnabled", NULL);

        if (pty->n_monitors >= MONITOR_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyMonitors", NULL);

        _cleanup_(terminal_settings_done) TerminalSettings merged_ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_copy(&pty->terminal_settings, &merged_ts);
        if (r < 0)
                return r;

        r = terminal_settings_merge(&merged_ts, &ts);
        if (r < 0)
                return r;

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = NULL;
        r = pseudo_tty_monitor_new(link, p.osc2811, &monitor);
        if (r < 0)
                return r;

        monitor->hang_up_on_disconnect = p.hang_up_on_disconnect;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tb = NULL;
        r = pseudo_tty_track_buffer_to_json(pty, p.track_buffer_lines, &tb);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire track buffer: %m");

        /* Wire the monitor up before enqueuing the upgrade reply: the upgrade callback (which needs the
         * monitor as connection userdata) may fire as soon as the reply has been flushed. */
        pseudo_tty_monitor_link(monitor, pty);

        r = pseudo_tty_monitor_push_pending(monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to enqueue pending output for monitor: %m");

        /* Move the new dimensions over */
        terminal_settings_done(&pty->terminal_settings);
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(merged_ts);

        /* Apply them to the TTY device */
        (void) terminal_settings_sync_size_fd(&pty->terminal_settings, pty->frontend_fd, pty->backend_path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire terminal settings: %m");

        r = sd_varlink_respond_and_upgradebo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", pty->description),
                        JSON_BUILD_PAIR_ENUM("frontendType", frontend_type_to_string(pty->frontend_type)),
                        JSON_BUILD_PAIR_ENUM("backendType", backend_type_to_string(pty->backend_type)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tag", pty->tag),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("backendPath", pty->backend_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("unit", pty->unit),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("trackBuffer", tb),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        if (r < 0)
                return r;

        TAKE_PTR(monitor);
        return 0;
}

static int vl_method_configure_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        struct {
                const char *name;
                sd_json_variant *terminal_settings; /* no reference */
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",             SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  voffsetof(p, name),              SD_JSON_MANDATORY },
                { "terminalSettings", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, voffsetof(p, terminal_settings), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        if (!pseudo_tty_name_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        PseudoTTY *pty = manager_get_alive_pty(m, p.name);
        if (!pty)
                return sd_varlink_error(link, "io.systemd.PTYBroker.NoSuchPty", NULL);

        /* The owner of the pty may reconfigure it without further authentication. (Note that once the
         * asynchronous polkit check completed the method call is dispatched again, and hence the lookup
         * above is repeated.) */
        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.configure-pty",
                        (const char**) STRV_MAKE("name", p.name),
                        /* good_user= */ pty->owner_uid,
                        /* flags= */ 0,
                        &m->polkit_registry,
                        /* ret_admin= */ NULL);
        if (r <= 0)
                return r;

        if (pty->frontend_fd < 0)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TrackingNotEnabled", NULL);

        _cleanup_(terminal_settings_done) TerminalSettings merged_ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_copy(&pty->terminal_settings, &merged_ts);
        if (r < 0)
                return r;

        r = terminal_settings_merge(&merged_ts, &ts);
        if (r < 0)
                return r;

        terminal_settings_done(&pty->terminal_settings);
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(merged_ts);

        (void) terminal_settings_sync_size_fd(&pty->terminal_settings, pty->frontend_fd, pty->backend_path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire terminal settings: %m");

        return sd_varlink_replybo(
                        link,
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
}

static int pseudo_tty_reply_description(PseudoTTY *pty, sd_varlink *link) {
        assert(pty);
        assert(link);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", pty->description),
                        JSON_BUILD_PAIR_ENUM("frontendType", frontend_type_to_string(pty->frontend_type)),
                        JSON_BUILD_PAIR_ENUM("backendType", backend_type_to_string(pty->backend_type)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tag", pty->tag),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("backendPath", pty->backend_path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("unit", pty->unit),
                        JSON_BUILD_PAIR_PIDREF_NON_NULL("owner", &pty->owner_pidref),
                        SD_JSON_BUILD_PAIR_CONDITION(uid_is_valid(pty->owner_uid), "ownerUID", SD_JSON_BUILD_UNSIGNED(pty->owner_uid)),
                        SD_JSON_BUILD_PAIR_CONDITION(gid_is_valid(pty->owner_gid), "ownerGID", SD_JSON_BUILD_UNSIGNED(pty->owner_gid)));
}

static int vl_method_list_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        const char *name = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &name);
        if (r != 0)
                return r;

        if (!name && !FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.list-ptys",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.PTYBroker.NoSuchPty");
        if (r < 0)
                return r;

        PseudoTTY *pty;
        if (name) {
                pty = manager_get_alive_pty(m, name);
                if (pty) {
                        r = pseudo_tty_reply_description(pty, link);
                        if (r < 0)
                                return r;
                }
        } else
                HASHMAP_FOREACH(pty, m->ptys) {
                        if (pty->in_free_queue)
                                continue;

                        r = pseudo_tty_reply_description(pty, link);
                        if (r < 0)
                                return r;
                }

        return 0;
}

static int vl_method_hang_up_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        const char *name = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &name);
        if (r != 0)
                return r;

        if (!pseudo_tty_name_valid(name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        PseudoTTY *pty = hashmap_get(m->ptys, name);
        if (!pty)
                return sd_varlink_error(link, "io.systemd.PTYBroker.NoSuchPty", NULL);

        /* The owner of the pty may hang it up without further authentication. (Note that once the
         * asynchronous polkit check completed the method call is dispatched again, and hence the lookup
         * above is repeated.) */
        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.hang-up-pty",
                        (const char**) STRV_MAKE("name", name),
                        /* good_user= */ pty->owner_uid,
                        /* flags= */ 0,
                        &m->polkit_registry,
                        /* ret_admin= */ NULL);
        if (r <= 0)
                return r;

        if (pty->in_free_queue)
                /* The hang-up already completed and its callback (which answers the registered calls) has
                 * run; the pty is merely waiting for the deferred free. Answer right away, registering in
                 * vhangup_links would mean never getting a reply. */
                return sd_varlink_reply(link, NULL);

        /* Register the link first, so that we never hang up the PTY without being able to send a reply */
        r = set_ensure_put(&pty->vhangup_links, &varlink_hash_ops, link);
        if (r < 0)
                return r;
        bool added = r > 0;
        if (added) /* Take a reference only if the link was actually added to the set */
                sd_varlink_ref(link);

        r = pseudo_tty_vhangup(pty);
        if (r < 0) {
                if (added)
                        sd_varlink_unref(set_remove(pty->vhangup_links, link));
                return r;
        }

        return 0;
}

#define EXIT_ON_IDLE_USEC (3 * USEC_PER_SEC)

static bool manager_is_idle(Manager *m) {
        assert(m);

        /* PTYs may outlive their Varlink connections, and unit references may outlive their PTYs. Check all
         * three before exiting, as sd_varlink_server_set_exit_on_idle() would release references early. */

        return sd_varlink_server_current_connections(m->varlink_server) == 0 &&
                hashmap_isempty(m->ptys) &&
                set_isempty(m->unit_references);
}

static int on_exit_on_idle(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        /* Re-check before acting: a client might have reconnected (or a PTY been allocated) during the grace
         * period. */
        if (!manager_is_idle(m))
                return 0;

        log_debug("Still idle after grace period, exiting.");
        return sd_event_exit(m->event, 0);
}

static void manager_schedule_idle_check(Manager *m) {
        int r;

        assert(m);

        /* As a socket-activated singleton, exit once fully idle so we get garbage collected. Don't exit right
         * away though, but arm a short grace timer first, so that a client that reconnects quickly (e.g.
         * between two Varlink calls) doesn't pay the cost of us shutting down and being respawned. */

        if (!manager_is_idle(m)) {
                (void) sd_event_source_set_enabled(m->exit_on_idle_event_source, SD_EVENT_OFF);
                return;
        }

        /* force_reset=true: restart the grace period from scratch every time we become idle again. */
        r = event_reset_time_relative(
                        m->event,
                        &m->exit_on_idle_event_source,
                        CLOCK_MONOTONIC,
                        EXIT_ON_IDLE_USEC,
                        /* accuracy= */ 0,
                        on_exit_on_idle,
                        m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "exit-on-idle",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to arm exit-on-idle timer, ignoring: %m");
}

static void manager_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        /* The connection userdata is either the Manager (inherited from the server) or, for connections
         * that are to be upgraded into a monitor connection, the PseudoTTYMonitor object. */
        void *u = sd_varlink_get_userdata(link);
        if (u && u != m)
                pseudo_tty_monitor_on_link_disconnect(u);

        PseudoTTY *pty;
        HASHMAP_FOREACH(pty, m->ptys)
                if (pty->unit_reference && pty->acquire_link == link)
                        pseudo_tty_add_to_free_queue(pty);

        manager_schedule_idle_check(m);
}

static int on_ptys_free_queue(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        PseudoTTY *pty;
        while ((pty = m->ptys_free_queue))
                pseudo_tty_free(pty);

        manager_schedule_idle_check(m);
        return 0;
}

static int manager_new(RuntimeScope scope, Manager **ret) {
        int r;

        assert(ret);
        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));

        _cleanup_(manager_freep) Manager *m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .scope = scope,
        };

        r = sd_event_new(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, /* ret= */ NULL, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to allocate memory pressure event source, ignoring: %m");

        r = sd_event_add_defer(m->event, &m->ptys_free_queue_event_source, on_ptys_free_queue, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(m->ptys_free_queue_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->ptys_free_queue_event_source, "ptys-free-queue");

        (void) sd_event_set_watchdog(m->event, true);

        *ret = TAKE_PTR(m);
        return 0;
}

static int manager_startup(Manager *m) {
        int r;

        assert(m);

        r = varlink_server_new(
                        &m->varlink_server,
                        (m->scope != RUNTIME_SCOPE_USER ? SD_VARLINK_SERVER_ACCOUNT_UID : 0)|
                        SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_PTYBroker,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add interfaces to Varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.PTYBroker.AcquirePty",   vl_method_acquire_pty,
                        "io.systemd.PTYBroker.EnrollPty",    vl_method_enroll_pty,
                        "io.systemd.PTYBroker.MonitorPty",   vl_method_monitor_pty,
                        "io.systemd.PTYBroker.ConfigurePty", vl_method_configure_pty,
                        "io.systemd.PTYBroker.ListPty",      vl_method_list_pty,
                        "io.systemd.PTYBroker.HangUpPty",    vl_method_hang_up_pty);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = varlink_set_info_systemd(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to set Varlink server info: %m");

        r = sd_varlink_server_listen_auto(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0) {
                /* Not socket activated, bind our own socket as a fallback. */
                _cleanup_free_ char *socket_path = NULL;
                r = runtime_directory_generic(m->scope, "systemd/io.systemd.PTYBroker", &socket_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine Varlink socket path: %m");

                r = sd_varlink_server_listen_address(m->varlink_server, socket_path, runtime_scope_to_socket_mode(m->scope) | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to io.systemd.PTYBroker Varlink socket: %m");
        }

        r = sd_varlink_server_bind_disconnect(m->varlink_server, manager_on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink disconnect handler: %m");

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        /* Arm the idle timer right away: if we were started but nobody ever connects (e.g. a spurious socket
         * activation), we'll shut down again after the grace period instead of lingering forever. */
        manager_schedule_idle_check(m);

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        RuntimeScope scope = RUNTIME_SCOPE_SYSTEM;
        r = service_parse_argv(
                        /* bus_objects= */ NULL,
                        &scope,
                        argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        _cleanup_(manager_freep) Manager *m = NULL;
        r = manager_new(scope, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to create manager: %m");

        r = manager_startup(m);
        if (r < 0)
                return r;

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop =
                notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

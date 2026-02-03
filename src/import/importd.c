/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build-path.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "common-signal.h"
#include "constants.h"
#include "daemon-util.h"
#include "discover-image.h"
#include "env-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "float.h"
#include "hashmap.h"
#include "import-common.h"
#include "import-util.h"
#include "json-util.h"
#include "main-func.h"
#include "notify-recv.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "percent-util.h"
#include "pidref.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "service-util.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "syslog-util.h"
#include "varlink-io.systemd.Import.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"
#include "web-util.h"

typedef struct Manager Manager;

typedef enum TransferType {
        TRANSFER_IMPORT_TAR,
        TRANSFER_IMPORT_RAW,
        TRANSFER_IMPORT_FS,
        TRANSFER_EXPORT_TAR,
        TRANSFER_EXPORT_RAW,
        TRANSFER_PULL_TAR,
        TRANSFER_PULL_RAW,
        _TRANSFER_TYPE_MAX,
        _TRANSFER_TYPE_INVALID = -EINVAL,
} TransferType;

typedef struct Transfer {
        Manager *manager;

        uint32_t id;
        char *object_path;

        TransferType type;
        ImportVerify verify;

        char *remote;
        char *local;
        char *image_root;
        ImageClass class;
        ImportFlags flags;
        char *format;

        PidRef pidref;

        int log_fd;

        char log_message[LINE_MAX];
        size_t log_message_size;

        sd_event_source *pid_event_source;
        sd_event_source *log_event_source;

        unsigned n_canceled;
        unsigned progress_percent;
        unsigned progress_percent_sent;

        int stdin_fd;
        int stdout_fd;

        Set *varlink_subscribed;
} Transfer;

typedef struct Manager {
        sd_event *event;
        sd_bus *api_bus;
        sd_bus *system_bus;
        sd_varlink_server *varlink_server;

        uint32_t current_transfer_id;
        Hashmap *transfers;

        Hashmap *polkit_registry;

        char *notify_socket_path;

        bool use_btrfs_subvol;
        bool use_btrfs_quota;

        RuntimeScope runtime_scope;
} Manager;

#define TRANSFERS_MAX 64

static const char* const transfer_type_table[_TRANSFER_TYPE_MAX] = {
        [TRANSFER_IMPORT_TAR] = "import-tar",
        [TRANSFER_IMPORT_RAW] = "import-raw",
        [TRANSFER_IMPORT_FS]  = "import-fs",
        [TRANSFER_EXPORT_TAR] = "export-tar",
        [TRANSFER_EXPORT_RAW] = "export-raw",
        [TRANSFER_PULL_TAR]   = "pull-tar",
        [TRANSFER_PULL_RAW]   = "pull-raw",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(transfer_type, TransferType);

static Transfer *transfer_unref(Transfer *t) {
        if (!t)
                return NULL;

        if (t->manager)
                hashmap_remove(t->manager->transfers, UINT32_TO_PTR(t->id));

        sd_event_source_unref(t->pid_event_source);
        sd_event_source_unref(t->log_event_source);

        free(t->remote);
        free(t->local);
        free(t->format);
        free(t->image_root);
        free(t->object_path);

        pidref_done_sigkill_wait(&t->pidref);

        safe_close(t->log_fd);
        safe_close(t->stdin_fd);
        safe_close(t->stdout_fd);

        set_free(t->varlink_subscribed);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Transfer*, transfer_unref);

static int transfer_new(Manager *m, Transfer **ret) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        uint32_t id;
        int r;

        assert(m);
        assert(ret);

        if (hashmap_size(m->transfers) >= TRANSFERS_MAX)
                return -E2BIG;

        t = new(Transfer, 1);
        if (!t)
                return -ENOMEM;

        *t = (Transfer) {
                .type = _TRANSFER_TYPE_INVALID,
                .log_fd = -EBADF,
                .stdin_fd = -EBADF,
                .stdout_fd = -EBADF,
                .verify = _IMPORT_VERIFY_INVALID,
                .progress_percent = UINT_MAX,
                .progress_percent_sent = UINT_MAX,
        };

        id = m->current_transfer_id + 1;

        if (asprintf(&t->object_path, "/org/freedesktop/import1/transfer/_%" PRIu32, id) < 0)
                return -ENOMEM;

        r = hashmap_ensure_put(&m->transfers, &trivial_hash_ops, UINT32_TO_PTR(id), t);
        if (r < 0)
                return r;

        m->current_transfer_id = id;

        t->manager = m;
        t->id = id;

        *ret = TAKE_PTR(t);

        return 0;
}

static double transfer_percent_as_double(Transfer *t) {
        assert(t);

        if (t->progress_percent == UINT_MAX)
                return -DBL_MAX;

        return (double) t->progress_percent / 100.0;
}

static void transfer_send_log_line(Transfer *t, const char *line) {
        int r, priority = LOG_INFO;

        assert(t);
        assert(line);

        syslog_parse_priority(&line, &priority, true);

        log_full(priority, "(transfer%" PRIu32 ") %s", t->id, line);

        r = sd_bus_emit_signal(
                        t->manager->api_bus,
                        t->object_path,
                        "org.freedesktop.import1.Transfer",
                        "LogMessage",
                        "us",
                        priority,
                        line);
        if (r < 0)
                log_warning_errno(r, "Cannot emit log message bus signal, ignoring: %m");

        r = varlink_many_notifybo(
                        t->varlink_subscribed,
                        SD_JSON_BUILD_PAIR("log",
                                           SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR_UNSIGNED("priority", priority),
                                                           SD_JSON_BUILD_PAIR_STRING("message", line))));
        if (r < 0)
                log_warning_errno(r, "Cannot emit log message varlink message, ignoring: %m");
}

static void transfer_send_progress_update(Transfer *t) {
        int r;

        assert(t);

        if (t->progress_percent_sent == t->progress_percent)
                return;

        double progress = transfer_percent_as_double(t);

        r = sd_bus_emit_signal(
                        t->manager->api_bus,
                        t->object_path,
                        "org.freedesktop.import1.Transfer",
                        "ProgressUpdate",
                        "d",
                        progress);
        if (r < 0)
                log_warning_errno(r, "Cannot emit progress update bus signal, ignoring: %m");

        r = varlink_many_notifybo(
                        t->varlink_subscribed,
                        SD_JSON_BUILD_PAIR_REAL("progress", progress));
        if (r < 0)
                log_warning_errno(r, "Cannot emit progress update varlink message, ignoring: %m");

        t->progress_percent_sent = t->progress_percent;
}

static void transfer_send_logs(Transfer *t, bool flush) {
        assert(t);

        /* Try to send out all log messages, if we can. But if we
         * can't we remove the messages from the buffer, but don't
         * fail */

        while (t->log_message_size > 0) {
                _cleanup_free_ char *n = NULL;
                char *e;

                if (t->log_message_size >= sizeof(t->log_message))
                        e = t->log_message + sizeof(t->log_message);
                else {
                        char *a, *b;

                        a = memchr(t->log_message, 0, t->log_message_size);
                        b = memchr(t->log_message, '\n', t->log_message_size);

                        if (a && b)
                                e = a < b ? a : b;
                        else if (a)
                                e = a;
                        else
                                e = b;
                }

                if (!e) {
                        if (!flush)
                                return;

                        e = t->log_message + t->log_message_size;
                }

                n = strndup(t->log_message, e - t->log_message);

                /* Skip over NUL and newlines */
                while (e < t->log_message + t->log_message_size && IN_SET(*e, 0, '\n'))
                        e++;

                memmove(t->log_message, e, t->log_message + sizeof(t->log_message) - e);
                t->log_message_size -= e - t->log_message;

                if (!n) {
                        log_oom();
                        continue;
                }

                if (isempty(n))
                        continue;

                transfer_send_log_line(t, n);
        }
}

static int transfer_finalize(Transfer *t, bool success) {
        int r;

        assert(t);

        transfer_send_logs(t, true);

        r = sd_bus_emit_signal(
                        t->manager->api_bus,
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "TransferRemoved",
                        "uos",
                        t->id,
                        t->object_path,
                        success ? "done" :
                        t->n_canceled > 0 ? "canceled" : "failed");
        if (r < 0)
                log_error_errno(r, "Cannot emit message: %m");

        if (success)
                r = varlink_many_reply(t->varlink_subscribed, NULL);
        else if (t->n_canceled > 0)
                r = varlink_many_error(t->varlink_subscribed, "io.systemd.Import.TransferCancelled", NULL);
        else
                r = varlink_many_error(t->varlink_subscribed, "io.systemd.Import.TransferFailed", NULL);
        if (r < 0)
                log_warning_errno(r, "Cannot emit varlink reply, ignoring: %m");

        transfer_unref(t);
        return 0;
}

static int transfer_cancel(Transfer *t) {
        int r;

        assert(t);

        r = pidref_kill_and_sigcont(&t->pidref, t->n_canceled < 3 ? SIGTERM : SIGKILL);
        if (r < 0)
                return r;

        t->n_canceled++;
        return 0;
}

static int transfer_on_pid(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Transfer *t = ASSERT_PTR(userdata);
        bool success = false;

        assert(s);

        if (si->si_code == CLD_EXITED) {
                if (si->si_status != 0)
                        log_error("Transfer process failed with exit code %i.", si->si_status);
                else {
                        log_debug("Transfer process succeeded.");
                        success = true;
                }

        } else if (IN_SET(si->si_code, CLD_KILLED, CLD_DUMPED))
                log_error("Transfer process terminated by signal %s.", signal_to_string(si->si_status));
        else
                log_error("Transfer process failed due to unknown reason.");

        pidref_done(&t->pidref);

        return transfer_finalize(t, success);
}

static int transfer_on_log(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Transfer *t = ASSERT_PTR(userdata);
        ssize_t l;

        assert(s);

        l = read(fd, t->log_message + t->log_message_size, sizeof(t->log_message) - t->log_message_size);
        if (l < 0)
                log_error_errno(errno, "Failed to read log message: %m");
        if (l <= 0) {
                /* EOF/read error. We just close the pipe here, and
                 * close the watch, waiting for the child to exit,
                 * before we do anything else. */
                t->log_event_source = sd_event_source_unref(t->log_event_source);
                return 0;
        }

        t->log_message_size += l;

        transfer_send_logs(t, false);

        return 0;
}

static int transfer_start(Transfer *t) {
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        int r;

        assert(t);
        assert(!pidref_is_set(&t->pidref));

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return -errno;

        r = pidref_safe_fork_full(
                        "(sd-transfer)",
                        (int[]) { t->stdin_fd, t->stdout_fd < 0 ? pipefd[1] : t->stdout_fd, pipefd[1] },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_REOPEN_LOG,
                        &t->pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *cmd[] = {
                        NULL, /* systemd-import, systemd-import-fs, systemd-export or systemd-pull */
                        NULL, /* tar, raw  */
                        NULL, /* --system or --user */
                        NULL, /* --verify= */
                        NULL, /* verify argument */
                        NULL, /* --class= */
                        NULL, /* class argument */
                        NULL, /* --keep-download= */
                        NULL, /* maybe --force */
                        NULL, /* maybe --read-only */
                        NULL, /* if so: the actual URL */
                        NULL, /* maybe --format= */
                        NULL, /* if so: the actual format */
                        NULL, /* maybe --image-root= */
                        NULL, /* if so: the image root path */
                        NULL, /* remote */
                        NULL, /* local */
                        NULL
                };
                size_t k = 0;

                /* Child */

                if (setenv("SYSTEMD_LOG_TARGET", "console-prefixed", 1) < 0 ||
                    setenv("NOTIFY_SOCKET", t->manager->notify_socket_path, 1) < 0) {
                        log_error_errno(errno, "setenv() failed: %m");
                        _exit(EXIT_FAILURE);
                }

                r = setenv_systemd_log_level();
                if (r < 0)
                        log_warning_errno(r, "Failed to update $SYSTEMD_LOG_LEVEL, ignoring: %m");

                r = setenv_systemd_exec_pid(true);
                if (r < 0)
                        log_warning_errno(r, "Failed to update $SYSTEMD_EXEC_PID, ignoring: %m");

                switch (t->type) {

                case TRANSFER_IMPORT_TAR:
                case TRANSFER_IMPORT_RAW:
                        cmd[k++] = SYSTEMD_IMPORT_PATH;
                        break;

                case TRANSFER_IMPORT_FS:
                        cmd[k++] = SYSTEMD_IMPORT_FS_PATH;
                        break;

                case TRANSFER_EXPORT_TAR:
                case TRANSFER_EXPORT_RAW:
                        cmd[k++] = SYSTEMD_EXPORT_PATH;
                        break;

                case TRANSFER_PULL_TAR:
                case TRANSFER_PULL_RAW:
                        cmd[k++] = SYSTEMD_PULL_PATH;
                        break;

                default:
                        assert_not_reached();
                }

                switch (t->type) {

                case TRANSFER_IMPORT_TAR:
                case TRANSFER_EXPORT_TAR:
                case TRANSFER_PULL_TAR:
                        cmd[k++] = "tar";
                        break;

                case TRANSFER_IMPORT_RAW:
                case TRANSFER_EXPORT_RAW:
                case TRANSFER_PULL_RAW:
                        cmd[k++] = "raw";
                        break;

                case TRANSFER_IMPORT_FS:
                        cmd[k++] = "run";
                        break;

                default:
                        ;
                }

                cmd[k++] = runtime_scope_cmdline_option_to_string(t->manager->runtime_scope);

                if (t->verify != _IMPORT_VERIFY_INVALID) {
                        cmd[k++] = "--verify";
                        cmd[k++] = import_verify_to_string(t->verify);
                }

                if (t->class != IMAGE_MACHINE) {
                        cmd[k++] = "--class";
                        cmd[k++] = image_class_to_string(t->class);
                }

                if (IN_SET(t->type, TRANSFER_PULL_TAR, TRANSFER_PULL_RAW))
                        cmd[k++] = FLAGS_SET(t->flags, IMPORT_PULL_KEEP_DOWNLOAD) ?
                                "--keep-download=yes" : "--keep-download=no";

                if (FLAGS_SET(t->flags, IMPORT_FORCE))
                        cmd[k++] = "--force";
                if (FLAGS_SET(t->flags, IMPORT_READ_ONLY))
                        cmd[k++] = "--read-only";

                if (t->format) {
                        cmd[k++] = "--format";
                        cmd[k++] = t->format;
                }

                if (t->image_root) {
                        cmd[k++] = "--image-root";
                        cmd[k++] = t->image_root;
                }

                if (!IN_SET(t->type, TRANSFER_EXPORT_TAR, TRANSFER_EXPORT_RAW)) {
                        if (t->remote)
                                cmd[k++] = t->remote;
                        else
                                cmd[k++] = "-";
                }

                if (t->local)
                        cmd[k++] = t->local;
                cmd[k] = NULL;

                assert(k < ELEMENTSOF(cmd));

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *joined = strv_join((char**) cmd, " ");
                        log_debug("Calling: %s", strnull(joined));
                }

                r = invoke_callout_binary(cmd[0], (char * const *) cmd);
                log_error_errno(r, "Failed to execute %s tool: %m", cmd[0]);
                _exit(EXIT_FAILURE);
        }

        pipefd[1] = safe_close(pipefd[1]);
        t->log_fd = TAKE_FD(pipefd[0]);

        t->stdin_fd = safe_close(t->stdin_fd);

        r = event_add_child_pidref(
                        t->manager->event,
                        &t->pid_event_source,
                        &t->pidref,
                        WEXITED,
                        transfer_on_pid,
                        t);
        if (r < 0)
                return r;

        r = sd_event_add_io(t->manager->event, &t->log_event_source,
                            t->log_fd, EPOLLIN, transfer_on_log, t);
        if (r < 0)
                return r;

        /* Make sure always process logging before child exit */
        r = sd_event_source_set_priority(t->log_event_source, SD_EVENT_PRIORITY_NORMAL -5);
        if (r < 0)
                return r;

        r = sd_bus_emit_signal(
                        t->manager->api_bus,
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "TransferNew",
                        "uo",
                        t->id,
                        t->object_path);
        if (r < 0)
                return r;

        return 0;
}

static Manager *manager_unref(Manager *m) {
        Transfer *t;

        if (!m)
                return NULL;

        free(m->notify_socket_path);

        while ((t = hashmap_first(m->transfers)))
                transfer_unref(t);

        hashmap_free(m->transfers);

        hashmap_free(m->polkit_registry);

        m->api_bus = sd_bus_flush_close_unref(m->api_bus);
        m->system_bus = sd_bus_flush_close_unref(m->system_bus);
        m->varlink_server = sd_varlink_server_unref(m->varlink_server);

        sd_event_unref(m->event);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

static int manager_on_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        _cleanup_free_ char *buf = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = notify_recv(fd, &buf, /* ret_ucred= */ NULL, &pidref);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        Transfer *t;
        HASHMAP_FOREACH(t, m->transfers)
                if (pidref_equal(&pidref, &t->pidref))
                        break;
        if (!t) {
                log_warning("Got notification datagram from unexpected peer, ignoring.");
                return 0;
        }

        char *p = find_line_startswith(buf, "X_IMPORT_PROGRESS=");
        if (!p)
                return 0;

        truncate_nl(p);

        r = parse_percent(p);
        if (r < 0) {
                log_warning("Got invalid percent value '%s', ignoring.", p);
                return 0;
        }

        t->progress_percent = (unsigned) r;

        log_debug("Got percentage from client: %u%%", t->progress_percent);

        transfer_send_progress_update(t);
        return 0;
}

static int manager_new(RuntimeScope scope, Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .use_btrfs_subvol = true,
                .use_btrfs_quota = true,
                .runtime_scope = scope,
        };

        r = sd_event_default(&m->event);
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
                log_debug_errno(r, "Failed to enable watchdog logic, ignoring: %m");

        r = notify_socket_prepare(
                        m->event,
                        SD_EVENT_PRIORITY_NORMAL - 1, /* Make this processed before child exit. */
                        manager_on_notify,
                        m,
                        &m->notify_socket_path);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

static Transfer *manager_find(Manager *m, TransferType type, const char *remote) {
        Transfer *t;

        assert(m);
        assert(type >= 0);
        assert(type < _TRANSFER_TYPE_MAX);

        HASHMAP_FOREACH(t, m->transfers)
                if (t->type == type && streq_ptr(t->remote, remote))
                        return t;

        return NULL;
}

static int method_import_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        ImageClass class = _IMAGE_CLASS_INVALID;
        Manager *m = ASSERT_PTR(userdata);
        const char *local;
        TransferType type;
        struct stat st;
        uint64_t flags;
        int fd, r;

        assert(msg);

        if (m->runtime_scope != RUNTIME_SCOPE_USER) {
                r = bus_verify_polkit_async(
                                msg,
                                "org.freedesktop.import1.import",
                                /* details= */ NULL,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        if (endswith(sd_bus_message_get_member(msg), "Ex")) {
                const char *sclass;

                r = sd_bus_message_read(msg, "hsst", &fd, &local, &sclass, &flags);
                if (r < 0)
                        return r;

                class = image_class_from_string(sclass);
                if (class < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image class '%s' not known", sclass);

                if (flags & ~(IMPORT_READ_ONLY|IMPORT_FORCE))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Flags 0x%" PRIx64 " invalid", flags);
        } else {
                int force, read_only;

                r = sd_bus_message_read(msg, "hsbb", &fd, &local, &force, &read_only);
                if (r < 0)
                        return r;

                class = IMAGE_MACHINE;

                flags = 0;
                SET_FLAG(flags, IMPORT_FORCE, force);
                SET_FLAG(flags, IMPORT_READ_ONLY, read_only);
        }

        r = fd_verify_safe_flags(fd);
        if (r < 0)
                return r;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode))
                return -EINVAL;

        if (!image_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local image name %s is invalid", local);

        if (class == IMAGE_MACHINE) {
                r = image_setup_pool(m->runtime_scope, class, m->use_btrfs_subvol, m->use_btrfs_quota);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to set up machine pool: %m");
        }

        type = startswith(sd_bus_message_get_member(msg), "ImportTar") ?
                TRANSFER_IMPORT_TAR : TRANSFER_IMPORT_RAW;

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = type;
        t->class = class;
        t->flags = flags;

        t->local = strdup(local);
        if (!t->local)
                return -ENOMEM;

        t->stdin_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (t->stdin_fd < 0)
                return -errno;

        r = transfer_start(t);
        if (r < 0)
                return r;

        r = sd_bus_reply_method_return(msg, "uo", t->id, t->object_path);
        if (r < 0)
                return r;

        TAKE_PTR(t);
        return 1;
}

static int method_import_fs(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        ImageClass class = _IMAGE_CLASS_INVALID;
        Manager *m = ASSERT_PTR(userdata);
        const char *local;
        uint64_t flags;
        int fd, r;

        assert(msg);

        if (m->runtime_scope != RUNTIME_SCOPE_USER) {
                r = bus_verify_polkit_async(
                                msg,
                                "org.freedesktop.import1.import",
                                /* details= */ NULL,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        if (endswith(sd_bus_message_get_member(msg), "Ex")) {
                const char *sclass;

                r = sd_bus_message_read(msg, "hsst", &fd, &local, &sclass, &flags);
                if (r < 0)
                        return r;

                class = image_class_from_string(sclass);
                if (class < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image class '%s' not known", sclass);

                if (flags & ~(IMPORT_READ_ONLY|IMPORT_FORCE))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Flags 0x%" PRIx64 " invalid", flags);
        } else {
                int force, read_only;

                r = sd_bus_message_read(msg, "hsbb", &fd, &local, &force, &read_only);
                if (r < 0)
                        return r;

                class = IMAGE_MACHINE;

                flags = 0;
                SET_FLAG(flags, IMPORT_FORCE, force);
                SET_FLAG(flags, IMPORT_READ_ONLY, read_only);
        }

        r = fd_verify_safe_flags_full(fd, O_DIRECTORY);
        if (r < 0)
                return r;

        r = fd_verify_directory(fd);
        if (r < 0)
                return r;

        if (!image_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local image name %s is invalid", local);

        if (class == IMAGE_MACHINE) {
                r = image_setup_pool(m->runtime_scope, class, m->use_btrfs_subvol, m->use_btrfs_quota);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to set up machine pool: %m");
        }

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = TRANSFER_IMPORT_FS;
        t->class = class;
        t->flags = flags;

        t->local = strdup(local);
        if (!t->local)
                return -ENOMEM;

        t->stdin_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (t->stdin_fd < 0)
                return -errno;

        r = transfer_start(t);
        if (r < 0)
                return r;

        r = sd_bus_reply_method_return(msg, "uo", t->id, t->object_path);
        if (r < 0)
                return r;

        TAKE_PTR(t);
        return 1;
}

static int method_export_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        ImageClass class = _IMAGE_CLASS_INVALID;
        Manager *m = ASSERT_PTR(userdata);
        const char *local, *format;
        TransferType type;
        uint64_t flags;
        struct stat st;
        int fd, r;

        assert(msg);

        if (m->runtime_scope != RUNTIME_SCOPE_USER) {
                r = bus_verify_polkit_async(
                                msg,
                                "org.freedesktop.import1.export",
                                /* details= */ NULL,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        if (endswith(sd_bus_message_get_member(msg), "Ex")) {
                const char *sclass;

                r = sd_bus_message_read(msg, "sshst", &local, &sclass, &fd, &format, &flags);
                if (r < 0)
                        return r;

                class = image_class_from_string(sclass);
                if (class < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image class '%s' not known", sclass);

                if (flags != 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Flags 0x%" PRIx64 " invalid", flags);
        } else {
                r = sd_bus_message_read(msg, "shs", &local, &fd, &format);
                if (r < 0)
                        return r;

                class = IMAGE_MACHINE;
                flags = 0;
        }

        if (!image_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local image name %s is invalid", local);

        r = fd_verify_safe_flags(fd);
        if (r < 0)
                return r;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode))
                return -EINVAL;

        type = startswith(sd_bus_message_get_member(msg), "ExportTar") ?
                TRANSFER_EXPORT_TAR : TRANSFER_EXPORT_RAW;

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = type;
        t->class = class;
        t->flags = flags;

        if (!isempty(format)) {
                t->format = strdup(format);
                if (!t->format)
                        return -ENOMEM;
        }

        t->local = strdup(local);
        if (!t->local)
                return -ENOMEM;

        t->stdout_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (t->stdout_fd < 0)
                return -errno;

        r = transfer_start(t);
        if (r < 0)
                return r;

        r = sd_bus_reply_method_return(msg, "uo", t->id, t->object_path);
        if (r < 0)
                return r;

        TAKE_PTR(t);
        return 1;
}

static int method_pull_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        ImageClass class = _IMAGE_CLASS_INVALID;
        const char *remote, *local, *verify;
        Manager *m = ASSERT_PTR(userdata);
        TransferType type;
        uint64_t flags;
        ImportVerify v;
        int r;

        assert(msg);

        if (m->runtime_scope != RUNTIME_SCOPE_USER) {
                r = bus_verify_polkit_async(
                                msg,
                                "org.freedesktop.import1.pull",
                                /* details= */ NULL,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* Will call us back */
        }

        if (endswith(sd_bus_message_get_member(msg), "Ex")) {
                const char *sclass;

                r = sd_bus_message_read(msg, "sssst", &remote, &local, &sclass, &verify, &flags);
                if (r < 0)
                        return r;

                class = image_class_from_string(sclass);
                if (class < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image class '%s' not known", sclass);

                if (flags & ~(IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_PULL_KEEP_DOWNLOAD))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Flags 0x%" PRIx64 " invalid", flags);
        } else {
                int force;

                r = sd_bus_message_read(msg, "sssb", &remote, &local, &verify, &force);
                if (r < 0)
                        return r;

                class = IMAGE_MACHINE;

                flags = 0;
                SET_FLAG(flags, IMPORT_FORCE, force);
        }

        if (!http_url_is_valid(remote) && !file_url_is_valid(remote))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "URL %s is invalid", remote);

        if (isempty(local))
                local = NULL;
        else if (!image_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local image name %s is invalid", local);

        if (isempty(verify))
                v = IMPORT_VERIFY_SIGNATURE;
        else
                v = import_verify_from_string(verify);
        if (v < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Unknown verification mode %s", verify);

        if (class == IMAGE_MACHINE) {
                r = image_setup_pool(m->runtime_scope, class, m->use_btrfs_subvol, m->use_btrfs_quota);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to set up machine pool: %m");
        }

        type = startswith(sd_bus_message_get_member(msg), "PullTar") ?
                TRANSFER_PULL_TAR : TRANSFER_PULL_RAW;

        if (manager_find(m, type, remote))
                return sd_bus_error_setf(error, BUS_ERROR_TRANSFER_IN_PROGRESS,
                                         "Transfer for %s already in progress.", remote);

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = type;
        t->verify = v;
        t->flags = flags;
        t->class = class;

        t->remote = strdup(remote);
        if (!t->remote)
                return -ENOMEM;

        if (local) {
                t->local = strdup(local);
                if (!t->local)
                        return -ENOMEM;
        }

        r = transfer_start(t);
        if (r < 0)
                return r;

        r = sd_bus_reply_method_return(msg, "uo", t->id, t->object_path);
        if (r < 0)
                return r;

        TAKE_PTR(t);
        return 1;
}

static int method_list_transfers(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        ImageClass class = _IMAGE_CLASS_INVALID;
        Transfer *t;
        int r;

        assert(msg);

        bool ex = endswith(sd_bus_message_get_member(msg), "Ex");
        if (ex) {
                const char *sclass;
                uint64_t flags;

                r = sd_bus_message_read(msg, "st", &sclass, &flags);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (!isempty(sclass)) {
                        class = image_class_from_string(sclass);
                        if (class < 0)
                                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                         "Image class '%s' not known", sclass);
                }

                if (flags != 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Flags 0x%" PRIx64 " invalid", flags);
        }

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        if (ex)
                r = sd_bus_message_open_container(reply, 'a', "(ussssdo)");
        else
                r = sd_bus_message_open_container(reply, 'a', "(usssdo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(t, m->transfers) {

                if (class >= 0 && class != t->class)
                        continue;

                if (ex)
                        r = sd_bus_message_append(
                                        reply,
                                        "(ussssdo)",
                                        t->id,
                                        transfer_type_to_string(t->type),
                                        t->remote,
                                        t->local,
                                        image_class_to_string(t->class),
                                        transfer_percent_as_double(t),
                                        t->object_path);
                else
                        r = sd_bus_message_append(
                                        reply,
                                        "(usssdo)",
                                        t->id,
                                        transfer_type_to_string(t->type),
                                        t->remote,
                                        t->local,
                                        transfer_percent_as_double(t),
                                        t->object_path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_cancel(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Transfer *t = ASSERT_PTR(userdata);
        int r;

        assert(msg);

        r = bus_verify_polkit_async(
                        msg,
                        "org.freedesktop.import1.pull",
                        /* details= */ NULL,
                        &t->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = transfer_cancel(t);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(msg, NULL);
}

static int method_cancel_transfer(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Transfer *t;
        uint32_t id;
        int r;

        assert(msg);

        r = bus_verify_polkit_async(
                        msg,
                        "org.freedesktop.import1.cancel",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(msg, "u", &id);
        if (r < 0)
                return r;
        if (id <= 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid transfer id");

        t = hashmap_get(m->transfers, UINT32_TO_PTR(id));
        if (!t)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_TRANSFER, "No transfer by id %" PRIu32, id);

        r = transfer_cancel(t);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(msg, NULL);
}

static int method_list_images(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        ImageClass class = _IMAGE_CLASS_INVALID;
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(msg);

        const char *sclass;
        uint64_t flags;

        r = sd_bus_message_read(msg, "st", &sclass, &flags);
        if (r < 0)
                return r;

        if (!isempty(sclass)) {
                class = image_class_from_string(sclass);
                if (class < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Image class '%s' not known", sclass);
        }

        if (flags != 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Flags 0x%" PRIx64 " invalid", flags);

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssbtttttt)");
        if (r < 0)
                return r;

        for (ImageClass c = class < 0 ? 0 : class;
             class < 0 ? (c < _IMAGE_CLASS_MAX) : (c == class);
             c++) {

                _cleanup_hashmap_free_ Hashmap *images = NULL;

                r = image_discover(m->runtime_scope, c, /* root= */ NULL, &images);
                if (r < 0) {
                        if (class >= 0)
                                return r;

                        log_warning_errno(r, "Failed to discover images of type %s: %m", image_class_to_string(c));
                        continue;
                }

                Image *i;
                HASHMAP_FOREACH(i, images) {
                        r = sd_bus_message_append(
                                        reply,
                                        "(ssssbtttttt)",
                                        image_class_to_string(i->class),
                                        i->name,
                                        image_type_to_string(i->type),
                                        i->path,
                                        image_is_read_only(i),
                                        i->crtime,
                                        i->mtime,
                                        i->usage,
                                        i->usage_exclusive,
                                        i->limit,
                                        i->limit_exclusive);
                        if (r < 0)
                                return r;
                }
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int property_get_progress(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Transfer *t = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "d", transfer_percent_as_double(t));
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, transfer_type, TransferType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_verify, import_verify, ImportVerify);

static int transfer_object_find(
                sd_bus *bus,
                const char *path,
                const char *interface,
                void *userdata,
                void **found,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Transfer *t;
        const char *p;
        uint32_t id;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        p = startswith(path, "/org/freedesktop/import1/transfer/_");
        if (!p)
                return 0;

        r = safe_atou32(p, &id);
        if (r < 0 || id == 0)
                return 0;

        t = hashmap_get(m->transfers, UINT32_TO_PTR(id));
        if (!t)
                return 0;

        *found = t;
        return 1;
}

static int transfer_node_enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***nodes,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        Transfer *t;
        unsigned k = 0;

        l = new0(char*, hashmap_size(m->transfers) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(t, m->transfers) {

                l[k] = strdup(t->object_path);
                if (!l[k])
                        return -ENOMEM;

                k++;
        }

        *nodes = TAKE_PTR(l);

        return 1;
}

static const sd_bus_vtable transfer_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "u", NULL, offsetof(Transfer, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Local", "s", NULL, offsetof(Transfer, local), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Remote", "s", NULL, offsetof(Transfer, remote), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Type", "s", property_get_type, offsetof(Transfer, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Verify", "s", property_get_verify, offsetof(Transfer, verify), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Progress", "d", property_get_progress, 0, 0),

        SD_BUS_METHOD("Cancel", NULL, NULL, method_cancel, SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_NAMES("LogMessage",
                                 "us",
                                 SD_BUS_PARAM(priority)
                                 SD_BUS_PARAM(line),
                                 0),
        SD_BUS_SIGNAL_WITH_NAMES("ProgressUpdate",
                                 "d",
                                 SD_BUS_PARAM(progress),
                                 0),

        SD_BUS_VTABLE_END,
};

static const BusObjectImplementation transfer_object = {
        "/org/freedesktop/import1/transfer",
        "org.freedesktop.import1.Transfer",
        .fallback_vtables = BUS_FALLBACK_VTABLES({transfer_vtable, transfer_object_find}),
        .node_enumerator = transfer_node_enumerator,
};

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD_WITH_NAMES("ImportTar",
                                 "hsbb",
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(force)
                                 SD_BUS_PARAM(read_only),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_import_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ImportTarEx",
                                 "hsst",
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_import_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ImportRaw",
                                 "hsbb",
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(force)
                                 SD_BUS_PARAM(read_only),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_import_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ImportRawEx",
                                 "hsst",
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_import_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ImportFileSystem",
                                 "hsbb",
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(force)
                                 SD_BUS_PARAM(read_only),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_import_fs,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ImportFileSystemEx",
                                 "hsst",
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_import_fs,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ExportTar",
                                 "shs",
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(format),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_export_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ExportTarEx",
                                 "sshst",
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(format)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_export_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ExportRaw",
                                 "shs",
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(format),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_export_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ExportRawEx",
                                 "sshst",
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(fd)
                                 SD_BUS_PARAM(format)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_export_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("PullTar",
                                 "sssb",
                                 SD_BUS_PARAM(url)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(verify_mode)
                                 SD_BUS_PARAM(force),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_pull_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("PullTarEx",
                                 "sssst",
                                 SD_BUS_PARAM(url)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(verify_mode)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_pull_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("PullRaw",
                                 "sssb",
                                 SD_BUS_PARAM(url)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(verify_mode)
                                 SD_BUS_PARAM(force),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_pull_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("PullRawEx",
                                 "sssst",
                                 SD_BUS_PARAM(url)
                                 SD_BUS_PARAM(local_name)
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(verify_mode)
                                 SD_BUS_PARAM(flags),
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 method_pull_tar_or_raw,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ListTransfers",
                                 NULL,,
                                 "a(usssdo)",
                                 SD_BUS_PARAM(transfers),
                                 method_list_transfers,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ListTransfersEx",
                                 "st",
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(flags),
                                 "a(ussssdo)",
                                 SD_BUS_PARAM(transfers),
                                 method_list_transfers,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("CancelTransfer",
                                 "u",
                                 SD_BUS_PARAM(transfer_id),
                                 NULL,,
                                 method_cancel_transfer,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("ListImages",
                                 "st",
                                 SD_BUS_PARAM(class)
                                 SD_BUS_PARAM(flags),
                                 "a(ssssbtttttt)",
                                 SD_BUS_PARAM(images),
                                 method_list_images,
                                 SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_NAMES("TransferNew",
                                 "uo",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path),
                                 0),
        SD_BUS_SIGNAL_WITH_NAMES("TransferRemoved",
                                 "uos",
                                 SD_BUS_PARAM(transfer_id)
                                 SD_BUS_PARAM(transfer_path)
                                 SD_BUS_PARAM(result),
                                 0),

        SD_BUS_VTABLE_END,
};

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/import1",
        "org.freedesktop.import1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS(&transfer_object),
};

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->system_bus);
        assert(!m->api_bus);

        r = bus_open_system_watch_bind(&m->system_bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = sd_bus_attach_event(m->system_bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach system bus to event loop: %m");

        if (m->runtime_scope == RUNTIME_SCOPE_SYSTEM)
                m->api_bus = sd_bus_ref(m->system_bus);
        else {
                assert(m->runtime_scope == RUNTIME_SCOPE_USER);

                r = sd_bus_default_user(&m->api_bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to get user bus connection: %m");

                r = sd_bus_attach_event(m->api_bus, m->event, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach user bus to event loop: %m");
        }

        r = bus_add_implementation(m->api_bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->api_bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->api_bus, NULL, "org.freedesktop.import1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_image_class, ImageClass, image_class_from_string);

static int make_transfer_json(Transfer *t, sd_json_variant **ret) {
        int r;

        assert(t);

        r = sd_json_buildo(ret,
                           SD_JSON_BUILD_PAIR_UNSIGNED("id", t->id),
                           SD_JSON_BUILD_PAIR("type", JSON_BUILD_STRING_UNDERSCORIFY(transfer_type_to_string(t->type))),
                           SD_JSON_BUILD_PAIR_STRING("remote", t->remote),
                           SD_JSON_BUILD_PAIR_STRING("local", t->local),
                           SD_JSON_BUILD_PAIR("class", JSON_BUILD_STRING_UNDERSCORIFY(image_class_to_string(t->class))),
                           SD_JSON_BUILD_PAIR_REAL("percent", transfer_percent_as_double(t)));
        if (r < 0)
                return log_error_errno(r, "Failed to build transfer JSON data: %m");

        return 0;
}

static int vl_method_list_transfers(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        struct p {
                ImageClass class;
        } p = {
                .class = _IMAGE_CLASS_INVALID,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "class", SD_JSON_VARIANT_STRING, json_dispatch_image_class, offsetof(struct p, class), 0 },
                {},
        };

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = varlink_set_sentinel(link, "io.systemd.Import.NoTransfers");
        if (r < 0)
                return r;

        Transfer *t;
        HASHMAP_FOREACH(t, m->transfers) {
                if (p.class >= 0 && p.class != t->class)
                        continue;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = make_transfer_json(t, &v);
                if (r < 0)
                        return r;

                r = sd_varlink_reply(link, v);
                if (r < 0)
                        return r;
        }

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_import_verify, ImportVerify, import_verify_from_string);
static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_import_type, ImportType, import_type_from_string);

static int vl_method_pull(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        struct p {
                const char *remote, *local;
                ImageClass class;
                ImportType type;
                ImportVerify verify;
                bool force;
                bool read_only;
                bool keep_download;
                const char *image_root;
        } p = {
                .class = _IMAGE_CLASS_INVALID,
                .verify = IMPORT_VERIFY_SIGNATURE,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "remote",       SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(struct p, remote),        SD_JSON_MANDATORY },
                { "local",        SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(struct p, local),         0                 },
                { "class",        SD_JSON_VARIANT_STRING,  json_dispatch_image_class,     offsetof(struct p, class),         SD_JSON_MANDATORY },
                { "type",         SD_JSON_VARIANT_STRING,  json_dispatch_import_type,     offsetof(struct p, type),          SD_JSON_MANDATORY },
                { "verify",       SD_JSON_VARIANT_STRING,  json_dispatch_import_verify,   offsetof(struct p, verify),        SD_JSON_STRICT    },
                { "force",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(struct p, force),         0                 },
                { "readOnly",     SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(struct p, read_only),     0                 },
                { "keepDownload", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(struct p, keep_download), 0                 },
                { "imageRoot",    SD_JSON_VARIANT_STRING,  json_dispatch_const_path,      offsetof(struct p, image_root),    SD_JSON_STRICT    },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!http_url_is_valid(p.remote) && !file_url_is_valid(p.remote))
                return sd_varlink_error_invalid_parameter_name(link, "remote");

        if (p.local && !image_name_is_valid(p.local))
                return sd_varlink_error_invalid_parameter_name(link, "local");

        uint64_t transfer_flags = (p.force * IMPORT_FORCE) | (p.read_only * IMPORT_READ_ONLY) | (p.keep_download * IMPORT_PULL_KEEP_DOWNLOAD);

        TransferType tt =
                p.type == IMPORT_TAR ? TRANSFER_PULL_TAR :
                p.type == IMPORT_RAW ? TRANSFER_PULL_RAW : _TRANSFER_TYPE_INVALID;

        assert(tt >= 0);

        if (manager_find(m, tt, p.remote))
                return sd_varlink_errorbo(link, "io.systemd.Import.AlreadyInProgress", SD_JSON_BUILD_PAIR_STRING("remote", p.remote));

        if (m->runtime_scope != RUNTIME_SCOPE_USER) {
                r = varlink_verify_polkit_async(
                                link,
                                m->system_bus,
                                "org.freedesktop.import1.pull",
                                (const char**) STRV_MAKE(
                                                "remote", p.remote,
                                                "local",  p.local,
                                                "class",  image_class_to_string(p.class),
                                                "type",   import_type_to_string(p.type),
                                                "verify", import_verify_to_string(p.verify)),
                                &m->polkit_registry);
                if (r <= 0)
                        return r;
        }

        _cleanup_(transfer_unrefp) Transfer *t = NULL;

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = tt;
        t->verify = p.verify;
        t->flags = transfer_flags;
        t->class = p.class;

        t->remote = strdup(p.remote);
        if (!t->remote)
                return -ENOMEM;

        if (p.local) {
                t->local = strdup(p.local);
                if (!t->local)
                        return -ENOMEM;
        }

        if (p.image_root) {
                t->image_root = strdup(p.image_root);
                if (!t->image_root)
                        return -ENOMEM;
        }

        r = transfer_start(t);
        if (r < 0)
                return r;

        /* If more was not set, just return the download id, and be done with it */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_UNSIGNED("id", t->id));

        /* Otherwise add this connection to the set of subscriptions, return the id, but keep the thing running */
        r = set_ensure_put(&t->varlink_subscribed, &varlink_hash_ops, link);
        if (r < 0)
                return r;

        sd_varlink_ref(link);

        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_UNSIGNED("id", t->id));
        if (r < 0)
                return r;

        TAKE_PTR(t);
        return 0;
}

static int manager_connect_varlink(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->varlink_server);

        r = varlink_server_new(
                        &m->varlink_server,
                        (m->runtime_scope != RUNTIME_SCOPE_USER ? SD_VARLINK_SERVER_ACCOUNT_UID : 0)|
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_Import,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Import interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.Import.ListTransfers",   vl_method_list_transfers,
                        "io.systemd.Import.Pull",            vl_method_pull,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method calls: %m");

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        r = sd_varlink_server_listen_auto(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0) {
                _cleanup_free_ char *socket_path = NULL;
                r = runtime_directory_generic(m->runtime_scope, "systemd/io.systemd.Import", &socket_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine socket path: %m");

                r = sd_varlink_server_listen_address(m->varlink_server, socket_path, runtime_scope_to_socket_mode(m->runtime_scope) | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to Varlink socket: %m");
        }

        return 0;
}

static bool manager_check_idle(void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return hashmap_isempty(m->transfers) &&
                hashmap_isempty(m->polkit_registry) &&
                sd_varlink_server_current_connections(m->varlink_server) == 0;
}

static void manager_parse_env(Manager *m) {
        int r;

        assert(m);

        /* Same as src/import/{import,pull}.c:
         * Let's make these relatively low-level settings also controllable via env vars. User can then set
         * them for systemd-importd.service if they like to tweak behaviour */

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_SUBVOL");
        if (r >= 0)
                m->use_btrfs_subvol = r;
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_SUBVOL: %m");

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_QUOTA");
        if (r >= 0)
                m->use_btrfs_quota = r;
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_QUOTA: %m");
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        RuntimeScope scope = RUNTIME_SCOPE_SYSTEM;
        int r;

        log_setup();

        r = service_parse_argv("systemd-importd.service",
                               "VM and container image import and export service.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               &scope,
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = manager_new(scope, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        manager_parse_env(m);

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = manager_connect_varlink(m);
        if (r < 0)
                return r;

        r = sd_notify(false, NOTIFY_READY_MESSAGE);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(
                        m->event,
                        m->api_bus,
                        "org.freedesktop.import1",
                        DEFAULT_EXIT_USEC,
                        manager_check_idle,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

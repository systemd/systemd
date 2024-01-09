/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/prctl.h>
#include <sys/wait.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
#include "common-signal.h"
#include "constants.h"
#include "env-util.h"
#include "fd-util.h"
#include "float.h"
#include "hostname-util.h"
#include "import-util.h"
#include "machine-pool.h"
#include "main-func.h"
#include "missing_capability.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "syslog-util.h"
#include "user-util.h"
#include "web-util.h"

typedef struct Transfer Transfer;
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

struct Transfer {
        Manager *manager;

        uint32_t id;
        char *object_path;

        TransferType type;
        ImportVerify verify;

        char *remote;
        char *local;
        bool force_local;
        bool read_only;

        char *format;

        pid_t pid;

        int log_fd;

        char log_message[LINE_MAX];
        size_t log_message_size;

        sd_event_source *pid_event_source;
        sd_event_source *log_event_source;

        unsigned n_canceled;
        unsigned progress_percent;

        int stdin_fd;
        int stdout_fd;
};

struct Manager {
        sd_event *event;
        sd_bus *bus;

        uint32_t current_transfer_id;
        Hashmap *transfers;

        Hashmap *polkit_registry;

        int notify_fd;

        sd_event_source *notify_event_source;

        bool use_btrfs_subvol;
        bool use_btrfs_quota;
};

#define TRANSFERS_MAX 64

static const char* const transfer_type_table[_TRANSFER_TYPE_MAX] = {
        [TRANSFER_IMPORT_TAR] = "import-tar",
        [TRANSFER_IMPORT_RAW] = "import-raw",
        [TRANSFER_IMPORT_FS] = "import-fs",
        [TRANSFER_EXPORT_TAR] = "export-tar",
        [TRANSFER_EXPORT_RAW] = "export-raw",
        [TRANSFER_PULL_TAR] = "pull-tar",
        [TRANSFER_PULL_RAW] = "pull-raw",
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
        free(t->object_path);

        if (t->pid > 1)
                sigkill_wait(t->pid);

        safe_close(t->log_fd);
        safe_close(t->stdin_fd);
        safe_close(t->stdout_fd);

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
                .progress_percent= UINT_MAX,
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
                        t->manager->bus,
                        t->object_path,
                        "org.freedesktop.import1.Transfer",
                        "LogMessage",
                        "us",
                        priority,
                        line);
        if (r < 0)
                log_warning_errno(r, "Cannot emit log message signal, ignoring: %m");
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
                        t->manager->bus,
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

        transfer_unref(t);
        return 0;
}

static int transfer_cancel(Transfer *t) {
        int r;

        assert(t);

        r = kill_and_sigcont(t->pid, t->n_canceled < 3 ? SIGTERM : SIGKILL);
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

        t->pid = 0;

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
                 * close the watch, waiting for the SIGCHLD to arrive,
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
        assert(t->pid <= 0);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return -errno;

        r = safe_fork_full("(sd-transfer)",
                           (int[]) { t->stdin_fd, t->stdout_fd < 0 ? pipefd[1] : t->stdout_fd, pipefd[1] },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO, &t->pid);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *cmd[] = {
                        NULL, /* systemd-import, systemd-import-fs, systemd-export or systemd-pull */
                        NULL, /* tar, raw  */
                        NULL, /* --verify= */
                        NULL, /* verify argument */
                        NULL, /* maybe --force */
                        NULL, /* maybe --read-only */
                        NULL, /* if so: the actual URL */
                        NULL, /* maybe --format= */
                        NULL, /* if so: the actual format */
                        NULL, /* remote */
                        NULL, /* local */
                        NULL
                };
                unsigned k = 0;

                /* Child */

                if (setenv("SYSTEMD_LOG_TARGET", "console-prefixed", 1) < 0 ||
                    setenv("NOTIFY_SOCKET", "/run/systemd/import/notify", 1) < 0) {
                        log_error_errno(errno, "setenv() failed: %m");
                        _exit(EXIT_FAILURE);
                }

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
                        break;
                }

                if (t->verify != _IMPORT_VERIFY_INVALID) {
                        cmd[k++] = "--verify";
                        cmd[k++] = import_verify_to_string(t->verify);
                }

                if (t->force_local)
                        cmd[k++] = "--force";
                if (t->read_only)
                        cmd[k++] = "--read-only";

                if (t->format) {
                        cmd[k++] = "--format";
                        cmd[k++] = t->format;
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

                execv(cmd[0], (char * const *) cmd);
                log_error_errno(errno, "Failed to execute %s tool: %m", cmd[0]);
                _exit(EXIT_FAILURE);
        }

        pipefd[1] = safe_close(pipefd[1]);
        t->log_fd = TAKE_FD(pipefd[0]);

        t->stdin_fd = safe_close(t->stdin_fd);

        r = sd_event_add_child(t->manager->event, &t->pid_event_source,
                               t->pid, WEXITED, transfer_on_pid, t);
        if (r < 0)
                return r;

        r = sd_event_add_io(t->manager->event, &t->log_event_source,
                            t->log_fd, EPOLLIN, transfer_on_log, t);
        if (r < 0)
                return r;

        /* Make sure always process logging before SIGCHLD */
        r = sd_event_source_set_priority(t->log_event_source, SD_EVENT_PRIORITY_NORMAL -5);
        if (r < 0)
                return r;

        r = sd_bus_emit_signal(
                        t->manager->bus,
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

        sd_event_source_unref(m->notify_event_source);
        safe_close(m->notify_fd);

        while ((t = hashmap_first(m->transfers)))
                transfer_unref(t);

        hashmap_free(m->transfers);

        hashmap_free(m->polkit_registry);

        m->bus = sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

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
        Manager *m = userdata;
        Transfer *t;
        ssize_t n;
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

        HASHMAP_FOREACH(t, m->transfers)
                if (ucred->pid == t->pid)
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

        r = parse_percent(p);
        if (r < 0) {
                log_warning("Got invalid percent value '%s', ignoring.", p);
                return 0;
        }

        t->progress_percent = (unsigned) r;

        log_debug("Got percentage from client: %u%%", t->progress_percent);
        return 0;
}

static int manager_new(Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/import/notify",
        };
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .use_btrfs_subvol = true,
                .use_btrfs_quota = true,
        };

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

        r = sd_event_add_io(m->event, &m->notify_event_source,
                            m->notify_fd, EPOLLIN, manager_on_notify, m);
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
        int fd, force, read_only, r;
        const char *local, *object;
        Manager *m = ASSERT_PTR(userdata);
        TransferType type;
        struct stat st;
        uint32_t id;

        assert(msg);

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

        r = sd_bus_message_read(msg, "hsbb", &fd, &local, &force, &read_only);
        if (r < 0)
                return r;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode))
                return -EINVAL;

        if (!hostname_is_valid(local, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local name %s is invalid", local);

        r = setup_machine_directory(error, m->use_btrfs_subvol, m->use_btrfs_quota);
        if (r < 0)
                return r;

        type = streq_ptr(sd_bus_message_get_member(msg), "ImportTar") ?
                TRANSFER_IMPORT_TAR : TRANSFER_IMPORT_RAW;

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = type;
        t->force_local = force;
        t->read_only = read_only;

        t->local = strdup(local);
        if (!t->local)
                return -ENOMEM;

        t->stdin_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (t->stdin_fd < 0)
                return -errno;

        r = transfer_start(t);
        if (r < 0)
                return r;

        object = t->object_path;
        id = t->id;
        t = NULL;

        return sd_bus_reply_method_return(msg, "uo", id, object);
}

static int method_import_fs(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        int fd, force, read_only, r;
        const char *local, *object;
        Manager *m = ASSERT_PTR(userdata);
        uint32_t id;

        assert(msg);

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

        r = sd_bus_message_read(msg, "hsbb", &fd, &local, &force, &read_only);
        if (r < 0)
                return r;

        r = fd_verify_directory(fd);
        if (r < 0)
                return r;

        if (!hostname_is_valid(local, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local name %s is invalid", local);

        r = setup_machine_directory(error, m->use_btrfs_subvol, m->use_btrfs_quota);
        if (r < 0)
                return r;

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = TRANSFER_IMPORT_FS;
        t->force_local = force;
        t->read_only = read_only;

        t->local = strdup(local);
        if (!t->local)
                return -ENOMEM;

        t->stdin_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (t->stdin_fd < 0)
                return -errno;

        r = transfer_start(t);
        if (r < 0)
                return r;

        object = t->object_path;
        id = t->id;
        t = NULL;

        return sd_bus_reply_method_return(msg, "uo", id, object);
}

static int method_export_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        int fd, r;
        const char *local, *object, *format;
        Manager *m = ASSERT_PTR(userdata);
        TransferType type;
        struct stat st;
        uint32_t id;

        assert(msg);

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

        r = sd_bus_message_read(msg, "shs", &local, &fd, &format);
        if (r < 0)
                return r;

        if (!hostname_is_valid(local, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local name %s is invalid", local);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode))
                return -EINVAL;

        type = streq_ptr(sd_bus_message_get_member(msg), "ExportTar") ?
                TRANSFER_EXPORT_TAR : TRANSFER_EXPORT_RAW;

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = type;

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

        object = t->object_path;
        id = t->id;
        t = NULL;

        return sd_bus_reply_method_return(msg, "uo", id, object);
}

static int method_pull_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        const char *remote, *local, *verify, *object;
        Manager *m = ASSERT_PTR(userdata);
        ImportVerify v;
        TransferType type;
        int force, r;
        uint32_t id;

        assert(msg);

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

        r = sd_bus_message_read(msg, "sssb", &remote, &local, &verify, &force);
        if (r < 0)
                return r;

        if (!http_url_is_valid(remote) && !file_url_is_valid(remote))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "URL %s is invalid", remote);

        if (isempty(local))
                local = NULL;
        else if (!hostname_is_valid(local, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Local name %s is invalid", local);

        if (isempty(verify))
                v = IMPORT_VERIFY_SIGNATURE;
        else
                v = import_verify_from_string(verify);
        if (v < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Unknown verification mode %s", verify);

        r = setup_machine_directory(error, m->use_btrfs_subvol, m->use_btrfs_quota);
        if (r < 0)
                return r;

        type = streq_ptr(sd_bus_message_get_member(msg), "PullTar") ?
                TRANSFER_PULL_TAR : TRANSFER_PULL_RAW;

        if (manager_find(m, type, remote))
                return sd_bus_error_setf(error, BUS_ERROR_TRANSFER_IN_PROGRESS,
                                         "Transfer for %s already in progress.", remote);

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = type;
        t->verify = v;
        t->force_local = force;

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

        object = t->object_path;
        id = t->id;
        t = NULL;

        return sd_bus_reply_method_return(msg, "uo", id, object);
}

static int method_list_transfers(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Transfer *t;
        int r;

        assert(msg);

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssdo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(t, m->transfers) {

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

        return sd_bus_send(NULL, reply, NULL);
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
                        "org.freedesktop.import1.pull",
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
        SD_BUS_METHOD_WITH_NAMES("ListTransfers",
                                 NULL,,
                                 "a(usssdo)",
                                 SD_BUS_PARAM(transfers),
                                 method_list_transfers,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("CancelTransfer",
                                 "u",
                                 SD_BUS_PARAM(transfer_id),
                                 NULL,,
                                 method_cancel_transfer,
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

static int manager_add_bus_objects(Manager *m) {
        int r;

        assert(m);

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.import1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static bool manager_check_idle(void *userdata) {
        Manager *m = userdata;

        return hashmap_isempty(m->transfers);
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
        int r;

        log_setup();

        r = service_parse_argv("systemd-importd.service",
                               "VM and container image import and export service.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGTERM, SIGINT, SIGRTMIN+18, -1) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        manager_parse_env(m);

        r = manager_add_bus_objects(m);
        if (r < 0)
                return r;

        r = sd_notify(false, NOTIFY_READY);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(
                        m->event,
                        m->bus,
                        "org.freedesktop.import1",
                        DEFAULT_EXIT_USEC,
                        manager_check_idle,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/prctl.h>

#include "sd-bus.h"
#include "util.h"
#include "strv.h"
#include "bus-util.h"
#include "bus-common-errors.h"
#include "socket-util.h"
#include "mkdir.h"
#include "def.h"
#include "missing.h"
#include "machine-pool.h"
#include "path-util.h"
#include "import-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "hostname-util.h"

typedef struct Transfer Transfer;
typedef struct Manager Manager;

typedef enum TransferType {
        TRANSFER_IMPORT_TAR,
        TRANSFER_IMPORT_RAW,
        TRANSFER_EXPORT_TAR,
        TRANSFER_EXPORT_RAW,
        TRANSFER_PULL_TAR,
        TRANSFER_PULL_RAW,
        TRANSFER_PULL_DKR,
        _TRANSFER_TYPE_MAX,
        _TRANSFER_TYPE_INVALID = -1,
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

        char *dkr_index_url;
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
};

#define TRANSFERS_MAX 64

static const char* const transfer_type_table[_TRANSFER_TYPE_MAX] = {
        [TRANSFER_IMPORT_TAR] = "import-tar",
        [TRANSFER_IMPORT_RAW] = "import-raw",
        [TRANSFER_EXPORT_TAR] = "export-tar",
        [TRANSFER_EXPORT_RAW] = "export-raw",
        [TRANSFER_PULL_TAR] = "pull-tar",
        [TRANSFER_PULL_RAW] = "pull-raw",
        [TRANSFER_PULL_DKR] = "pull-dkr",
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
        free(t->dkr_index_url);
        free(t->format);
        free(t->object_path);

        if (t->pid > 0) {
                (void) kill_and_sigcont(t->pid, SIGKILL);
                (void) wait_for_terminate(t->pid, NULL);
        }

        safe_close(t->log_fd);
        safe_close(t->stdin_fd);
        safe_close(t->stdout_fd);

        free(t);
        return NULL;
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

        r = hashmap_ensure_allocated(&m->transfers, &trivial_hash_ops);
        if (r < 0)
                return r;

        t = new0(Transfer, 1);
        if (!t)
                return -ENOMEM;

        t->type = _TRANSFER_TYPE_INVALID;
        t->log_fd = -1;
        t->stdin_fd = -1;
        t->verify = _IMPORT_VERIFY_INVALID;

        id = m->current_transfer_id + 1;

        if (asprintf(&t->object_path, "/org/freedesktop/import1/transfer/_%" PRIu32, id) < 0)
                return -ENOMEM;

        r = hashmap_put(m->transfers, UINT32_TO_PTR(id), t);
        if (r < 0)
                return r;

        m->current_transfer_id = id;

        t->manager = m;
        t->id = id;

        *ret = t;
        t = NULL;

        return 0;
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
                log_error_errno(r, "Cannot emit message: %m");
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
                while ((e < t->log_message + t->log_message_size) && (*e == 0 || *e == '\n'))
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
        Transfer *t = userdata;
        bool success = false;

        assert(s);
        assert(t);

        if (si->si_code == CLD_EXITED) {
                if (si->si_status != 0)
                        log_error("Import process failed with exit code %i.", si->si_status);
                else {
                        log_debug("Import process succeeded.");
                        success = true;
                }

        } else if (si->si_code == CLD_KILLED ||
                   si->si_code == CLD_DUMPED)

                log_error("Import process terminated by signal %s.", signal_to_string(si->si_status));
        else
                log_error("Import process failed due to unknown reason.");

        t->pid = 0;

        return transfer_finalize(t, success);
}

static int transfer_on_log(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Transfer *t = userdata;
        ssize_t l;

        assert(s);
        assert(t);

        l = read(fd, t->log_message + t->log_message_size, sizeof(t->log_message) - t->log_message_size);
        if (l <= 0) {
                /* EOF/read error. We just close the pipe here, and
                 * close the watch, waiting for the SIGCHLD to arrive,
                 * before we do anything else. */

                if (l < 0)
                        log_error_errno(errno, "Failed to read log message: %m");

                t->log_event_source = sd_event_source_unref(t->log_event_source);
                return 0;
        }

        t->log_message_size += l;

        transfer_send_logs(t, false);

        return 0;
}

static int transfer_start(Transfer *t) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        int r;

        assert(t);
        assert(t->pid <= 0);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return -errno;

        t->pid = fork();
        if (t->pid < 0)
                return -errno;
        if (t->pid == 0) {
                const char *cmd[] = {
                        NULL, /* systemd-import, systemd-export or systemd-pull */
                        NULL, /* tar, raw, dkr */
                        NULL, /* --verify= */
                        NULL, /* verify argument */
                        NULL, /* maybe --force */
                        NULL, /* maybe --read-only */
                        NULL, /* maybe --dkr-index-url */
                        NULL, /* if so: the actual URL */
                        NULL, /* maybe --format= */
                        NULL, /* if so: the actual format */
                        NULL, /* remote */
                        NULL, /* local */
                        NULL
                };
                unsigned k = 0;

                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                pipefd[0] = safe_close(pipefd[0]);

                if (dup2(pipefd[1], STDERR_FILENO) != STDERR_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (t->stdout_fd >= 0) {
                        if (dup2(t->stdout_fd, STDOUT_FILENO) != STDOUT_FILENO) {
                                log_error_errno(errno, "Failed to dup2() fd: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (t->stdout_fd != STDOUT_FILENO)
                                safe_close(t->stdout_fd);
                } else {
                        if (dup2(pipefd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                                log_error_errno(errno, "Failed to dup2() fd: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                if (pipefd[1] != STDOUT_FILENO && pipefd[1] != STDERR_FILENO)
                        pipefd[1] = safe_close(pipefd[1]);

                if (t->stdin_fd >= 0) {
                        if (dup2(t->stdin_fd, STDIN_FILENO) != STDIN_FILENO) {
                                log_error_errno(errno, "Failed to dup2() fd: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (t->stdin_fd != STDIN_FILENO)
                                safe_close(t->stdin_fd);
                } else {
                        int null_fd;

                        null_fd = open("/dev/null", O_RDONLY|O_NOCTTY);
                        if (null_fd < 0) {
                                log_error_errno(errno, "Failed to open /dev/null: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (dup2(null_fd, STDIN_FILENO) != STDIN_FILENO) {
                                log_error_errno(errno, "Failed to dup2() fd: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (null_fd != STDIN_FILENO)
                                safe_close(null_fd);
                }

                fd_cloexec(STDIN_FILENO, false);
                fd_cloexec(STDOUT_FILENO, false);
                fd_cloexec(STDERR_FILENO, false);

                setenv("SYSTEMD_LOG_TARGET", "console-prefixed", 1);
                setenv("NOTIFY_SOCKET", "/run/systemd/import/notify", 1);

                if (IN_SET(t->type, TRANSFER_IMPORT_TAR, TRANSFER_IMPORT_RAW))
                        cmd[k++] = SYSTEMD_IMPORT_PATH;
                else if (IN_SET(t->type, TRANSFER_EXPORT_TAR, TRANSFER_EXPORT_RAW))
                        cmd[k++] = SYSTEMD_EXPORT_PATH;
                else
                        cmd[k++] = SYSTEMD_PULL_PATH;

                if (IN_SET(t->type, TRANSFER_IMPORT_TAR, TRANSFER_EXPORT_TAR, TRANSFER_PULL_TAR))
                        cmd[k++] = "tar";
                else if (IN_SET(t->type, TRANSFER_IMPORT_RAW, TRANSFER_EXPORT_RAW, TRANSFER_PULL_RAW))
                        cmd[k++] = "raw";
                else
                        cmd[k++] = "dkr";

                if (t->verify != _IMPORT_VERIFY_INVALID) {
                        cmd[k++] = "--verify";
                        cmd[k++] = import_verify_to_string(t->verify);
                }

                if (t->force_local)
                        cmd[k++] = "--force";
                if (t->read_only)
                        cmd[k++] = "--read-only";

                if (t->dkr_index_url) {
                        cmd[k++] = "--dkr-index-url";
                        cmd[k++] = t->dkr_index_url;
                }

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
        t->log_fd = pipefd[0];
        pipefd[0] = -1;

        t->stdin_fd = safe_close(t->stdin_fd);

        r = sd_event_add_child(t->manager->event, &t->pid_event_source, t->pid, WEXITED, transfer_on_pid, t);
        if (r < 0)
                return r;

        r = sd_event_add_io(t->manager->event, &t->log_event_source, t->log_fd, EPOLLIN, transfer_on_log, t);
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

        bus_verify_polkit_async_registry_free(m->polkit_registry);

        m->bus = sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        free(m);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

static int manager_on_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {

        char buf[NOTIFY_BUFFER_MAX+1];
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf)-1,
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                            CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)];
        } control = {};
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct ucred *ucred = NULL;
        Manager *m = userdata;
        struct cmsghdr *cmsg;
        unsigned percent;
        char *p, *e;
        Transfer *t;
        Iterator i;
        ssize_t n;
        int r;

        n = recvmsg(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (n < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return -errno;
        }

        cmsg_close_all(&msghdr);

        CMSG_FOREACH(cmsg, &msghdr) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                           cmsg->cmsg_type == SCM_CREDENTIALS &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        ucred = (struct ucred*) CMSG_DATA(cmsg);
                }
        }

        if (msghdr.msg_flags & MSG_TRUNC) {
                log_warning("Got overly long notification datagram, ignoring.");
                return 0;
        }

        if (!ucred || ucred->pid <= 0) {
                log_warning("Got notification datagram lacking credential information, ignoring.");
                return 0;
        }

        HASHMAP_FOREACH(t, m->transfers, i)
                if (ucred->pid == t->pid)
                        break;

        if (!t) {
                log_warning("Got notification datagram from unexpected peer, ignoring.");
                return 0;
        }

        buf[n] = 0;

        p = startswith(buf, "X_IMPORT_PROGRESS=");
        if (!p) {
                p = strstr(buf, "\nX_IMPORT_PROGRESS=");
                if (!p)
                        return 0;

                p += 19;
        }

        e = strchrnul(p, '\n');
        *e = 0;

        r = safe_atou(p, &percent);
        if (r < 0 || percent > 100) {
                log_warning("Got invalid percent value, ignoring.");
                return 0;
        }

        t->progress_percent = percent;

        log_debug("Got percentage from client: %u%%", percent);
        return 0;
}

static int manager_new(Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/import/notify",
        };
        static const int one = 1;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_set_watchdog(m->event, true);

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return r;

        m->notify_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->notify_fd < 0)
                return -errno;

        (void) mkdir_parents_label(sa.un.sun_path, 0755);
        (void) unlink(sa.un.sun_path);

        if (bind(m->notify_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path)) < 0)
                return -errno;

        if (setsockopt(m->notify_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0)
                return -errno;

        r = sd_event_add_io(m->event, &m->notify_event_source, m->notify_fd, EPOLLIN, manager_on_notify, m);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

static Transfer *manager_find(Manager *m, TransferType type, const char *dkr_index_url, const char *remote) {
        Transfer *t;
        Iterator i;

        assert(m);
        assert(type >= 0);
        assert(type < _TRANSFER_TYPE_MAX);

        HASHMAP_FOREACH(t, m->transfers, i) {

                if (t->type == type &&
                    streq_ptr(t->remote, remote) &&
                    streq_ptr(t->dkr_index_url, dkr_index_url))
                        return t;
        }

        return NULL;
}

static int method_import_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        int fd, force, read_only, r;
        const char *local, *object;
        Manager *m = userdata;
        TransferType type;
        uint32_t id;

        assert(msg);
        assert(m);

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.import1.import",
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(msg, "hsbb", &fd, &local, &force, &read_only);
        if (r < 0)
                return r;

        if (!machine_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Local name %s is invalid", local);

        r = setup_machine_directory((uint64_t) -1, error);
        if (r < 0)
                return r;

        type = streq_ptr(sd_bus_message_get_member(msg), "ImportTar") ? TRANSFER_IMPORT_TAR : TRANSFER_IMPORT_RAW;

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

static int method_export_tar_or_raw(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        int fd, r;
        const char *local, *object, *format;
        Manager *m = userdata;
        TransferType type;
        uint32_t id;

        assert(msg);
        assert(m);

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.import1.export",
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(msg, "shs", &local, &fd, &format);
        if (r < 0)
                return r;

        if (!machine_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Local name %s is invalid", local);

        type = streq_ptr(sd_bus_message_get_member(msg), "ExportTar") ? TRANSFER_EXPORT_TAR : TRANSFER_EXPORT_RAW;

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
        Manager *m = userdata;
        ImportVerify v;
        TransferType type;
        int force, r;
        uint32_t id;

        assert(msg);
        assert(m);

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.import1.pull",
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(msg, "sssb", &remote, &local, &verify, &force);
        if (r < 0)
                return r;

        if (!http_url_is_valid(remote))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "URL %s is invalid", remote);

        if (isempty(local))
                local = NULL;
        else if (!machine_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Local name %s is invalid", local);

        if (isempty(verify))
                v = IMPORT_VERIFY_SIGNATURE;
        else
                v = import_verify_from_string(verify);
        if (v < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown verification mode %s", verify);

        r = setup_machine_directory((uint64_t) -1, error);
        if (r < 0)
                return r;

        type = streq_ptr(sd_bus_message_get_member(msg), "PullTar") ? TRANSFER_PULL_TAR : TRANSFER_PULL_RAW;

        if (manager_find(m, type, NULL, remote))
                return sd_bus_error_setf(error, BUS_ERROR_TRANSFER_IN_PROGRESS, "Transfer for %s already in progress.", remote);

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

static int method_pull_dkr(sd_bus_message *msg, void *userdata, sd_bus_error *error) {
        _cleanup_(transfer_unrefp) Transfer *t = NULL;
        const char *index_url, *remote, *tag, *local, *verify, *object;
        Manager *m = userdata;
        ImportVerify v;
        int force, r;
        uint32_t id;

        assert(msg);
        assert(m);

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.import1.pull",
                        false,
                        UID_INVALID,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = sd_bus_message_read(msg, "sssssb", &index_url, &remote, &tag, &local, &verify, &force);
        if (r < 0)
                return r;

        if (isempty(index_url))
                index_url = DEFAULT_DKR_INDEX_URL;
        if (!index_url)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Index URL must be specified.");
        if (!http_url_is_valid(index_url))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Index URL %s is invalid", index_url);

        if (!dkr_name_is_valid(remote))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Remote name %s is not valid", remote);

        if (isempty(tag))
                tag = "latest";
        else if (!dkr_tag_is_valid(tag))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Tag %s is not valid", tag);

        if (isempty(local))
                local = NULL;
        else if (!machine_name_is_valid(local))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Local name %s is invalid", local);

        if (isempty(verify))
                v = IMPORT_VERIFY_SIGNATURE;
        else
                v = import_verify_from_string(verify);
        if (v < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown verification mode %s", verify);

        if (v != IMPORT_VERIFY_NO)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "DKR does not support verification.");

        r = setup_machine_directory((uint64_t) -1, error);
        if (r < 0)
                return r;

        if (manager_find(m, TRANSFER_PULL_DKR, index_url, remote))
                return sd_bus_error_setf(error, BUS_ERROR_TRANSFER_IN_PROGRESS, "Transfer for %s already in progress.", remote);

        r = transfer_new(m, &t);
        if (r < 0)
                return r;

        t->type = TRANSFER_PULL_DKR;
        t->verify = v;
        t->force_local = force;

        t->dkr_index_url = strdup(index_url);
        if (!t->dkr_index_url)
                return -ENOMEM;

        t->remote = strjoin(remote, ":", tag, NULL);
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
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        Manager *m = userdata;
        Transfer *t;
        Iterator i;
        int r;

        assert(msg);
        assert(m);

        r = sd_bus_message_new_method_return(msg, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(usssdo)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(t, m->transfers, i) {

                r = sd_bus_message_append(
                                reply,
                                "(usssdo)",
                                t->id,
                                transfer_type_to_string(t->type),
                                t->remote,
                                t->local,
                                (double) t->progress_percent / 100.0,
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
        Transfer *t = userdata;
        int r;

        assert(msg);
        assert(t);

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.import1.pull",
                        false,
                        UID_INVALID,
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
        Manager *m = userdata;
        Transfer *t;
        uint32_t id;
        int r;

        assert(msg);
        assert(m);

        r = bus_verify_polkit_async(
                        msg,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.import1.pull",
                        false,
                        UID_INVALID,
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
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid transfer id");

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

        Transfer *t = userdata;

        assert(bus);
        assert(reply);
        assert(t);

        return sd_bus_message_append(reply, "d", (double) t->progress_percent / 100.0);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, transfer_type, TransferType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_verify, import_verify, ImportVerify);

static const sd_bus_vtable transfer_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Id", "u", NULL, offsetof(Transfer, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Local", "s", NULL, offsetof(Transfer, local), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Remote", "s", NULL, offsetof(Transfer, remote), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Type", "s", property_get_type, offsetof(Transfer, type), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Verify", "s", property_get_verify, offsetof(Transfer, verify), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Progress", "d", property_get_progress, 0, 0),
        SD_BUS_METHOD("Cancel", NULL, NULL, method_cancel, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("LogMessage", "us", 0),
        SD_BUS_VTABLE_END,
};

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("ImportTar", "hsbb", "uo", method_import_tar_or_raw, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ImportRaw", "hsbb", "uo", method_import_tar_or_raw, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ExportTar", "shs", "uo", method_export_tar_or_raw, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ExportRaw", "shs", "uo", method_export_tar_or_raw, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PullTar", "sssb", "uo", method_pull_tar_or_raw, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PullRaw", "sssb", "uo", method_pull_tar_or_raw, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("PullDkr", "sssssb", "uo", method_pull_dkr, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ListTransfers", NULL, "a(usssdo)", method_list_transfers, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("CancelTransfer", "u", NULL, method_cancel_transfer, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("TransferNew", "uo", 0),
        SD_BUS_SIGNAL("TransferRemoved", "uos", 0),
        SD_BUS_VTABLE_END,
};

static int transfer_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = userdata;
        Transfer *t;
        const char *p;
        uint32_t id;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);
        assert(m);

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

static int transfer_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        Transfer *t;
        unsigned k = 0;
        Iterator i;

        l = new0(char*, hashmap_size(m->transfers) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(t, m->transfers, i) {

                l[k] = strdup(t->object_path);
                if (!l[k])
                        return -ENOMEM;

                k++;
        }

        *nodes = l;
        l = NULL;

        return 1;
}

static int manager_add_bus_objects(Manager *m) {
        int r;

        assert(m);

        r = sd_bus_add_object_vtable(m->bus, NULL, "/org/freedesktop/import1", "org.freedesktop.import1.Manager", manager_vtable, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

        r = sd_bus_add_fallback_vtable(m->bus, NULL, "/org/freedesktop/import1/transfer", "org.freedesktop.import1.Transfer", transfer_vtable, transfer_object_find, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

        r = sd_bus_add_node_enumerator(m->bus, NULL, "/org/freedesktop/import1/transfer", transfer_node_enumerator, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add transfer enumerator: %m");

        r = sd_bus_request_name(m->bus, "org.freedesktop.import1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to register name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static bool manager_check_idle(void *userdata) {
        Manager *m = userdata;

        return hashmap_isempty(m->transfers);
}

static int manager_run(Manager *m) {
        assert(m);

        return bus_event_loop_with_idle(
                        m->event,
                        m->bus,
                        "org.freedesktop.import1",
                        DEFAULT_EXIT_USEC,
                        manager_check_idle,
                        m);
}

int main(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, -1) >= 0);

        r = manager_new(&m);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate manager object: %m");
                goto finish;
        }

        r = manager_add_bus_objects(m);
        if (r < 0)
                goto finish;

        r = manager_run(m);
        if (r < 0) {
                log_error_errno(r, "Failed to run event loop: %m");
                goto finish;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

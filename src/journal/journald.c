/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/acl.h>
#include <acl/libacl.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/statvfs.h>

#include "hashmap.h"
#include "journal-file.h"
#include "sd-daemon.h"
#include "socket-util.h"
#include "acl-util.h"
#include "cgroup-util.h"
#include "list.h"
#include "journal-rate-limit.h"
#include "sd-journal.h"
#include "sd-login.h"
#include "journal-internal.h"

#define USER_JOURNALS_MAX 1024
#define STDOUT_STREAMS_MAX 4096

#define DEFAULT_RATE_LIMIT_INTERVAL (10*USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST 200

#define RECHECK_AVAILABLE_SPACE_USEC (30*USEC_PER_SEC)

#define RECHECK_VAR_AVAILABLE_USEC (30*USEC_PER_SEC)

#define SYSLOG_TIMEOUT_USEC (5*USEC_PER_SEC)

typedef struct StdoutStream StdoutStream;

typedef struct Server {
        int epoll_fd;
        int signal_fd;
        int syslog_fd;
        int native_fd;
        int stdout_fd;

        JournalFile *runtime_journal;
        JournalFile *system_journal;
        Hashmap *user_journals;

        uint64_t seqnum;

        char *buffer;
        size_t buffer_size;

        JournalRateLimit *rate_limit;

        JournalMetrics runtime_metrics;
        JournalMetrics system_metrics;

        bool compress;

        uint64_t cached_available_space;
        usec_t cached_available_space_timestamp;

        uint64_t var_available_timestamp;

        LIST_HEAD(StdoutStream, stdout_streams);
        unsigned n_stdout_streams;
} Server;

typedef enum StdoutStreamState {
        STDOUT_STREAM_TAG,
        STDOUT_STREAM_PRIORITY,
        STDOUT_STREAM_PRIORITY_PREFIX,
        STDOUT_STREAM_TEE_CONSOLE,
        STDOUT_STREAM_RUNNING
} StdoutStreamState;

struct StdoutStream {
        Server *server;
        StdoutStreamState state;

        int fd;

        struct ucred ucred;

        char *tag;
        int priority;
        bool priority_prefix:1;
        bool tee_console:1;

        char buffer[LINE_MAX+1];
        size_t length;

        LIST_FIELDS(StdoutStream, stdout_stream);
};

static int server_flush_to_var(Server *s);

static uint64_t available_space(Server *s) {
        char ids[33], *p;
        const char *f;
        sd_id128_t machine;
        struct statvfs ss;
        uint64_t sum = 0, avail = 0, ss_avail = 0;
        int r;
        DIR *d;
        usec_t ts;
        JournalMetrics *m;

        ts = now(CLOCK_MONOTONIC);

        if (s->cached_available_space_timestamp + RECHECK_AVAILABLE_SPACE_USEC > ts)
                return s->cached_available_space;

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return 0;

        if (s->system_journal) {
                f = "/var/log/journal/";
                m = &s->system_metrics;
        } else {
                f = "/run/log/journal/";
                m = &s->runtime_metrics;
        }

        assert(m);

        p = strappend(f, sd_id128_to_string(machine, ids));
        if (!p)
                return 0;

        d = opendir(p);
        free(p);

        if (!d)
                return 0;

        if (fstatvfs(dirfd(d), &ss) < 0)
                goto finish;

        for (;;) {
                struct stat st;
                struct dirent buf, *de;
                int k;

                k = readdir_r(d, &buf, &de);
                if (k != 0) {
                        r = -k;
                        goto finish;
                }

                if (!de)
                        break;

                if (!dirent_is_file_with_suffix(de, ".journal"))
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                sum += (uint64_t) st.st_blocks * (uint64_t) st.st_blksize;
        }

        avail = sum >= m->max_use ? 0 : m->max_use - sum;

        ss_avail = ss.f_bsize * ss.f_bavail;

        ss_avail = ss_avail < m->keep_free ? 0 : ss_avail - m->keep_free;

        if (ss_avail < avail)
                avail = ss_avail;

        s->cached_available_space = avail;
        s->cached_available_space_timestamp = ts;

finish:
        closedir(d);

        return avail;
}

static void fix_perms(JournalFile *f, uid_t uid) {
        acl_t acl;
        acl_entry_t entry;
        acl_permset_t permset;
        int r;

        assert(f);

        r = fchmod_and_fchown(f->fd, 0640, 0, 0);
        if (r < 0)
                log_warning("Failed to fix access mode/rights on %s, ignoring: %s", f->path, strerror(-r));

        if (uid <= 0)
                return;

        acl = acl_get_fd(f->fd);
        if (!acl) {
                log_warning("Failed to read ACL on %s, ignoring: %m", f->path);
                return;
        }

        r = acl_find_uid(acl, uid, &entry);
        if (r <= 0) {

                if (acl_create_entry(&acl, &entry) < 0 ||
                    acl_set_tag_type(entry, ACL_USER) < 0 ||
                    acl_set_qualifier(entry, &uid) < 0) {
                        log_warning("Failed to patch ACL on %s, ignoring: %m", f->path);
                        goto finish;
                }
        }

        if (acl_get_permset(entry, &permset) < 0 ||
            acl_add_perm(permset, ACL_READ) < 0 ||
            acl_calc_mask(&acl) < 0) {
                log_warning("Failed to patch ACL on %s, ignoring: %m", f->path);
                goto finish;
        }

        if (acl_set_fd(f->fd, acl) < 0)
                log_warning("Failed to set ACL on %s, ignoring: %m", f->path);

finish:
        acl_free(acl);
}

static JournalFile* find_journal(Server *s, uid_t uid) {
        char *p;
        int r;
        JournalFile *f;
        char ids[33];
        sd_id128_t machine;

        assert(s);

        /* We split up user logs only on /var, not on /run. If the
         * runtime file is open, we write to it exclusively, in order
         * to guarantee proper order as soon as we flush /run to
         * /var and close the runtime file. */

        if (s->runtime_journal)
                return s->runtime_journal;

        if (uid <= 0)
                return s->system_journal;

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return s->system_journal;

        f = hashmap_get(s->user_journals, UINT32_TO_PTR(uid));
        if (f)
                return f;

        if (asprintf(&p, "/var/log/journal/%s/user-%lu.journal", sd_id128_to_string(machine, ids), (unsigned long) uid) < 0)
                return s->system_journal;

        while (hashmap_size(s->user_journals) >= USER_JOURNALS_MAX) {
                /* Too many open? Then let's close one */
                f = hashmap_steal_first(s->user_journals);
                assert(f);
                journal_file_close(f);
        }

        r = journal_file_open(p, O_RDWR|O_CREAT, 0640, s->system_journal, &f);
        free(p);

        if (r < 0)
                return s->system_journal;

        fix_perms(f, uid);
        f->metrics = s->system_metrics;
        f->compress = s->compress;

        r = hashmap_put(s->user_journals, UINT32_TO_PTR(uid), f);
        if (r < 0) {
                journal_file_close(f);
                return s->system_journal;
        }

        return f;
}

static void server_vacuum(Server *s) {
        Iterator i;
        void *k;
        char *p;
        char ids[33];
        sd_id128_t machine;
        int r;
        JournalFile *f;

        log_info("Rotating...");

        if (s->runtime_journal) {
                r = journal_file_rotate(&s->runtime_journal);
                if (r < 0)
                        log_error("Failed to rotate %s: %s", s->runtime_journal->path, strerror(-r));
        }

        if (s->system_journal) {
                r = journal_file_rotate(&s->system_journal);
                if (r < 0)
                        log_error("Failed to rotate %s: %s", s->system_journal->path, strerror(-r));
        }

        HASHMAP_FOREACH_KEY(f, k, s->user_journals, i) {
                r = journal_file_rotate(&f);
                if (r < 0)
                        log_error("Failed to rotate %s: %s", f->path, strerror(-r));
                else
                        hashmap_replace(s->user_journals, k, f);
        }

        log_info("Vacuuming...");

        r = sd_id128_get_machine(&machine);
        if (r < 0) {
                log_error("Failed to get machine ID: %s", strerror(-r));
                return;
        }

        sd_id128_to_string(machine, ids);

        if (s->system_journal) {
                if (asprintf(&p, "/var/log/journal/%s", ids) < 0) {
                        log_error("Out of memory.");
                        return;
                }

                r = journal_directory_vacuum(p, s->system_metrics.max_use, s->system_metrics.keep_free);
                if (r < 0 && r != -ENOENT)
                        log_error("Failed to vacuum %s: %s", p, strerror(-r));
                free(p);
        }


        if (s->runtime_journal) {
                if (asprintf(&p, "/run/log/journal/%s", ids) < 0) {
                        log_error("Out of memory.");
                        return;
                }

                r = journal_directory_vacuum(p, s->runtime_metrics.max_use, s->runtime_metrics.keep_free);
                if (r < 0 && r != -ENOENT)
                        log_error("Failed to vacuum %s: %s", p, strerror(-r));
                free(p);
        }

        s->cached_available_space_timestamp = 0;
}

static char *shortened_cgroup_path(pid_t pid) {
        int r;
        char *process_path, *init_path, *path;

        assert(pid > 0);

        r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, pid, &process_path);
        if (r < 0)
                return NULL;

        r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, 1, &init_path);
        if (r < 0) {
                free(process_path);
                return NULL;
        }

        if (streq(init_path, "/"))
                init_path[0] = 0;

        if (startswith(process_path, init_path)) {
                char *p;

                p = strdup(process_path + strlen(init_path));
                if (!p) {
                        free(process_path);
                        free(init_path);
                        return NULL;
                }
                path = p;
        } else {
                path = process_path;
                process_path = NULL;
        }

        free(process_path);
        free(init_path);

        return path;
}

static void dispatch_message_real(Server *s,
                             struct iovec *iovec, unsigned n, unsigned m,
                             struct ucred *ucred,
                             struct timeval *tv) {

        char *pid = NULL, *uid = NULL, *gid = NULL,
                *source_time = NULL, *boot_id = NULL, *machine_id = NULL,
                *comm = NULL, *cmdline = NULL, *hostname = NULL,
                *audit_session = NULL, *audit_loginuid = NULL,
                *exe = NULL, *cgroup = NULL, *session = NULL,
                *owner_uid = NULL, *service = NULL;

        char idbuf[33];
        sd_id128_t id;
        int r;
        char *t;
        uid_t loginuid = 0, realuid = 0;
        JournalFile *f;
        bool vacuumed = false;

        assert(s);
        assert(iovec);
        assert(n > 0);
        assert(n + 16 <= m);

        if (ucred) {
                uint32_t audit;
                uid_t owner;

                realuid = ucred->uid;

                if (asprintf(&pid, "_PID=%lu", (unsigned long) ucred->pid) >= 0)
                        IOVEC_SET_STRING(iovec[n++], pid);

                if (asprintf(&uid, "_UID=%lu", (unsigned long) ucred->uid) >= 0)
                        IOVEC_SET_STRING(iovec[n++], uid);

                if (asprintf(&gid, "_GID=%lu", (unsigned long) ucred->gid) >= 0)
                        IOVEC_SET_STRING(iovec[n++], gid);

                r = get_process_comm(ucred->pid, &t);
                if (r >= 0) {
                        comm = strappend("_COMM=", t);
                        free(t);

                        if (comm)
                                IOVEC_SET_STRING(iovec[n++], comm);
                }

                r = get_process_exe(ucred->pid, &t);
                if (r >= 0) {
                        exe = strappend("_EXE=", t);
                        free(t);

                        if (comm)
                                IOVEC_SET_STRING(iovec[n++], exe);
                }

                r = get_process_cmdline(ucred->pid, LINE_MAX, false, &t);
                if (r >= 0) {
                        cmdline = strappend("_CMDLINE=", t);
                        free(t);

                        if (cmdline)
                                IOVEC_SET_STRING(iovec[n++], cmdline);
                }

                r = audit_session_from_pid(ucred->pid, &audit);
                if (r >= 0)
                        if (asprintf(&audit_session, "_AUDIT_SESSION=%lu", (unsigned long) audit) >= 0)
                                IOVEC_SET_STRING(iovec[n++], audit_session);

                r = audit_loginuid_from_pid(ucred->pid, &loginuid);
                if (r >= 0)
                        if (asprintf(&audit_loginuid, "_AUDIT_LOGINUID=%lu", (unsigned long) loginuid) >= 0)
                                IOVEC_SET_STRING(iovec[n++], audit_loginuid);

                t = shortened_cgroup_path(ucred->pid);
                if (t) {
                        cgroup = strappend("_SYSTEMD_CGROUP=", t);
                        free(t);

                        if (cgroup)
                                IOVEC_SET_STRING(iovec[n++], cgroup);
                }

                if (sd_pid_get_session(ucred->pid, &t) >= 0) {
                        session = strappend("_SYSTEMD_SESSION=", t);
                        free(t);

                        if (session)
                                IOVEC_SET_STRING(iovec[n++], session);
                }

                if (sd_pid_get_service(ucred->pid, &t) >= 0) {
                        service = strappend("_SYSTEMD_SERVICE=", t);
                        free(t);

                        if (service)
                                IOVEC_SET_STRING(iovec[n++], service);
                }

                if (sd_pid_get_owner_uid(ucred->uid, &owner) >= 0)
                        if (asprintf(&owner_uid, "_SYSTEMD_OWNER_UID=%lu", (unsigned long) owner) >= 0)
                                IOVEC_SET_STRING(iovec[n++], owner_uid);
        }

        if (tv) {
                if (asprintf(&source_time, "_SOURCE_REALTIME_TIMESTAMP=%llu",
                             (unsigned long long) timeval_load(tv)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], source_time);
        }

        /* Note that strictly speaking storing the boot id here is
         * redundant since the entry includes this in-line
         * anyway. However, we need this indexed, too. */
        r = sd_id128_get_boot(&id);
        if (r >= 0)
                if (asprintf(&boot_id, "_BOOT_ID=%s", sd_id128_to_string(id, idbuf)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], boot_id);

        r = sd_id128_get_machine(&id);
        if (r >= 0)
                if (asprintf(&machine_id, "_MACHINE_ID=%s", sd_id128_to_string(id, idbuf)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], machine_id);

        t = gethostname_malloc();
        if (t) {
                hostname = strappend("_HOSTNAME=", t);
                free(t);
                if (hostname)
                        IOVEC_SET_STRING(iovec[n++], hostname);
        }

        assert(n <= m);

        server_flush_to_var(s);

retry:
        f = find_journal(s, realuid == 0 ? 0 : loginuid);
        if (!f)
                log_warning("Dropping message, as we can't find a place to store the data.");
        else {
                r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL, NULL);

                if (r == -E2BIG && !vacuumed) {
                        log_info("Allocation limit reached.");

                        server_vacuum(s);
                        vacuumed = true;

                        log_info("Retrying write.");
                        goto retry;
                }

                if (r < 0)
                        log_error("Failed to write entry, ignoring: %s", strerror(-r));
        }

        free(pid);
        free(uid);
        free(gid);
        free(comm);
        free(exe);
        free(cmdline);
        free(source_time);
        free(boot_id);
        free(machine_id);
        free(hostname);
        free(audit_session);
        free(audit_loginuid);
        free(cgroup);
        free(session);
        free(owner_uid);
        free(service);
}

static void dispatch_message(Server *s,
                             struct iovec *iovec, unsigned n, unsigned m,
                             struct ucred *ucred,
                             struct timeval *tv,
                             int priority) {
        int rl;
        char *path = NULL, *c;

        assert(s);
        assert(iovec || n == 0);

        if (n == 0)
                return;

        if (!ucred)
                goto finish;

        path = shortened_cgroup_path(ucred->pid);
        if (!path)
                goto finish;

        /* example: /user/lennart/3/foobar
         *          /system/dbus.service/foobar
         *
         * So let's cut of everything past the third /, since that is
         * wher user directories start */

        c = strchr(path, '/');
        if (c) {
                c = strchr(c+1, '/');
                if (c) {
                        c = strchr(c+1, '/');
                        if (c)
                                *c = 0;
                }
        }

        rl = journal_rate_limit_test(s->rate_limit, path, priority, available_space(s));

        if (rl == 0) {
                free(path);
                return;
        }

        if (rl > 1) {
                int j = 0;
                char suppress_message[LINE_MAX];
                struct iovec suppress_iovec[18];

                /* Write a suppression message if we suppressed something */

                snprintf(suppress_message, sizeof(suppress_message), "MESSAGE=Suppressed %u messages from %s", rl - 1, path);
                char_array_0(suppress_message);

                IOVEC_SET_STRING(suppress_iovec[j++], "PRIORITY=5");
                IOVEC_SET_STRING(suppress_iovec[j++], suppress_message);

                dispatch_message_real(s, suppress_iovec, j, ELEMENTSOF(suppress_iovec), NULL, NULL);
        }

        free(path);

finish:
        dispatch_message_real(s, iovec, n, m, ucred, tv);
}

static void process_syslog_message(Server *s, const char *buf, struct ucred *ucred, struct timeval *tv) {
        char *message = NULL, *syslog_priority = NULL, *syslog_facility = NULL;
        struct iovec iovec[19];
        unsigned n = 0;
        int priority = LOG_USER | LOG_INFO;

        assert(s);
        assert(buf);

        parse_syslog_priority((char**) &buf, &priority);
        skip_syslog_date((char**) &buf);

        if (asprintf(&syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_priority);

        if (asprintf(&syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority)) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_facility);

        message = strappend("MESSAGE=", buf);
        if (message)
                IOVEC_SET_STRING(iovec[n++], message);

        dispatch_message(s, iovec, n, ELEMENTSOF(iovec), ucred, tv, priority & LOG_PRIMASK);

        free(message);
        free(syslog_facility);
        free(syslog_priority);
}

static bool valid_user_field(const char *p, size_t l) {
        const char *a;

        /* We kinda enforce POSIX syntax recommendations for
           environment variables here, but make a couple of additional
           requirements.

           http://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap08.html */

        /* No empty field names */
        if (l <= 0)
                return false;

        /* Don't allow names longer than 64 chars */
        if (l > 64)
                return false;

        /* Variables starting with an underscore are protected */
        if (p[0] == '_')
                return false;

        /* Don't allow digits as first character */
        if (p[0] >= '0' && p[0] <= '9')
                return false;

        /* Only allow A-Z0-9 and '_' */
        for (a = p; a < p + l; a++)
                if (!((*a >= 'A' && *a <= 'Z') ||
                      (*a >= '0' && *a <= '9') ||
                      *a == '_'))
                        return false;

        return true;
}

static void process_native_message(Server *s, const void *buffer, size_t buffer_size, struct ucred *ucred, struct timeval *tv) {
        struct iovec *iovec = NULL;
        unsigned n = 0, m = 0, j;
        const char *p;
        size_t remaining;
        int priority = LOG_INFO;

        assert(s);
        assert(buffer || n == 0);

        p = buffer;
        remaining = buffer_size;

        while (remaining > 0) {
                const char *e, *q;

                e = memchr(p, '\n', remaining);

                if (!e) {
                        /* Trailing noise, let's ignore it, and flush what we collected */
                        log_debug("Received message with trailing noise, ignoring.");
                        break;
                }

                if (e == p) {
                        /* Entry separator */
                        dispatch_message(s, iovec, n, m, ucred, tv, priority);
                        n = 0;
                        priority = LOG_INFO;

                        p++;
                        remaining--;
                        continue;
                }

                if (*p == '.' || *p == '#') {
                        /* Ignore control commands for now, and
                         * comments too. */
                        remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                }

                /* A property follows */

                if (n+16 >= m) {
                        struct iovec *c;
                        unsigned u;

                        u = MAX((n+16U) * 2U, 4U);
                        c = realloc(iovec, u * sizeof(struct iovec));
                        if (!c) {
                                log_error("Out of memory");
                                break;
                        }

                        iovec = c;
                        m = u;
                }

                q = memchr(p, '=', e - p);
                if (q) {
                        if (valid_user_field(p, q - p)) {
                                /* If the field name starts with an
                                 * underscore, skip the variable,
                                 * since that indidates a trusted
                                 * field */
                                iovec[n].iov_base = (char*) p;
                                iovec[n].iov_len = e - p;
                                n++;

                                /* We need to determine the priority
                                 * of this entry for the rate limiting
                                 * logic */
                                if (e - p == 10 &&
                                    memcmp(p, "PRIORITY=", 10) == 0 &&
                                    p[10] >= '0' &&
                                    p[10] <= '9')
                                        priority = p[10] - '0';
                        }

                        remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                } else {
                        uint64_t l;
                        char *k;

                        if (remaining < e - p + 1 + sizeof(uint64_t) + 1) {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        memcpy(&l, e + 1, sizeof(uint64_t));
                        l = le64toh(l);

                        if (remaining < e - p + 1 + sizeof(uint64_t) + l + 1 ||
                            e[1+sizeof(uint64_t)+l] != '\n') {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        k = malloc((e - p) + 1 + l);
                        if (!k) {
                                log_error("Out of memory");
                                break;
                        }

                        memcpy(k, p, e - p);
                        k[e - p] = '=';
                        memcpy(k + (e - p) + 1, e + 1 + sizeof(uint64_t), l);

                        if (valid_user_field(p, e - p)) {
                                iovec[n].iov_base = k;
                                iovec[n].iov_len = (e - p) + 1 + l;
                                n++;
                        } else
                                free(k);

                        remaining -= (e - p) + 1 + sizeof(uint64_t) + l + 1;
                        p = e + 1 + sizeof(uint64_t) + l + 1;
                }
        }

        dispatch_message(s, iovec, n, m, ucred, tv, priority);

        for (j = 0; j < n; j++)
                if (iovec[j].iov_base < buffer ||
                    (const uint8_t*) iovec[j].iov_base >= (const uint8_t*) buffer + buffer_size)
                        free(iovec[j].iov_base);
}

static int stdout_stream_log(StdoutStream *s, const char *p, size_t l) {
        struct iovec iovec[18];
        char *message = NULL, *syslog_priority = NULL;
        unsigned n = 0;
        size_t tag_len;
        int priority;

        assert(s);
        assert(p);

        priority = s->priority;

        if (s->priority_prefix &&
            l > 3 &&
            p[0] == '<' &&
            p[1] >= '0' && p[1] <= '7' &&
            p[2] == '>') {

                priority = p[1] - '0';
                p += 3;
                l -= 3;
        }

        if (l <= 0)
                return 0;

        if (asprintf(&syslog_priority, "PRIORITY=%i", priority) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_priority);

        tag_len = s->tag ? strlen(s->tag) + 2: 0;
        message = malloc(8 + tag_len + l);
        if (message) {
                memcpy(message, "MESSAGE=", 8);

                if (s->tag) {
                        memcpy(message+8, s->tag, tag_len-2);
                        memcpy(message+8+tag_len-2, ": ", 2);
                }

                memcpy(message+8+tag_len, p, l);
                iovec[n].iov_base = message;
                iovec[n].iov_len = 8+tag_len+l;
                n++;
        }

        dispatch_message(s->server, iovec, n, ELEMENTSOF(iovec), &s->ucred, NULL, priority);

        if (s->tee_console) {
                int console;

                console = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (console >= 0) {
                        n = 0;
                        if (s->tag) {
                                IOVEC_SET_STRING(iovec[n++], s->tag);
                                IOVEC_SET_STRING(iovec[n++], ": ");
                        }

                        iovec[n].iov_base = (void*) p;
                        iovec[n].iov_len = l;
                        n++;

                        IOVEC_SET_STRING(iovec[n++], (char*) "\n");

                        writev(console, iovec, n);
                }
        }

        free(message);
        free(syslog_priority);

        return 0;
}

static int stdout_stream_line(StdoutStream *s, const char *p, size_t l) {
        assert(s);
        assert(p);

        while (l > 0 && strchr(WHITESPACE, *p)) {
                l--;
                p++;
        }

        while (l > 0 && strchr(WHITESPACE, *(p+l-1)))
                l--;

        switch (s->state) {

        case STDOUT_STREAM_TAG:

                if (l > 0) {
                        s->tag = strndup(p, l);
                        if (!s->tag) {
                                log_error("Out of memory");
                                return -EINVAL;
                        }
                }

                s->state = STDOUT_STREAM_PRIORITY;
                return 0;

        case STDOUT_STREAM_PRIORITY:
                if (l != 1 || *p < '0' || *p > '7') {
                        log_warning("Failed to parse log priority line.");
                        return -EINVAL;
                }

                s->priority = *p - '0';
                s->state = STDOUT_STREAM_PRIORITY_PREFIX;
                return 0;

        case STDOUT_STREAM_PRIORITY_PREFIX:
                if (l != 1 || *p < '0' || *p > '1') {
                        log_warning("Failed to parse priority prefix line.");
                        return -EINVAL;
                }

                s->priority_prefix = *p - '0';
                s->state = STDOUT_STREAM_TEE_CONSOLE;
                return 0;

        case STDOUT_STREAM_TEE_CONSOLE:
                if (l != 1 || *p < '0' || *p > '1') {
                        log_warning("Failed to parse tee to console line.");
                        return -EINVAL;
                }

                s->tee_console = *p - '0';
                s->state = STDOUT_STREAM_RUNNING;
                return 0;

        case STDOUT_STREAM_RUNNING:
                return stdout_stream_log(s, p, l);
        }

        assert_not_reached("Unknown stream state");
}

static int stdout_stream_scan(StdoutStream *s, bool force_flush) {
        char *p;
        size_t remaining;
        int r;

        assert(s);

        p = s->buffer;
        remaining = s->length;
        for (;;) {
                char *end;
                size_t skip;

                end = memchr(p, '\n', remaining);
                if (!end) {
                        if (remaining >= LINE_MAX) {
                                end = p + LINE_MAX;
                                skip = LINE_MAX;
                        } else
                                break;
                } else
                        skip = end - p + 1;

                r = stdout_stream_line(s, p, end - p);
                if (r < 0)
                        return r;

                remaining -= skip;
                p += skip;
        }

        if (force_flush && remaining > 0) {
                r = stdout_stream_line(s, p, remaining);
                if (r < 0)
                        return r;

                p += remaining;
                remaining = 0;
        }

        if (p > s->buffer) {
                memmove(s->buffer, p, remaining);
                s->length = remaining;
        }

        return 0;
}

static int stdout_stream_process(StdoutStream *s) {
        ssize_t l;
        int r;

        assert(s);

        l = read(s->fd, s->buffer+s->length, sizeof(s->buffer)-1-s->length);
        if (l < 0) {

                if (errno == EAGAIN)
                        return 0;

                log_warning("Failed to read from stream: %m");
                return -errno;
        }

        if (l == 0) {
                r = stdout_stream_scan(s, true);
                if (r < 0)
                        return r;

                return 0;
        }

        s->length += l;
        r = stdout_stream_scan(s, false);
        if (r < 0)
                return r;

        return 1;

}

static void stdout_stream_free(StdoutStream *s) {
        assert(s);

        if (s->server) {
                assert(s->server->n_stdout_streams > 0);
                s->server->n_stdout_streams --;
                LIST_REMOVE(StdoutStream, stdout_stream, s->server->stdout_streams, s);
        }

        if (s->fd >= 0) {
                if (s->server)
                        epoll_ctl(s->server->epoll_fd, EPOLL_CTL_DEL, s->fd, NULL);

                close_nointr_nofail(s->fd);
        }

        free(s->tag);
        free(s);
}

static int stdout_stream_new(Server *s) {
        StdoutStream *stream;
        int fd, r;
        socklen_t len;
        struct epoll_event ev;

        assert(s);

        fd = accept4(s->stdout_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd < 0) {
                if (errno == EAGAIN)
                        return 0;

                log_error("Failed to accept stdout connection: %m");
                return -errno;
        }

        if (s->n_stdout_streams >= STDOUT_STREAMS_MAX) {
                log_warning("Too many stdout streams, refusing connection.");
                close_nointr_nofail(fd);
                return 0;
        }

        stream = new0(StdoutStream, 1);
        if (!stream) {
                log_error("Out of memory.");
                close_nointr_nofail(fd);
                return -ENOMEM;
        }

        stream->fd = fd;

        len = sizeof(stream->ucred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &stream->ucred, &len) < 0) {
                log_error("Failed to determine peer credentials: %m");
                r = -errno;
                goto fail;
        }

        if (shutdown(fd, SHUT_WR) < 0) {
                log_error("Failed to shutdown writing side of socket: %m");
                r = -errno;
                goto fail;
        }

        zero(ev);
        ev.data.ptr = stream;
        ev.events = EPOLLIN;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                log_error("Failed to add stream to event loop: %m");
                r = -errno;
                goto fail;
        }

        stream->server = s;
        LIST_PREPEND(StdoutStream, stdout_stream, s->stdout_streams, stream);
        s->n_stdout_streams ++;

        return 0;

fail:
        stdout_stream_free(stream);
        return r;
}

static int system_journal_open(Server *s) {
        int r;
        char *fn;
        sd_id128_t machine;
        char ids[33];

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        sd_id128_to_string(machine, ids);

        if (!s->system_journal) {

                /* First try to create the machine path, but not the prefix */
                fn = strappend("/var/log/journal/", ids);
                if (!fn)
                        return -ENOMEM;
                (void) mkdir(fn, 0755);
                free(fn);

                /* The create the system journal file */
                fn = join("/var/log/journal/", ids, "/system.journal", NULL);
                if (!fn)
                        return -ENOMEM;

                r = journal_file_open(fn, O_RDWR|O_CREAT, 0640, NULL, &s->system_journal);
                free(fn);

                if (r >= 0) {
                        journal_default_metrics(&s->system_metrics, s->system_journal->fd);

                        s->system_journal->metrics = s->system_metrics;
                        s->system_journal->compress = s->compress;

                        fix_perms(s->system_journal, 0);
                } else if (r < 0) {

                        if (r == -ENOENT)
                                r = 0;
                        else {
                                log_error("Failed to open system journal: %s", strerror(-r));
                                return r;
                        }
                }
        }

        if (!s->runtime_journal) {

                fn = join("/run/log/journal/", ids, "/system.journal", NULL);
                if (!fn)
                        return -ENOMEM;

                if (s->system_journal) {

                        /* Try to open the runtime journal, but only
                         * if it already exists, so that we can flush
                         * it into the system journal */

                        r = journal_file_open(fn, O_RDWR, 0640, NULL, &s->runtime_journal);
                        free(fn);

                        if (r < 0) {

                                if (r == -ENOENT)
                                        r = 0;
                                else {
                                        log_error("Failed to open runtime journal: %s", strerror(-r));
                                        return r;
                                }
                        }

                } else {

                        /* OK, we really need the runtime journal, so create
                         * it if necessary. */

                        (void) mkdir_parents(fn, 0755);
                        r = journal_file_open(fn, O_RDWR|O_CREAT, 0640, NULL, &s->runtime_journal);
                        free(fn);

                        if (r < 0) {
                                log_error("Failed to open runtime journal: %s", strerror(-r));
                                return r;
                        }
                }

                if (s->runtime_journal) {
                        journal_default_metrics(&s->runtime_metrics, s->runtime_journal->fd);

                        s->runtime_journal->metrics = s->runtime_metrics;
                        s->runtime_journal->compress = s->compress;

                        fix_perms(s->runtime_journal, 0);
                }
        }

        return r;
}

static int server_flush_to_var(Server *s) {
        char path[] = "/run/log/journal/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        Object *o = NULL;
        int r;
        sd_id128_t machine;
        sd_journal *j;
        usec_t ts;

        assert(s);

        if (!s->runtime_journal)
                return 0;

        ts = now(CLOCK_MONOTONIC);
        if (s->var_available_timestamp + RECHECK_VAR_AVAILABLE_USEC > ts)
                return 0;

        s->var_available_timestamp = ts;

        system_journal_open(s);

        if (!s->system_journal)
                return 0;

        r = sd_id128_get_machine(&machine);
        if (r < 0) {
                log_error("Failed to get machine id: %s", strerror(-r));
                return r;
        }

        r = sd_journal_open(&j, SD_JOURNAL_RUNTIME_ONLY);
        if (r < 0) {
                log_error("Failed to read runtime journal: %s", strerror(-r));
                return r;
        }

        SD_JOURNAL_FOREACH(j) {
                JournalFile *f;

                f = j->current_file;
                assert(f && f->current_offset > 0);

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0) {
                        log_error("Can't read entry: %s", strerror(-r));
                        goto finish;
                }

                r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset, NULL, NULL, NULL);
                if (r == -E2BIG) {
                        log_info("Allocation limit reached.");

                        journal_file_post_change(s->system_journal);
                        server_vacuum(s);

                        r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset, NULL, NULL, NULL);
                }

                if (r < 0) {
                        log_error("Can't write entry: %s", strerror(-r));
                        goto finish;
                }
        }

finish:
        journal_file_post_change(s->system_journal);

        journal_file_close(s->runtime_journal);
        s->runtime_journal = NULL;

        if (r >= 0) {
                sd_id128_to_string(machine, path + 17);
                rm_rf(path, false, true, false);
        }

        return r;
}

static void forward_syslog(Server *s, const void *buffer, size_t length, struct ucred *ucred, struct timeval *tv) {
        struct msghdr msghdr;
        struct iovec iovec;
        struct cmsghdr *cmsg;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                            CMSG_SPACE(sizeof(struct timeval))];
        } control;
        union sockaddr_union sa;

        assert(s);

        zero(msghdr);

        zero(iovec);
        iovec.iov_base = (void*) buffer;
        iovec.iov_len = length;
        msghdr.msg_iov = &iovec;
        msghdr.msg_iovlen = 1;

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/run/systemd/syslog", sizeof(sa.un.sun_path));
        msghdr.msg_name = &sa;
        msghdr.msg_namelen = offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path);

        zero(control);
        msghdr.msg_control = &control;
        msghdr.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msghdr);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_CREDENTIALS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));
        msghdr.msg_controllen = cmsg->cmsg_len;

        /* Forward the syslog message we received via /dev/log to
         * /run/systemd/syslog. Unfortunately we currently can't set
         * the SO_TIMESTAMP auxiliary data, and hence we don't. */

        if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                return;

        if (errno == ESRCH) {
                struct ucred u;

                /* Hmm, presumably the sender process vanished
                 * by now, so let's fix it as good as we
                 * can, and retry */

                u = *ucred;
                u.pid = getpid();
                memcpy(CMSG_DATA(cmsg), &u, sizeof(struct ucred));

                if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                        return;
        }

        log_debug("Failed to forward syslog message: %m");
}

static int process_event(Server *s, struct epoll_event *ev) {
        assert(s);

        if (ev->data.fd == s->signal_fd) {
                struct signalfd_siginfo sfsi;
                ssize_t n;

                if (ev->events != EPOLLIN) {
                        log_info("Got invalid event from epoll.");
                        return -EIO;
                }

                n = read(s->signal_fd, &sfsi, sizeof(sfsi));
                if (n != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                if (sfsi.ssi_signo == SIGUSR1) {
                        server_flush_to_var(s);
                        return 0;
                }

                log_debug("Received SIG%s", signal_to_string(sfsi.ssi_signo));
                return 0;

        } else if (ev->data.fd == s->native_fd ||
                   ev->data.fd == s->syslog_fd) {

                if (ev->events != EPOLLIN) {
                        log_info("Got invalid event from epoll.");
                        return -EIO;
                }

                for (;;) {
                        struct msghdr msghdr;
                        struct iovec iovec;
                        struct ucred *ucred = NULL;
                        struct timeval *tv = NULL;
                        struct cmsghdr *cmsg;
                        union {
                                struct cmsghdr cmsghdr;
                                uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                                            CMSG_SPACE(sizeof(struct timeval))];
                        } control;
                        ssize_t n;
                        int v;

                        if (ioctl(ev->data.fd, SIOCINQ, &v) < 0) {
                                log_error("SIOCINQ failed: %m");
                                return -errno;
                        }

                        if (v <= 0)
                                return 1;

                        if (s->buffer_size < (size_t) v) {
                                void *b;
                                size_t l;

                                l = MAX(LINE_MAX + (size_t) v, s->buffer_size * 2);
                                b = realloc(s->buffer, l+1);

                                if (!b) {
                                        log_error("Couldn't increase buffer.");
                                        return -ENOMEM;
                                }

                                s->buffer_size = l;
                                s->buffer = b;
                        }

                        zero(iovec);
                        iovec.iov_base = s->buffer;
                        iovec.iov_len = s->buffer_size;

                        zero(control);
                        zero(msghdr);
                        msghdr.msg_iov = &iovec;
                        msghdr.msg_iovlen = 1;
                        msghdr.msg_control = &control;
                        msghdr.msg_controllen = sizeof(control);

                        n = recvmsg(ev->data.fd, &msghdr, MSG_DONTWAIT);
                        if (n < 0) {

                                if (errno == EINTR || errno == EAGAIN)
                                        return 1;

                                log_error("recvmsg() failed: %m");
                                return -errno;
                        }

                        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {

                                if (cmsg->cmsg_level == SOL_SOCKET &&
                                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)))
                                        ucred = (struct ucred*) CMSG_DATA(cmsg);
                                else if (cmsg->cmsg_level == SOL_SOCKET &&
                                         cmsg->cmsg_type == SO_TIMESTAMP &&
                                         cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
                                        tv = (struct timeval*) CMSG_DATA(cmsg);
                        }

                        if (ev->data.fd == s->syslog_fd) {
                                char *e;

                                e = memchr(s->buffer, '\n', n);
                                if (e)
                                        *e = 0;
                                else
                                        s->buffer[n] = 0;

                                forward_syslog(s, s->buffer, n, ucred, tv);
                                process_syslog_message(s, strstrip(s->buffer), ucred, tv);
                        } else
                                process_native_message(s, s->buffer, n, ucred, tv);
                }

                return 1;

        } else if (ev->data.fd == s->stdout_fd) {

                if (ev->events != EPOLLIN) {
                        log_info("Got invalid event from epoll.");
                        return -EIO;
                }

                stdout_stream_new(s);
                return 1;

        } else {
                StdoutStream *stream;

                if ((ev->events|EPOLLIN|EPOLLHUP) != (EPOLLIN|EPOLLHUP)) {
                        log_info("Got invalid event from epoll.");
                        return -EIO;
                }

                /* If it is none of the well-known fds, it must be an
                 * stdout stream fd. Note that this is a bit ugly here
                 * (since we rely that none of the well-known fds
                 * could be interpreted as pointer), but nonetheless
                 * safe, since the well-known fds would never get an
                 * fd > 4096, i.e. beyond the first memory page */

                stream = ev->data.ptr;

                if (stdout_stream_process(stream) <= 0)
                        stdout_stream_free(stream);

                return 1;
        }

        log_error("Unknown event.");
        return 0;
}

static int open_syslog_socket(Server *s) {
        union sockaddr_union sa;
        int one, r;
        struct epoll_event ev;
        struct timeval tv;

        assert(s);

        if (s->syslog_fd < 0) {

                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                if (s->syslog_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/dev/log", sizeof(sa.un.sun_path));

                unlink(sa.un.sun_path);

                r = bind(s->syslog_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0) {
                        log_error("bind() failed: %m");
                        return -errno;
                }

                chmod(sa.un.sun_path, 0666);
        }

        one = 1;
        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_PASSCRED failed: %m");
                return -errno;
        }

        one = 1;
        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_TIMESTAMP failed: %m");
                return -errno;
        }

        /* Since we use the same socket for forwarding this to some
         * other syslog implementation, make sure we don't hang
         * forever */
        timeval_store(&tv, SYSLOG_TIMEOUT_USEC);
        if (setsockopt(s->syslog_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
                log_error("SO_SNDTIMEO failed: %m");
                return -errno;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->syslog_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->syslog_fd, &ev) < 0) {
                log_error("Failed to add syslog server fd to epoll object: %m");
                return -errno;
        }

        return 0;
}

static int open_native_socket(Server*s) {
        union sockaddr_union sa;
        int one, r;
        struct epoll_event ev;

        assert(s);

        if (s->native_fd < 0) {

                s->native_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                if (s->native_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/run/systemd/journal", sizeof(sa.un.sun_path));

                unlink(sa.un.sun_path);

                r = bind(s->native_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0) {
                        log_error("bind() failed: %m");
                        return -errno;
                }

                chmod(sa.un.sun_path, 0666);
        }

        one = 1;
        r = setsockopt(s->native_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_PASSCRED failed: %m");
                return -errno;
        }

        one = 1;
        r = setsockopt(s->native_fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_TIMESTAMP failed: %m");
                return -errno;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->native_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->native_fd, &ev) < 0) {
                log_error("Failed to add native server fd to epoll object: %m");
                return -errno;
        }

        return 0;
}

static int open_stdout_socket(Server *s) {
        union sockaddr_union sa;
        int r;
        struct epoll_event ev;

        assert(s);

        if (s->stdout_fd < 0) {

                s->stdout_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
                if (s->stdout_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/run/systemd/stdout", sizeof(sa.un.sun_path));

                unlink(sa.un.sun_path);

                r = bind(s->stdout_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0) {
                        log_error("bind() failed: %m");
                        return -errno;
                }

                chmod(sa.un.sun_path, 0666);

                if (listen(s->stdout_fd, SOMAXCONN) < 0) {
                        log_error("liste() failed: %m");
                        return -errno;
                }
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->stdout_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->stdout_fd, &ev) < 0) {
                log_error("Failed to add stdout server fd to epoll object: %m");
                return -errno;
        }

        return 0;
}

static int open_signalfd(Server *s) {
        sigset_t mask;
        struct epoll_event ev;

        assert(s);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, SIGUSR1, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        s->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (s->signal_fd < 0) {
                log_error("signalfd(): %m");
                return -errno;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->signal_fd;

        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->signal_fd, &ev) < 0) {
                log_error("epoll_ctl(): %m");
                return -errno;
        }

        return 0;
}

static int server_init(Server *s) {
        int n, r, fd;

        assert(s);

        zero(*s);
        s->syslog_fd = s->native_fd = s->stdout_fd = s->signal_fd = s->epoll_fd = -1;
        s->compress = true;

        memset(&s->system_metrics, 0xFF, sizeof(s->system_metrics));
        memset(&s->runtime_metrics, 0xFF, sizeof(s->runtime_metrics));

        s->user_journals = hashmap_new(trivial_hash_func, trivial_compare_func);
        if (!s->user_journals) {
                log_error("Out of memory.");
                return -ENOMEM;
        }

        s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (s->epoll_fd < 0) {
                log_error("Failed to create epoll object: %m");
                return -errno;
        }

        n = sd_listen_fds(true);
        if (n < 0) {
                log_error("Failed to read listening file descriptors from environment: %s", strerror(-n));
                return n;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {

                if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/run/systemd/native", 0) > 0) {

                        if (s->native_fd >= 0) {
                                log_error("Too many native sockets passed.");
                                return -EINVAL;
                        }

                        s->native_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_STREAM, 1, "/run/systemd/stdout", 0) > 0) {

                        if (s->stdout_fd >= 0) {
                                log_error("Too many stdout sockets passed.");
                                return -EINVAL;
                        }

                        s->stdout_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/dev/log", 0) > 0) {

                        if (s->syslog_fd >= 0) {
                                log_error("Too many /dev/log sockets passed.");
                                return -EINVAL;
                        }

                        s->syslog_fd = fd;

                } else {
                        log_error("Unknown socket passed.");
                        return -EINVAL;
                }
        }

        r = open_syslog_socket(s);
        if (r < 0)
                return r;

        r = open_native_socket(s);
        if (r < 0)
                return r;

        r = open_stdout_socket(s);
        if (r < 0)
                return r;

        r = system_journal_open(s);
        if (r < 0)
                return r;

        r = open_signalfd(s);
        if (r < 0)
                return r;

        s->rate_limit = journal_rate_limit_new(DEFAULT_RATE_LIMIT_INTERVAL, DEFAULT_RATE_LIMIT_BURST);
        if (!s->rate_limit)
                return -ENOMEM;

        return 0;
}

static void server_done(Server *s) {
        JournalFile *f;
        assert(s);

        while (s->stdout_streams)
                stdout_stream_free(s->stdout_streams);

        if (s->system_journal)
                journal_file_close(s->system_journal);

        if (s->runtime_journal)
                journal_file_close(s->runtime_journal);

        while ((f = hashmap_steal_first(s->user_journals)))
                journal_file_close(f);

        hashmap_free(s->user_journals);

        if (s->epoll_fd >= 0)
                close_nointr_nofail(s->epoll_fd);

        if (s->signal_fd >= 0)
                close_nointr_nofail(s->signal_fd);

        if (s->syslog_fd >= 0)
                close_nointr_nofail(s->syslog_fd);

        if (s->native_fd >= 0)
                close_nointr_nofail(s->native_fd);

        if (s->stdout_fd >= 0)
                close_nointr_nofail(s->stdout_fd);

        if (s->rate_limit)
                journal_rate_limit_free(s->rate_limit);

        free(s->buffer);
}

int main(int argc, char *argv[]) {
        Server server;
        int r;

        /* if (getppid() != 1) { */
        /*         log_error("This program should be invoked by init only."); */
        /*         return EXIT_FAILURE; */
        /* } */

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_CONSOLE);
        log_parse_environment();
        log_open();

        umask(0022);

        r = server_init(&server);
        if (r < 0)
                goto finish;

        log_debug("systemd-journald running as pid %lu", (unsigned long) getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        server_vacuum(&server);
        server_flush_to_var(&server);

        for (;;) {
                struct epoll_event event;

                r = epoll_wait(server.epoll_fd, &event, 1, -1);
                if (r < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %m");
                        r = -errno;
                        goto finish;
                } else if (r == 0)
                        break;

                r = process_event(&server, &event);
                if (r < 0)
                        goto finish;
                else if (r == 0)
                        break;
        }

        log_debug("systemd-journald stopped as pid %lu", (unsigned long) getpid());

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

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

#include "hashmap.h"
#include "journal-file.h"
#include "sd-daemon.h"
#include "socket-util.h"
#include "acl-util.h"
#include "cgroup-util.h"

#define USER_JOURNALS_MAX 1024

typedef struct Server {
        int epoll_fd;
        int signal_fd;
        int syslog_fd;
        int native_fd;

        JournalFile *runtime_journal;
        JournalFile *system_journal;
        Hashmap *user_journals;

        uint64_t seqnum;

        char *buffer;
        size_t buffer_size;
} Server;

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

        /* We split up user logs only on /var, not on /run */
        if (!s->system_journal)
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

        r = hashmap_put(s->user_journals, UINT32_TO_PTR(uid), f);
        if (r < 0) {
                journal_file_close(f);
                return s->system_journal;
        }

        return f;
}

static void dispatch_message(Server *s, struct iovec *iovec, unsigned n, unsigned m, struct ucred *ucred, struct timeval *tv) {
        char *pid = NULL, *uid = NULL, *gid = NULL,
                *source_time = NULL, *boot_id = NULL, *machine_id = NULL,
                *comm = NULL, *cmdline = NULL, *hostname = NULL,
                *audit_session = NULL, *audit_loginuid = NULL,
                *exe = NULL, *cgroup = NULL;

        char idbuf[33];
        sd_id128_t id;
        int r;
        char *t;
        uid_t loginuid = 0, realuid = 0;
        JournalFile *f;

        assert(s);
        assert(iovec || n == 0);

        if (n == 0)
                return;

        assert(n + 13 <= m);

        if (ucred) {
                uint32_t session;
                char *path;

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
                        if (comm)
                                IOVEC_SET_STRING(iovec[n++], comm);
                        free(t);
                }

                r = get_process_exe(ucred->pid, &t);
                if (r >= 0) {
                        exe = strappend("_EXE=", t);
                        if (comm)
                                IOVEC_SET_STRING(iovec[n++], exe);
                        free(t);
                }

                r = get_process_cmdline(ucred->pid, LINE_MAX, false, &t);
                if (r >= 0) {
                        cmdline = strappend("_CMDLINE=", t);
                        if (cmdline)
                                IOVEC_SET_STRING(iovec[n++], cmdline);
                        free(t);
                }

                r = audit_session_from_pid(ucred->pid, &session);
                if (r >= 0)
                        if (asprintf(&audit_session, "_AUDIT_SESSION=%lu", (unsigned long) session) >= 0)
                                IOVEC_SET_STRING(iovec[n++], audit_session);

                r = audit_loginuid_from_pid(ucred->pid, &loginuid);
                if (r >= 0)
                        if (asprintf(&audit_loginuid, "_AUDIT_LOGINUID=%lu", (unsigned long) loginuid) >= 0)
                                IOVEC_SET_STRING(iovec[n++], audit_loginuid);

                r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, ucred->pid, &path);
                if (r >= 0) {
                        cgroup = strappend("_SYSTEMD_CGROUP=", path);
                        if (cgroup)
                                IOVEC_SET_STRING(iovec[n++], cgroup);
                        free(path);
                }
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
                if (hostname)
                        IOVEC_SET_STRING(iovec[n++], hostname);
                free(t);
        }

        assert(n <= m);

        f = find_journal(s, realuid == 0 ? 0 : loginuid);
        if (!f)
                log_warning("Dropping message, as we can't find a place to store the data.");
        else {
                r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL, NULL);

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

}

static void process_syslog_message(Server *s, const char *buf, struct ucred *ucred, struct timeval *tv) {
        char *message = NULL, *syslog_priority = NULL, *syslog_facility = NULL;
        struct iovec iovec[16];
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

        dispatch_message(s, iovec, n, ELEMENTSOF(iovec), ucred, tv);

        free(message);
        free(syslog_facility);
        free(syslog_priority);
}

static void process_native_message(Server *s, const void *buffer, size_t buffer_size, struct ucred *ucred, struct timeval *tv) {
        struct iovec *iovec = NULL;
        unsigned n = 0, m = 0, j;
        const char *p;
        size_t remaining;

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
                        dispatch_message(s, iovec, n, m, ucred, tv);
                        n = 0;

                        p++;
                        remaining--;
                        continue;
                }

                if (*p == '.') {
                        /* Control command, ignore for now */
                        remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                }

                /* A property follows */

                if (n+13 >= m) {
                        struct iovec *c;
                        unsigned u;

                        u = MAX((n+13U) * 2U, 4U);
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
                        if (p[0] != '_') {
                                /* If the field name starts with an
                                 * underscore, skip the variable,
                                 * since that indidates a trusted
                                 * field */
                                iovec[n].iov_base = (char*) p;
                                iovec[n].iov_len = e - p;
                                n++;
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

                        if (k[0] != '_') {
                                iovec[n].iov_base = k;
                                iovec[n].iov_len = (e - p) + 1 + l;
                                n++;
                        } else
                                free(k);

                        remaining -= (e - p) + 1 + sizeof(uint64_t) + l + 1;
                        p = e + 1 + sizeof(uint64_t) + l + 1;
                }
        }

        dispatch_message(s, iovec, n, m, ucred, tv);

        for (j = 0; j < n; j++)
                if (iovec[j].iov_base < buffer ||
                    (const uint8_t*) iovec[j].iov_base >= (const uint8_t*) buffer + buffer_size)
                        free(iovec[j].iov_base);
}

static int process_event(Server *s, struct epoll_event *ev) {
        assert(s);

        if (ev->events != EPOLLIN) {
                log_info("Got invalid event from epoll.");
                return -EIO;
        }

        if (ev->data.fd == s->signal_fd) {
                struct signalfd_siginfo sfsi;
                ssize_t n;

                n = read(s->signal_fd, &sfsi, sizeof(sfsi));
                if (n != sizeof(sfsi)) {

                        if (n >= 0)
                                return -EIO;

                        if (errno == EINTR || errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                log_debug("Received SIG%s", signal_to_string(sfsi.ssi_signo));
                return 0;

        }

        if (ev->data.fd == s->native_fd ||
            ev->data.fd == s->syslog_fd) {
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

                                process_syslog_message(s, strstrip(s->buffer), ucred, tv);
                        } else
                                process_native_message(s, s->buffer, n, ucred, tv);
                }

                return 1;
        }

        log_error("Unknown event.");
        return 0;
}

static int system_journal_open(Server *s) {
        int r;
        char *fn;
        sd_id128_t machine;
        char ids[33];

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        /* First try to create the machine path, but not the prefix */
        fn = strappend("/var/log/journal/", sd_id128_to_string(machine, ids));
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
                fix_perms(s->system_journal, 0);
                return r;
        }

        if (r < 0 && r != -ENOENT) {
                log_error("Failed to open system journal: %s", strerror(-r));
                return r;
        }

        /* /var didn't work, so try /run, but this time we
         * create the prefix too */
        fn = join("/run/log/journal/", ids, "/system.journal", NULL);
        if (!fn)
                return -ENOMEM;

        (void) mkdir_parents(fn, 0755);
        r = journal_file_open(fn, O_RDWR|O_CREAT, 0640, NULL, &s->runtime_journal);
        free(fn);

        if (r < 0) {
                log_error("Failed to open runtime journal: %s", strerror(-r));
                return r;
        }

        fix_perms(s->runtime_journal, 0);
        return r;
}

static int open_syslog_socket(Server *s) {
        union sockaddr_union sa;
        int one, r;

        assert(s);

        if (s->syslog_fd < 0) {

                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                if (s->syslog_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/run/systemd/syslog", sizeof(sa.un.sun_path));

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

        return 0;
}

static int open_native_socket(Server*s) {
        union sockaddr_union sa;
        int one, r;

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

        return 0;
}

static int server_init(Server *s) {
        int n, r, fd;
        struct epoll_event ev;
        sigset_t mask;

        assert(s);

        zero(*s);
        s->syslog_fd = s->native_fd = s->signal_fd = -1;

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

                if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/dev/log", 0) > 0) {

                        if (s->syslog_fd >= 0) {
                                log_error("Too many /dev/log sockets passed.");
                                return -EINVAL;
                        }

                        s->syslog_fd = fd;

                } else if (sd_is_socket(fd, AF_UNIX, SOCK_DGRAM, -1) > 0) {

                        if (s->native_fd >= 0) {
                                log_error("Too many native sockets passed.");
                                return -EINVAL;
                        }

                        s->native_fd = fd;
                } else {
                        log_error("Unknown socket passed.");
                        return -EINVAL;
                }
        }

        r = open_syslog_socket(s);
        if (r < 0)
                return r;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->syslog_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->syslog_fd, &ev) < 0) {
                log_error("Failed to add syslog server fd to epoll object: %m");
                return -errno;
        }

        r = open_native_socket(s);
        if (r < 0)
                return r;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->native_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->native_fd, &ev) < 0) {
                log_error("Failed to add native server fd to epoll object: %m");
                return -errno;
        }

        s->user_journals = hashmap_new(trivial_hash_func, trivial_compare_func);
        if (!s->user_journals) {
                log_error("Out of memory.");
                return -ENOMEM;
        }

        r = system_journal_open(s);
        if (r < 0)
                return r;

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
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

static void server_done(Server *s) {
        JournalFile *f;
        assert(s);

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
                  "STATUS=Processing messages...");

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

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

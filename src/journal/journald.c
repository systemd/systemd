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

#include "hashmap.h"
#include "journal-file.h"
#include "sd-daemon.h"
#include "socket-util.h"
#include "acl-util.h"
#include "cgroup-util.h"

typedef struct Server {
        int syslog_fd;
        int epoll_fd;
        int signal_fd;

        JournalFile *runtime_journal;
        JournalFile *system_journal;
        Hashmap *user_journals;
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

        assert(s);

        /* We split up user logs only on /var, not on /run */
        if (!s->system_journal)
                return s->runtime_journal;

        if (uid <= 0)
                return s->system_journal;

        f = hashmap_get(s->user_journals, UINT32_TO_PTR(uid));
        if (f)
                return f;

        if (asprintf(&p, "/var/log/journal/%lu.journal", (unsigned long) uid) < 0)
                return s->system_journal;

        r = journal_file_open(p, O_RDWR|O_CREAT, 0640, &f);
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

static void process_message(Server *s, const char *buf, struct ucred *ucred, struct timeval *tv) {
        char *message = NULL, *pid = NULL, *uid = NULL, *gid = NULL,
                *source_time = NULL, *boot_id = NULL, *machine_id = NULL,
                *comm = NULL, *cmdline = NULL, *hostname = NULL,
                *audit_session = NULL, *audit_loginuid = NULL,
                *syslog_priority = NULL, *syslog_facility = NULL,
                *exe = NULL, *cgroup = NULL;
        struct iovec iovec[16];
        unsigned n = 0;
        char idbuf[33];
        sd_id128_t id;
        int r;
        char *t;
        int priority = LOG_USER | LOG_INFO;
        uid_t loginuid = 0;
        JournalFile *f;

        parse_syslog_priority((char**) &buf, &priority);
        skip_syslog_date((char**) &buf);

        if (asprintf(&syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_priority);

        if (asprintf(&syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority)) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_facility);

        message = strappend("MESSAGE=", buf);
        if (message)
                IOVEC_SET_STRING(iovec[n++], message);

        if (ucred) {
                uint32_t session;
                char *path;

                if (asprintf(&pid, "PID=%lu", (unsigned long) ucred->pid) >= 0)
                        IOVEC_SET_STRING(iovec[n++], pid);

                if (asprintf(&uid, "UID=%lu", (unsigned long) ucred->uid) >= 0)
                        IOVEC_SET_STRING(iovec[n++], uid);

                if (asprintf(&gid, "GID=%lu", (unsigned long) ucred->gid) >= 0)
                        IOVEC_SET_STRING(iovec[n++], gid);

                r = get_process_comm(ucred->pid, &t);
                if (r >= 0) {
                        comm = strappend("COMM=", t);
                        if (comm)
                                IOVEC_SET_STRING(iovec[n++], comm);
                        free(t);
                }

                r = get_process_exe(ucred->pid, &t);
                if (r >= 0) {
                        exe = strappend("EXE=", t);
                        if (comm)
                                IOVEC_SET_STRING(iovec[n++], exe);
                        free(t);
                }

                r = get_process_cmdline(ucred->pid, LINE_MAX, false, &t);
                if (r >= 0) {
                        cmdline = strappend("CMDLINE=", t);
                        if (cmdline)
                                IOVEC_SET_STRING(iovec[n++], cmdline);
                        free(t);
                }

                r = audit_session_from_pid(ucred->pid, &session);
                if (r >= 0)
                        if (asprintf(&audit_session, "AUDIT_SESSION=%lu", (unsigned long) session) >= 0)
                                IOVEC_SET_STRING(iovec[n++], audit_session);

                r = audit_loginuid_from_pid(ucred->pid, &loginuid);
                if (r >= 0)
                        if (asprintf(&audit_loginuid, "AUDIT_LOGINUID=%lu", (unsigned long) loginuid) >= 0)
                                IOVEC_SET_STRING(iovec[n++], audit_loginuid);

                r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, ucred->pid, &path);
                if (r >= 0) {
                        cgroup = strappend("SYSTEMD_CGROUP=", path);
                        if (cgroup)
                                IOVEC_SET_STRING(iovec[n++], cgroup);
                        free(path);
                }
        }

        if (tv) {
                if (asprintf(&source_time, "SOURCE_REALTIME_TIMESTAMP=%llu",
                             (unsigned long long) timeval_load(tv)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], source_time);
        }

        /* Note that strictly speaking storing the boot id here is
         * redundant since the entry includes this in-line
         * anyway. However, we need this indexed, too. */
        r = sd_id128_get_boot(&id);
        if (r >= 0)
                if (asprintf(&boot_id, "BOOT_ID=%s", sd_id128_to_string(id, idbuf)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], boot_id);

        r = sd_id128_get_machine(&id);
        if (r >= 0)
                if (asprintf(&machine_id, "MACHINE_ID=%s", sd_id128_to_string(id, idbuf)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], machine_id);

        t = gethostname_malloc();
        if (t) {
                hostname = strappend("HOSTNAME=", t);
                if (hostname)
                        IOVEC_SET_STRING(iovec[n++], hostname);
                free(t);
        }

        f = find_journal(s, loginuid);
        if (!f)
                log_warning("Dropping message, as we can't find a place to store the data.");
        else {
                r = journal_file_append_entry(f, NULL, iovec, n, NULL, NULL);

                if (r < 0)
                        log_error("Failed to write entry, ignoring: %s", strerror(-r));
        }

        free(message);
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
        free(syslog_facility);
        free(syslog_priority);
        free(cgroup);
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

        if (ev->data.fd == s->syslog_fd) {
                for (;;) {
                        char buf[LINE_MAX+1];
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
                        char *e;

                        zero(iovec);
                        iovec.iov_base = buf;
                        iovec.iov_len = sizeof(buf)-1;

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

                        e = memchr(buf, '\n', n);
                        if (e)
                                *e = 0;
                        else
                                buf[n] = 0;

                        process_message(s, strstrip(buf), ucred, tv);
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
        fn = join("/var/log/journal/", sd_id128_to_string(machine, ids), NULL);
        if (!fn)
                return -ENOMEM;
        (void) mkdir(fn, 0755);
        free(fn);

        /* The create the system journal file */
        fn = join("/var/log/journal/", ids, "/system.journal", NULL);
        if (!fn)
                return -ENOMEM;

        r = journal_file_open(fn, O_RDWR|O_CREAT, 0640, &s->system_journal);
        free(fn);

        if (r >= 0)
                fix_perms(s->system_journal, 0);
        else if (r == -ENOENT) {

                /* /var didn't work, so try /run, but this time we
                 * create the prefix too */
                fn = join("/run/log/journal/", ids, NULL);
                if (!fn)
                        return -ENOMEM;
                (void) mkdir_p(fn, 0755);
                free(fn);

                /* Then create the runtime journal file */
                fn = join("/run/log/journal/", ids, "/system.journal", NULL);
                if (!fn)
                        return -ENOMEM;
                r = journal_file_open(fn, O_RDWR|O_CREAT, 0640, &s->runtime_journal);
                free(fn);

                if (r >= 0)
                        fix_perms(s->runtime_journal, 0);
        }

        if (r < 0 && r != -ENOENT) {
                log_error("Failed to open journal: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int server_init(Server *s) {
        int n, one, r;
        struct epoll_event ev;
        sigset_t mask;

        assert(s);

        zero(*s);
        s->syslog_fd = s->signal_fd = -1;

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

        if (n > 1) {
                log_error("Too many file descriptors passed.");
                return -EINVAL;
        }

        if (n == 1)
                s->syslog_fd = SD_LISTEN_FDS_START;
        else {
                union sockaddr_union sa;

                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
                if (s->syslog_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/run/systemd/syslog", sizeof(sa.un.sun_path));

                unlink(sa.un.sun_path);

                r = bind(s->syslog_fd, &sa.sa, sizeof(sa.un));
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

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->syslog_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->syslog_fd, &ev) < 0) {
                log_error("Failed to add server fd to epoll object: %m");
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

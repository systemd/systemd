/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/statvfs.h>

#include <systemd/sd-journal.h>
#include <systemd/sd-login.h>
#include <systemd/sd-messages.h>
#include <systemd/sd-daemon.h>

#include "mkdir.h"
#include "hashmap.h"
#include "journal-file.h"
#include "socket-util.h"
#include "cgroup-util.h"
#include "list.h"
#include "journal-rate-limit.h"
#include "journal-internal.h"
#include "conf-parser.h"
#include "journald.h"
#include "virt.h"
#include "missing.h"

#ifdef HAVE_ACL
#include <sys/acl.h>
#include <acl/libacl.h>
#include "acl-util.h"
#endif

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#define USER_JOURNALS_MAX 1024
#define STDOUT_STREAMS_MAX 4096

#define DEFAULT_RATE_LIMIT_INTERVAL (10*USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST 200

#define RECHECK_AVAILABLE_SPACE_USEC (30*USEC_PER_SEC)

#define RECHECK_VAR_AVAILABLE_USEC (30*USEC_PER_SEC)

#define N_IOVEC_META_FIELDS 17

#define ENTRY_SIZE_MAX (1024*1024*32)

typedef enum StdoutStreamState {
        STDOUT_STREAM_IDENTIFIER,
        STDOUT_STREAM_PRIORITY,
        STDOUT_STREAM_LEVEL_PREFIX,
        STDOUT_STREAM_FORWARD_TO_SYSLOG,
        STDOUT_STREAM_FORWARD_TO_KMSG,
        STDOUT_STREAM_FORWARD_TO_CONSOLE,
        STDOUT_STREAM_RUNNING
} StdoutStreamState;

struct StdoutStream {
        Server *server;
        StdoutStreamState state;

        int fd;

        struct ucred ucred;
#ifdef HAVE_SELINUX
        security_context_t security_context;
#endif

        char *identifier;
        int priority;
        bool level_prefix:1;
        bool forward_to_syslog:1;
        bool forward_to_kmsg:1;
        bool forward_to_console:1;

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

                r = readdir_r(d, &buf, &de);
                if (r != 0)
                        break;

                if (!de)
                        break;

                if (!endswith(de->d_name, ".journal") &&
                    !endswith(de->d_name, ".journal~"))
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;

                if (!S_ISREG(st.st_mode))
                        continue;

                sum += (uint64_t) st.st_blocks * 512UL;
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

static void server_read_file_gid(Server *s) {
        const char *adm = "adm";
        int r;

        assert(s);

        if (s->file_gid_valid)
                return;

        r = get_group_creds(&adm, &s->file_gid);
        if (r < 0)
                log_warning("Failed to resolve 'adm' group: %s", strerror(-r));

        /* if we couldn't read the gid, then it will be 0, but that's
         * fine and we shouldn't try to resolve the group again, so
         * let's just pretend it worked right-away. */
        s->file_gid_valid = true;
}

static void server_fix_perms(Server *s, JournalFile *f, uid_t uid) {
        int r;
#ifdef HAVE_ACL
        acl_t acl;
        acl_entry_t entry;
        acl_permset_t permset;
#endif

        assert(f);

        server_read_file_gid(s);

        r = fchmod_and_fchown(f->fd, 0640, 0, s->file_gid);
        if (r < 0)
                log_warning("Failed to fix access mode/rights on %s, ignoring: %s", f->path, strerror(-r));

#ifdef HAVE_ACL
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
#endif
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

        r = journal_file_open_reliably(p, O_RDWR|O_CREAT, 0640, s->system_journal, &f);
        free(p);

        if (r < 0)
                return s->system_journal;

        server_fix_perms(s, f, uid);

        r = hashmap_put(s->user_journals, UINT32_TO_PTR(uid), f);
        if (r < 0) {
                journal_file_close(f);
                return s->system_journal;
        }

        return f;
}

static void server_rotate(Server *s) {
        JournalFile *f;
        void *k;
        Iterator i;
        int r;

        log_info("Rotating...");

        if (s->runtime_journal) {
                r = journal_file_rotate(&s->runtime_journal);
                if (r < 0)
                        if (s->runtime_journal)
                                log_error("Failed to rotate %s: %s", s->runtime_journal->path, strerror(-r));
                        else
                                log_error("Failed to create new runtime journal: %s", strerror(-r));
                else
                        server_fix_perms(s, s->runtime_journal, 0);
        }

        if (s->system_journal) {
                r = journal_file_rotate(&s->system_journal);
                if (r < 0)
                        if (s->system_journal)
                                log_error("Failed to rotate %s: %s", s->system_journal->path, strerror(-r));
                        else
                                log_error("Failed to create new system journal: %s", strerror(-r));

                else
                        server_fix_perms(s, s->system_journal, 0);
        }

        HASHMAP_FOREACH_KEY(f, k, s->user_journals, i) {
                r = journal_file_rotate(&f);
                if (r < 0)
                        if (f->path)
                                log_error("Failed to rotate %s: %s", f->path, strerror(-r));
                        else
                                log_error("Failed to create user journal: %s", strerror(-r));
                else {
                        hashmap_replace(s->user_journals, k, f);
                        server_fix_perms(s, s->system_journal, PTR_TO_UINT32(k));
                }
        }
}

static void server_vacuum(Server *s) {
        char *p;
        char ids[33];
        sd_id128_t machine;
        int r;

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

        if (endswith(init_path, "/system"))
                init_path[strlen(init_path) - 7] = 0;
        else if (streq(init_path, "/"))
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

static void dispatch_message_real(
                Server *s,
                struct iovec *iovec, unsigned n, unsigned m,
                struct ucred *ucred,
                struct timeval *tv,
                const char *label, size_t label_len) {

        char *pid = NULL, *uid = NULL, *gid = NULL,
                *source_time = NULL, *boot_id = NULL, *machine_id = NULL,
                *comm = NULL, *cmdline = NULL, *hostname = NULL,
                *audit_session = NULL, *audit_loginuid = NULL,
                *exe = NULL, *cgroup = NULL, *session = NULL,
                *owner_uid = NULL, *unit = NULL, *selinux_context = NULL;

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
        assert(n + N_IOVEC_META_FIELDS <= m);

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

                        if (exe)
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

                if (sd_pid_get_unit(ucred->pid, &t) >= 0) {
                        unit = strappend("_SYSTEMD_UNIT=", t);
                        free(t);

                        if (unit)
                                IOVEC_SET_STRING(iovec[n++], unit);
                }

                if (sd_pid_get_owner_uid(ucred->uid, &owner) >= 0)
                        if (asprintf(&owner_uid, "_SYSTEMD_OWNER_UID=%lu", (unsigned long) owner) >= 0)
                                IOVEC_SET_STRING(iovec[n++], owner_uid);

#ifdef HAVE_SELINUX
                if (label) {
                        selinux_context = malloc(sizeof("_SELINUX_CONTEXT=") + label_len);
                        if (selinux_context) {
                                memcpy(selinux_context, "_SELINUX_CONTEXT=", sizeof("_SELINUX_CONTEXT=")-1);
                                memcpy(selinux_context+sizeof("_SELINUX_CONTEXT=")-1, label, label_len);
                                selinux_context[sizeof("_SELINUX_CONTEXT=")-1+label_len] = 0;
                                IOVEC_SET_STRING(iovec[n++], selinux_context);
                        }
                } else {
                        security_context_t con;

                        if (getpidcon(ucred->pid, &con) >= 0) {
                                selinux_context = strappend("_SELINUX_CONTEXT=", con);
                                if (selinux_context)
                                        IOVEC_SET_STRING(iovec[n++], selinux_context);

                                freecon(con);
                        }
                }
#endif
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

                if ((r == -E2BIG || /* hit limit */
                     r == -EFBIG || /* hit fs limit */
                     r == -EDQUOT || /* quota hit */
                     r == -ENOSPC || /* disk full */
                     r == -EBADMSG || /* corrupted */
                     r == -ENODATA || /* truncated */
                     r == -EHOSTDOWN || /* other machine */
                     r == -EPROTONOSUPPORT) && /* unsupported feature */
                    !vacuumed) {

                        if (r == -E2BIG)
                                log_info("Allocation limit reached, rotating.");
                        else
                                log_warning("Journal file corrupted, rotating.");

                        server_rotate(s);
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
        free(unit);
        free(selinux_context);
}

static void driver_message(Server *s, sd_id128_t message_id, const char *format, ...) {
        char mid[11 + 32 + 1];
        char buffer[16 + LINE_MAX + 1];
        struct iovec iovec[N_IOVEC_META_FIELDS + 4];
        int n = 0;
        va_list ap;
        struct ucred ucred;

        assert(s);
        assert(format);

        IOVEC_SET_STRING(iovec[n++], "PRIORITY=5");
        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=driver");

        memcpy(buffer, "MESSAGE=", 8);
        va_start(ap, format);
        vsnprintf(buffer + 8, sizeof(buffer) - 8, format, ap);
        va_end(ap);
        char_array_0(buffer);
        IOVEC_SET_STRING(iovec[n++], buffer);

        snprintf(mid, sizeof(mid), "MESSAGE_ID=" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(message_id));
        char_array_0(mid);
        IOVEC_SET_STRING(iovec[n++], mid);

        zero(ucred);
        ucred.pid = getpid();
        ucred.uid = getuid();
        ucred.gid = getgid();

        dispatch_message_real(s, iovec, n, ELEMENTSOF(iovec), &ucred, NULL, NULL, 0);
}

static void dispatch_message(Server *s,
                             struct iovec *iovec, unsigned n, unsigned m,
                             struct ucred *ucred,
                             struct timeval *tv,
                             const char *label, size_t label_len,
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

        rl = journal_rate_limit_test(s->rate_limit, path, priority & LOG_PRIMASK, available_space(s));

        if (rl == 0) {
                free(path);
                return;
        }

        /* Write a suppression message if we suppressed something */
        if (rl > 1)
                driver_message(s, SD_MESSAGE_JOURNAL_DROPPED, "Suppressed %u messages from %s", rl - 1, path);

        free(path);

finish:
        dispatch_message_real(s, iovec, n, m, ucred, tv, label, label_len);
}

static void forward_syslog_iovec(Server *s, const struct iovec *iovec, unsigned n_iovec, struct ucred *ucred, struct timeval *tv) {
        struct msghdr msghdr;
        struct cmsghdr *cmsg;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred))];
        } control;
        union sockaddr_union sa;

        assert(s);
        assert(iovec);
        assert(n_iovec > 0);

        zero(msghdr);
        msghdr.msg_iov = (struct iovec*) iovec;
        msghdr.msg_iovlen = n_iovec;

        zero(sa);
        sa.un.sun_family = AF_UNIX;
        strncpy(sa.un.sun_path, "/run/systemd/journal/syslog", sizeof(sa.un.sun_path));
        msghdr.msg_name = &sa;
        msghdr.msg_namelen = offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path);

        if (ucred) {
                zero(control);
                msghdr.msg_control = &control;
                msghdr.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&msghdr);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_CREDENTIALS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
                memcpy(CMSG_DATA(cmsg), ucred, sizeof(struct ucred));
                msghdr.msg_controllen = cmsg->cmsg_len;
        }

        /* Forward the syslog message we received via /dev/log to
         * /run/systemd/syslog. Unfortunately we currently can't set
         * the SO_TIMESTAMP auxiliary data, and hence we don't. */

        if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                return;

        /* The socket is full? I guess the syslog implementation is
         * too slow, and we shouldn't wait for that... */
        if (errno == EAGAIN)
                return;

        if (ucred && errno == ESRCH) {
                struct ucred u;

                /* Hmm, presumably the sender process vanished
                 * by now, so let's fix it as good as we
                 * can, and retry */

                u = *ucred;
                u.pid = getpid();
                memcpy(CMSG_DATA(cmsg), &u, sizeof(struct ucred));

                if (sendmsg(s->syslog_fd, &msghdr, MSG_NOSIGNAL) >= 0)
                        return;

                if (errno == EAGAIN)
                        return;
        }

        log_debug("Failed to forward syslog message: %m");
}

static void forward_syslog_raw(Server *s, const char *buffer, struct ucred *ucred, struct timeval *tv) {
        struct iovec iovec;

        assert(s);
        assert(buffer);

        IOVEC_SET_STRING(iovec, buffer);
        forward_syslog_iovec(s, &iovec, 1, ucred, tv);
}

static void forward_syslog(Server *s, int priority, const char *identifier, const char *message, struct ucred *ucred, struct timeval *tv) {
        struct iovec iovec[5];
        char header_priority[6], header_time[64], header_pid[16];
        int n = 0;
        time_t t;
        struct tm *tm;
        char *ident_buf = NULL;

        assert(s);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        /* First: priority field */
        snprintf(header_priority, sizeof(header_priority), "<%i>", priority);
        char_array_0(header_priority);
        IOVEC_SET_STRING(iovec[n++], header_priority);

        /* Second: timestamp */
        t = tv ? tv->tv_sec : ((time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC));
        tm = localtime(&t);
        if (!tm)
                return;
        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return;
        IOVEC_SET_STRING(iovec[n++], header_time);

        /* Third: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) ucred->pid);
                char_array_0(header_pid);

                if (identifier)
                        IOVEC_SET_STRING(iovec[n++], identifier);

                IOVEC_SET_STRING(iovec[n++], header_pid);
        } else if (identifier) {
                IOVEC_SET_STRING(iovec[n++], identifier);
                IOVEC_SET_STRING(iovec[n++], ": ");
        }

        /* Fourth: message */
        IOVEC_SET_STRING(iovec[n++], message);

        forward_syslog_iovec(s, iovec, n, ucred, tv);

        free(ident_buf);
}

static int fixup_priority(int priority) {

        if ((priority & LOG_FACMASK) == 0)
                return (priority & LOG_PRIMASK) | LOG_USER;

        return priority;
}

static void forward_kmsg(Server *s, int priority, const char *identifier, const char *message, struct ucred *ucred) {
        struct iovec iovec[5];
        char header_priority[6], header_pid[16];
        int n = 0;
        char *ident_buf = NULL;
        int fd;

        assert(s);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        /* Never allow messages with kernel facility to be written to
         * kmsg, regardless where the data comes from. */
        priority = fixup_priority(priority);

        /* First: priority field */
        snprintf(header_priority, sizeof(header_priority), "<%i>", priority);
        char_array_0(header_priority);
        IOVEC_SET_STRING(iovec[n++], header_priority);

        /* Second: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) ucred->pid);
                char_array_0(header_pid);

                if (identifier)
                        IOVEC_SET_STRING(iovec[n++], identifier);

                IOVEC_SET_STRING(iovec[n++], header_pid);
        } else if (identifier) {
                IOVEC_SET_STRING(iovec[n++], identifier);
                IOVEC_SET_STRING(iovec[n++], ": ");
        }

        /* Fourth: message */
        IOVEC_SET_STRING(iovec[n++], message);
        IOVEC_SET_STRING(iovec[n++], "\n");

        fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                log_debug("Failed to open /dev/kmsg for logging: %s", strerror(errno));
                goto finish;
        }

        if (writev(fd, iovec, n) < 0)
                log_debug("Failed to write to /dev/kmsg for logging: %s", strerror(errno));

        close_nointr_nofail(fd);

finish:
        free(ident_buf);
}

static void forward_console(Server *s, const char *identifier, const char *message, struct ucred *ucred) {
        struct iovec iovec[4];
        char header_pid[16];
        int n = 0, fd;
        char *ident_buf = NULL;

        assert(s);
        assert(message);

        /* First: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) ucred->pid);
                char_array_0(header_pid);

                if (identifier)
                        IOVEC_SET_STRING(iovec[n++], identifier);

                IOVEC_SET_STRING(iovec[n++], header_pid);
        } else if (identifier) {
                IOVEC_SET_STRING(iovec[n++], identifier);
                IOVEC_SET_STRING(iovec[n++], ": ");
        }

        /* Third: message */
        IOVEC_SET_STRING(iovec[n++], message);
        IOVEC_SET_STRING(iovec[n++], "\n");

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                log_debug("Failed to open /dev/console for logging: %s", strerror(errno));
                goto finish;
        }

        if (writev(fd, iovec, n) < 0)
                log_debug("Failed to write to /dev/console for logging: %s", strerror(errno));

        close_nointr_nofail(fd);

finish:
        free(ident_buf);
}

static void read_identifier(const char **buf, char **identifier, char **pid) {
        const char *p;
        char *t;
        size_t l, e;

        assert(buf);
        assert(identifier);
        assert(pid);

        p = *buf;

        p += strspn(p, WHITESPACE);
        l = strcspn(p, WHITESPACE);

        if (l <= 0 ||
            p[l-1] != ':')
                return;

        e = l;
        l--;

        if (p[l-1] == ']') {
                size_t k = l-1;

                for (;;) {

                        if (p[k] == '[') {
                                t = strndup(p+k+1, l-k-2);
                                if (t)
                                        *pid = t;

                                l = k;
                                break;
                        }

                        if (k == 0)
                                break;

                        k--;
                }
        }

        t = strndup(p, l);
        if (t)
                *identifier = t;

        *buf = p + e;
        *buf += strspn(*buf, WHITESPACE);
}

static void process_syslog_message(Server *s, const char *buf, struct ucred *ucred, struct timeval *tv, const char *label, size_t label_len) {
        char *message = NULL, *syslog_priority = NULL, *syslog_facility = NULL, *syslog_identifier = NULL, *syslog_pid = NULL;
        struct iovec iovec[N_IOVEC_META_FIELDS + 6];
        unsigned n = 0;
        int priority = LOG_USER | LOG_INFO;
        char *identifier = NULL, *pid = NULL;

        assert(s);
        assert(buf);

        if (s->forward_to_syslog)
                forward_syslog_raw(s, buf, ucred, tv);

        parse_syslog_priority((char**) &buf, &priority);
        skip_syslog_date((char**) &buf);
        read_identifier(&buf, &identifier, &pid);

        if (s->forward_to_kmsg)
                forward_kmsg(s, priority, identifier, buf, ucred);

        if (s->forward_to_console)
                forward_console(s, identifier, buf, ucred);

        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=syslog");

        if (asprintf(&syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_priority);

        if (priority & LOG_FACMASK)
                if (asprintf(&syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], syslog_facility);

        if (identifier) {
                syslog_identifier = strappend("SYSLOG_IDENTIFIER=", identifier);
                if (syslog_identifier)
                        IOVEC_SET_STRING(iovec[n++], syslog_identifier);
        }

        if (pid) {
                syslog_pid = strappend("SYSLOG_PID=", pid);
                if (syslog_pid)
                        IOVEC_SET_STRING(iovec[n++], syslog_pid);
        }

        message = strappend("MESSAGE=", buf);
        if (message)
                IOVEC_SET_STRING(iovec[n++], message);

        dispatch_message(s, iovec, n, ELEMENTSOF(iovec), ucred, tv, label, label_len, priority);

        free(message);
        free(identifier);
        free(pid);
        free(syslog_priority);
        free(syslog_facility);
        free(syslog_identifier);
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

static void process_native_message(
                Server *s,
                const void *buffer, size_t buffer_size,
                struct ucred *ucred,
                struct timeval *tv,
                const char *label, size_t label_len) {

        struct iovec *iovec = NULL;
        unsigned n = 0, m = 0, j, tn = (unsigned) -1;
        const char *p;
        size_t remaining;
        int priority = LOG_INFO;
        char *identifier = NULL, *message = NULL;

        assert(s);
        assert(buffer || buffer_size == 0);

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
                        dispatch_message(s, iovec, n, m, ucred, tv, label, label_len, priority);
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

                if (n+N_IOVEC_META_FIELDS >= m) {
                        struct iovec *c;
                        unsigned u;

                        u = MAX((n+N_IOVEC_META_FIELDS+1) * 2U, 4U);
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
                                size_t l;

                                l = e - p;

                                /* If the field name starts with an
                                 * underscore, skip the variable,
                                 * since that indidates a trusted
                                 * field */
                                iovec[n].iov_base = (char*) p;
                                iovec[n].iov_len = l;
                                n++;

                                /* We need to determine the priority
                                 * of this entry for the rate limiting
                                 * logic */
                                if (l == 10 &&
                                    memcmp(p, "PRIORITY=", 9) == 0 &&
                                    p[9] >= '0' && p[9] <= '9')
                                        priority = (priority & LOG_FACMASK) | (p[9] - '0');

                                else if (l == 17 &&
                                         memcmp(p, "SYSLOG_FACILITY=", 16) == 0 &&
                                         p[16] >= '0' && p[16] <= '9')
                                        priority = (priority & LOG_PRIMASK) | ((p[16] - '0') << 3);

                                else if (l == 18 &&
                                         memcmp(p, "SYSLOG_FACILITY=", 16) == 0 &&
                                         p[16] >= '0' && p[16] <= '9' &&
                                         p[17] >= '0' && p[17] <= '9')
                                        priority = (priority & LOG_PRIMASK) | (((p[16] - '0')*10 + (p[17] - '0')) << 3);

                                else if (l >= 19 &&
                                         memcmp(p, "SYSLOG_IDENTIFIER=", 18) == 0) {
                                        char *t;

                                        t = strndup(p + 18, l - 18);
                                        if (t) {
                                                free(identifier);
                                                identifier = t;
                                        }
                                } else if (l >= 8 &&
                                           memcmp(p, "MESSAGE=", 8) == 0) {
                                        char *t;

                                        t = strndup(p + 8, l - 8);
                                        if (t) {
                                                free(message);
                                                message = t;
                                        }
                                }
                        }

                        remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                } else {
                        le64_t l_le;
                        uint64_t l;
                        char *k;

                        if (remaining < e - p + 1 + sizeof(uint64_t) + 1) {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        memcpy(&l_le, e + 1, sizeof(uint64_t));
                        l = le64toh(l_le);

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

        if (n <= 0)
                goto finish;

        tn = n++;
        IOVEC_SET_STRING(iovec[tn], "_TRANSPORT=journal");

        if (message) {
                if (s->forward_to_syslog)
                        forward_syslog(s, priority, identifier, message, ucred, tv);

                if (s->forward_to_kmsg)
                        forward_kmsg(s, priority, identifier, message, ucred);

                if (s->forward_to_console)
                        forward_console(s, identifier, message, ucred);
        }

        dispatch_message(s, iovec, n, m, ucred, tv, label, label_len, priority);

finish:
        for (j = 0; j < n; j++)  {
                if (j == tn)
                        continue;

                if (iovec[j].iov_base < buffer ||
                    (const uint8_t*) iovec[j].iov_base >= (const uint8_t*) buffer + buffer_size)
                        free(iovec[j].iov_base);
        }

        free(iovec);
        free(identifier);
        free(message);
}

static void process_native_file(
                Server *s,
                int fd,
                struct ucred *ucred,
                struct timeval *tv,
                const char *label, size_t label_len) {

        struct stat st;
        void *p;
        ssize_t n;

        assert(s);
        assert(fd >= 0);

        /* Data is in the passed file, since it didn't fit in a
         * datagram. We can't map the file here, since clients might
         * then truncate it and trigger a SIGBUS for us. So let's
         * stupidly read it */

        if (fstat(fd, &st) < 0) {
                log_error("Failed to stat passed file, ignoring: %m");
                return;
        }

        if (!S_ISREG(st.st_mode)) {
                log_error("File passed is not regular. Ignoring.");
                return;
        }

        if (st.st_size <= 0)
                return;

        if (st.st_size > ENTRY_SIZE_MAX) {
                log_error("File passed too large. Ignoring.");
                return;
        }

        p = malloc(st.st_size);
        if (!p) {
                log_error("Out of memory");
                return;
        }

        n = pread(fd, p, st.st_size, 0);
        if (n < 0)
                log_error("Failed to read file, ignoring: %s", strerror(-n));
        else if (n > 0)
                process_native_message(s, p, n, ucred, tv, label, label_len);

        free(p);
}

static int stdout_stream_log(StdoutStream *s, const char *p) {
        struct iovec iovec[N_IOVEC_META_FIELDS + 5];
        char *message = NULL, *syslog_priority = NULL, *syslog_facility = NULL, *syslog_identifier = NULL;
        unsigned n = 0;
        int priority;
        char *label = NULL;
        size_t label_len = 0;

        assert(s);
        assert(p);

        if (isempty(p))
                return 0;

        priority = s->priority;

        if (s->level_prefix)
                parse_syslog_priority((char**) &p, &priority);

        if (s->forward_to_syslog || s->server->forward_to_syslog)
                forward_syslog(s->server, fixup_priority(priority), s->identifier, p, &s->ucred, NULL);

        if (s->forward_to_kmsg || s->server->forward_to_kmsg)
                forward_kmsg(s->server, priority, s->identifier, p, &s->ucred);

        if (s->forward_to_console || s->server->forward_to_console)
                forward_console(s->server, s->identifier, p, &s->ucred);

        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=stdout");

        if (asprintf(&syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_priority);

        if (priority & LOG_FACMASK)
                if (asprintf(&syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], syslog_facility);

        if (s->identifier) {
                syslog_identifier = strappend("SYSLOG_IDENTIFIER=", s->identifier);
                if (syslog_identifier)
                        IOVEC_SET_STRING(iovec[n++], syslog_identifier);
        }

        message = strappend("MESSAGE=", p);
        if (message)
                IOVEC_SET_STRING(iovec[n++], message);

#ifdef HAVE_SELINUX
        if (s->security_context) {
                label = (char*) s->security_context;
                label_len = strlen((char*) s->security_context);
        }
#endif

        dispatch_message(s->server, iovec, n, ELEMENTSOF(iovec), &s->ucred, NULL, label, label_len, priority);

        free(message);
        free(syslog_priority);
        free(syslog_facility);
        free(syslog_identifier);

        return 0;
}

static int stdout_stream_line(StdoutStream *s, char *p) {
        int r;

        assert(s);
        assert(p);

        p = strstrip(p);

        switch (s->state) {

        case STDOUT_STREAM_IDENTIFIER:
                if (isempty(p))
                        s->identifier = NULL;
                else  {
                        s->identifier = strdup(p);
                        if (!s->identifier) {
                                log_error("Out of memory");
                                return -ENOMEM;
                        }
                }

                s->state = STDOUT_STREAM_PRIORITY;
                return 0;

        case STDOUT_STREAM_PRIORITY:
                r = safe_atoi(p, &s->priority);
                if (r < 0 || s->priority <= 0 || s->priority >= 999) {
                        log_warning("Failed to parse log priority line.");
                        return -EINVAL;
                }

                s->state = STDOUT_STREAM_LEVEL_PREFIX;
                return 0;

        case STDOUT_STREAM_LEVEL_PREFIX:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse level prefix line.");
                        return -EINVAL;
                }

                s->level_prefix = !!r;
                s->state = STDOUT_STREAM_FORWARD_TO_SYSLOG;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_SYSLOG:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse forward to syslog line.");
                        return -EINVAL;
                }

                s->forward_to_syslog = !!r;
                s->state = STDOUT_STREAM_FORWARD_TO_KMSG;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_KMSG:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse copy to kmsg line.");
                        return -EINVAL;
                }

                s->forward_to_kmsg = !!r;
                s->state = STDOUT_STREAM_FORWARD_TO_CONSOLE;
                return 0;

        case STDOUT_STREAM_FORWARD_TO_CONSOLE:
                r = parse_boolean(p);
                if (r < 0) {
                        log_warning("Failed to parse copy to console line.");
                        return -EINVAL;
                }

                s->forward_to_console = !!r;
                s->state = STDOUT_STREAM_RUNNING;
                return 0;

        case STDOUT_STREAM_RUNNING:
                return stdout_stream_log(s, p);
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
                if (end)
                        skip = end - p + 1;
                else if (remaining >= sizeof(s->buffer) - 1) {
                        end = p + sizeof(s->buffer) - 1;
                        skip = remaining;
                } else
                        break;

                *end = 0;

                r = stdout_stream_line(s, p);
                if (r < 0)
                        return r;

                remaining -= skip;
                p += skip;
        }

        if (force_flush && remaining > 0) {
                p[remaining] = 0;
                r = stdout_stream_line(s, p);
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

#ifdef HAVE_SELINUX
        if (s->security_context)
                freecon(s->security_context);
#endif

        free(s->identifier);
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

#ifdef HAVE_SELINUX
        if (getpeercon(fd, &stream->security_context) < 0 && errno != ENOPROTOOPT)
                log_error("Failed to determine peer security context: %m");
#endif

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

static int parse_kernel_timestamp(char **_p, usec_t *t) {
        usec_t r;
        int k, i;
        char *p;

        assert(_p);
        assert(*_p);
        assert(t);

        p = *_p;

        if (strlen(p) < 14 || p[0] != '[' || p[13] != ']' || p[6] != '.')
                return 0;

        r = 0;

        for (i = 1; i <= 5; i++) {
                r *= 10;

                if (p[i] == ' ')
                        continue;

                k = undecchar(p[i]);
                if (k < 0)
                        return 0;

                r += k;
        }

        for (i = 7; i <= 12; i++) {
                r *= 10;

                k = undecchar(p[i]);
                if (k < 0)
                        return 0;

                r += k;
        }

        *t = r;
        *_p += 14;
        *_p += strspn(*_p, WHITESPACE);

        return 1;
}

static bool is_us(const char *pid) {
        pid_t t;

        assert(pid);

        if (parse_pid(pid, &t) < 0)
                return false;

        return t == getpid();
}

static void proc_kmsg_line(Server *s, const char *p) {
        struct iovec iovec[N_IOVEC_META_FIELDS + 7];
        char *message = NULL, *syslog_priority = NULL, *syslog_pid = NULL, *syslog_facility = NULL, *syslog_identifier = NULL, *source_time = NULL;
        int priority = LOG_KERN | LOG_INFO;
        unsigned n = 0;
        usec_t usec;
        char *identifier = NULL, *pid = NULL;

        assert(s);
        assert(p);

        if (isempty(p))
                return;

        parse_syslog_priority((char **) &p, &priority);

        if (s->forward_to_kmsg && (priority & LOG_FACMASK) != LOG_KERN)
                return;

        if (parse_kernel_timestamp((char **) &p, &usec) > 0) {
                if (asprintf(&source_time, "_SOURCE_MONOTONIC_TIMESTAMP=%llu",
                             (unsigned long long) usec) >= 0)
                        IOVEC_SET_STRING(iovec[n++], source_time);
        }

        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=kernel");

        if (asprintf(&syslog_priority, "PRIORITY=%i", priority & LOG_PRIMASK) >= 0)
                IOVEC_SET_STRING(iovec[n++], syslog_priority);

        if ((priority & LOG_FACMASK) == LOG_KERN) {

                if (s->forward_to_syslog)
                        forward_syslog(s, priority, "kernel", p, NULL, NULL);

                IOVEC_SET_STRING(iovec[n++], "SYSLOG_IDENTIFIER=kernel");
        } else {
                read_identifier(&p, &identifier, &pid);

                /* Avoid any messages we generated ourselves via
                 * log_info() and friends. */
                if (is_us(pid))
                        goto finish;

                if (s->forward_to_syslog)
                        forward_syslog(s, priority, identifier, p, NULL, NULL);

                if (identifier) {
                        syslog_identifier = strappend("SYSLOG_IDENTIFIER=", identifier);
                        if (syslog_identifier)
                                IOVEC_SET_STRING(iovec[n++], syslog_identifier);
                }

                if (pid) {
                        syslog_pid = strappend("SYSLOG_PID=", pid);
                        if (syslog_pid)
                                IOVEC_SET_STRING(iovec[n++], syslog_pid);
                }

                if (asprintf(&syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority)) >= 0)
                        IOVEC_SET_STRING(iovec[n++], syslog_facility);
        }

        message = strappend("MESSAGE=", p);
        if (message)
                IOVEC_SET_STRING(iovec[n++], message);

        dispatch_message(s, iovec, n, ELEMENTSOF(iovec), NULL, NULL, NULL, 0, priority);

finish:
        free(message);
        free(syslog_priority);
        free(syslog_identifier);
        free(syslog_pid);
        free(syslog_facility);
        free(source_time);
        free(identifier);
        free(pid);
}

static void proc_kmsg_scan(Server *s) {
        char *p;
        size_t remaining;

        assert(s);

        p = s->proc_kmsg_buffer;
        remaining = s->proc_kmsg_length;
        for (;;) {
                char *end;
                size_t skip;

                end = memchr(p, '\n', remaining);
                if (end)
                        skip = end - p + 1;
                else if (remaining >= sizeof(s->proc_kmsg_buffer) - 1) {
                        end = p + sizeof(s->proc_kmsg_buffer) - 1;
                        skip = remaining;
                } else
                        break;

                *end = 0;

                proc_kmsg_line(s, p);

                remaining -= skip;
                p += skip;
        }

        if (p > s->proc_kmsg_buffer) {
                memmove(s->proc_kmsg_buffer, p, remaining);
                s->proc_kmsg_length = remaining;
        }
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

                r = journal_file_open_reliably(fn, O_RDWR|O_CREAT, 0640, NULL, &s->system_journal);
                free(fn);

                if (r >= 0) {
                        journal_default_metrics(&s->system_metrics, s->system_journal->fd);

                        s->system_journal->metrics = s->system_metrics;
                        s->system_journal->compress = s->compress;

                        server_fix_perms(s, s->system_journal, 0);
                } else if (r < 0) {

                        if (r != -ENOENT && r != -EROFS)
                                log_warning("Failed to open system journal: %s", strerror(-r));

                        r = 0;
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
                                if (r != -ENOENT)
                                        log_warning("Failed to open runtime journal: %s", strerror(-r));

                                r = 0;
                        }

                } else {

                        /* OK, we really need the runtime journal, so create
                         * it if necessary. */

                        (void) mkdir_parents(fn, 0755);
                        r = journal_file_open_reliably(fn, O_RDWR|O_CREAT, 0640, NULL, &s->runtime_journal);
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

                        server_fix_perms(s, s->runtime_journal, 0);
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

        log_info("Flushing to /var...");

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
                        server_rotate(s);
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

static int server_read_proc_kmsg(Server *s) {
        ssize_t l;
        assert(s);
        assert(s->proc_kmsg_fd >= 0);

        l = read(s->proc_kmsg_fd, s->proc_kmsg_buffer + s->proc_kmsg_length, sizeof(s->proc_kmsg_buffer) - 1 - s->proc_kmsg_length);
        if (l < 0) {

                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                log_error("Failed to read from kernel: %m");
                return -errno;
        }

        s->proc_kmsg_length += l;

        proc_kmsg_scan(s);
        return 1;
}

static int server_flush_proc_kmsg(Server *s) {
        int r;

        assert(s);

        if (s->proc_kmsg_fd < 0)
                return 0;

        log_info("Flushing /proc/kmsg...");

        for (;;) {
                r = server_read_proc_kmsg(s);
                if (r < 0)
                        return r;

                if (r == 0)
                        break;
        }

        return 0;
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
                                return 1;

                        return -errno;
                }

                if (sfsi.ssi_signo == SIGUSR1) {
                        server_flush_to_var(s);
                        return 0;
                }

                log_debug("Received SIG%s", signal_to_string(sfsi.ssi_signo));
                return 0;

        } else if (ev->data.fd == s->proc_kmsg_fd) {
                int r;

                if (ev->events != EPOLLIN) {
                        log_info("Got invalid event from epoll.");
                        return -EIO;
                }

                r = server_read_proc_kmsg(s);
                if (r < 0)
                        return r;

                return 1;

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
                        char *label = NULL;
                        size_t label_len = 0;
                        union {
                                struct cmsghdr cmsghdr;

                                /* We use NAME_MAX space for the
                                 * SELinux label here. The kernel
                                 * currently enforces no limit, but
                                 * according to suggestions from the
                                 * SELinux people this will change and
                                 * it will probably be identical to
                                 * NAME_MAX. For now we use that, but
                                 * this should be updated one day when
                                 * the final limit is known.*/
                                uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                                            CMSG_SPACE(sizeof(struct timeval)) +
                                            CMSG_SPACE(sizeof(int)) + /* fd */
                                            CMSG_SPACE(NAME_MAX)]; /* selinux label */
                        } control;
                        ssize_t n;
                        int v;
                        int *fds = NULL;
                        unsigned n_fds = 0;

                        if (ioctl(ev->data.fd, SIOCINQ, &v) < 0) {
                                log_error("SIOCINQ failed: %m");
                                return -errno;
                        }

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

                        n = recvmsg(ev->data.fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
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
                                         cmsg->cmsg_type == SCM_SECURITY) {
                                        label = (char*) CMSG_DATA(cmsg);
                                        label_len = cmsg->cmsg_len - CMSG_LEN(0);
                                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                                         cmsg->cmsg_type == SO_TIMESTAMP &&
                                         cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
                                        tv = (struct timeval*) CMSG_DATA(cmsg);
                                else if (cmsg->cmsg_level == SOL_SOCKET &&
                                         cmsg->cmsg_type == SCM_RIGHTS) {
                                        fds = (int*) CMSG_DATA(cmsg);
                                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                                }
                        }

                        if (ev->data.fd == s->syslog_fd) {
                                char *e;

                                if (n > 0 && n_fds == 0) {
                                        e = memchr(s->buffer, '\n', n);
                                        if (e)
                                                *e = 0;
                                        else
                                                s->buffer[n] = 0;

                                        process_syslog_message(s, strstrip(s->buffer), ucred, tv, label, label_len);
                                } else if (n_fds > 0)
                                        log_warning("Got file descriptors via syslog socket. Ignoring.");

                        } else {
                                if (n > 0 && n_fds == 0)
                                        process_native_message(s, s->buffer, n, ucred, tv, label, label_len);
                                else if (n == 0 && n_fds == 1)
                                        process_native_file(s, fds[0], ucred, tv, label, label_len);
                                else if (n_fds > 0)
                                        log_warning("Got too many file descriptors via native socket. Ignoring.");
                        }

                        close_many(fds, n_fds);
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

        assert(s);

        if (s->syslog_fd < 0) {

                s->syslog_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
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
        } else
                fd_nonblock(s->syslog_fd, 1);

        one = 1;
        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_PASSCRED failed: %m");
                return -errno;
        }

#ifdef HAVE_SELINUX
        one = 1;
        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));
        if (r < 0)
                log_warning("SO_PASSSEC failed: %m");
#endif

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

                s->native_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->native_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/run/systemd/journal/socket", sizeof(sa.un.sun_path));

                unlink(sa.un.sun_path);

                r = bind(s->native_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0) {
                        log_error("bind() failed: %m");
                        return -errno;
                }

                chmod(sa.un.sun_path, 0666);
        } else
                fd_nonblock(s->native_fd, 1);

        one = 1;
        r = setsockopt(s->native_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0) {
                log_error("SO_PASSCRED failed: %m");
                return -errno;
        }

#ifdef HAVE_SELINUX
        one = 1;
        r = setsockopt(s->syslog_fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));
        if (r < 0)
                log_warning("SO_PASSSEC failed: %m");
#endif

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

                s->stdout_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->stdout_fd < 0) {
                        log_error("socket() failed: %m");
                        return -errno;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, "/run/systemd/journal/stdout", sizeof(sa.un.sun_path));

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
        } else
                fd_nonblock(s->stdout_fd, 1);

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->stdout_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->stdout_fd, &ev) < 0) {
                log_error("Failed to add stdout server fd to epoll object: %m");
                return -errno;
        }

        return 0;
}

static int open_proc_kmsg(Server *s) {
        struct epoll_event ev;

        assert(s);

        if (!s->import_proc_kmsg)
                return 0;

        s->proc_kmsg_fd = open("/proc/kmsg", O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (s->proc_kmsg_fd < 0) {
                log_warning("Failed to open /proc/kmsg, ignoring: %m");
                return 0;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.fd = s->proc_kmsg_fd;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->proc_kmsg_fd, &ev) < 0) {
                log_error("Failed to add /proc/kmsg fd to epoll object: %m");
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

static int server_parse_proc_cmdline(Server *s) {
        char *line, *w, *state;
        int r;
        size_t l;

        if (detect_container(NULL) > 0)
                return 0;

        r = read_one_line_file("/proc/cmdline", &line);
        if (r < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {
                char *word;

                word = strndup(w, l);
                if (!word) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (startswith(word, "systemd_journald.forward_to_syslog=")) {
                        r = parse_boolean(word + 35);
                        if (r < 0)
                                log_warning("Failed to parse forward to syslog switch %s. Ignoring.", word + 35);
                        else
                                s->forward_to_syslog = r;
                } else if (startswith(word, "systemd_journald.forward_to_kmsg=")) {
                        r = parse_boolean(word + 33);
                        if (r < 0)
                                log_warning("Failed to parse forward to kmsg switch %s. Ignoring.", word + 33);
                        else
                                s->forward_to_kmsg = r;
                } else if (startswith(word, "systemd_journald.forward_to_console=")) {
                        r = parse_boolean(word + 36);
                        if (r < 0)
                                log_warning("Failed to parse forward to console switch %s. Ignoring.", word + 36);
                        else
                                s->forward_to_console = r;
                }

                free(word);
        }

        r = 0;

finish:
        free(line);
        return r;
}

static int server_parse_config_file(Server *s) {
        FILE *f;
        const char *fn;
        int r;

        assert(s);

        fn = "/etc/systemd/journald.conf";
        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file %s: %m", fn);
                return -errno;
        }

        r = config_parse(fn, f, "Journal\0", config_item_perf_lookup, (void*) journald_gperf_lookup, false, s);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        fclose(f);

        return r;
}

static int server_init(Server *s) {
        int n, r, fd;

        assert(s);

        zero(*s);
        s->syslog_fd = s->native_fd = s->stdout_fd = s->signal_fd = s->epoll_fd = s->proc_kmsg_fd = -1;
        s->compress = true;

        s->rate_limit_interval = DEFAULT_RATE_LIMIT_INTERVAL;
        s->rate_limit_burst = DEFAULT_RATE_LIMIT_BURST;

        s->forward_to_syslog = true;
        s->import_proc_kmsg = true;

        memset(&s->system_metrics, 0xFF, sizeof(s->system_metrics));
        memset(&s->runtime_metrics, 0xFF, sizeof(s->runtime_metrics));

        server_parse_config_file(s);
        server_parse_proc_cmdline(s);

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

                if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/run/systemd/journal/socket", 0) > 0) {

                        if (s->native_fd >= 0) {
                                log_error("Too many native sockets passed.");
                                return -EINVAL;
                        }

                        s->native_fd = fd;

                } else if (sd_is_socket_unix(fd, SOCK_STREAM, 1, "/run/systemd/journal/stdout", 0) > 0) {

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

        r = open_proc_kmsg(s);
        if (r < 0)
                return r;

        r = open_signalfd(s);
        if (r < 0)
                return r;

        s->rate_limit = journal_rate_limit_new(s->rate_limit_interval, s->rate_limit_burst);
        if (!s->rate_limit)
                return -ENOMEM;

        r = system_journal_open(s);
        if (r < 0)
                return r;

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

        if (s->proc_kmsg_fd >= 0)
                close_nointr_nofail(s->proc_kmsg_fd);

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

        log_set_target(LOG_TARGET_SAFE);
        log_set_facility(LOG_SYSLOG);
        log_parse_environment();
        log_open();

        umask(0022);

        r = server_init(&server);
        if (r < 0)
                goto finish;

        server_vacuum(&server);
        server_flush_to_var(&server);
        server_flush_proc_kmsg(&server);

        log_debug("systemd-journald running as pid %lu", (unsigned long) getpid());
        driver_message(&server, SD_MESSAGE_JOURNAL_START, "Journal started");

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

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
        driver_message(&server, SD_MESSAGE_JOURNAL_STOP, "Journal stopped");

finish:
        sd_notify(false,
                  "STATUS=Shutting down...");

        server_done(&server);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

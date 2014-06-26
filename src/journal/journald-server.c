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

#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/timerfd.h>

#include <libudev.h>

#include "sd-journal.h"
#include "sd-messages.h"
#include "sd-daemon.h"
#include "fileio.h"
#include "mkdir.h"
#include "hashmap.h"
#include "journal-file.h"
#include "socket-util.h"
#include "cgroup-util.h"
#include "list.h"
#include "missing.h"
#include "conf-parser.h"
#include "selinux-util.h"
#include "journal-internal.h"
#include "journal-vacuum.h"
#include "journal-authenticate.h"
#include "journald-rate-limit.h"
#include "journald-kmsg.h"
#include "journald-syslog.h"
#include "journald-stream.h"
#include "journald-console.h"
#include "journald-native.h"
#include "journald-server.h"

#ifdef HAVE_ACL
#include <sys/acl.h>
#include <acl/libacl.h>
#include "acl-util.h"
#endif

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#define USER_JOURNALS_MAX 1024

#define DEFAULT_SYNC_INTERVAL_USEC (5*USEC_PER_MINUTE)
#define DEFAULT_RATE_LIMIT_INTERVAL (30*USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST 1000
#define DEFAULT_MAX_FILE_USEC USEC_PER_MONTH

#define RECHECK_AVAILABLE_SPACE_USEC (30*USEC_PER_SEC)

static const char* const storage_table[_STORAGE_MAX] = {
        [STORAGE_AUTO] = "auto",
        [STORAGE_VOLATILE] = "volatile",
        [STORAGE_PERSISTENT] = "persistent",
        [STORAGE_NONE] = "none"
};

DEFINE_STRING_TABLE_LOOKUP(storage, Storage);
DEFINE_CONFIG_PARSE_ENUM(config_parse_storage, storage, Storage, "Failed to parse storage setting");

static const char* const split_mode_table[_SPLIT_MAX] = {
        [SPLIT_LOGIN] = "login",
        [SPLIT_UID] = "uid",
        [SPLIT_NONE] = "none",
};

DEFINE_STRING_TABLE_LOOKUP(split_mode, SplitMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_split_mode, split_mode, SplitMode, "Failed to parse split mode setting");

static uint64_t available_space(Server *s, bool verbose) {
        char ids[33];
        _cleanup_free_ char *p = NULL;
        sd_id128_t machine;
        struct statvfs ss;
        uint64_t sum = 0, ss_avail = 0, avail = 0;
        int r;
        _cleanup_closedir_ DIR *d = NULL;
        usec_t ts;
        const char *f;
        JournalMetrics *m;

        ts = now(CLOCK_MONOTONIC);

        if (s->cached_available_space_timestamp + RECHECK_AVAILABLE_SPACE_USEC > ts
            && !verbose)
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
        if (!d)
                return 0;

        if (fstatvfs(dirfd(d), &ss) < 0)
                return 0;

        for (;;) {
                struct stat st;
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0)
                        return 0;

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

        ss_avail = ss.f_bsize * ss.f_bavail;

        /* If we reached a high mark, we will always allow this much
         * again, unless usage goes above max_use. This watermark
         * value is cached so that we don't give up space on pressure,
         * but hover below the maximum usage. */

        if (m->use < sum)
                m->use = sum;

        avail = LESS_BY(ss_avail, m->keep_free);

        s->cached_available_space = LESS_BY(MIN(m->max_use, avail), sum);
        s->cached_available_space_timestamp = ts;

        if (verbose) {
                char    fb1[FORMAT_BYTES_MAX], fb2[FORMAT_BYTES_MAX], fb3[FORMAT_BYTES_MAX],
                        fb4[FORMAT_BYTES_MAX], fb5[FORMAT_BYTES_MAX];

                server_driver_message(s, SD_MESSAGE_JOURNAL_USAGE,
                                      "%s journal is using %s (max allowed %s, "
                                      "trying to leave %s free of %s available → current limit %s).",
                                      s->system_journal ? "Permanent" : "Runtime",
                                      format_bytes(fb1, sizeof(fb1), sum),
                                      format_bytes(fb2, sizeof(fb2), m->max_use),
                                      format_bytes(fb3, sizeof(fb3), m->keep_free),
                                      format_bytes(fb4, sizeof(fb4), ss_avail),
                                      format_bytes(fb5, sizeof(fb5), s->cached_available_space + sum));
        }

        return s->cached_available_space;
}

void server_fix_perms(Server *s, JournalFile *f, uid_t uid) {
        int r;
#ifdef HAVE_ACL
        acl_t acl;
        acl_entry_t entry;
        acl_permset_t permset;
#endif

        assert(f);

        r = fchmod(f->fd, 0640);
        if (r < 0)
                log_warning("Failed to fix access mode on %s, ignoring: %s", f->path, strerror(-r));

#ifdef HAVE_ACL
        if (uid <= SYSTEM_UID_MAX)
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

        /* We do not recalculate the mask unconditionally here,
         * so that the fchmod() mask above stays intact. */
        if (acl_get_permset(entry, &permset) < 0 ||
            acl_add_perm(permset, ACL_READ) < 0 ||
            calc_acl_mask_if_needed(&acl) < 0) {
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
        _cleanup_free_ char *p = NULL;
        int r;
        JournalFile *f;
        sd_id128_t machine;

        assert(s);

        /* We split up user logs only on /var, not on /run. If the
         * runtime file is open, we write to it exclusively, in order
         * to guarantee proper order as soon as we flush /run to
         * /var and close the runtime file. */

        if (s->runtime_journal)
                return s->runtime_journal;

        if (uid <= SYSTEM_UID_MAX)
                return s->system_journal;

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return s->system_journal;

        f = hashmap_get(s->user_journals, UINT32_TO_PTR(uid));
        if (f)
                return f;

        if (asprintf(&p, "/var/log/journal/" SD_ID128_FORMAT_STR "/user-"UID_FMT".journal",
                     SD_ID128_FORMAT_VAL(machine), uid) < 0)
                return s->system_journal;

        while (hashmap_size(s->user_journals) >= USER_JOURNALS_MAX) {
                /* Too many open? Then let's close one */
                f = hashmap_steal_first(s->user_journals);
                assert(f);
                journal_file_close(f);
        }

        r = journal_file_open_reliably(p, O_RDWR|O_CREAT, 0640, s->compress, s->seal, &s->system_metrics, s->mmap, NULL, &f);
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

static int do_rotate(Server *s, JournalFile **f, const char* name,
                     bool seal, uint32_t uid) {
        int r;
        assert(s);

        if (!*f)
                return -EINVAL;

        r = journal_file_rotate(f, s->compress, seal);
        if (r < 0)
                if (*f)
                        log_error("Failed to rotate %s: %s",
                                  (*f)->path, strerror(-r));
                else
                        log_error("Failed to create new %s journal: %s",
                                  name, strerror(-r));
        else
                server_fix_perms(s, *f, uid);
        return r;
}

void server_rotate(Server *s) {
        JournalFile *f;
        void *k;
        Iterator i;
        int r;

        log_debug("Rotating...");

        do_rotate(s, &s->runtime_journal, "runtime", false, 0);
        do_rotate(s, &s->system_journal, "system", s->seal, 0);

        HASHMAP_FOREACH_KEY(f, k, s->user_journals, i) {
                r = do_rotate(s, &f, "user", s->seal, PTR_TO_UINT32(k));
                if (r >= 0)
                        hashmap_replace(s->user_journals, k, f);
                else if (!f)
                        /* Old file has been closed and deallocated */
                        hashmap_remove(s->user_journals, k);
        }
}

void server_sync(Server *s) {
        JournalFile *f;
        void *k;
        Iterator i;
        int r;

        if (s->system_journal) {
                r = journal_file_set_offline(s->system_journal);
                if (r < 0)
                        log_error("Failed to sync system journal: %s", strerror(-r));
        }

        HASHMAP_FOREACH_KEY(f, k, s->user_journals, i) {
                r = journal_file_set_offline(f);
                if (r < 0)
                        log_error("Failed to sync user journal: %s", strerror(-r));
        }

        if (s->sync_event_source) {
                r = sd_event_source_set_enabled(s->sync_event_source, SD_EVENT_OFF);
                if (r < 0)
                        log_error("Failed to disable sync timer source: %s", strerror(-r));
        }

        s->sync_scheduled = false;
}

static void do_vacuum(Server *s, char *ids, JournalFile *f, const char* path,
                      JournalMetrics *metrics) {
        char *p;
        int r;

        if (!f)
                return;

        p = strappenda(path, ids);
        r = journal_directory_vacuum(p, metrics->max_use, s->max_retention_usec, &s->oldest_file_usec);
        if (r < 0 && r != -ENOENT)
                log_error("Failed to vacuum %s: %s", p, strerror(-r));
}

void server_vacuum(Server *s) {
        char ids[33];
        sd_id128_t machine;
        int r;

        log_debug("Vacuuming...");

        s->oldest_file_usec = 0;

        r = sd_id128_get_machine(&machine);
        if (r < 0) {
                log_error("Failed to get machine ID: %s", strerror(-r));
                return;
        }
        sd_id128_to_string(machine, ids);

        do_vacuum(s, ids, s->system_journal, "/var/log/journal/", &s->system_metrics);
        do_vacuum(s, ids, s->runtime_journal, "/run/log/journal/", &s->runtime_metrics);

        s->cached_available_space_timestamp = 0;
}

static void server_cache_machine_id(Server *s) {
        sd_id128_t id;
        int r;

        assert(s);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return;

        sd_id128_to_string(id, stpcpy(s->machine_id_field, "_MACHINE_ID="));
}

static void server_cache_boot_id(Server *s) {
        sd_id128_t id;
        int r;

        assert(s);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return;

        sd_id128_to_string(id, stpcpy(s->boot_id_field, "_BOOT_ID="));
}

static void server_cache_hostname(Server *s) {
        _cleanup_free_ char *t = NULL;
        char *x;

        assert(s);

        t = gethostname_malloc();
        if (!t)
                return;

        x = strappend("_HOSTNAME=", t);
        if (!x)
                return;

        free(s->hostname_field);
        s->hostname_field = x;
}

bool shall_try_append_again(JournalFile *f, int r) {

        /* -E2BIG            Hit configured limit
           -EFBIG            Hit fs limit
           -EDQUOT           Quota limit hit
           -ENOSPC           Disk full
           -EHOSTDOWN        Other machine
           -EBUSY            Unclean shutdown
           -EPROTONOSUPPORT  Unsupported feature
           -EBADMSG          Corrupted
           -ENODATA          Truncated
           -ESHUTDOWN        Already archived */

        if (r == -E2BIG || r == -EFBIG || r == -EDQUOT || r == -ENOSPC)
                log_debug("%s: Allocation limit reached, rotating.", f->path);
        else if (r == -EHOSTDOWN)
                log_info("%s: Journal file from other machine, rotating.", f->path);
        else if (r == -EBUSY)
                log_info("%s: Unclean shutdown, rotating.", f->path);
        else if (r == -EPROTONOSUPPORT)
                log_info("%s: Unsupported feature, rotating.", f->path);
        else if (r == -EBADMSG || r == -ENODATA || r == ESHUTDOWN)
                log_warning("%s: Journal file corrupted, rotating.", f->path);
        else
                return false;

        return true;
}

static void write_to_journal(Server *s, uid_t uid, struct iovec *iovec, unsigned n, int priority) {
        JournalFile *f;
        bool vacuumed = false;
        int r;

        assert(s);
        assert(iovec);
        assert(n > 0);

        f = find_journal(s, uid);
        if (!f)
                return;

        if (journal_file_rotate_suggested(f, s->max_file_usec)) {
                log_debug("%s: Journal header limits reached or header out-of-date, rotating.", f->path);
                server_rotate(s);
                server_vacuum(s);
                vacuumed = true;

                f = find_journal(s, uid);
                if (!f)
                        return;
        }

        r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL, NULL);
        if (r >= 0) {
                server_schedule_sync(s, priority);
                return;
        }

        if (vacuumed || !shall_try_append_again(f, r)) {
                size_t size = 0;
                unsigned i;
                for (i = 0; i < n; i++)
                        size += iovec[i].iov_len;

                log_error("Failed to write entry (%d items, %zu bytes), ignoring: %s", n, size, strerror(-r));
                return;
        }

        server_rotate(s);
        server_vacuum(s);

        f = find_journal(s, uid);
        if (!f)
                return;

        log_debug("Retrying write.");
        r = journal_file_append_entry(f, NULL, iovec, n, &s->seqnum, NULL, NULL);
        if (r < 0) {
                size_t size = 0;
                unsigned i;
                for (i = 0; i < n; i++)
                        size += iovec[i].iov_len;

                log_error("Failed to write entry (%d items, %zu bytes) despite vacuuming, ignoring: %s", n, size, strerror(-r));
        } else
                server_schedule_sync(s, priority);
}

static void dispatch_message_real(
                Server *s,
                struct iovec *iovec, unsigned n, unsigned m,
                struct ucred *ucred,
                struct timeval *tv,
                const char *label, size_t label_len,
                const char *unit_id,
                int priority,
                pid_t object_pid) {

        char    pid[sizeof("_PID=") + DECIMAL_STR_MAX(pid_t)],
                uid[sizeof("_UID=") + DECIMAL_STR_MAX(uid_t)],
                gid[sizeof("_GID=") + DECIMAL_STR_MAX(gid_t)],
                owner_uid[sizeof("_SYSTEMD_OWNER_UID=") + DECIMAL_STR_MAX(uid_t)],
                source_time[sizeof("_SOURCE_REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t)],
                o_uid[sizeof("OBJECT_UID=") + DECIMAL_STR_MAX(uid_t)],
                o_gid[sizeof("OBJECT_GID=") + DECIMAL_STR_MAX(gid_t)],
                o_owner_uid[sizeof("OBJECT_SYSTEMD_OWNER_UID=") + DECIMAL_STR_MAX(uid_t)];
        uid_t object_uid;
        gid_t object_gid;
        char *x;
        int r;
        char *t, *c;
        uid_t realuid = 0, owner = 0, journal_uid;
        bool owner_valid = false;
#ifdef HAVE_AUDIT
        char    audit_session[sizeof("_AUDIT_SESSION=") + DECIMAL_STR_MAX(uint32_t)],
                audit_loginuid[sizeof("_AUDIT_LOGINUID=") + DECIMAL_STR_MAX(uid_t)],
                o_audit_session[sizeof("OBJECT_AUDIT_SESSION=") + DECIMAL_STR_MAX(uint32_t)],
                o_audit_loginuid[sizeof("OBJECT_AUDIT_LOGINUID=") + DECIMAL_STR_MAX(uid_t)];

        uint32_t audit;
        uid_t loginuid;
#endif

        assert(s);
        assert(iovec);
        assert(n > 0);
        assert(n + N_IOVEC_META_FIELDS + (object_pid ? N_IOVEC_OBJECT_FIELDS : 0) <= m);

        if (ucred) {
                realuid = ucred->uid;

                sprintf(pid, "_PID="PID_FMT, ucred->pid);
                IOVEC_SET_STRING(iovec[n++], pid);

                sprintf(uid, "_UID="UID_FMT, ucred->uid);
                IOVEC_SET_STRING(iovec[n++], uid);

                sprintf(gid, "_GID="GID_FMT, ucred->gid);
                IOVEC_SET_STRING(iovec[n++], gid);

                r = get_process_comm(ucred->pid, &t);
                if (r >= 0) {
                        x = strappenda("_COMM=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

                r = get_process_exe(ucred->pid, &t);
                if (r >= 0) {
                        x = strappenda("_EXE=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

                r = get_process_cmdline(ucred->pid, 0, false, &t);
                if (r >= 0) {
                        x = strappenda("_CMDLINE=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

                r = get_process_capeff(ucred->pid, &t);
                if (r >= 0) {
                        x = strappenda("_CAP_EFFECTIVE=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

#ifdef HAVE_AUDIT
                r = audit_session_from_pid(ucred->pid, &audit);
                if (r >= 0) {
                        sprintf(audit_session, "_AUDIT_SESSION=%"PRIu32, audit);
                        IOVEC_SET_STRING(iovec[n++], audit_session);
                }

                r = audit_loginuid_from_pid(ucred->pid, &loginuid);
                if (r >= 0) {
                        sprintf(audit_loginuid, "_AUDIT_LOGINUID="UID_FMT, loginuid);
                        IOVEC_SET_STRING(iovec[n++], audit_loginuid);
                }
#endif

                r = cg_pid_get_path_shifted(ucred->pid, s->cgroup_root, &c);
                if (r >= 0) {
                        char *session = NULL;

                        x = strappenda("_SYSTEMD_CGROUP=", c);
                        IOVEC_SET_STRING(iovec[n++], x);

                        r = cg_path_get_session(c, &t);
                        if (r >= 0) {
                                session = strappenda("_SYSTEMD_SESSION=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], session);
                        }

                        if (cg_path_get_owner_uid(c, &owner) >= 0) {
                                owner_valid = true;

                                sprintf(owner_uid, "_SYSTEMD_OWNER_UID="UID_FMT, owner);
                                IOVEC_SET_STRING(iovec[n++], owner_uid);
                        }

                        if (cg_path_get_unit(c, &t) >= 0) {
                                x = strappenda("_SYSTEMD_UNIT=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], x);
                        } else if (unit_id && !session) {
                                x = strappenda("_SYSTEMD_UNIT=", unit_id);
                                IOVEC_SET_STRING(iovec[n++], x);
                        }

                        if (cg_path_get_user_unit(c, &t) >= 0) {
                                x = strappenda("_SYSTEMD_USER_UNIT=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], x);
                        } else if (unit_id && session) {
                                x = strappenda("_SYSTEMD_USER_UNIT=", unit_id);
                                IOVEC_SET_STRING(iovec[n++], x);
                        }

                        if (cg_path_get_slice(c, &t) >= 0) {
                                x = strappenda("_SYSTEMD_SLICE=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], x);
                        }

                        free(c);
                } else if (unit_id) {
                        x = strappenda("_SYSTEMD_UNIT=", unit_id);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

#ifdef HAVE_SELINUX
                if (use_selinux()) {
                        if (label) {
                                x = alloca(strlen("_SELINUX_CONTEXT=") + label_len + 1);

                                *((char*) mempcpy(stpcpy(x, "_SELINUX_CONTEXT="), label, label_len)) = 0;
                                IOVEC_SET_STRING(iovec[n++], x);
                        } else {
                                security_context_t con;

                                if (getpidcon(ucred->pid, &con) >= 0) {
                                        x = strappenda("_SELINUX_CONTEXT=", con);

                                        freecon(con);
                                        IOVEC_SET_STRING(iovec[n++], x);
                                }
                        }
                }
#endif
        }
        assert(n <= m);

        if (object_pid) {
                r = get_process_uid(object_pid, &object_uid);
                if (r >= 0) {
                        sprintf(o_uid, "OBJECT_UID="UID_FMT, object_uid);
                        IOVEC_SET_STRING(iovec[n++], o_uid);
                }

                r = get_process_gid(object_pid, &object_gid);
                if (r >= 0) {
                        sprintf(o_gid, "OBJECT_GID="GID_FMT, object_gid);
                        IOVEC_SET_STRING(iovec[n++], o_gid);
                }

                r = get_process_comm(object_pid, &t);
                if (r >= 0) {
                        x = strappenda("OBJECT_COMM=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

                r = get_process_exe(object_pid, &t);
                if (r >= 0) {
                        x = strappenda("OBJECT_EXE=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

                r = get_process_cmdline(object_pid, 0, false, &t);
                if (r >= 0) {
                        x = strappenda("OBJECT_CMDLINE=", t);
                        free(t);
                        IOVEC_SET_STRING(iovec[n++], x);
                }

#ifdef HAVE_AUDIT
                r = audit_session_from_pid(object_pid, &audit);
                if (r >= 0) {
                        sprintf(o_audit_session, "OBJECT_AUDIT_SESSION=%"PRIu32, audit);
                        IOVEC_SET_STRING(iovec[n++], o_audit_session);
                }

                r = audit_loginuid_from_pid(object_pid, &loginuid);
                if (r >= 0) {
                        sprintf(o_audit_loginuid, "OBJECT_AUDIT_LOGINUID="UID_FMT, loginuid);
                        IOVEC_SET_STRING(iovec[n++], o_audit_loginuid);
                }
#endif

                r = cg_pid_get_path_shifted(object_pid, s->cgroup_root, &c);
                if (r >= 0) {
                        x = strappenda("OBJECT_SYSTEMD_CGROUP=", c);
                        IOVEC_SET_STRING(iovec[n++], x);

                        r = cg_path_get_session(c, &t);
                        if (r >= 0) {
                                x = strappenda("OBJECT_SYSTEMD_SESSION=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], x);
                        }

                        if (cg_path_get_owner_uid(c, &owner) >= 0) {
                                sprintf(o_owner_uid, "OBJECT_SYSTEMD_OWNER_UID="UID_FMT, owner);
                                IOVEC_SET_STRING(iovec[n++], o_owner_uid);
                        }

                        if (cg_path_get_unit(c, &t) >= 0) {
                                x = strappenda("OBJECT_SYSTEMD_UNIT=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], x);
                        }

                        if (cg_path_get_user_unit(c, &t) >= 0) {
                                x = strappenda("OBJECT_SYSTEMD_USER_UNIT=", t);
                                free(t);
                                IOVEC_SET_STRING(iovec[n++], x);
                        }

                        free(c);
                }
        }
        assert(n <= m);

        if (tv) {
                sprintf(source_time, "_SOURCE_REALTIME_TIMESTAMP=%llu", (unsigned long long) timeval_load(tv));
                IOVEC_SET_STRING(iovec[n++], source_time);
        }

        /* Note that strictly speaking storing the boot id here is
         * redundant since the entry includes this in-line
         * anyway. However, we need this indexed, too. */
        if (!isempty(s->boot_id_field))
                IOVEC_SET_STRING(iovec[n++], s->boot_id_field);

        if (!isempty(s->machine_id_field))
                IOVEC_SET_STRING(iovec[n++], s->machine_id_field);

        if (!isempty(s->hostname_field))
                IOVEC_SET_STRING(iovec[n++], s->hostname_field);

        assert(n <= m);

        if (s->split_mode == SPLIT_UID && realuid > 0)
                /* Split up strictly by any UID */
                journal_uid = realuid;
        else if (s->split_mode == SPLIT_LOGIN && realuid > 0 && owner_valid && owner > 0)
                /* Split up by login UIDs.  We do this only if the
                 * realuid is not root, in order not to accidentally
                 * leak privileged information to the user that is
                 * logged by a privileged process that is part of an
                 * unprivileged session.*/
                journal_uid = owner;
        else
                journal_uid = 0;

        write_to_journal(s, journal_uid, iovec, n, priority);
}

void server_driver_message(Server *s, sd_id128_t message_id, const char *format, ...) {
        char mid[11 + 32 + 1];
        char buffer[16 + LINE_MAX + 1];
        struct iovec iovec[N_IOVEC_META_FIELDS + 4];
        int n = 0;
        va_list ap;
        struct ucred ucred = {};

        assert(s);
        assert(format);

        IOVEC_SET_STRING(iovec[n++], "PRIORITY=6");
        IOVEC_SET_STRING(iovec[n++], "_TRANSPORT=driver");

        memcpy(buffer, "MESSAGE=", 8);
        va_start(ap, format);
        vsnprintf(buffer + 8, sizeof(buffer) - 8, format, ap);
        va_end(ap);
        char_array_0(buffer);
        IOVEC_SET_STRING(iovec[n++], buffer);

        if (!sd_id128_equal(message_id, SD_ID128_NULL)) {
                snprintf(mid, sizeof(mid), MESSAGE_ID(message_id));
                char_array_0(mid);
                IOVEC_SET_STRING(iovec[n++], mid);
        }

        ucred.pid = getpid();
        ucred.uid = getuid();
        ucred.gid = getgid();

        dispatch_message_real(s, iovec, n, ELEMENTSOF(iovec), &ucred, NULL, NULL, 0, NULL, LOG_INFO, 0);
}

void server_dispatch_message(
                Server *s,
                struct iovec *iovec, unsigned n, unsigned m,
                struct ucred *ucred,
                struct timeval *tv,
                const char *label, size_t label_len,
                const char *unit_id,
                int priority,
                pid_t object_pid) {

        int rl, r;
        _cleanup_free_ char *path = NULL;
        char *c;

        assert(s);
        assert(iovec || n == 0);

        if (n == 0)
                return;

        if (LOG_PRI(priority) > s->max_level_store)
                return;

        /* Stop early in case the information will not be stored
         * in a journal. */
        if (s->storage == STORAGE_NONE)
                return;

        if (!ucred)
                goto finish;

        r = cg_pid_get_path_shifted(ucred->pid, s->cgroup_root, &path);
        if (r < 0)
                goto finish;

        /* example: /user/lennart/3/foobar
         *          /system/dbus.service/foobar
         *
         * So let's cut of everything past the third /, since that is
         * where user directories start */

        c = strchr(path, '/');
        if (c) {
                c = strchr(c+1, '/');
                if (c) {
                        c = strchr(c+1, '/');
                        if (c)
                                *c = 0;
                }
        }

        rl = journal_rate_limit_test(s->rate_limit, path,
                                     priority & LOG_PRIMASK, available_space(s, false));

        if (rl == 0)
                return;

        /* Write a suppression message if we suppressed something */
        if (rl > 1)
                server_driver_message(s, SD_MESSAGE_JOURNAL_DROPPED,
                                      "Suppressed %u messages from %s", rl - 1, path);

finish:
        dispatch_message_real(s, iovec, n, m, ucred, tv, label, label_len, unit_id, priority, object_pid);
}


static int system_journal_open(Server *s) {
        int r;
        char *fn;
        sd_id128_t machine;
        char ids[33];

        r = sd_id128_get_machine(&machine);
        if (r < 0) {
                log_error("Failed to get machine id: %s", strerror(-r));
                return r;
        }

        sd_id128_to_string(machine, ids);

        if (!s->system_journal &&
            (s->storage == STORAGE_PERSISTENT || s->storage == STORAGE_AUTO) &&
            access("/run/systemd/journal/flushed", F_OK) >= 0) {

                /* If in auto mode: first try to create the machine
                 * path, but not the prefix.
                 *
                 * If in persistent mode: create /var/log/journal and
                 * the machine path */

                if (s->storage == STORAGE_PERSISTENT)
                        (void) mkdir("/var/log/journal/", 0755);

                fn = strappenda("/var/log/journal/", ids);
                (void) mkdir(fn, 0755);

                fn = strappenda(fn, "/system.journal");
                r = journal_file_open_reliably(fn, O_RDWR|O_CREAT, 0640, s->compress, s->seal, &s->system_metrics, s->mmap, NULL, &s->system_journal);

                if (r >= 0)
                        server_fix_perms(s, s->system_journal, 0);
                else if (r < 0) {
                        if (r != -ENOENT && r != -EROFS)
                                log_warning("Failed to open system journal: %s", strerror(-r));

                        r = 0;
                }
        }

        if (!s->runtime_journal &&
            (s->storage != STORAGE_NONE)) {

                fn = strjoin("/run/log/journal/", ids, "/system.journal", NULL);
                if (!fn)
                        return -ENOMEM;

                if (s->system_journal) {

                        /* Try to open the runtime journal, but only
                         * if it already exists, so that we can flush
                         * it into the system journal */

                        r = journal_file_open(fn, O_RDWR, 0640, s->compress, false, &s->runtime_metrics, s->mmap, NULL, &s->runtime_journal);
                        free(fn);

                        if (r < 0) {
                                if (r != -ENOENT)
                                        log_warning("Failed to open runtime journal: %s", strerror(-r));

                                r = 0;
                        }

                } else {

                        /* OK, we really need the runtime journal, so create
                         * it if necessary. */

                        (void) mkdir("/run/log", 0755);
                        (void) mkdir("/run/log/journal", 0755);
                        (void) mkdir_parents(fn, 0750);

                        r = journal_file_open_reliably(fn, O_RDWR|O_CREAT, 0640, s->compress, false, &s->runtime_metrics, s->mmap, NULL, &s->runtime_journal);
                        free(fn);

                        if (r < 0) {
                                log_error("Failed to open runtime journal: %s", strerror(-r));
                                return r;
                        }
                }

                if (s->runtime_journal)
                        server_fix_perms(s, s->runtime_journal, 0);
        }

        available_space(s, true);

        return r;
}

int server_flush_to_var(Server *s) {
        sd_id128_t machine;
        sd_journal *j = NULL;
        char ts[FORMAT_TIMESPAN_MAX];
        usec_t start;
        unsigned n = 0;
        int r;

        assert(s);

        if (s->storage != STORAGE_AUTO &&
            s->storage != STORAGE_PERSISTENT)
                return 0;

        if (!s->runtime_journal)
                return 0;

        system_journal_open(s);

        if (!s->system_journal)
                return 0;

        log_debug("Flushing to /var...");

        start = now(CLOCK_MONOTONIC);

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        r = sd_journal_open(&j, SD_JOURNAL_RUNTIME_ONLY);
        if (r < 0) {
                log_error("Failed to read runtime journal: %s", strerror(-r));
                return r;
        }

        sd_journal_set_data_threshold(j, 0);

        SD_JOURNAL_FOREACH(j) {
                Object *o = NULL;
                JournalFile *f;

                f = j->current_file;
                assert(f && f->current_offset > 0);

                n++;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0) {
                        log_error("Can't read entry: %s", strerror(-r));
                        goto finish;
                }

                r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset, NULL, NULL, NULL);
                if (r >= 0)
                        continue;

                if (!shall_try_append_again(s->system_journal, r)) {
                        log_error("Can't write entry: %s", strerror(-r));
                        goto finish;
                }

                server_rotate(s);
                server_vacuum(s);

                if (!s->system_journal) {
                        log_notice("Didn't flush runtime journal since rotation of system journal wasn't successful.");
                        r = -EIO;
                        goto finish;
                }

                log_debug("Retrying write.");
                r = journal_file_copy_entry(f, s->system_journal, o, f->current_offset, NULL, NULL, NULL);
                if (r < 0) {
                        log_error("Can't write entry: %s", strerror(-r));
                        goto finish;
                }
        }

finish:
        journal_file_post_change(s->system_journal);

        journal_file_close(s->runtime_journal);
        s->runtime_journal = NULL;

        if (r >= 0)
                rm_rf("/run/log/journal", false, true, false);

        sd_journal_close(j);

        server_driver_message(s, SD_ID128_NULL, "Time spent on flushing to /var is %s for %u entries.", format_timespan(ts, sizeof(ts), now(CLOCK_MONOTONIC) - start, 0), n);

        return r;
}

int process_datagram(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Server *s = userdata;

        assert(s);
        assert(fd == s->native_fd || fd == s->syslog_fd);

        if (revents != EPOLLIN) {
                log_error("Got invalid event from epoll for datagram fd: %"PRIx32, revents);
                return -EIO;
        }

        for (;;) {
                struct ucred *ucred = NULL;
                struct timeval *tv = NULL;
                struct cmsghdr *cmsg;
                char *label = NULL;
                size_t label_len = 0;
                struct iovec iovec;

                union {
                        struct cmsghdr cmsghdr;

                        /* We use NAME_MAX space for the SELinux label
                         * here. The kernel currently enforces no
                         * limit, but according to suggestions from
                         * the SELinux people this will change and it
                         * will probably be identical to NAME_MAX. For
                         * now we use that, but this should be updated
                         * one day when the final limit is known.*/
                        uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                                    CMSG_SPACE(sizeof(struct timeval)) +
                                    CMSG_SPACE(sizeof(int)) + /* fd */
                                    CMSG_SPACE(NAME_MAX)]; /* selinux label */
                } control = {};
                struct msghdr msghdr = {
                        .msg_iov = &iovec,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };

                ssize_t n;
                int v;
                int *fds = NULL;
                unsigned n_fds = 0;

                if (ioctl(fd, SIOCINQ, &v) < 0) {
                        log_error("SIOCINQ failed: %m");
                        return -errno;
                }

                if (!GREEDY_REALLOC(s->buffer, s->buffer_size, LINE_MAX + (size_t) v))
                        return log_oom();

                iovec.iov_base = s->buffer;
                iovec.iov_len = s->buffer_size;

                n = recvmsg(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
                if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                return 0;

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

                if (fd == s->syslog_fd) {
                        if (n > 0 && n_fds == 0) {
                                s->buffer[n] = 0;
                                server_process_syslog_message(s, strstrip(s->buffer), ucred, tv, label, label_len);
                        } else if (n_fds > 0)
                                log_warning("Got file descriptors via syslog socket. Ignoring.");

                } else {
                        if (n > 0 && n_fds == 0)
                                server_process_native_message(s, s->buffer, n, ucred, tv, label, label_len);
                        else if (n == 0 && n_fds == 1)
                                server_process_native_file(s, fds[0], ucred, tv, label, label_len);
                        else if (n_fds > 0)
                                log_warning("Got too many file descriptors via native socket. Ignoring.");
                }

                close_many(fds, n_fds);
        }
}

static int dispatch_sigusr1(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_info("Received request to flush runtime journal from PID %"PRIu32, si->ssi_pid);

        touch("/run/systemd/journal/flushed");
        server_flush_to_var(s);
        server_sync(s);

        return 0;
}

static int dispatch_sigusr2(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_info("Received request to rotate journal from PID %"PRIu32, si->ssi_pid);
        server_rotate(s);
        server_vacuum(s);

        return 0;
}

static int dispatch_sigterm(sd_event_source *es, const struct signalfd_siginfo *si, void *userdata) {
        Server *s = userdata;

        assert(s);

        log_received_signal(LOG_INFO, si);

        sd_event_exit(s->event, 0);
        return 0;
}

static int setup_signals(Server *s) {
        sigset_t mask;
        int r;

        assert(s);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        r = sd_event_add_signal(s->event, &s->sigusr1_event_source, SIGUSR1, dispatch_sigusr1, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->event, &s->sigusr2_event_source, SIGUSR2, dispatch_sigusr2, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->event, &s->sigterm_event_source, SIGTERM, dispatch_sigterm, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->event, &s->sigint_event_source, SIGINT, dispatch_sigterm, s);
        if (r < 0)
                return r;

        return 0;
}

static int server_parse_proc_cmdline(Server *s) {
        _cleanup_free_ char *line = NULL;
        char *w, *state;
        size_t l;
        int r;

        r = proc_cmdline(&line);
        if (r < 0)
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
        if (r <= 0)
                return 0;

        FOREACH_WORD_QUOTED(w, l, line, state) {
                _cleanup_free_ char *word;

                word = strndup(w, l);
                if (!word)
                        return -ENOMEM;

                if (startswith(word, "systemd.journald.forward_to_syslog=")) {
                        r = parse_boolean(word + 35);
                        if (r < 0)
                                log_warning("Failed to parse forward to syslog switch %s. Ignoring.", word + 35);
                        else
                                s->forward_to_syslog = r;
                } else if (startswith(word, "systemd.journald.forward_to_kmsg=")) {
                        r = parse_boolean(word + 33);
                        if (r < 0)
                                log_warning("Failed to parse forward to kmsg switch %s. Ignoring.", word + 33);
                        else
                                s->forward_to_kmsg = r;
                } else if (startswith(word, "systemd.journald.forward_to_console=")) {
                        r = parse_boolean(word + 36);
                        if (r < 0)
                                log_warning("Failed to parse forward to console switch %s. Ignoring.", word + 36);
                        else
                                s->forward_to_console = r;
                } else if (startswith(word, "systemd.journald.forward_to_wall=")) {
                        r = parse_boolean(word + 33);
                        if (r < 0)
                                log_warning("Failed to parse forward to wall switch %s. Ignoring.", word + 33);
                        else
                                s->forward_to_wall = r;
                } else if (startswith(word, "systemd.journald"))
                        log_warning("Invalid systemd.journald parameter. Ignoring.");
        }

        return 0;
}

static int server_parse_config_file(Server *s) {
        static const char fn[] = "/etc/systemd/journald.conf";
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(s);

        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file %s: %m", fn);
                return -errno;
        }

        r = config_parse(NULL, fn, f, "Journal\0", config_item_perf_lookup,
                         (void*) journald_gperf_lookup, false, false, s);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        return r;
}

static int server_dispatch_sync(sd_event_source *es, usec_t t, void *userdata) {
        Server *s = userdata;

        assert(s);

        server_sync(s);
        return 0;
}

int server_schedule_sync(Server *s, int priority) {
        int r;

        assert(s);

        if (priority <= LOG_CRIT) {
                /* Immediately sync to disk when this is of priority CRIT, ALERT, EMERG */
                server_sync(s);
                return 0;
        }

        if (s->sync_scheduled)
                return 0;

        if (s->sync_interval_usec > 0) {
                usec_t when;

                r = sd_event_now(s->event, CLOCK_MONOTONIC, &when);
                if (r < 0)
                        return r;

                when += s->sync_interval_usec;

                if (!s->sync_event_source) {
                        r = sd_event_add_time(
                                        s->event,
                                        &s->sync_event_source,
                                        CLOCK_MONOTONIC,
                                        when, 0,
                                        server_dispatch_sync, s);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_priority(s->sync_event_source, SD_EVENT_PRIORITY_IMPORTANT);
                } else {
                        r = sd_event_source_set_time(s->sync_event_source, when);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_enabled(s->sync_event_source, SD_EVENT_ONESHOT);
                }
                if (r < 0)
                        return r;

                s->sync_scheduled = true;
        }

        return 0;
}

static int dispatch_hostname_change(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Server *s = userdata;

        assert(s);

        server_cache_hostname(s);
        return 0;
}

static int server_open_hostname(Server *s) {
        int r;

        assert(s);

        s->hostname_fd = open("/proc/sys/kernel/hostname", O_RDONLY|O_CLOEXEC|O_NDELAY|O_NOCTTY);
        if (s->hostname_fd < 0) {
                log_error("Failed to open /proc/sys/kernel/hostname: %m");
                return -errno;
        }

        r = sd_event_add_io(s->event, &s->hostname_event_source, s->hostname_fd, 0, dispatch_hostname_change, s);
        if (r < 0) {
                /* kernels prior to 3.2 don't support polling this file. Ignore
                 * the failure. */
                if (r == -EPERM) {
                        log_warning("Failed to register hostname fd in event loop: %s. Ignoring.",
                                        strerror(-r));
                        s->hostname_fd = safe_close(s->hostname_fd);
                        return 0;
                }

                log_error("Failed to register hostname fd in event loop: %s", strerror(-r));
                return r;
        }

        r = sd_event_source_set_priority(s->hostname_event_source, SD_EVENT_PRIORITY_IMPORTANT-10);
        if (r < 0) {
                log_error("Failed to adjust priority of host name event source: %s", strerror(-r));
                return r;
        }

        return 0;
}

int server_init(Server *s) {
        int n, r, fd;

        assert(s);

        zero(*s);
        s->syslog_fd = s->native_fd = s->stdout_fd = s->dev_kmsg_fd = s->hostname_fd = -1;
        s->compress = true;
        s->seal = true;

        s->sync_interval_usec = DEFAULT_SYNC_INTERVAL_USEC;
        s->sync_scheduled = false;

        s->rate_limit_interval = DEFAULT_RATE_LIMIT_INTERVAL;
        s->rate_limit_burst = DEFAULT_RATE_LIMIT_BURST;

        s->forward_to_syslog = true;
        s->forward_to_wall = true;

        s->max_file_usec = DEFAULT_MAX_FILE_USEC;

        s->max_level_store = LOG_DEBUG;
        s->max_level_syslog = LOG_DEBUG;
        s->max_level_kmsg = LOG_NOTICE;
        s->max_level_console = LOG_INFO;
        s->max_level_wall = LOG_EMERG;

        memset(&s->system_metrics, 0xFF, sizeof(s->system_metrics));
        memset(&s->runtime_metrics, 0xFF, sizeof(s->runtime_metrics));

        server_parse_config_file(s);
        server_parse_proc_cmdline(s);
        if (!!s->rate_limit_interval ^ !!s->rate_limit_burst) {
                log_debug("Setting both rate limit interval and burst from %llu,%u to 0,0",
                          (long long unsigned) s->rate_limit_interval,
                          s->rate_limit_burst);
                s->rate_limit_interval = s->rate_limit_burst = 0;
        }

        mkdir_p("/run/systemd/journal", 0755);

        s->user_journals = hashmap_new(trivial_hash_func, trivial_compare_func);
        if (!s->user_journals)
                return log_oom();

        s->mmap = mmap_cache_new();
        if (!s->mmap)
                return log_oom();

        r = sd_event_default(&s->event);
        if (r < 0) {
                log_error("Failed to create event loop: %s", strerror(-r));
                return r;
        }

        sd_event_set_watchdog(s->event, true);

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

                } else if (sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/dev/log", 0) > 0 ||
                           sd_is_socket_unix(fd, SOCK_DGRAM, -1, "/run/systemd/journal/dev-log", 0) > 0) {

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

        r = server_open_syslog_socket(s);
        if (r < 0)
                return r;

        r = server_open_native_socket(s);
        if (r < 0)
                return r;

        r = server_open_stdout_socket(s);
        if (r < 0)
                return r;

        r = server_open_dev_kmsg(s);
        if (r < 0)
                return r;

        r = server_open_kernel_seqnum(s);
        if (r < 0)
                return r;

        r = server_open_hostname(s);
        if (r < 0)
                return r;

        r = setup_signals(s);
        if (r < 0)
                return r;

        s->udev = udev_new();
        if (!s->udev)
                return -ENOMEM;

        s->rate_limit = journal_rate_limit_new(s->rate_limit_interval, s->rate_limit_burst);
        if (!s->rate_limit)
                return -ENOMEM;

        r = cg_get_root_path(&s->cgroup_root);
        if (r < 0)
                return r;

        server_cache_hostname(s);
        server_cache_boot_id(s);
        server_cache_machine_id(s);

        r = system_journal_open(s);
        if (r < 0)
                return r;

        return 0;
}

void server_maybe_append_tags(Server *s) {
#ifdef HAVE_GCRYPT
        JournalFile *f;
        Iterator i;
        usec_t n;

        n = now(CLOCK_REALTIME);

        if (s->system_journal)
                journal_file_maybe_append_tag(s->system_journal, n);

        HASHMAP_FOREACH(f, s->user_journals, i)
                journal_file_maybe_append_tag(f, n);
#endif
}

void server_done(Server *s) {
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

        sd_event_source_unref(s->syslog_event_source);
        sd_event_source_unref(s->native_event_source);
        sd_event_source_unref(s->stdout_event_source);
        sd_event_source_unref(s->dev_kmsg_event_source);
        sd_event_source_unref(s->sync_event_source);
        sd_event_source_unref(s->sigusr1_event_source);
        sd_event_source_unref(s->sigusr2_event_source);
        sd_event_source_unref(s->sigterm_event_source);
        sd_event_source_unref(s->sigint_event_source);
        sd_event_source_unref(s->hostname_event_source);
        sd_event_unref(s->event);

        safe_close(s->syslog_fd);
        safe_close(s->native_fd);
        safe_close(s->stdout_fd);
        safe_close(s->dev_kmsg_fd);
        safe_close(s->hostname_fd);

        if (s->rate_limit)
                journal_rate_limit_free(s->rate_limit);

        if (s->kernel_seqnum)
                munmap(s->kernel_seqnum, sizeof(uint64_t));

        free(s->buffer);
        free(s->tty_path);
        free(s->cgroup_root);

        if (s->mmap)
                mmap_cache_unref(s->mmap);

        if (s->udev)
                udev_unref(s->udev);
}

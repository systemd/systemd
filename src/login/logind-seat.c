/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "device-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "id128-util.h"
#include "log.h"
#include "logind.h"
#include "logind-device.h"
#include "logind-seat.h"
#include "logind-seat-dbus.h"
#include "logind-session.h"
#include "logind-session-dbus.h"
#include "logind-session-device.h"
#include "logind-user.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "user-record.h"
#include "user-util.h"

int seat_new(Manager *m, const char *id, Seat **ret) {
        _cleanup_(seat_freep) Seat *s = NULL;
        int r;

        assert(m);
        assert(id);
        assert(ret);

        if (!seat_name_is_valid(id))
                return -EINVAL;

        s = new(Seat, 1);
        if (!s)
                return -ENOMEM;

        *s = (Seat) {
                .manager = m,
                .id = strdup(id),
                .state_file = path_join("/run/systemd/seats/", id),
        };
        if (!s->id || !s->state_file)
                return -ENOMEM;

        r = hashmap_put(m->seats, s->id, s);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

Seat* seat_free(Seat *s) {
        if (!s)
                return NULL;

        if (s->in_gc_queue)
                LIST_REMOVE(gc_queue, s->manager->seat_gc_queue, s);

        while (s->sessions)
                session_free(s->sessions);

        assert(!s->active);

        while (s->devices)
                device_free(s->devices);

        hashmap_remove(s->manager->seats, s->id);

        set_free(s->uevents);
        free(s->positions);
        free(s->state_file);
        free(s->id);

        return mfree(s);
}

int seat_save(Seat *s) {
        int r;

        assert(s);

        if (!s->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/seats", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/seats/: %m");

        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable(s->state_file, O_WRONLY|O_CLOEXEC, &temp_path, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create state file '%s': %m", s->state_file);

        if (fchmod(fileno(f), 0644) < 0)
                return log_error_errno(errno, "Failed to set access mode for state file '%s' to 0644: %m", s->state_file);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "IS_SEAT0=%i\n"
                "CAN_MULTI_SESSION=1\n"
                "CAN_TTY=%i\n"
                "CAN_GRAPHICAL=%i\n",
                seat_is_seat0(s),
                seat_can_tty(s),
                seat_can_graphical(s));

        if (s->active) {
                assert(s->active->user);

                fprintf(f,
                        "ACTIVE=%s\n"
                        "ACTIVE_UID="UID_FMT"\n",
                        s->active->id,
                        s->active->user->user_record->uid);
        }

        if (s->sessions) {
                fputs("SESSIONS=", f);
                LIST_FOREACH(sessions_by_seat, i, s->sessions) {
                        fprintf(f,
                                "%s%c",
                                i->id,
                                i->sessions_by_seat_next ? ' ' : '\n');
                }

                fputs("UIDS=", f);
                LIST_FOREACH(sessions_by_seat, i, s->sessions)
                        fprintf(f,
                                UID_FMT"%c",
                                i->user->user_record->uid,
                                i->sessions_by_seat_next ? ' ' : '\n');
        }

        r = flink_tmpfile(f, temp_path, s->state_file, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", s->state_file);

        temp_path = mfree(temp_path); /* disarm auto-destroy: temporary file does not exist anymore */
        return 0;
}

int seat_load(Seat *s) {
        assert(s);

        /* There isn't actually anything to read here ... */

        return 0;
}

static int vt_allocate(unsigned vtnr) {
        char p[sizeof("/dev/tty") + DECIMAL_STR_MAX(unsigned)];
        _cleanup_close_ int fd = -EBADF;

        assert(vtnr >= 1);

        xsprintf(p, "/dev/tty%u", vtnr);
        fd = open_terminal(p, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        return 0;
}

int seat_preallocate_vts(Seat *s) {
        int r = 0;
        unsigned i;

        assert(s);
        assert(s->manager);

        if (s->manager->n_autovts <= 0)
                return 0;

        if (!seat_has_vts(s))
                return 0;

        log_debug("Preallocating VTs...");

        for (i = 1; i <= s->manager->n_autovts; i++) {
                int q;

                q = vt_allocate(i);
                if (q < 0)
                        r = log_error_errno(q, "Failed to preallocate VT %u: %m", i);
        }

        return r;
}

static void seat_triggered_uevents_done(Seat *s) {
        assert(s);

        if (!set_isempty(s->uevents)) {
                log_debug("%s: waiting for %u events being processed by udevd.", s->id, set_size(s->uevents));
                return;
        }

        Session *session = s->active;

        if (session) {
                session_save(session);
                user_save(session->user);
        }

        if (session && session->started) {
                session_send_changed(session, "Active");
                session_device_resume_all(session);
        }

        if (!session || session->started)
                seat_send_changed(s, "ActiveSession");
}

int manager_process_device_triggered_by_seat(Manager *m, sd_device *dev) {
        int r;

        assert(m);
        assert(dev);

        sd_id128_t uuid;
        r = sd_device_get_trigger_uuid(dev, &uuid);
        if (IN_SET(r, -ENOENT, -ENODATA))
                return 0;
        if (r < 0)
                return r;

        Seat *s;
        HASHMAP_FOREACH(s, m->seats)
                if (set_contains(s->uevents, &uuid))
                        break;
        if (!s)
                return 0;

        log_device_uevent(dev, "Received event processed by udevd");
        free(ASSERT_PTR(set_remove(s->uevents, &uuid)));
        seat_triggered_uevents_done(s);

        const char *id;
        r = device_get_seat(dev, &id);
        if (r < 0)
                return r;

        if (!streq(id, s->id)) {
                log_device_debug(dev, "ID_SEAT is changed in the triggered uevent: \"%s\" -> \"%s\"", s->id, id);
                return 0;
        }

        return 1; /* The uevent is triggered by the relevant seat. */
}

static int seat_trigger_devices(Seat *s) {
        int r;

        assert(s);

        set_clear(s->uevents);

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_tag(e, "uaccess");
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                /* Verify that the tag is still in place. */
                r = sd_device_has_current_tag(d, "uaccess");
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* In case people mistag devices without nodes, we need to ignore this. */
                r = sd_device_get_devname(d, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                const char *id;
                r = device_get_seat(d, &id);
                if (r < 0)
                        return r;

                if (!streq(id, s->id))
                        continue;

                sd_id128_t uuid;
                r = sd_device_trigger_with_uuid(d, SD_DEVICE_CHANGE, &uuid);
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to trigger 'change' event, ignoring: %m");
                        continue;
                }

                log_device_debug(d, "Triggered synthetic event (ACTION=change, UUID=%s).", SD_ID128_TO_UUID_STRING(uuid));

                _cleanup_free_ sd_id128_t *copy = newdup(sd_id128_t, &uuid, 1);
                if (!copy)
                        return -ENOMEM;

                r = set_ensure_consume(&s->uevents, &id128_hash_ops_free, TAKE_PTR(copy));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int static_node_acl(Seat *s) {
#if HAVE_ACL
        int r, ret = 0;
        _cleanup_set_free_ Set *uids = NULL;

        assert(s);

        if (s->active) {
                r = set_ensure_put(&uids, NULL, UID_TO_PTR(s->active->user->user_record->uid));
                if (r < 0)
                        return log_oom();
        }

        _cleanup_closedir_ DIR *dir = opendir("/run/udev/static_node-tags/uaccess/");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                return log_debug_errno(errno, "Failed to open /run/udev/static_node-tags/uaccess/: %m");
        }

        FOREACH_DIRENT(de, dir, return -errno) {
                _cleanup_close_ int fd = RET_NERRNO(openat(dirfd(dir), de->d_name, O_CLOEXEC|O_PATH));
                if (ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(fd))
                        continue;
                if (fd < 0) {
                        RET_GATHER(ret, log_debug_errno(fd, "Failed to open '/run/udev/static_node-tags/uaccess/%s': %m", de->d_name));
                        continue;
                }

                struct stat st;
                if (fstat(fd, &st) < 0) {
                        RET_GATHER(ret, log_debug_errno(errno, "Failed to stat '/run/udev/static_node-tags/uaccess/%s': %m", de->d_name));
                        continue;
                }

                r = stat_verify_device_node(&st);
                if (r < 0) {
                        RET_GATHER(ret, log_debug_errno(fd, "'/run/udev/static_node-tags/uaccess/%s' points to a non-device node: %m", de->d_name));
                        continue;
                }

                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                r = sd_device_new_from_stat_rdev(&dev, &st);
                if (r >= 0) {
                        log_device_debug(dev, "'/run/udev/static_node-tags/uaccess/%s' points to a non-static device node, ignoring.", de->d_name);
                        continue;
                }
                if (!ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(r))
                        log_debug_errno(r, "Failed to check if '/run/udev/static_node-tags/uaccess/%s' points to a static device node, ignoring: %m", de->d_name);

                r = devnode_acl(fd, uids);
                if (r >= 0 || r == -ENOENT)
                        continue;

                /* de->d_name is escaped, like "snd\x2ftimer", hence let's use the path to node, if possible. */
                _cleanup_free_ char *node = NULL;
                (void) fd_get_path(fd, &node);

                if (!set_isempty(uids)) {
                        RET_GATHER(ret, log_debug_errno(r, "Failed to apply ACL on '%s': %m", node ?: de->d_name));

                        /* Better be safe than sorry and reset ACL */
                        r = devnode_acl(fd, /* uids= */ NULL);
                        if (r >= 0 || r == -ENOENT)
                                continue;
                }
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to flush ACL on '%s': %m", node ?: de->d_name));
        }

        return ret;
#else
        return 0;
#endif
}

int seat_set_active(Seat *s, Session *session) {
        Session *old_active;
        int r;

        assert(s);
        assert(!session || session->seat == s);

        /* When logind receives the SIGRTMIN signal from the kernel, it will
         * execute session_leave_vt and stop all devices of the session; at
         * this time, if the session is active and there is no change in the
         * session, then the session does not have the permissions of the device,
         * and the machine will have a black screen and suspended animation.
         * Therefore, if the active session has executed session_leave_vt ,
         * A resume is required here. */
        if (session == s->active) {
                if (session && set_isempty(s->uevents)) {
                        log_debug("Active session remains unchanged, resuming session devices.");
                        session_device_resume_all(session);
                }
                return 0;
        }

        old_active = s->active;
        s->active = session;

        seat_save(s);

        if (old_active) {
                user_save(old_active->user);
                session_save(old_active);
                session_device_pause_all(old_active);
                session_send_changed(old_active, "Active");
        }

        r = seat_trigger_devices(s);
        if (r < 0)
                return r;

        r = static_node_acl(s);
        if (r < 0)
                return r;

        seat_triggered_uevents_done(s);
        return 0;
}

static Session* seat_get_position(Seat *s, unsigned pos) {
        assert(s);

        if (pos >= MALLOC_ELEMENTSOF(s->positions))
                return NULL;

        return s->positions[pos];
}

int seat_switch_to(Seat *s, unsigned num) {
        Session *session;

        /* Public session positions skip 0 (there is only F1-F12). Maybe it
         * will get reassigned in the future, so return error for now. */
        if (num == 0)
                return -EINVAL;

        session = seat_get_position(s, num);
        if (!session) {
                /* allow switching to unused VTs to trigger auto-activate */
                if (seat_has_vts(s) && num < 64)
                        return chvt(num);

                return -EINVAL;
        }

        return session_activate(session);
}

int seat_switch_to_next(Seat *s) {
        unsigned start, i;
        Session *session;

        if (MALLOC_ELEMENTSOF(s->positions) == 0)
                return -EINVAL;

        start = 1;
        if (s->active && s->active->position > 0)
                start = s->active->position;

        for (i = start + 1; i < MALLOC_ELEMENTSOF(s->positions); ++i) {
                session = seat_get_position(s, i);
                if (session)
                        return session_activate(session);
        }

        for (i = 1; i < start; ++i) {
                session = seat_get_position(s, i);
                if (session)
                        return session_activate(session);
        }

        return -EINVAL;
}

int seat_switch_to_previous(Seat *s) {
        if (MALLOC_ELEMENTSOF(s->positions) == 0)
                return -EINVAL;

        size_t start = s->active && s->active->position > 0 ? s->active->position : 1;

        for (size_t i = start - 1; i > 0; i--) {
                Session *session = seat_get_position(s, i);
                if (session)
                        return session_activate(session);
        }

        for (size_t i = MALLOC_ELEMENTSOF(s->positions) - 1; i > start; i--) {
                Session *session = seat_get_position(s, i);
                if (session)
                        return session_activate(session);
        }

        return -EINVAL;
}

int seat_active_vt_changed(Seat *s, unsigned vtnr) {
        Session *new_active = NULL;
        int r;

        assert(s);
        assert(vtnr >= 1);

        if (!seat_has_vts(s))
                return -EINVAL;

        log_debug("VT changed to %u", vtnr);

        /* we might have earlier closing sessions on the same VT, so try to
         * find a running one first */
        LIST_FOREACH(sessions_by_seat, i, s->sessions)
                if (i->vtnr == vtnr && !i->stopping) {
                        new_active = i;
                        break;
                }

        if (!new_active)
                /* no running one? then we can't decide which one is the
                 * active one, let the first one win */
                LIST_FOREACH(sessions_by_seat, i, s->sessions)
                        if (i->vtnr == vtnr) {
                                new_active = i;
                                break;
                        }

        r = seat_set_active(s, new_active);
        manager_spawn_autovt(s->manager, vtnr);

        return r;
}

int seat_read_active_vt(Seat *s) {
        char t[64];
        ssize_t k;
        int vtnr;

        assert(s);

        if (!seat_has_vts(s))
                return 0;

        if (lseek(s->manager->console_active_fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "lseek() on console_active_fd failed: %m");

        errno = 0;
        k = read(s->manager->console_active_fd, t, sizeof(t)-1);
        if (k <= 0)
                return log_error_errno(errno ?: EIO,
                                       "Failed to read current console: %s", STRERROR_OR_EOF(errno));

        t[k] = 0;
        truncate_nl(t);

        vtnr = vtnr_from_tty(t);
        if (vtnr < 0) {
                log_error_errno(vtnr, "Hm, /sys/class/tty/tty0/active is badly formatted: %m");
                return -EIO;
        }

        return seat_active_vt_changed(s, vtnr);
}

int seat_start(Seat *s) {
        assert(s);

        if (s->started)
                return 0;

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_SEAT_START_STR,
                   "SEAT_ID=%s", s->id,
                   LOG_MESSAGE("New seat %s.", s->id));

        /* Initialize VT magic stuff */
        seat_preallocate_vts(s);

        /* Read current VT */
        seat_read_active_vt(s);

        s->started = true;

        /* Save seat data */
        seat_save(s);

        seat_send_signal(s, true);

        return 0;
}

int seat_stop(Seat *s, bool force) {
        int r;

        assert(s);

        if (s->started)
                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_SEAT_STOP_STR,
                           "SEAT_ID=%s", s->id,
                           LOG_MESSAGE("Removed seat %s.", s->id));

        r = seat_stop_sessions(s, force);

        (void) unlink(s->state_file);
        seat_add_to_gc_queue(s);

        if (s->started)
                seat_send_signal(s, false);

        s->started = false;

        return r;
}

int seat_stop_sessions(Seat *s, bool force) {
        int r = 0, k;

        assert(s);

        LIST_FOREACH(sessions_by_seat, session, s->sessions) {
                k = session_stop(session, force);
                if (k < 0)
                        r = k;
        }

        return r;
}

void seat_evict_position(Seat *s, Session *session) {
        unsigned pos = session->position;

        session->position = 0;

        if (pos == 0)
                return;

        if (pos < MALLOC_ELEMENTSOF(s->positions) && s->positions[pos] == session) {
                s->positions[pos] = NULL;

                /* There might be another session claiming the same
                 * position (eg., during gdm->session transition), so let's look
                 * for it and set it on the free slot. */
                LIST_FOREACH(sessions_by_seat, iter, s->sessions)
                        if (iter->position == pos && session_get_state(iter) != SESSION_CLOSING) {
                                s->positions[pos] = iter;
                                break;
                        }
        }
}

void seat_claim_position(Seat *s, Session *session, unsigned pos) {
        /* with VTs, the position is always the same as the VTnr */
        if (seat_has_vts(s))
                pos = session->vtnr;

        if (!GREEDY_REALLOC0(s->positions, pos + 1))
                return;

        seat_evict_position(s, session);

        session->position = pos;
        if (pos > 0)
                s->positions[pos] = session;
}

static void seat_assign_position(Seat *s, Session *session) {
        unsigned pos;

        if (session->position > 0)
                return;

        for (pos = 1; pos < MALLOC_ELEMENTSOF(s->positions); ++pos)
                if (!s->positions[pos])
                        break;

        seat_claim_position(s, session, pos);
}

int seat_attach_session(Seat *s, Session *session) {
        assert(s);
        assert(session);
        assert(!session->seat);

        if (!seat_has_vts(s) != !session->vtnr)
                return -EINVAL;

        session->seat = s;
        LIST_PREPEND(sessions_by_seat, s->sessions, session);
        seat_assign_position(s, session);

        /* On seats with VTs, the VT logic defines which session is active. On
         * seats without VTs, we automatically activate new sessions. */
        if (!seat_has_vts(s))
                seat_set_active(s, session);

        return 0;
}

void seat_complete_switch(Seat *s) {
        Session *session;

        assert(s);

        /* if no session-switch is pending or if it got canceled, do nothing */
        if (!s->pending_switch)
                return;

        session = TAKE_PTR(s->pending_switch);

        seat_set_active(s, session);
}

bool seat_has_vts(Seat *s) {
        assert(s);

        return seat_is_seat0(s) && s->manager->console_active_fd >= 0;
}

bool seat_is_seat0(Seat *s) {
        assert(s);

        return s->manager->seat0 == s;
}

bool seat_can_tty(Seat *s) {
        assert(s);

        return seat_has_vts(s);
}

bool seat_has_master_device(Seat *s) {
        assert(s);

        /* device list is ordered by "master" flag */
        return !!s->devices && s->devices->master;
}

bool seat_can_graphical(Seat *s) {
        assert(s);

        return seat_has_master_device(s);
}

int seat_get_idle_hint(Seat *s, dual_timestamp *t) {
        bool idle_hint = true;
        dual_timestamp ts = DUAL_TIMESTAMP_NULL;

        assert(s);

        LIST_FOREACH(sessions_by_seat, session, s->sessions) {
                dual_timestamp k;
                int ih;

                ih = session_get_idle_hint(session, &k);
                if (ih < 0)
                        return ih;

                if (!ih) {
                        if (!idle_hint) {
                                if (k.monotonic > ts.monotonic)
                                        ts = k;
                        } else {
                                idle_hint = false;
                                ts = k;
                        }
                } else if (idle_hint) {

                        if (k.monotonic > ts.monotonic)
                                ts = k;
                }
        }

        if (t)
                *t = ts;

        return idle_hint;
}

bool seat_may_gc(Seat *s, bool drop_not_started) {
        assert(s);

        if (drop_not_started && !s->started)
                return true;

        if (seat_is_seat0(s))
                return false;

        return !seat_has_master_device(s);
}

void seat_add_to_gc_queue(Seat *s) {
        assert(s);

        if (s->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, s->manager->seat_gc_queue, s);
        s->in_gc_queue = true;
}

static bool seat_name_valid_char(char c) {
        return
                ascii_isalpha(c) ||
                ascii_isdigit(c) ||
                IN_SET(c, '-', '_');
}

bool seat_name_is_valid(const char *name) {
        const char *p;

        assert(name);

        if (!startswith(name, "seat"))
                return false;

        if (!name[4])
                return false;

        for (p = name; *p; p++)
                if (!seat_name_valid_char(*p))
                        return false;

        if (strlen(name) > 255)
                return false;

        return true;
}

bool seat_is_self(const char *name) {
        return isempty(name) || streq(name, "self");
}

bool seat_is_auto(const char *name) {
        return streq_ptr(name, "auto");
}

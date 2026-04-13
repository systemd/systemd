/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-event.h"
#include "sd-messages.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "audit-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "daemon-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "login-util.h"
#include "logind.h"
#include "logind-dbus.h"
#include "logind-seat.h"
#include "logind-seat-dbus.h"
#include "logind-session.h"
#include "logind-session-dbus.h"
#include "logind-session-device.h"
#include "logind-user.h"
#include "logind-user-dbus.h"
#include "logind-varlink.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "user-record.h"
#include "user-util.h"

#define RELEASE_USEC (20*USEC_PER_SEC)

static void session_restore_vt(Session *s);

int session_new(Manager *m, const char *id, Session **ret) {
        _cleanup_(session_freep) Session *s = NULL;
        int r;

        assert(m);
        assert(id);
        assert(ret);

        if (!session_id_valid(id))
                return -EINVAL;

        s = new(Session, 1);
        if (!s)
                return -ENOMEM;

        *s = (Session) {
                .manager = m,
                .id = strdup(id),
                .state_file = path_join("/run/systemd/sessions/", id),
                .vtfd = -EBADF,
                .audit_id = AUDIT_SESSION_INVALID,
                .tty_validity = _TTY_VALIDITY_INVALID,
                .leader = PIDREF_NULL,
        };
        if (!s->id || !s->state_file)
                return -ENOMEM;

        s->devices = hashmap_new(&devt_hash_ops);
        if (!s->devices)
                return -ENOMEM;

        r = hashmap_put(m->sessions, s->id, s);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

static int session_dispatch_leader_pidfd(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Session *s = ASSERT_PTR(userdata);

        assert(s->leader.fd == fd);

        s->leader_pidfd_event_source = sd_event_source_unref(s->leader_pidfd_event_source);

        session_stop(s, /* force= */ false);

        session_add_to_gc_queue(s);

        return 1;
}

static int session_watch_pidfd(Session *s) {
        int r;

        assert(s);
        assert(s->manager);
        assert(pidref_is_set(&s->leader));
        assert(s->leader.fd >= 0);
        assert(!s->leader_pidfd_event_source);

        r = sd_event_add_io(s->manager->event, &s->leader_pidfd_event_source, s->leader.fd, EPOLLIN, session_dispatch_leader_pidfd, s);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s->leader_pidfd_event_source, SD_EVENT_PRIORITY_IMPORTANT);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s->leader_pidfd_event_source, "session-pidfd");

        return 0;
}

static void session_reset_leader(Session *s, bool keep_fdstore) {
        assert(s);

        if (!keep_fdstore) {
                /* Clear fdstore if we're asked to, no matter if s->leader is set or not, so that when
                 * initially deserializing leader fd we clear the old fd too. */
                (void) notify_remove_fd_warnf("session-%s-leader-fd", s->id);
                s->leader_fd_saved = false;
        }

        if (!pidref_is_set(&s->leader))
                return;

        s->leader_pidfd_event_source = sd_event_source_disable_unref(s->leader_pidfd_event_source);

        (void) hashmap_remove_value(s->manager->sessions_by_leader, &s->leader, s);

        return pidref_done(&s->leader);
}

Session* session_free(Session *s) {
        SessionDevice *sd;

        if (!s)
                return NULL;

        sd_event_source_unref(s->stop_on_idle_event_source);

        if (s->in_gc_queue) {
                assert(s->manager);
                LIST_REMOVE(gc_queue, s->manager->session_gc_queue, s);
        }

        sd_event_source_unref(s->timer_event_source);

        session_drop_controller(s);

        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        hashmap_free(s->devices);

        if (s->user) {
                LIST_REMOVE(sessions_by_user, s->user->sessions, s);

                if (s->user->display == s)
                        s->user->display = NULL;

                user_update_last_session_timer(s->user);
        }

        if (s->seat) {
                if (s->seat->active == s)
                        s->seat->active = NULL;
                if (s->seat->pending_switch == s)
                        s->seat->pending_switch = NULL;

                seat_evict_position(s->seat, s);
                LIST_REMOVE(sessions_by_seat, s->seat->sessions, s);
        }

        if (s->scope) {
                hashmap_remove(s->manager->session_units, s->scope);
                free(s->scope);
        }

        free(s->scope_job);

        session_reset_leader(s, /* keep_fdstore= */ true);

        sd_bus_message_unref(s->create_message);
        sd_bus_message_unref(s->upgrade_message);

        sd_varlink_unref(s->create_link);

        free(s->tty);
        free(s->display);
        free(s->remote_host);
        free(s->remote_user);
        free(s->service);
        free(s->desktop);
        strv_free(s->extra_device_access);

        hashmap_remove(s->manager->sessions, s->id);

        /* Note that we don't remove the state file here, since it's supposed to survive daemon restarts */
        free(s->state_file);
        free(s->id);

        return mfree(s);
}

void session_set_user(Session *s, User *u) {
        assert(s);
        assert(!s->user);

        s->user = u;
        LIST_PREPEND(sessions_by_user, u->sessions, s);

        user_update_last_session_timer(u);
}

int session_set_leader_consume(Session *s, PidRef _leader) {
        _cleanup_(pidref_done) PidRef pidref = _leader;
        int r;

        assert(s);
        assert(pidref_is_set(&pidref));
        assert(pidref.fd >= 0);

        if (pidref_equal(&s->leader, &pidref))
                return 0;

        session_reset_leader(s, /* keep_fdstore= */ false);

        s->leader = TAKE_PIDREF(pidref);

        r = session_watch_pidfd(s);
        if (r < 0)
                return log_error_errno(r, "Failed to watch leader pidfd for session '%s': %m", s->id);

        r = hashmap_ensure_put(&s->manager->sessions_by_leader, &pidref_hash_ops, &s->leader, s);
        if (r < 0)
                return r;
        assert(r > 0);

        if (s->leader.fd >= 0) {
                r = notify_push_fdf(s->leader.fd, "session-%s-leader-fd", s->id);
                if (r < 0)
                        log_warning_errno(r, "Failed to push leader pidfd for session '%s', ignoring: %m", s->id);
                else
                        s->leader_fd_saved = true;
        }

        (void) audit_session_from_pid(&s->leader, &s->audit_id);

        return 1;
}

static void session_save_devices(Session *s, FILE *f) {
        SessionDevice *sd;

        if (!hashmap_isempty(s->devices)) {
                fprintf(f, "DEVICES=");
                HASHMAP_FOREACH(sd, s->devices)
                        fprintf(f, DEVNUM_FORMAT_STR " ", DEVNUM_FORMAT_VAL(sd->dev));
                fprintf(f, "\n");
        }
}

static int trigger_xaccess(char * const *extra_devices) {
        int r;

        if (strv_isempty(extra_devices))
                return 0;

        _cleanup_strv_free_ char **tags = NULL;
        r = strv_extend_strv_biconcat(&tags, "xaccess-", (const char * const *)extra_devices, /* suffix= */ NULL);
        if (r < 0)
                return r;

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        STRV_FOREACH(tag, tags) {
                r = sd_device_enumerator_add_match_tag(e, *tag);
                if (r < 0)
                        return r;
        }

        FOREACH_DEVICE(e, d) {
                /* Verify that the tag is still in place. */
                bool has_xaccess = false;
                STRV_FOREACH(tag, tags)
                        if (sd_device_has_current_tag(d, *tag)) {
                                has_xaccess = true;
                                break;
                        }
                if (!has_xaccess)
                        continue;

                /* In case people mistag devices without nodes, we need to ignore this. */
                r = sd_device_get_devname(d, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                sd_id128_t uuid;
                r = sd_device_trigger_with_uuid(d, SD_DEVICE_CHANGE, &uuid);
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to trigger 'change' event, ignoring: %m");
                        continue;
                }

                log_device_debug(d, "Triggered synthetic event (ACTION=change, UUID=%s).", SD_ID128_TO_UUID_STRING(uuid));
        }

        return 0;
}

int session_save(Session *s) {
        int r;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (!s->started)
                return 0;

        r = mkdir_safe_label("/run/systemd/sessions", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/sessions/: %m");

        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        r = fopen_tmpfile_linkable(s->state_file, O_WRONLY|O_CLOEXEC, &temp_path, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create state file '%s': %m", s->state_file);

        if (fchmod(fileno(f), 0644) < 0)
                return log_error_errno(errno, "Failed to set access mode for state file '%s' to 0644: %m", s->state_file);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "UID="UID_FMT"\n"
                "ACTIVE=%s\n"
                "IS_DISPLAY=%s\n"
                "STATE=%s\n"
                "REMOTE=%s\n"
                "LEADER_FD_SAVED=%s\n",
                s->user->user_record->uid,
                one_zero(session_is_active(s)),
                one_zero(s->user->display == s),
                session_state_to_string(session_get_state(s)),
                one_zero(s->remote),
                one_zero(s->leader_fd_saved));

        env_file_fputs_assignment(f, "USER=", s->user->user_record->user_name);

        if (s->type >= 0)
                fprintf(f, "TYPE=%s\n", session_type_to_string(s->type));

        if (s->original_type >= 0)
                fprintf(f, "ORIGINAL_TYPE=%s\n", session_type_to_string(s->original_type));

        if (s->class >= 0)
                fprintf(f, "CLASS=%s\n", session_class_to_string(s->class));

        env_file_fputs_assignment(f, "SCOPE=", s->scope);
        env_file_fputs_assignment(f, "SCOPE_JOB=", s->scope_job);
        if (s->seat)
                env_file_fputs_assignment(f, "SEAT=", s->seat->id);
        env_file_fputs_assignment(f, "TTY=", s->tty);

        if (s->tty_validity >= 0)
                fprintf(f, "TTY_VALIDITY=%s\n", tty_validity_to_string(s->tty_validity));

        env_file_fputs_assignment(f, "DISPLAY=", s->display);
        env_file_fputs_assignment(f, "REMOTE_HOST=", s->remote_host);
        env_file_fputs_assignment(f, "REMOTE_USER=", s->remote_user);
        env_file_fputs_assignment(f, "SERVICE=", s->service);
        env_file_fputs_assignment(f, "DESKTOP=", s->desktop);

        if (s->seat) {
                if (!seat_has_vts(s->seat))
                        fprintf(f, "POSITION=%u\n", s->position);
                else if (s->vtnr > 0)
                        fprintf(f, "VTNR=%u\n", s->vtnr);
        }

        if (pidref_is_set(&s->leader)) {
                fprintf(f, "LEADER="PID_FMT"\n", s->leader.pid);
                (void) pidref_acquire_pidfd_id(&s->leader);
                if (s->leader.fd_id != 0)
                        fprintf(f, "LEADER_PIDFDID=%" PRIu64 "\n", s->leader.fd_id);
        }

        if (audit_session_is_valid(s->audit_id))
                fprintf(f, "AUDIT=%"PRIu32"\n", s->audit_id);

        if (dual_timestamp_is_set(&s->timestamp))
                fprintf(f,
                        "REALTIME="USEC_FMT"\n"
                        "MONOTONIC="USEC_FMT"\n",
                        s->timestamp.realtime,
                        s->timestamp.monotonic);

        if (s->controller) {
                env_file_fputs_assignment(f, "CONTROLLER=", s->controller);
                session_save_devices(s, f);
        }

        if (s->extra_device_access) {
                _cleanup_free_ char *extra_devices = strv_join(s->extra_device_access, " ");
                if (!extra_devices)
                        return log_oom();
                fprintf(f, "EXTRA_DEVICE_ACCESS=%s\n", extra_devices);
        }

        r = flink_tmpfile(f, temp_path, s->state_file, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", s->state_file);

        temp_path = mfree(temp_path); /* disarm auto-destroy: temporary file does not exist anymore */
        return 0;
}

static int session_load_devices(Session *s, const char *devices) {
        int r = 0;

        assert(s);

        for (const char *p = devices;;) {
                _cleanup_free_ char *word = NULL;
                dev_t dev;
                int k;

                k = extract_first_word(&p, &word, NULL, 0);
                if (k <= 0) {
                        RET_GATHER(r, k);
                        break;
                }

                k = parse_devnum(word, &dev);
                if (k < 0) {
                        RET_GATHER(r, k);
                        continue;
                }

                /* The file descriptors for loaded devices will be reattached later. */
                RET_GATHER(r, session_device_new(s, dev, /* open_device= */ false, /* ret= */ NULL));
        }

        if (r < 0)
                log_error_errno(r, "Failed to load some session devices for session '%s': %m", s->id);
        return r;
}

static int session_load_leader(Session *s, uint64_t pidfdid) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(s);
        assert(pid_is_valid(s->deserialized_pid));
        assert(!pidref_is_set(&s->leader));

        if (pidfdid == 0 && s->leader_fd_saved)
                /* We have no pidfd id for stable reference, but the pidfd has been submitted to fdstore.
                 * manager_enumerate_fds() will dispatch the leader fd for us later. */
                return 0;

        r = pidref_set_pid(&pidref, s->deserialized_pid);
        if (r == -ESRCH)
                return log_warning_errno(r, "Leader of session '%s' is gone while deserializing.", s->id);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize leader PID for session '%s': %m", s->id);
        if (pidref.fd < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to acquire pidfd for session leader '" PID_FMT "', refusing.",
                                       pidref.pid);

        if (pidfdid > 0) {
                r = pidref_acquire_pidfd_id(&pidref);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire pidfd id of deserialized leader '" PID_FMT "': %m",
                                               pidref.pid);

                if (pidref.fd_id != pidfdid)
                        return log_warning_errno(SYNTHETIC_ERRNO(ESRCH),
                                                 "Deserialized pidfd id for process " PID_FMT " (%" PRIu64 ") doesn't match the current one (%" PRIu64 "). PID recycled while deserializing?",
                                                 pidref.pid, pidfdid, pidref.fd_id);
        }

        r = session_set_leader_consume(s, TAKE_PIDREF(pidref));
        if (r < 0)
                return log_error_errno(r, "Failed to set leader PID for session '%s': %m", s->id);

        return 1;
}

int session_load(Session *s) {
        _cleanup_free_ char *remote = NULL,
                *extra_device_access = NULL,
                *seat = NULL,
                *tty_validity = NULL,
                *vtnr = NULL,
                *state = NULL,
                *position = NULL,
                *leader_pid = NULL,
                *leader_fd_saved = NULL,
                *leader_pidfdid = NULL,
                *type = NULL,
                *original_type = NULL,
                *class = NULL,
                *uid = NULL,
                *realtime = NULL,
                *monotonic = NULL,
                *controller = NULL,
                *active = NULL,
                *devices = NULL,
                *is_display = NULL,
                *fifo_path = NULL; /* compat only, not used */

        int k, r;

        assert(s);

        r = parse_env_file(NULL, s->state_file,
                           "REMOTE",              &remote,
                           "EXTRA_DEVICE_ACCESS", &extra_device_access,
                           "SCOPE",               &s->scope,
                           "SCOPE_JOB",           &s->scope_job,
                           "FIFO",                &fifo_path,
                           "SEAT",                &seat,
                           "TTY",                 &s->tty,
                           "TTY_VALIDITY",        &tty_validity,
                           "DISPLAY",             &s->display,
                           "REMOTE_HOST",         &s->remote_host,
                           "REMOTE_USER",         &s->remote_user,
                           "SERVICE",             &s->service,
                           "DESKTOP",             &s->desktop,
                           "VTNR",                &vtnr,
                           "STATE",               &state,
                           "POSITION",            &position,
                           "LEADER",              &leader_pid,
                           "LEADER_FD_SAVED",     &leader_fd_saved,
                           "LEADER_PIDFDID",      &leader_pidfdid,
                           "TYPE",                &type,
                           "ORIGINAL_TYPE",       &original_type,
                           "CLASS",               &class,
                           "UID",                 &uid,
                           "REALTIME",            &realtime,
                           "MONOTONIC",           &monotonic,
                           "CONTROLLER",          &controller,
                           "ACTIVE",              &active,
                           "DEVICES",             &devices,
                           "IS_DISPLAY",          &is_display);
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", s->state_file);

        if (!s->user) {
                uid_t u;
                User *user;

                if (!uid)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "UID not specified for session %s",
                                               s->id);

                r = parse_uid(uid, &u);
                if (r < 0)  {
                        log_error("Failed to parse UID value %s for session %s.", uid, s->id);
                        return r;
                }

                user = hashmap_get(s->manager->users, UID_TO_PTR(u));
                if (!user)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "User of session %s not known.",
                                               s->id);

                session_set_user(s, user);
        }

        if (remote) {
                k = parse_boolean(remote);
                if (k >= 0)
                        s->remote = k;
        }

        if (extra_device_access) {
                s->extra_device_access = strv_split(extra_device_access, /* separators= */ NULL);
                if (!s->extra_device_access)
                        return log_oom();
        }

        if (vtnr)
                (void) safe_atou(vtnr, &s->vtnr);

        if (seat && !s->seat) {
                Seat *o;

                o = hashmap_get(s->manager->seats, seat);
                if (o)
                        r = seat_attach_session(o, s);
                if (!o || r < 0)
                        log_error("Cannot attach session %s to seat %s", s->id, seat);
        }

        if (!s->seat || !seat_has_vts(s->seat))
                s->vtnr = 0;

        if (position && s->seat) {
                unsigned npos;

                (void) safe_atou(position, &npos);
                seat_claim_position(s->seat, s, npos);
        }

        if (tty_validity) {
                TTYValidity v;

                v = tty_validity_from_string(tty_validity);
                if (v < 0)
                        log_debug("Failed to parse TTY validity: %s", tty_validity);
                else
                        s->tty_validity = v;
        }

        if (type) {
                SessionType t;

                t = session_type_from_string(type);
                if (t >= 0)
                        s->type = t;
        }

        if (original_type) {
                SessionType ot;

                ot = session_type_from_string(original_type);
                if (ot >= 0)
                        s->original_type = ot;
        } else
                /* Pre-v246 compat: initialize original_type if not set in the state file */
                s->original_type = s->type;

        if (class) {
                SessionClass c;

                c = session_class_from_string(class);
                if (c >= 0)
                        s->class = c;
        }

        if (streq_ptr(state, "closing"))
                s->stopping = true;

        /* logind before v258 used a fifo for session close notification. Since v258 we fully employ
         * pidfd for the job, hence just unlink the legacy fifo. */
        if (fifo_path)
                (void) unlink(fifo_path);

        if (realtime)
                (void) deserialize_usec(realtime, &s->timestamp.realtime);
        if (monotonic)
                (void) deserialize_usec(monotonic, &s->timestamp.monotonic);

        if (active) {
                k = parse_boolean(active);
                if (k >= 0)
                        s->was_active = k;
        }

        if (is_display) {
                /* Note that when enumerating users are loaded before sessions, hence the display session to use is
                 * something we have to store along with the session and not the user, as in that case we couldn't
                 * apply it at the time we load the user. */

                k = parse_boolean(is_display);
                if (k < 0)
                        log_warning_errno(k, "Failed to parse IS_DISPLAY session property: %m");
                else if (k > 0)
                        s->user->display = s;
        }

        if (controller) {
                if (bus_name_has_owner(s->manager->bus, controller, NULL) > 0) {
                        session_set_controller(s, controller, false, false);
                        session_load_devices(s, devices);
                } else
                        session_restore_vt(s);
        }

        if (leader_pid) {
                r = parse_pid(leader_pid, &s->deserialized_pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse LEADER=%s: %m", leader_pid);

                if (leader_fd_saved) {
                        r = parse_boolean(leader_fd_saved);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse LEADER_FD_SAVED=%s: %m", leader_fd_saved);
                        s->leader_fd_saved = r > 0;
                }

                uint64_t pidfdid;
                if (leader_pidfdid) {
                        r = safe_atou64(leader_pidfdid, &pidfdid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse LEADER_PIDFDID=%s: %m", leader_pidfdid);
                } else
                        pidfdid = 0;

                r = session_load_leader(s, pidfdid);
                if (r < 0)
                        return r;
        }

        return 0;
}

int session_activate(Session *s) {
        unsigned num_pending;

        assert(s);
        assert(s->user);

        if (!s->seat)
                return -EOPNOTSUPP;

        if (s->seat->active == s)
                return 0;

        /* on seats with VTs, we let VTs manage session-switching */
        if (seat_has_vts(s->seat)) {
                if (s->vtnr == 0)
                        return -EOPNOTSUPP;

                return chvt(s->vtnr);
        }

        /* On seats without VTs, we implement session-switching in logind. We
         * try to pause all session-devices and wait until the session
         * controller acknowledged them. Once all devices are asleep, we simply
         * switch the active session and be done.
         * We save the session we want to switch to in seat->pending_switch and
         * seat_complete_switch() will perform the final switch. */

        s->seat->pending_switch = s;

        /* if no devices are running, immediately perform the session switch */
        num_pending = session_device_try_pause_all(s);
        if (!num_pending)
                seat_complete_switch(s->seat);

        return 0;
}

static int session_start_scope(Session *s, sd_bus_message *properties, sd_bus_error *error) {
        _cleanup_free_ char *scope = NULL;
        const char *description;
        int r;

        assert(s);
        assert(s->user);

        if (!SESSION_CLASS_WANTS_SCOPE(s->class))
                return 0;

        if (s->scope)
                goto finish;

        s->scope_job = mfree(s->scope_job);

        scope = strjoin("session-", s->id, ".scope");
        if (!scope)
                return log_oom();

        description = strjoina("Session ", s->id, " of User ", s->user->user_record->user_name);

        r = manager_start_scope(
                        s->manager,
                        scope,
                        &s->leader,
                        /* allow_pidfd= */ true,
                        s->user->slice,
                        description,
                        /* These should have been pulled in explicitly in user_start(). Just to be sure. */
                        /* requires= */ STRV_MAKE_CONST(s->user->runtime_dir_unit),
                        /* wants= */ STRV_MAKE_CONST(SESSION_CLASS_WANTS_SERVICE_MANAGER(s->class) ? s->user->service_manager_unit : NULL),
                        /* We usually want to order session scopes after systemd-user-sessions.service
                         * since the unit is used as login session barrier for unprivileged users. However
                         * the barrier doesn't apply for root as sysadmin should always be able to log in
                         * (and without waiting for any timeout to expire) in case something goes wrong
                         * during the boot process. */
                        /* extra_after= */ STRV_MAKE_CONST("systemd-logind.service",
                                                            SESSION_CLASS_IS_EARLY(s->class) ? NULL : "systemd-user-sessions.service"),
                        user_record_home_directory(s->user->user_record),
                        properties,
                        error,
                        &s->scope_job);
        if (r < 0)
                return log_error_errno(r, "Failed to start session scope %s: %s",
                                       scope, bus_error_message(error, r));

        s->scope = TAKE_PTR(scope);

finish:
        (void) hashmap_put(s->manager->session_units, s->scope, s);
        return 0;
}

static int session_dispatch_stop_on_idle(sd_event_source *source, uint64_t t, void *userdata) {
        Session *s = userdata;
        dual_timestamp ts;
        int r, idle;

        assert(s);

        if (s->stopping)
                return 0;

        idle = session_get_idle_hint(s, &ts);
        if (idle) {
                log_info("Session \"%s\" of user \"%s\" is idle, stopping.", s->id, s->user->user_record->user_name);

                return session_stop(s, /* force= */ true);
        }

        r = sd_event_source_set_time(
                        source,
                        usec_add(dual_timestamp_is_set(&ts) ? ts.monotonic : now(CLOCK_MONOTONIC),
                                 s->manager->stop_idle_session_usec));
        if (r < 0)
                return log_error_errno(r, "Failed to configure stop on idle session event source: %m");

        r = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_error_errno(r, "Failed to enable stop on idle session event source: %m");

        return 1;
}

static int session_setup_stop_on_idle_timer(Session *s) {
        int r;

        assert(s);

        if (s->manager->stop_idle_session_usec == USEC_INFINITY || !SESSION_CLASS_CAN_STOP_ON_IDLE(s->class))
                return 0;

        r = sd_event_add_time_relative(
                        s->manager->event,
                        &s->stop_on_idle_event_source,
                        CLOCK_MONOTONIC,
                        s->manager->stop_idle_session_usec,
                        0,
                        session_dispatch_stop_on_idle, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add stop on idle session event source: %m");

        return 0;
}

int session_start(Session *s, sd_bus_message *properties, sd_bus_error *error) {
        int r;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (s->stopping)
                return -EINVAL;

        if (s->started)
                return 0;

        r = user_start(s->user);
        if (r < 0)
                return r;

        r = session_start_scope(s, properties, error);
        if (r < 0)
                return r;

        r = session_setup_stop_on_idle_timer(s);
        if (r < 0)
                return r;

        log_struct(s->class == SESSION_BACKGROUND ? LOG_DEBUG : LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_SESSION_START_STR),
                   LOG_ITEM("SESSION_ID=%s", s->id),
                   LOG_ITEM("USER_ID=%s", s->user->user_record->user_name),
                   LOG_ITEM("LEADER="PID_FMT, s->leader.pid),
                   LOG_ITEM("CLASS=%s", session_class_to_string(s->class)),
                   LOG_ITEM("TYPE=%s", session_type_to_string(s->type)),
                   LOG_MESSAGE("New session '%s' of user '%s' with class '%s' and type '%s'.",
                               s->id,
                               s->user->user_record->user_name,
                               session_class_to_string(s->class),
                               session_type_to_string(s->type)));

        if (!dual_timestamp_is_set(&s->timestamp))
                dual_timestamp_now(&s->timestamp);

        if (s->seat)
                seat_read_active_vt(s->seat);

        s->started = true;

        user_elect_display(s->user);

        /* Save data */
        (void) session_save(s);
        (void) user_save(s->user);
        if (s->seat)
                (void) seat_save(s->seat);

        (void) trigger_xaccess(s->extra_device_access);

        /* Send signals */
        (void) session_send_signal(s, true);
        (void) user_send_changed(s->user, "Display");

        if (s->seat && s->seat->active == s)
                (void) seat_send_changed(s->seat, "ActiveSession");

        return 0;
}

static int session_stop_scope(Session *s, bool force) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(s);

        if (!s->scope)
                return 0;

        /* Let's always abandon the scope first. This tells systemd that we are not interested anymore, and everything
         * that is left in the scope is "left-over". Informing systemd about this has the benefit that it will log
         * when killing any processes left after this point. */
        r = manager_abandon_scope(s->manager, s->scope, &error);
        if (r < 0) {
                log_warning_errno(r, "Failed to abandon session scope, ignoring: %s", bus_error_message(&error, r));
                sd_bus_error_free(&error);
        }

        s->scope_job = mfree(s->scope_job);

        /* Optionally, let's kill everything that's left now. */
        if (force ||
            (s->user->user_record->kill_processes != 0 &&
             (s->user->user_record->kill_processes > 0 ||
              manager_shall_kill(s->manager, s->user->user_record->user_name)))) {

                r = manager_stop_unit(s->manager, s->scope, force ? "replace" : "fail", &error, &s->scope_job);
                if (r < 0) {
                        if (force)
                                return log_error_errno(r, "Failed to stop session scope: %s", bus_error_message(&error, r));

                        log_warning_errno(r, "Failed to stop session scope, ignoring: %s", bus_error_message(&error, r));
                }
        } else {

                /* With no killing, this session is allowed to persist in "closing" state indefinitely.
                 * Therefore session stop and session removal may be two distinct events.
                 * Session stop is quite significant on its own, let's log it. */
                log_struct(s->class == SESSION_BACKGROUND ? LOG_DEBUG : LOG_INFO,
                           LOG_ITEM("SESSION_ID=%s", s->id),
                           LOG_ITEM("USER_ID=%s", s->user->user_record->user_name),
                           LOG_ITEM("LEADER="PID_FMT, s->leader.pid),
                           LOG_MESSAGE("Session %s logged out. Waiting for processes to exit.", s->id));
        }

        return 0;
}

int session_stop(Session *s, bool force) {
        int r;

        assert(s);

        /* This is called whenever we begin with tearing down a session record. It's called in four cases: explicit API
         * request via the bus (either directly for the session object or for the seat or user object this session
         * belongs to; 'force' is true), or due to automatic GC (i.e. scope vanished; 'force' is false), or because the
         * session FIFO saw an EOF ('force' is false), or because the release timer hit ('force' is false). */

        if (!s->user)
                return -ESTALE;
        if (!s->started)
                return 0;
        if (s->stopping)
                return 0;

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (s->seat)
                seat_evict_position(s->seat, s);

        /* Kill cgroup */
        r = session_stop_scope(s, force);

        s->stopping = true;

        user_elect_display(s->user);

        (void) session_save(s);
        (void) user_save(s->user);

        (void) trigger_xaccess(s->extra_device_access);

        return r;
}

int session_finalize(Session *s) {
        SessionDevice *sd;

        assert(s);

        if (!s->user)
                return -ESTALE;

        if (s->started)
                log_struct(s->class == SESSION_BACKGROUND ? LOG_DEBUG : LOG_INFO,
                           LOG_MESSAGE_ID(SD_MESSAGE_SESSION_STOP_STR),
                           LOG_ITEM("SESSION_ID=%s", s->id),
                           LOG_ITEM("USER_ID=%s", s->user->user_record->user_name),
                           LOG_ITEM("LEADER="PID_FMT, s->leader.pid),
                           LOG_MESSAGE("Removed session %s.", s->id));

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (s->seat)
                seat_evict_position(s->seat, s);

        /* Kill session devices */
        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        (void) unlink(s->state_file);
        session_add_to_gc_queue(s);
        user_add_to_gc_queue(s->user);

        if (s->started) {
                session_send_signal(s, false);
                s->started = false;
        }

        if (s->seat) {
                if (s->seat->active == s)
                        seat_set_active(s->seat, NULL);

                seat_save(s->seat);
        }

        session_reset_leader(s, /* keep_fdstore= */ false);

        (void) user_save(s->user);
        (void) user_send_changed(s->user, "Display");

        return 0;
}

static int release_timeout_callback(sd_event_source *es, uint64_t usec, void *userdata) {
        Session *s = ASSERT_PTR(userdata);

        assert(es);

        session_stop(s, /* force= */ false);
        return 0;
}

int session_release(Session *s) {
        assert(s);

        if (!s->started || s->stopping)
                return 0;

        if (s->timer_event_source)
                return 0;

        return sd_event_add_time_relative(
                        s->manager->event,
                        &s->timer_event_source,
                        CLOCK_MONOTONIC,
                        RELEASE_USEC, 0,
                        release_timeout_callback, s);
}

bool session_is_active(Session *s) {
        assert(s);

        if (!s->seat)
                return true;

        return s->seat->active == s;
}

static int get_tty_atime(const char *tty, usec_t *atime) {
        _cleanup_free_ char *p = NULL;
        struct stat st;

        assert(tty);
        assert(atime);

        if (!path_is_absolute(tty)) {
                p = path_join("/dev", tty);
                if (!p)
                        return -ENOMEM;

                tty = p;
        } else if (!path_startswith(tty, "/dev/"))
                return -ENOENT;

        if (lstat(tty, &st) < 0)
                return -errno;

        *atime = timespec_load(&st.st_atim);
        return 0;
}

static int get_process_ctty_atime(pid_t pid, usec_t *atime) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(pid > 0);
        assert(atime);

        r = get_ctty(pid, NULL, &p);
        if (r < 0)
                return r;

        return get_tty_atime(p, atime);
}

int session_get_idle_hint(Session *s, dual_timestamp *t) {
        usec_t atime = 0, dtime = 0;
        int r;

        assert(s);

        if (!SESSION_CLASS_CAN_IDLE(s->class))
                return false;

        /* Graphical sessions have an explicit idle hint */
        if (SESSION_TYPE_IS_GRAPHICAL(s->type)) {
                if (t)
                        *t = s->idle_hint_timestamp;

                return s->idle_hint;
        }

        if (s->type == SESSION_TTY) {
                /* For sessions with an explicitly configured tty, let's check its atime */
                if (s->tty) {
                        r = get_tty_atime(s->tty, &atime);
                        if (r >= 0)
                                goto found_atime;
                }

                /* For sessions with a leader but no explicitly configured tty, let's check the controlling tty of
                 * the leader */
                if (pidref_is_set(&s->leader)) {
                        r = get_process_ctty_atime(s->leader.pid, &atime);
                        if (r >= 0)
                                goto found_atime;
                }
        }

        if (t)
                *t = DUAL_TIMESTAMP_NULL;

        return false;

found_atime:
        if (t)
                dual_timestamp_from_realtime(t, atime);

        if (s->manager->idle_action_usec > 0 && s->manager->stop_idle_session_usec != USEC_INFINITY)
                dtime = MIN(s->manager->idle_action_usec, s->manager->stop_idle_session_usec);
        else if (s->manager->idle_action_usec > 0)
                dtime = s->manager->idle_action_usec;
        else if (s->manager->stop_idle_session_usec != USEC_INFINITY)
                dtime = s->manager->stop_idle_session_usec;
        else
                return false;

        return usec_add(atime, dtime) <= now(CLOCK_REALTIME);
}

int session_set_idle_hint(Session *s, bool b) {
        assert(s);

        if (!SESSION_CLASS_CAN_IDLE(s->class)) /* Only some session classes know the idle concept at all */
                return -ENOTTY;
        if (!SESSION_TYPE_IS_GRAPHICAL(s->type)) /* And only graphical session types can set the field explicitly */
                return -ENOTTY;

        if (s->idle_hint == b)
                return 0;

        s->idle_hint = b;
        dual_timestamp_now(&s->idle_hint_timestamp);

        (void) session_send_changed(s, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic");

        if (s->seat)
                (void) seat_send_changed(s->seat, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic");

        (void) user_send_changed(s->user, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic");
        (void) manager_send_changed(s->manager, "IdleHint", "IdleSinceHint", "IdleSinceHintMonotonic");

        return 1;
}

int session_get_locked_hint(Session *s) {
        assert(s);

        return s->locked_hint;
}

int session_set_locked_hint(Session *s, bool b) {
        assert(s);

        if (!SESSION_CLASS_CAN_LOCK(s->class))
                return -ENOTTY;

        if (s->locked_hint == b)
                return 0;

        s->locked_hint = b;
        (void) session_save(s);
        (void) session_send_changed(s, "LockedHint");

        return 1;
}

void session_set_type(Session *s, SessionType t) {
        assert(s);

        if (s->type == t)
                return;

        s->type = t;
        (void) session_save(s);
        (void) session_send_changed(s, "Type");
}

void session_set_class(Session *s, SessionClass c) {
        assert(s);

        if (s->class == c)
                return;

        s->class = c;
        (void) session_save(s);
        (void) session_send_changed(s, "Class");

        /* This class change might mean we need the per-user session manager now. Try to start it. */
        (void) user_start_service_manager(s->user);
}

int session_set_display(Session *s, const char *display) {
        int r;

        assert(s);
        assert(display);

        r = free_and_strdup(&s->display, display);
        if (r <= 0)  /* 0 means the strings were equal */
                return r;

        (void) session_save(s);
        (void) session_send_changed(s, "Display");

        return 1;
}

int session_set_tty(Session *s, const char *tty) {
        int r;

        assert(s);
        assert(tty);

        r = free_and_strdup(&s->tty, tty);
        if (r <= 0)  /* 0 means the strings were equal */
                return r;

        (void) session_save(s);
        (void) session_send_changed(s, "TTY");

        return 1;
}

bool session_may_gc(Session *s, bool drop_not_started) {
        int r;

        assert(s);

        if (drop_not_started && !s->started)
                return true;

        if (!s->user)
                return true;

        r = pidref_is_alive(&s->leader);
        if (r == -ESRCH)
                /* Session has no leader. This is probably because the leader vanished before deserializing
                 * pidfd from FD store. */
                return true;
        if (r < 0)
                log_debug_errno(r, "Unable to determine if leader PID " PID_FMT " is still alive, assuming not: %m", s->leader.pid);
        if (r > 0)
                return false;

        if (s->scope_job) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_job_is_active(s->manager, s->scope_job, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether job '%s' is pending, ignoring: %s", s->scope_job, bus_error_message(&error, r));
                if (r != 0)
                        return false;
        }

        if (s->scope) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                r = manager_unit_is_active(s->manager, s->scope, &error);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether unit '%s' is active, ignoring: %s", s->scope, bus_error_message(&error, r));
                if (r != 0)
                        return false;
        }

        return true;
}

void session_add_to_gc_queue(Session *s) {
        assert(s);

        if (s->in_gc_queue)
                return;

        LIST_PREPEND(gc_queue, s->manager->session_gc_queue, s);
        s->in_gc_queue = true;
}

SessionState session_get_state(Session *s) {
        assert(s);

        /* always check closing first */
        if (s->stopping || s->timer_event_source)
                return SESSION_CLOSING;

        if (s->scope_job || !pidref_is_set(&s->leader))
                return SESSION_OPENING;

        if (session_is_active(s))
                return SESSION_ACTIVE;

        return SESSION_ONLINE;
}

int session_kill(Session *s, KillWhom whom, int signo, sd_bus_error *error) {
        assert(s);

        switch (whom) {

        case KILL_ALL:
                if (!SESSION_CLASS_WANTS_SCOPE(s->class))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                                 "Session '%s' has no associated scope", s->id);

                if (!s->scope)
                        return sd_bus_error_set_errnof(error, ESRCH, "Scope for session '%s' not active", s->id);

                return manager_kill_unit(s->manager, s->scope, KILL_ALL, signo, error);

        case KILL_LEADER:
                return pidref_kill(&s->leader, signo);

        default:
                assert_not_reached();
        }
}

static int session_open_vt(Session *s, bool reopen) {
        _cleanup_close_ int fd = -EBADF;
        char path[sizeof("/dev/tty") + DECIMAL_STR_MAX(s->vtnr)];

        assert(s);

        if (s->vtnr < 1)
                return -ENODEV;

        if (!reopen && s->vtfd >= 0)
                return s->vtfd;

        sprintf(path, "/dev/tty%u", s->vtnr);

        fd = open_terminal(path, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
        if (fd < 0)
                return log_error_errno(fd, "Cannot open VT %s of session %s: %m", path, s->id);

        close_and_replace(s->vtfd, fd);
        return s->vtfd;
}

static int session_prepare_vt(Session *s) {
        int vt, r;
        struct vt_mode mode = {};

        assert(s);

        if (s->vtnr < 1)
                return 0;

        vt = session_open_vt(s, /* reopen= */ false);
        if (vt < 0)
                return vt;

        r = fchown(vt, s->user->user_record->uid, -1);
        if (r < 0) {
                r = log_error_errno(errno,
                                    "Cannot change owner of /dev/tty%u: %m",
                                    s->vtnr);
                goto error;
        }

        r = ioctl(vt, KDSKBMODE, K_OFF);
        if (r < 0) {
                r = log_error_errno(errno,
                                    "Cannot set K_OFF on /dev/tty%u: %m",
                                    s->vtnr);
                goto error;
        }

        r = ioctl(vt, KDSETMODE, KD_GRAPHICS);
        if (r < 0) {
                r = log_error_errno(errno,
                                    "Cannot set KD_GRAPHICS on /dev/tty%u: %m",
                                    s->vtnr);
                goto error;
        }

        /* Oh, thanks to the VT layer, VT_AUTO does not work with KD_GRAPHICS.
         * So we need a dummy handler here which just acknowledges *all* VT
         * switch requests. */
        mode.mode = VT_PROCESS;
        mode.relsig = SIGRTMIN;
        mode.acqsig = SIGRTMIN + 1;
        r = ioctl(vt, VT_SETMODE, &mode);
        if (r < 0) {
                r = log_error_errno(errno,
                                    "Cannot set VT_PROCESS on /dev/tty%u: %m",
                                    s->vtnr);
                goto error;
        }

        return 0;

error:
        session_restore_vt(s);
        return r;
}

static void session_restore_vt(Session *s) {
        int r;

        assert(s);

        if (s->vtfd < 0)
                return;

        r = vt_restore(s->vtfd);
        if (r == -EIO) {
                /* It might happen if the controlling process exited before or while we were
                 * restoring the VT as it would leave the old file-descriptor in a hung-up
                 * state. In this case let's retry with a fresh handle to the virtual terminal. */

                /* We do a little dance to avoid having the terminal be available
                 * for reuse before we've cleaned it up. */

                int fd = session_open_vt(s, /* reopen= */ true);
                if (fd >= 0)
                        r = vt_restore(fd);
        }
        if (r < 0)
                log_warning_errno(r, "Failed to restore VT, ignoring: %m");

        s->vtfd = safe_close(s->vtfd);
}

void session_leave_vt(Session *s) {
        int r;

        assert(s);

        /* This is called whenever we get a VT-switch signal from the kernel.
         * We acknowledge all of them unconditionally. Note that session are
         * free to overwrite those handlers and we only register them for
         * sessions with controllers. Legacy sessions are not affected.
         * However, if we switch from a non-legacy to a legacy session, we must
         * make sure to pause all device before acknowledging the switch. We
         * process the real switch only after we are notified via sysfs, so the
         * legacy session might have already started using the devices. If we
         * don't pause the devices before the switch, we might confuse the
         * session we switch to. */

        if (s->vtfd < 0)
                return;

        session_device_pause_all(s);
        r = vt_release(s->vtfd, /* restore= */ false);
        if (r == -EIO) {
                /* Handle the same VT hung-up case as in session_restore_vt */

                int fd = session_open_vt(s, /* reopen= */ true);
                if (fd >= 0)
                        r = vt_release(fd, /* restore= */ false);
        }
        if (r < 0)
                log_debug_errno(r, "Cannot release VT of session %s: %m", s->id);
}

bool session_is_controller(Session *s, const char *sender) {
        return streq_ptr(ASSERT_PTR(s)->controller, sender);
}

static void session_release_controller(Session *s, bool notify) {
        _unused_ _cleanup_free_ char *name = NULL;
        SessionDevice *sd;

        assert(s);

        if (!s->controller)
                return;

        name = s->controller;

        /* By resetting the controller before releasing the devices, we won't send notification signals.
         * This avoids sending useless notifications if the controller is released on disconnects. */
        if (!notify)
                s->controller = NULL;

        while ((sd = hashmap_first(s->devices)))
                session_device_free(sd);

        s->controller = NULL;
        s->track = sd_bus_track_unref(s->track);
}

static int on_bus_track(sd_bus_track *track, void *userdata) {
        Session *s = ASSERT_PTR(userdata);

        assert(track);

        session_drop_controller(s);

        return 0;
}

int session_set_controller(Session *s, const char *sender, bool force, bool prepare) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(s);
        assert(sender);

        if (session_is_controller(s, sender))
                return 0;
        if (s->controller && !force)
                return -EBUSY;

        name = strdup(sender);
        if (!name)
                return -ENOMEM;

        s->track = sd_bus_track_unref(s->track);
        r = sd_bus_track_new(s->manager->bus, &s->track, on_bus_track, s);
        if (r < 0)
                return r;

        r = sd_bus_track_add_name(s->track, name);
        if (r < 0)
                return r;

        /* When setting a session controller, we forcibly mute the VT and set
         * it into graphics-mode. Applications can override that by changing
         * VT state after calling TakeControl(). However, this serves as a good
         * default and well-behaving controllers can now ignore VTs entirely.
         * Note that we reset the VT on ReleaseControl() and if the controller
         * exits.
         * If logind crashes/restarts, we restore the controller during restart
         * (without preparing the VT since the controller has probably overridden
         * VT state by now) or reset the VT in case it crashed/exited, too. */
        if (prepare) {
                r = session_prepare_vt(s);
                if (r < 0) {
                        s->track = sd_bus_track_unref(s->track);
                        return r;
                }
        }

        session_release_controller(s, true);
        s->controller = TAKE_PTR(name);
        (void) session_save(s);

        return 0;
}

void session_drop_controller(Session *s) {
        assert(s);

        if (!s->controller)
                return;

        s->track = sd_bus_track_unref(s->track);
        session_set_type(s, s->original_type);
        session_release_controller(s, false);
        (void) session_save(s);
        session_restore_vt(s);
}

bool session_job_pending(Session *s) {
        assert(s);
        assert(s->user);

        /* Check if we have some jobs enqueued and not finished yet. Each time we get JobRemoved signal about
         * relevant units, session_send_create_reply and hence us is called (see match_job_removed).
         * Note that we don't care about job result here. */

        return s->scope_job ||
               s->user->runtime_dir_job ||
               (SESSION_CLASS_WANTS_SERVICE_MANAGER(s->class) && s->user->service_manager_job);
}

int session_send_create_reply(Session *s, const sd_bus_error *error) {
        int r;

        assert(s);

        /* If error occurred, return it immediately. Otherwise let's wait for all jobs to finish before
         * continuing. */
        if (!sd_bus_error_is_set(error) && session_job_pending(s))
                return 0;

        r = 0;
        RET_GATHER(r, session_send_create_reply_bus(s, error));
        RET_GATHER(r, session_send_create_reply_varlink(s, error));
        return r;
}

bool session_is_self(const char *name) {
        return isempty(name) || streq(name, "self");
}

bool session_is_auto(const char *name) {
        return streq_ptr(name, "auto");
}

static const char* const session_state_table[_SESSION_STATE_MAX] = {
        [SESSION_OPENING] = "opening",
        [SESSION_ONLINE]  = "online",
        [SESSION_ACTIVE]  = "active",
        [SESSION_CLOSING] = "closing",
};

DEFINE_STRING_TABLE_LOOKUP(session_state, SessionState);

static const char* const session_type_table[_SESSION_TYPE_MAX] = {
        [SESSION_UNSPECIFIED] = "unspecified",
        [SESSION_TTY]         = "tty",
        [SESSION_X11]         = "x11",
        [SESSION_WAYLAND]     = "wayland",
        [SESSION_MIR]         = "mir",
        [SESSION_WEB]         = "web",
};

DEFINE_STRING_TABLE_LOOKUP(session_type, SessionType);

static const char* const session_class_table[_SESSION_CLASS_MAX] = {
        [SESSION_USER]              = "user",
        [SESSION_USER_EARLY]        = "user-early",
        [SESSION_USER_INCOMPLETE]   = "user-incomplete",
        [SESSION_USER_LIGHT]        = "user-light",
        [SESSION_USER_EARLY_LIGHT]  = "user-early-light",
        [SESSION_GREETER]           = "greeter",
        [SESSION_LOCK_SCREEN]       = "lock-screen",
        [SESSION_BACKGROUND]        = "background",
        [SESSION_BACKGROUND_LIGHT]  = "background-light",
        [SESSION_MANAGER]           = "manager",
        [SESSION_MANAGER_EARLY]     = "manager-early",
        [SESSION_NONE]              = "none",
};

DEFINE_STRING_TABLE_LOOKUP(session_class, SessionClass);

static const char* const kill_whom_table[_KILL_WHOM_MAX] = {
        [KILL_LEADER] = "leader",
        [KILL_ALL]    = "all",
};

DEFINE_STRING_TABLE_LOOKUP(kill_whom, KillWhom);

static const char* const tty_validity_table[_TTY_VALIDITY_MAX] = {
        [TTY_FROM_PAM]          = "from-pam",
        [TTY_FROM_UTMP]         = "from-utmp",
        [TTY_UTMP_INCONSISTENT] = "utmp-inconsistent",
};

DEFINE_STRING_TABLE_LOOKUP(tty_validity, TTYValidity);

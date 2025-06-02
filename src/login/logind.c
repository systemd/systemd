/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-device.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "label-util.h"
#include "logind-session.h"
#include "logind.h"
#include "logind-button.h"
#include "logind-dbus.h"
#include "logind-device.h"
#include "logind-seat.h"
#include "logind-session-device.h"
#include "logind-user.h"
#include "logind-utmp.h"
#include "logind-varlink.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "process-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "user-util.h"

static Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(device_hash_ops, char, string_hash_func, string_compare_func, Device, device_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(seat_hash_ops, char, string_hash_func, string_compare_func, Seat, seat_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(session_hash_ops, char, string_hash_func, string_compare_func, Session, session_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(user_hash_ops, void, trivial_hash_func, trivial_compare_func, User, user_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(inhibitor_hash_ops, char, string_hash_func, string_compare_func, Inhibitor, inhibitor_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(button_hash_ops, char, string_hash_func, string_compare_func, Button, button_free);

static int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .console_active_fd = -EBADF,
                .reserve_vt_fd = -EBADF,
                .idle_action_not_before_usec = now(CLOCK_MONOTONIC),
                .scheduled_shutdown_action = _HANDLE_ACTION_INVALID,

                .devices = hashmap_new(&device_hash_ops),
                .seats = hashmap_new(&seat_hash_ops),
                .sessions = hashmap_new(&session_hash_ops),
                .users = hashmap_new(&user_hash_ops),
                .inhibitors = hashmap_new(&inhibitor_hash_ops),
                .buttons = hashmap_new(&button_hash_ops),

                .user_units = hashmap_new(&string_hash_ops),
                .session_units = hashmap_new(&string_hash_ops),
        };

        if (!m->devices || !m->seats || !m->sessions || !m->users || !m->inhibitors || !m->buttons || !m->user_units || !m->session_units)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed allocate memory pressure event source, ignoring: %m");

        (void) sd_event_set_watchdog(m->event, true);

        dual_timestamp_now(&m->init_ts);

        manager_reset_config(m);

        *ret = TAKE_PTR(m);
        return 0;
}

static Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        hashmap_free(m->devices);
        hashmap_free(m->seats);
        hashmap_free(m->sessions);

        /* All records should have been removed by session_free */
        assert(hashmap_isempty(m->sessions_by_leader));
        hashmap_free(m->sessions_by_leader);

        hashmap_free(m->users);
        hashmap_free(m->inhibitors);
        hashmap_free(m->buttons);
        hashmap_free(m->brightness_writers);

        hashmap_free(m->user_units);
        hashmap_free(m->session_units);

        sd_event_source_unref(m->idle_action_event_source);
        sd_event_source_unref(m->inhibit_timeout_source);
        sd_event_source_unref(m->scheduled_shutdown_timeout_source);
        sd_event_source_unref(m->nologin_timeout_source);
        sd_event_source_unref(m->wall_message_timeout_source);

        sd_event_source_unref(m->console_active_event_source);
        sd_event_source_unref(m->lid_switch_ignore_event_source);

        sd_event_source_unref(m->reboot_key_long_press_event_source);

#if ENABLE_UTMP
        sd_event_source_unref(m->utmp_event_source);
#endif

        safe_close(m->console_active_fd);

        sd_device_monitor_unref(m->device_seat_monitor);
        sd_device_monitor_unref(m->device_monitor);
        sd_device_monitor_unref(m->device_vcsa_monitor);
        sd_device_monitor_unref(m->device_button_monitor);
        sd_device_monitor_unref(m->device_uaccess_monitor);

        if (m->unlink_nologin)
                (void) unlink_or_warn("/run/nologin");

        hashmap_free(m->polkit_registry);

        manager_varlink_done(m);

        sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        safe_close(m->reserve_vt_fd);

        strv_free(m->kill_only_users);
        strv_free(m->kill_exclude_users);

        free(m->scheduled_shutdown_tty);
        free(m->wall_message);
        free(m->action_job);

        strv_free(m->efi_boot_loader_entries);
        free(m->efi_loader_entry_one_shot);

        return mfree(m);
}

static int manager_enumerate_devices(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(m);

        /* Loads devices from udev and creates seats for them as
         * necessary */

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_tag(e, "master-of-seat");
        if (r < 0)
                return r;

        r = 0;

        FOREACH_DEVICE(e, d) {
                if (device_is_processed(d) <= 0)
                        continue;
                RET_GATHER(r, manager_process_seat_device(m, d));
        }

        return r;
}

static int manager_enumerate_buttons(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(m);

        /* Loads buttons from udev */

        if (manager_all_buttons_ignored(m))
                return 0;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "input", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_tag(e, "power-switch");
        if (r < 0)
                return r;

        r = 0;

        FOREACH_DEVICE(e, d) {
                if (device_is_processed(d) <= 0)
                        continue;
                RET_GATHER(r, manager_process_button_device(m, d));
        }

        return r;
}

static int manager_enumerate_seats(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        assert(m);

        /* This loads data about seats stored on disk, but does not
         * actually create any seats. Removes data of seats that no
         * longer exist. */

        d = opendir("/run/systemd/seats");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", "/run/systemd/seats/");
        }

        FOREACH_DIRENT(de, d, return -errno) {
                Seat *s;

                if (!dirent_is_file(de))
                        continue;

                s = hashmap_get(m->seats, de->d_name);
                if (!s) {
                        if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                                log_warning_errno(errno, "Failed to remove /run/systemd/seats/%s, ignoring: %m",
                                                  de->d_name);
                        continue;
                }

                RET_GATHER(r, seat_load(s));
        }

        return r;
}

static int manager_enumerate_linger_users(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        assert(m);

        d = opendir("/var/lib/systemd/linger");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", "/var/lib/systemd/linger/");
        }

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *n = NULL;
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = cunescape(de->d_name, 0, &n);
                if (k < 0) {
                        RET_GATHER(r, log_warning_errno(k, "Failed to unescape username '%s', ignoring: %m", de->d_name));
                        continue;
                }

                k = manager_add_user_by_name(m, n, NULL);
                if (k < 0)
                        RET_GATHER(r, log_warning_errno(k, "Couldn't add lingering user %s, ignoring: %m", de->d_name));
        }

        return r;
}

static int manager_enumerate_users(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        /* Add lingering users */
        r = manager_enumerate_linger_users(m);

        /* Read in user data stored on disk */
        d = opendir("/run/systemd/users");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", "/run/systemd/users/");
        }

        FOREACH_DIRENT(de, d, return -errno) {
                User *u;
                uid_t uid;
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = parse_uid(de->d_name, &uid);
                if (k < 0) {
                        RET_GATHER(r, log_warning_errno(k, "Failed to parse filename /run/systemd/users/%s as UID, ignoring: %m", de->d_name));
                        continue;
                }

                k = manager_add_user_by_uid(m, uid, &u);
                if (k < 0) {
                        RET_GATHER(r, log_warning_errno(k, "Failed to add user by filename %s, ignoring: %m", de->d_name));
                        continue;
                }

                user_add_to_gc_queue(u);

                RET_GATHER(r, user_load(u));
        }

        return r;
}

static int parse_fdname(const char *fdname, char **ret_session_id, dev_t *ret_devno) {
        _cleanup_strv_free_ char **parts = NULL;
        _cleanup_free_ char *id = NULL;
        int r;

        assert(ret_session_id);
        assert(ret_devno);

        parts = strv_split(fdname, "-");
        if (!parts)
                return -ENOMEM;

        if (_unlikely_(!streq(parts[0], "session")))
                return -EINVAL;

        id = strdup(parts[1]);
        if (!id)
                return -ENOMEM;

        if (streq(parts[2], "leader")) {
                *ret_session_id = TAKE_PTR(id);
                *ret_devno = 0;

                return 0;
        }

        if (_unlikely_(!streq(parts[2], "device")))
                return -EINVAL;

        unsigned major, minor;

        r = safe_atou(parts[3], &major);
        if (r < 0)
                return r;

        r = safe_atou(parts[4], &minor);
        if (r < 0)
                return r;

        *ret_session_id = TAKE_PTR(id);
        *ret_devno = makedev(major, minor);

        return 0;
}

static int deliver_session_device_fd(Session *s, const char *fdname, int fd, dev_t devno) {
        SessionDevice *sd;
        struct stat st;

        assert(s);
        assert(fdname);
        assert(fd >= 0);
        assert(devno > 0);

        if (fstat(fd, &st) < 0)
                /* The device is allowed to go away at a random point, in which case fstat() failing is
                 * expected. */
                return log_debug_errno(errno, "Failed to stat device fd '%s' for session '%s': %m",
                                       fdname, s->id);

        if (!S_ISCHR(st.st_mode) || st.st_rdev != devno)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODEV),
                                       "Device fd '%s' doesn't point to the expected character device node.",
                                       fdname);

        sd = hashmap_get(s->devices, &devno);
        if (!sd)
                /* Weird, we got an fd for a session device which wasn't recorded in the session state
                 * file... */
                return log_warning_errno(SYNTHETIC_ERRNO(ENODEV),
                                         "Got session device fd '%s' [" DEVNUM_FORMAT_STR "], but not present in session state.",
                                         fdname, DEVNUM_FORMAT_VAL(devno));

        log_debug("Attaching session device fd '%s' [" DEVNUM_FORMAT_STR "] to session '%s'.",
                  fdname, DEVNUM_FORMAT_VAL(devno), s->id);

        session_device_attach_fd(sd, fd, s->was_active);
        return 0;
}

static int deliver_session_leader_fd_consume(Session *s, const char *fdname, int fd) {
        _cleanup_(pidref_done) PidRef leader_fdstore = PIDREF_NULL;
        int r;

        assert(s);
        assert(fdname);
        assert(fd >= 0);

        if (!pid_is_valid(s->deserialized_pid)) {
                r = log_warning_errno(SYNTHETIC_ERRNO(EOWNERDEAD),
                                      "Got leader pidfd for session '%s', but LEADER= is not set, refusing.",
                                      s->id);
                goto fail_close;
        }

        if (!s->leader_fd_saved)
                log_warning("Got leader pidfd for session '%s', but not recorded in session state, proceeding anyway.",
                            s->id);
        else
                assert(!pidref_is_set(&s->leader));

        r = pidref_set_pidfd_take(&leader_fdstore, fd);
        if (r < 0) {
                if (r == -ESRCH)
                        log_debug_errno(r, "Leader of session '%s' is gone while deserializing.", s->id);
                else
                        log_warning_errno(r, "Failed to create reference to leader of session '%s': %m", s->id);
                goto fail_close;
        }

        if (leader_fdstore.pid != s->deserialized_pid)
                log_warning("Leader from pidfd (" PID_FMT ") doesn't match with LEADER=" PID_FMT " for session '%s', proceeding anyway.",
                            leader_fdstore.pid, s->deserialized_pid, s->id);

        r = session_set_leader_consume(s, TAKE_PIDREF(leader_fdstore));
        if (r < 0)
                return log_warning_errno(r, "Failed to attach leader pidfd for session '%s': %m", s->id);

        return 0;

fail_close:
        close_and_notify_warn(fd, fdname);
        return r;
}

static int manager_attach_session_fd_one_consume(Manager *m, const char *fdname, int fd) {
        _cleanup_free_ char *id = NULL;
        dev_t devno = 0; /* Explicit initialization to appease gcc */
        Session *s;
        int r;

        assert(m);
        assert(fdname);
        assert(fd >= 0);

        r = parse_fdname(fdname, &id, &devno);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse stored fd name '%s': %m", fdname);
                goto fail_close;
        }

        s = hashmap_get(m->sessions, id);
        if (!s) {
                /* If the session doesn't exist anymore, let's simply close this fd. */
                r = log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                                    "Cannot attach fd '%s' to unknown session '%s', ignoring.", fdname, id);
                goto fail_close;
        }

        if (devno > 0) {
                r = deliver_session_device_fd(s, fdname, fd, devno);
                if (r < 0)
                        goto fail_close;
                return 0;
        }

        /* Takes ownership of fd on both success and failure */
        return deliver_session_leader_fd_consume(s, fdname, fd);

fail_close:
        close_and_notify_warn(fd, fdname);
        return r;
}

static int manager_enumerate_sessions(Manager *m) {
        _cleanup_strv_free_ char **fdnames = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0, n;

        assert(m);

        /* Read in session data stored on disk */
        d = opendir("/run/systemd/sessions");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", "/run/systemd/sessions/");
        }

        FOREACH_DIRENT(de, d, return -errno) {
                Session *s;
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_session(m, de->d_name, &s);
                if (k < 0) {
                        RET_GATHER(r, log_warning_errno(k, "Failed to add session by filename %s, ignoring: %m", de->d_name));
                        continue;
                }

                session_add_to_gc_queue(s);

                k = session_load(s);
                if (k < 0)
                        RET_GATHER(r, log_warning_errno(k, "Failed to deserialize session '%s', ignoring: %m", s->id));
        }

        n = sd_listen_fds_with_names(/* unset_environment = */ true, &fdnames);
        if (n < 0)
                return log_error_errno(n, "Failed to acquire passed fd list: %m");

        for (int i = 0; i < n; i++) {
                int fd = SD_LISTEN_FDS_START + i;

                RET_GATHER(r, manager_attach_session_fd_one_consume(m, fdnames[i], fd));
        }

        return r;
}

static int manager_enumerate_inhibitors(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        assert(m);

        d = opendir("/run/systemd/inhibit");
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", "/run/systemd/inhibit/");
        }

        FOREACH_DIRENT(de, d, return -errno) {
                Inhibitor *i;
                int k;

                if (!dirent_is_file(de))
                        continue;

                k = manager_add_inhibitor(m, de->d_name, &i);
                if (k < 0) {
                        RET_GATHER(r, log_warning_errno(k, "Couldn't add inhibitor %s, ignoring: %m", de->d_name));
                        continue;
                }

                RET_GATHER(r, inhibitor_load(i));
        }

        return r;
}

static int manager_dispatch_seat_udev(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(device);

        /* If the event is triggered by us, do not try to start the relevant seat again. Otherwise, starting
         * the seat may trigger uevents again again again... */
        r = manager_process_device_triggered_by_seat(m, device);
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to process seat device event triggered by us, ignoring: %m");
        if (r != 0)
                return 0;

        r = manager_process_seat_device(m, device);
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to process seat device, ignoring: %m");

        return 0;
}

static int manager_dispatch_device_udev(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(device);

        /* If the device currently has "master-of-seat" tag, then it has been or will be processed by
         * manager_dispatch_seat_udev(). */
        r = sd_device_has_current_tag(device, "master-of-seat");
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to check if the device currently has master-of-seat tag, ignoring: %m");
        if (r != 0)
                return 0;

        /* If the event is triggered by us, do not try to start the relevant seat again. Otherwise, starting
         * the seat may trigger uevents again again again... */
        r = manager_process_device_triggered_by_seat(m, device);
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to process seat device event triggered by us, ignoring: %m");
        if (r != 0)
                return 0;

        r = manager_process_seat_device(m, device);
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to process seat device, ignoring: %m");

        return 0;
}

static int manager_dispatch_uaccess_udev(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(device);

        /* If the device currently has "master-of-seat" tag, then it has been or will be processed by
         * manager_dispatch_seat_udev(). */
        r = sd_device_has_current_tag(device, "master-of-seat");
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to check if the device currently has master-of-seat tag, ignoring: %m");
        if (r != 0)
                return 0;

        /* If the device is in input, graphics, or drm, then the event has been or will be processed by
         * manager_dispatch_device_udev(). */
        r = device_in_subsystem(device, "input", "graphics", "drm");
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to check device subsystem, ignoring: %m");
        if (r != 0)
                return 0;

        r = manager_process_device_triggered_by_seat(m, device);
        if (r < 0)
                log_device_warning_errno(device, r, "Failed to process seat device event triggered by us, ignoring: %m");

        return 0;
}

static int manager_dispatch_vcsa_udev(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(device);

        /* Whenever a VCSA device is removed try to reallocate our
         * VTs, to make sure our auto VTs never go away. */

        r = device_sysname_startswith(device, "vcsa");
        if (r < 0) {
                log_device_debug_errno(device, r, "Failed to check device sysname, ignoring: %m");
                return 0;
        }
        if (r == 0)
                return 0;

        if (device_for_action(device, SD_DEVICE_REMOVE))
                seat_preallocate_vts(m->seat0);

        return 0;
}

static int manager_dispatch_button_udev(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(device);

        manager_process_button_device(m, device);
        return 0;
}

static int manager_dispatch_console(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(m->seat0);
        assert(m->console_active_fd == fd);

        seat_read_active_vt(m->seat0);
        return 0;
}

static int manager_reserve_vt(Manager *m) {
        _cleanup_free_ char *p = NULL;

        assert(m);

        if (m->reserve_vt <= 0)
                return 0;

        if (asprintf(&p, "/dev/tty%u", m->reserve_vt) < 0)
                return log_oom();

        m->reserve_vt_fd = open(p, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (m->reserve_vt_fd < 0) {

                /* Don't complain on VT-less systems */
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to pin reserved VT: %m");
                return -errno;
        }

        return 0;
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->bus);

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = bus_match_signal_async(m->bus, NULL, bus_systemd_mgr, "JobRemoved", match_job_removed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for JobRemoved: %m");

        r = bus_match_signal_async(m->bus, NULL, bus_systemd_mgr, "UnitRemoved", match_unit_removed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for UnitRemoved: %m");

        r = sd_bus_match_signal_async(
                        m->bus,
                        NULL,
                        "org.freedesktop.systemd1",
                        NULL,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        match_properties_changed, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged: %m");

        r = bus_match_signal_async(m->bus, NULL, bus_systemd_mgr, "Reloading", match_reloading, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for Reloading: %m");

        r = bus_call_method_async(m->bus, NULL, bus_systemd_mgr, "Subscribe", NULL, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to enable subscription: %m");

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.login1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

static int manager_vt_switch(sd_event_source *src, const struct signalfd_siginfo *si, void *data) {
        Manager *m = ASSERT_PTR(data);
        Session *active;

        /*
         * We got a VT-switch signal and we have to acknowledge it immediately.
         * Preferably, we'd just use m->seat0->active->vtfd, but unfortunately,
         * old user-space might run multiple sessions on a single VT, *sigh*.
         * Therefore, we have to iterate all sessions and find one with a vtfd
         * on the requested VT.
         * As only VTs with active controllers have VT_PROCESS set, our current
         * notion of the active VT might be wrong (for instance if the switch
         * happens while we setup VT_PROCESS). Therefore, read the current VT
         * first and then use s->active->vtnr as reference. Note that this is
         * not racy, as no further VT-switch can happen as long as we're in
         * synchronous VT_PROCESS mode.
         */

        assert(m->seat0);

        seat_read_active_vt(m->seat0);

        active = m->seat0->active;
        if (!active || active->vtnr < 1) {
                _cleanup_close_ int fd = -EBADF;
                int r;

                /* We are requested to acknowledge the VT-switch signal by the kernel but
                 * there's no registered sessions for the current VT. Normally this
                 * shouldn't happen but something wrong might have happened when we tried
                 * to release the VT. Better be safe than sorry, and try to release the VT
                 * one more time otherwise the user will be locked with the current VT. */

                log_warning("Received VT_PROCESS signal without a registered session, restoring VT.");

                /* At this point we only have the kernel mapping for referring to the current VT. */
                fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0) {
                        log_warning_errno(fd, "Failed to open current VT, ignoring: %m");
                        return 0;
                }

                r = vt_release(fd, /* restore = */ true);
                if (r < 0)
                        log_warning_errno(r, "Failed to release current VT, ignoring: %m");

                return 0;
        }

        if (active->vtfd >= 0)
                session_leave_vt(active);
        else
                LIST_FOREACH(sessions_by_seat, iter, m->seat0->sessions)
                        if (iter->vtnr == active->vtnr && iter->vtfd >= 0) {
                                session_leave_vt(iter);
                                break;
                        }

        return 0;
}

static int manager_connect_console(Manager *m) {
        int r;

        assert(m);
        assert(m->console_active_fd < 0);

        /* On certain systems (such as S390, Xen, and containers) /dev/tty0 does not exist (as there is no VC), so
         * don't fail if we can't open it. */

        if (access("/dev/tty0", F_OK) < 0)
                return 0;

        m->console_active_fd = open("/sys/class/tty/tty0/active", O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (m->console_active_fd < 0) {

                /* On some systems /dev/tty0 may exist even though /sys/class/tty/tty0 does not. These are broken, but
                 * common. Let's complain but continue anyway. */
                if (errno == ENOENT) {
                        log_warning_errno(errno, "System has /dev/tty0 but not /sys/class/tty/tty0/active which is broken, ignoring: %m");
                        return 0;
                }

                return log_error_errno(errno, "Failed to open %s: %m", "/sys/class/tty/tty0/active");
        }

        r = sd_event_add_io(m->event, &m->console_active_event_source, m->console_active_fd, 0, manager_dispatch_console, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch foreground console: %m");

        /*
         * SIGRTMIN + 0 is used as global VT-release signal, SIGRTMIN + 1 is used
         * as VT-acquire signal. We ignore any acquire-events (yes, we still
         * have to provide a valid signal-number for it!) and acknowledge all
         * release events immediately.
         */

        if (SIGRTMIN + 1 > SIGRTMAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not enough real-time signals available: %i-%i",
                                       SIGRTMIN, SIGRTMAX);

        assert_se(ignore_signals(SIGRTMIN + 1) >= 0);

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN + 0) | SD_EVENT_SIGNAL_PROCMASK, manager_vt_switch, m);
        if (r < 0)
                return log_error_errno(r, "Failed to subscribe to SIGRTMIN+0 signal: %m");

        return 0;
}

static int manager_connect_udev(Manager *m) {
        int r;

        assert(m);
        assert(!m->device_seat_monitor);
        assert(!m->device_monitor);
        assert(!m->device_uaccess_monitor);
        assert(!m->device_vcsa_monitor);
        assert(!m->device_button_monitor);

        r = sd_device_monitor_new(&m->device_seat_monitor);
        if (r < 0)
                return r;

        r = sd_device_monitor_filter_add_match_tag(m->device_seat_monitor, "master-of-seat");
        if (r < 0)
                return r;

        r = sd_device_monitor_attach_event(m->device_seat_monitor, m->event);
        if (r < 0)
                return r;

        r = sd_device_monitor_start(m->device_seat_monitor, manager_dispatch_seat_udev, m);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(m->device_seat_monitor, "seat");

        r = sd_device_monitor_new(&m->device_monitor);
        if (r < 0)
                return r;

        FOREACH_STRING(s, "input", "graphics", "drm") {
                r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_monitor, s, /* devtype = */ NULL);
                if (r < 0)
                        return r;
        }

        r = sd_device_monitor_attach_event(m->device_monitor, m->event);
        if (r < 0)
                return r;

        r = sd_device_monitor_start(m->device_monitor, manager_dispatch_device_udev, m);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(m->device_monitor, "input,graphics,drm");

        r = sd_device_monitor_new(&m->device_uaccess_monitor);
        if (r < 0)
                return r;

        r = sd_device_monitor_filter_add_match_tag(m->device_uaccess_monitor, "uaccess");
        if (r < 0)
                return r;

        r = sd_device_monitor_attach_event(m->device_uaccess_monitor, m->event);
        if (r < 0)
                return r;

        r = sd_device_monitor_start(m->device_uaccess_monitor, manager_dispatch_uaccess_udev, m);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(m->device_uaccess_monitor, "uaccess");

        /* Don't watch keys if nobody cares */
        if (!manager_all_buttons_ignored(m)) {
                r = sd_device_monitor_new(&m->device_button_monitor);
                if (r < 0)
                        return r;

                r = sd_device_monitor_filter_add_match_tag(m->device_button_monitor, "power-switch");
                if (r < 0)
                        return r;

                r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_button_monitor, "input", NULL);
                if (r < 0)
                        return r;

                r = sd_device_monitor_attach_event(m->device_button_monitor, m->event);
                if (r < 0)
                        return r;

                r = sd_device_monitor_start(m->device_button_monitor, manager_dispatch_button_udev, m);
                if (r < 0)
                        return r;

                (void) sd_device_monitor_set_description(m->device_button_monitor, "button");
        }

        /* Don't bother watching VCSA devices, if nobody cares */
        if (m->n_autovts > 0 && m->console_active_fd >= 0) {

                r = sd_device_monitor_new(&m->device_vcsa_monitor);
                if (r < 0)
                        return r;

                r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_vcsa_monitor, "vc", NULL);
                if (r < 0)
                        return r;

                r = sd_device_monitor_attach_event(m->device_vcsa_monitor, m->event);
                if (r < 0)
                        return r;

                r = sd_device_monitor_start(m->device_vcsa_monitor, manager_dispatch_vcsa_udev, m);
                if (r < 0)
                        return r;

                (void) sd_device_monitor_set_description(m->device_vcsa_monitor, "vcsa");
        }

        return 0;
}

static void manager_gc(Manager *m, bool drop_not_started) {
        Seat *seat;
        Session *session;
        User *user;

        assert(m);

        while ((seat = LIST_POP(gc_queue, m->seat_gc_queue))) {
                seat->in_gc_queue = false;

                if (seat_may_gc(seat, drop_not_started)) {
                        seat_stop(seat, /* force = */ false);
                        seat_free(seat);
                }
        }

        while ((session = LIST_POP(gc_queue, m->session_gc_queue))) {
                session->in_gc_queue = false;

                /* First, if we are not closing yet, initiate stopping. */
                if (session_may_gc(session, drop_not_started) &&
                    session_get_state(session) != SESSION_CLOSING)
                        (void) session_stop(session, /* force = */ false);

                /* Normally, this should make the session referenced again, if it doesn't then let's get rid
                 * of it immediately. */
                if (session_may_gc(session, drop_not_started)) {
                        (void) session_finalize(session);
                        session_free(session);
                }
        }

        while ((user = LIST_POP(gc_queue, m->user_gc_queue))) {
                user->in_gc_queue = false;

                /* First step: queue stop jobs */
                if (user_may_gc(user, drop_not_started))
                        (void) user_stop(user, false);

                /* Second step: finalize user */
                if (user_may_gc(user, drop_not_started)) {
                        (void) user_finalize(user);
                        user_free(user);
                }
        }
}

static int manager_dispatch_idle_action(sd_event_source *s, uint64_t t, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        struct dual_timestamp since;
        usec_t n, elapse;
        int r;

        if (m->idle_action == HANDLE_IGNORE ||
            m->idle_action_usec <= 0)
                return 0;

        n = now(CLOCK_MONOTONIC);

        r = manager_get_idle_hint(m, &since);
        if (r <= 0) {
                /* Not idle. Let's check if after a timeout it might be idle then. */
                elapse = n + m->idle_action_usec;
                m->was_idle = false;
        } else {

                /* Idle! Let's see if it's time to do something, or if
                 * we shall sleep for longer. */

                if (n >= since.monotonic + m->idle_action_usec &&
                    (m->idle_action_not_before_usec <= 0 || n >= m->idle_action_not_before_usec + m->idle_action_usec)) {
                        bool is_edge = false;

                        /* We weren't idle previously or some activity happened while we were sleeping, and now we are
                         * idle. Let's remember that for the next time and make this an edge transition. */
                        if (!m->was_idle || since.monotonic >= m->idle_action_not_before_usec) {
                                is_edge = true;
                                m->was_idle = true;
                        }

                        if (m->idle_action == HANDLE_LOCK && !is_edge)
                                /* We are idle and we were before so we are actually not taking any action. */
                                log_debug("System idle.");
                        else
                                log_info("System idle. Will %s now.", handle_action_verb_to_string(m->idle_action));

                        manager_handle_action(m, /* inhibit_key= */ 0, m->idle_action, /* ignore_inhibited= */ false, is_edge, /* action_seat= */ NULL);
                        m->idle_action_not_before_usec = n;
                }

                elapse = MAX(since.monotonic, m->idle_action_not_before_usec) + m->idle_action_usec;
        }

        if (!m->idle_action_event_source) {

                r = sd_event_add_time(
                                m->event,
                                &m->idle_action_event_source,
                                CLOCK_MONOTONIC,
                                elapse, MIN(USEC_PER_SEC*30, m->idle_action_usec), /* accuracy of 30s, but don't have an accuracy lower than the idle action timeout */
                                manager_dispatch_idle_action, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to add idle event source: %m");

                r = sd_event_source_set_priority(m->idle_action_event_source, SD_EVENT_PRIORITY_IDLE+10);
                if (r < 0)
                        return log_error_errno(r, "Failed to set idle event source priority: %m");
        } else {
                r = sd_event_source_set_time(m->idle_action_event_source, elapse);
                if (r < 0)
                        return log_error_errno(r, "Failed to set idle event timer: %m");

                r = sd_event_source_set_enabled(m->idle_action_event_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable idle event timer: %m");
        }

        return 0;
}

static int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = userdata;
        int r;

        (void) notify_reloading();

        manager_reset_config(m);
        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse config file, using defaults: %m");
        else
                log_info("Config file reloaded.");

        (void) sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        return 0;
}

static int manager_startup(Manager *m) {
        int r;
        Seat *seat;
        Session *session;
        User *user;
        Button *button;
        Inhibitor *inhibitor;

        assert(m);

        r = sd_event_add_signal(m->event, /* ret= */ NULL, SIGHUP|SD_EVENT_SIGNAL_PROCMASK, manager_dispatch_reload_signal, m);
        if (r < 0)
                return log_error_errno(r, "Failed to register SIGHUP handler: %m");

        /* Connect to utmp */
        manager_connect_utmp(m);

        /* Connect to console */
        r = manager_connect_console(m);
        if (r < 0)
                return r;

        /* Connect to udev */
        r = manager_connect_udev(m);
        if (r < 0)
                return log_error_errno(r, "Failed to create udev watchers: %m");

        /* Connect to the bus */
        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = manager_varlink_init(m);
        if (r < 0)
                return r;

        /* Instantiate magic seat 0 */
        r = manager_add_seat(m, "seat0", &m->seat0);
        if (r < 0)
                return log_error_errno(r, "Failed to add seat0: %m");

        r = manager_set_lid_switch_ignore(m, 0 + m->holdoff_timeout_usec);
        if (r < 0)
                log_warning_errno(r, "Failed to set up lid switch ignore event source: %m");

        /* Deserialize state */
        r = manager_enumerate_devices(m);
        if (r < 0)
                log_warning_errno(r, "Device enumeration failed: %m");

        r = manager_enumerate_seats(m);
        if (r < 0)
                log_warning_errno(r, "Seat enumeration failed: %m");

        r = manager_enumerate_users(m);
        if (r < 0)
                log_warning_errno(r, "User enumeration failed: %m");

        r = manager_enumerate_sessions(m);
        if (r < 0)
                log_warning_errno(r, "Session enumeration failed: %m");

        r = manager_enumerate_inhibitors(m);
        if (r < 0)
                log_warning_errno(r, "Inhibitor enumeration failed: %m");

        r = manager_enumerate_buttons(m);
        if (r < 0)
                log_warning_errno(r, "Button enumeration failed: %m");

        manager_load_scheduled_shutdown(m);

        /* Remove stale objects before we start them */
        manager_gc(m, false);

        /* Reserve the special reserved VT */
        manager_reserve_vt(m);

        /* Read in utmp if it exists */
        manager_read_utmp(m);

        /* And start everything */
        HASHMAP_FOREACH(seat, m->seats)
                (void) seat_start(seat);

        HASHMAP_FOREACH(user, m->users)
                (void) user_start(user);

        HASHMAP_FOREACH(session, m->sessions)
                (void) session_start(session, NULL, NULL);

        HASHMAP_FOREACH(inhibitor, m->inhibitors) {
                (void) inhibitor_start(inhibitor);

                /* Let's see if the inhibitor is dead now, then remove it */
                if (inhibitor_is_orphan(inhibitor)) {
                        inhibitor_stop(inhibitor);
                        inhibitor_free(inhibitor);
                }
        }

        HASHMAP_FOREACH(button, m->buttons)
                button_check_switches(button);

        manager_dispatch_idle_action(NULL, 0, m);

        return 0;
}

static int manager_run(Manager *m) {
        int r;

        assert(m);

        for (;;) {
                r = sd_event_get_state(m->event);
                if (r < 0)
                        return r;
                if (r == SD_EVENT_FINISHED)
                        return 0;

                manager_gc(m, true);

                r = manager_dispatch_delayed(m, false);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = sd_event_run(m->event, UINT64_MAX);
                if (r < 0)
                        return r;
        }
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message = NULL;
        int r;

        log_set_facility(LOG_AUTH);
        log_setup();

        r = service_parse_argv("systemd-logind.service",
                               "Manager for user logins and devices and privileged operations.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        /* Always create the directories people can create inotify watches in. Note that some applications
         * might check for the existence of /run/systemd/seats/ to determine whether logind is available, so
         * please always make sure these directories are created early on and unconditionally. */
        (void) mkdir_label("/run/systemd/seats", 0755);
        (void) mkdir_label("/run/systemd/users", 0755);
        (void) mkdir_label("/run/systemd/sessions", 0755);

        assert_se(sigprocmask_many(SIG_BLOCK, /* ret_old_mask= */ NULL, SIGCHLD) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        (void) manager_parse_config_file(m);

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to fully start up daemon: %m");

        notify_message = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);
        return manager_run(m);
}

DEFINE_MAIN_FUNCTION(run);

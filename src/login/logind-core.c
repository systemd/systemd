/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/vt.h>
#include <sys/ioctl.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "battery-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "device-util.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "limits-util.h"
#include "logind.h"
#include "logind-button.h"
#include "logind-device.h"
#include "logind-seat.h"
#include "logind-session.h"
#include "logind-user.h"
#include "parse-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "user-util.h"
#include "userdb.h"

void manager_reset_config(Manager *m) {
        assert(m);

        m->n_autovts = 6;
        m->reserve_vt = 6;
        m->remove_ipc = true;
        m->inhibit_delay_max = 5 * USEC_PER_SEC;
        m->user_stop_delay = 10 * USEC_PER_SEC;
        m->wall_messages = true;

        m->handle_action_sleep_mask = HANDLE_ACTION_SLEEP_MASK_DEFAULT;

        m->handle_power_key = HANDLE_POWEROFF;
        m->handle_power_key_long_press = HANDLE_IGNORE;
        m->handle_reboot_key = HANDLE_REBOOT;
        m->handle_reboot_key_long_press = HANDLE_POWEROFF;
        m->handle_suspend_key = HANDLE_SUSPEND;
        m->handle_suspend_key_long_press = HANDLE_HIBERNATE;
        m->handle_hibernate_key = HANDLE_HIBERNATE;
        m->handle_hibernate_key_long_press = HANDLE_IGNORE;
        m->handle_secure_attention_key = HANDLE_SECURE_ATTENTION_KEY;

        m->handle_lid_switch = HANDLE_SUSPEND;
        m->handle_lid_switch_ep = _HANDLE_ACTION_INVALID;
        m->handle_lid_switch_docked = HANDLE_IGNORE;

        m->power_key_ignore_inhibited = false;
        m->suspend_key_ignore_inhibited = false;
        m->hibernate_key_ignore_inhibited = false;
        m->lid_switch_ignore_inhibited = true;
        m->reboot_key_ignore_inhibited = false;

        m->holdoff_timeout_usec = 30 * USEC_PER_SEC;

        m->idle_action_usec = 30 * USEC_PER_MINUTE;
        m->idle_action = HANDLE_IGNORE;

        m->runtime_dir_size = physical_memory_scale(10U, 100U); /* 10% */
        m->runtime_dir_inodes = DIV_ROUND_UP(m->runtime_dir_size, 4096); /* 4k per inode */
        m->sessions_max = 8192;
        m->inhibitors_max = 8192;

        m->kill_user_processes = KILL_USER_PROCESSES;

        m->kill_only_users = strv_free(m->kill_only_users);
        m->kill_exclude_users = strv_free(m->kill_exclude_users);

        m->stop_idle_session_usec = USEC_INFINITY;

        m->maintenance_time = calendar_spec_free(m->maintenance_time);
}

int manager_parse_config_file(Manager *m) {
        assert(m);

        return config_parse_standard_file_with_dropins(
                        "systemd/logind.conf",
                        "Login\0",
                        config_item_perf_lookup, logind_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ m);
}

int manager_add_device(Manager *m, const char *sysfs, bool master, Device **ret_device) {
        Device *d;

        assert(m);
        assert(sysfs);

        d = hashmap_get(m->devices, sysfs);
        if (d)
                /* we support adding master-flags, but not removing them */
                d->master = d->master || master;
        else {
                d = device_new(m, sysfs, master);
                if (!d)
                        return -ENOMEM;
        }

        if (ret_device)
                *ret_device = d;

        return 0;
}

int manager_add_seat(Manager *m, const char *id, Seat **ret_seat) {
        Seat *s;
        int r;

        assert(m);
        assert(id);

        s = hashmap_get(m->seats, id);
        if (!s) {
                r = seat_new(m, id, &s);
                if (r < 0)
                        return r;
        }

        if (ret_seat)
                *ret_seat = s;

        return 0;
}

int manager_add_session(Manager *m, const char *id, Session **ret_session) {
        Session *s;
        int r;

        assert(m);
        assert(id);

        s = hashmap_get(m->sessions, id);
        if (!s) {
                r = session_new(m, id, &s);
                if (r < 0)
                        return r;
        }

        if (ret_session)
                *ret_session = s;

        return 0;
}

int manager_add_user(
                Manager *m,
                UserRecord *ur,
                User **ret_user) {

        User *u;
        int r;

        assert(m);
        assert(ur);

        u = hashmap_get(m->users, UID_TO_PTR(ur->uid));
        if (!u) {
                r = user_new(m, ur, &u);
                if (r < 0)
                        return r;
        }

        if (ret_user)
                *ret_user = u;

        return 0;
}

int manager_add_user_by_name(
                Manager *m,
                const char *name,
                User **ret_user) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int r;

        assert(m);
        assert(name);

        r = userdb_by_name(name, /* match= */ NULL, USERDB_SUPPRESS_SHADOW, &ur);
        if (r < 0)
                return r;

        if (!uid_is_valid(ur->uid)) /* Refuse users without UID */
                return -ESRCH;

        return manager_add_user(m, ur, ret_user);
}

int manager_add_user_by_uid(
                Manager *m,
                uid_t uid,
                User **ret_user) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int r;

        assert(m);
        assert(uid_is_valid(uid));

        r = userdb_by_uid(uid, /* match= */ NULL, USERDB_SUPPRESS_SHADOW, &ur);
        if (r < 0)
                return r;

        return manager_add_user(m, ur, ret_user);
}

int manager_add_inhibitor(Manager *m, const char* id, Inhibitor **ret) {
        Inhibitor *i;
        int r;

        assert(m);
        assert(id);

        i = hashmap_get(m->inhibitors, id);
        if (!i) {
                r = inhibitor_new(m, id, &i);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = i;

        return 0;
}

int manager_add_button(Manager *m, const char *name, Button **ret_button) {
        Button *b;

        assert(m);
        assert(name);

        b = hashmap_get(m->buttons, name);
        if (!b) {
                b = button_new(m, name);
                if (!b)
                        return -ENOMEM;
        }

        if (ret_button)
                *ret_button = b;

        return 0;
}

int manager_process_seat_device(Manager *m, sd_device *d) {
        Device *device;
        int r;

        assert(m);

        if (device_for_action(d, SD_DEVICE_REMOVE) ||
            sd_device_has_current_tag(d, "seat") <= 0) {
                const char *syspath;

                r = sd_device_get_syspath(d, &syspath);
                if (r < 0)
                        return 0;

                device = hashmap_get(m->devices, syspath);
                if (!device)
                        return 0;

                seat_add_to_gc_queue(device->seat);
                device_free(device);

        } else {
                const char *sn, *syspath;
                bool master;
                Seat *seat;

                r = device_get_seat(d, &sn);
                if (r < 0)
                        return r;

                if (!seat_name_is_valid(sn)) {
                        log_device_warning(d, "Device with invalid seat name %s found, ignoring.", sn);
                        return 0;
                }

                seat = hashmap_get(m->seats, sn);
                master = sd_device_has_current_tag(d, "master-of-seat") > 0;

                /* Ignore non-master devices for unknown seats */
                if (!master && !seat)
                        return 0;

                r = sd_device_get_syspath(d, &syspath);
                if (r < 0)
                        return r;

                r = manager_add_device(m, syspath, master, &device);
                if (r < 0)
                        return r;

                if (!seat) {
                        r = manager_add_seat(m, sn, &seat);
                        if (r < 0) {
                                if (!device->seat)
                                        device_free(device);

                                return r;
                        }
                }

                device_attach(device, seat);
                seat_start(seat);
        }

        return 0;
}

int manager_process_button_device(Manager *m, sd_device *d) {
        const char *sysname;
        Button *b;
        int r;

        assert(m);

        r = sd_device_get_sysname(d, &sysname);
        if (r < 0)
                return r;

        if (device_for_action(d, SD_DEVICE_REMOVE) ||
            sd_device_has_current_tag(d, "power-switch") <= 0)

                button_free(hashmap_get(m->buttons, sysname));

        else {
                const char *sn;

                r = manager_add_button(m, sysname, &b);
                if (r < 0)
                        return r;

                r = device_get_seat(d, &sn);
                if (r < 0)
                        return r;

                button_set_seat(b, sn);

                r = button_open(b);
                if (r < 0) /* event device doesn't have any keys or switches relevant to us? (or any other error
                            * opening the device?) let's close the button again. */
                        button_free(b);
        }

        return 0;
}

int manager_get_session_by_pidref(Manager *m, const PidRef *pid, Session **ret) {
        _cleanup_free_ char *unit = NULL;
        Session *s = NULL;
        int r;

        assert(m);

        if (!pidref_is_set(pid))
                return -EINVAL;

        r = manager_get_session_by_leader(m, pid, ret);
        if (r != 0)
                return r;

        r = cg_pidref_get_unit(pid, &unit);
        if (r >= 0)
                s = hashmap_get(m->session_units, unit);

        if (ret)
                *ret = s;

        return !!s;
}

int manager_get_session_by_leader(Manager *m, const PidRef *pid, Session **ret) {
        Session *s;
        int r;

        assert(m);

        if (!pidref_is_set(pid))
                return -EINVAL;

        s = hashmap_get(m->sessions_by_leader, pid);
        if (s) {
                r = pidref_verify(pid);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = s;

        return !!s;
}

int manager_get_user_by_pid(Manager *m, pid_t pid, User **ret) {
        _cleanup_free_ char *unit = NULL;
        User *u = NULL;
        int r;

        assert(m);

        if (!pid_is_valid(pid))
                return -EINVAL;

        r = cg_pid_get_slice(pid, &unit);
        if (r >= 0)
                u = hashmap_get(m->user_units, unit);

        if (ret)
                *ret = u;

        return !!u;
}

int manager_get_idle_hint(Manager *m, dual_timestamp *t) {
        Session *s;
        bool idle_hint;
        dual_timestamp ts;

        assert(m);

        /* Initialize the baseline timestamp with the time the manager got initialized to avoid reporting
         * unreasonable large idle periods starting with the Unix epoch. */
        ts = m->init_ts;

        idle_hint = !manager_is_inhibited(m, INHIBIT_IDLE, t, /* flags= */ 0, UID_INVALID, NULL);

        HASHMAP_FOREACH(s, m->sessions) {
                dual_timestamp k;
                int ih;

                if (!SESSION_CLASS_CAN_IDLE(s->class))
                        continue;

                ih = session_get_idle_hint(s, &k);
                if (ih < 0)
                        return ih;

                if (!ih) {
                        if (!idle_hint) {
                                if (k.monotonic < ts.monotonic)
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

bool manager_shall_kill(Manager *m, const char *user) {
        assert(m);
        assert(user);

        if (!m->kill_exclude_users && streq(user, "root"))
                return false;

        if (strv_contains(m->kill_exclude_users, user))
                return false;

        if (!strv_isempty(m->kill_only_users))
                return strv_contains(m->kill_only_users, user);

        return m->kill_user_processes;
}

int config_parse_n_autovts(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned *n = ASSERT_PTR(data);
        unsigned o;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = safe_atou(rvalue, &o);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse number of autovts, ignoring: %s", rvalue);
                return 0;
        }

        if (o > 15) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "A maximum of 15 autovts are supported, ignoring: %s", rvalue);
                return 0;
        }

        *n = o;
        return 0;
}

static int vt_is_busy(unsigned vtnr) {
        struct vt_stat vt_stat;
        int r;
        _cleanup_close_ int fd = -EBADF;

        assert(vtnr >= 1);

        /* VT_GETSTATE "cannot return state for more than 16 VTs, since v_state is short" */
        assert(vtnr <= 15);

        /* We explicitly open /dev/tty1 here instead of /dev/tty0. If
         * we'd open the latter we'd open the foreground tty which
         * hence would be unconditionally busy. By opening /dev/tty1
         * we avoid this. Since tty1 is special and needs to be an
         * explicitly loaded getty or DM this is safe. */

        fd = open_terminal("/dev/tty1", O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ioctl(fd, VT_GETSTATE, &vt_stat) < 0)
                r = -errno;
        else
                r = !!(vt_stat.v_state & (1 << vtnr));

        return r;
}

int manager_spawn_autovt(Manager *m, unsigned vtnr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char name[sizeof("autovt@tty.service") + DECIMAL_STR_MAX(unsigned)];
        int r;

        assert(m);
        assert(vtnr >= 1);

        if (vtnr > m->n_autovts &&
            vtnr != m->reserve_vt)
                return 0;

        if (vtnr != m->reserve_vt) {
                /* If this is the reserved TTY, we'll start the getty
                 * on it in any case, but otherwise only if it is not
                 * busy. */

                r = vt_is_busy(vtnr);
                if (r < 0)
                        return r;
                else if (r > 0)
                        return -EBUSY;
        }

        xsprintf(name, "autovt@tty%u.service", vtnr);
        r = bus_call_method(m->bus, bus_systemd_mgr, "StartUnit", &error, NULL, "ss", name, "fail");
        if (r < 0)
                return log_error_errno(r, "Failed to start %s: %s", name, bus_error_message(&error, r));

        return 0;
}

bool manager_is_lid_closed(Manager *m) {
        Button *b;

        HASHMAP_FOREACH(b, m->buttons)
                if (b->lid_closed)
                        return true;

        return false;
}

static bool manager_is_docked(Manager *m) {
        Button *b;

        HASHMAP_FOREACH(b, m->buttons)
                if (b->docked)
                        return true;

        return false;
}

static int manager_count_external_displays(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r, n = 0;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "drm", true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                sd_device *p;

                if (sd_device_get_parent(d, &p) < 0)
                        continue;

                /* If the parent shares the same subsystem as the
                 * device we are looking at then it is a connector,
                 * which is what we are interested in. */
                r = device_in_subsystem(p, "drm");
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                const char *nn;
                r = sd_device_get_sysname(d, &nn);
                if (r < 0)
                        return r;

                /* Ignore internal displays: the type is encoded in the sysfs name, as the second dash
                 * separated item (the first is the card name, the last the connector number). We implement a
                 * deny list of external displays here, rather than an allow list of internal ones, to ensure
                 * we don't block suspends too eagerly. */
                const char *dash = strchr(nn, '-');
                if (!dash)
                        continue;

                dash++;
                if (!STARTSWITH_SET(dash,
                                    "VGA-", "DVI-I-", "DVI-D-", "DVI-A-"
                                    "Composite-", "SVIDEO-", "Component-",
                                    "DIN-", "DP-", "HDMI-A-", "HDMI-B-", "TV-"))
                        continue;

                /* Ignore ports that are not enabled */
                const char *enabled;
                r = sd_device_get_sysattr_value(d, "enabled", &enabled);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (!streq(enabled, "enabled"))
                        continue;

                /* We count any connector which is not explicitly "disconnected" as connected. */
                const char *status = NULL;
                r = sd_device_get_sysattr_value(d, "status", &status);
                if (r < 0 && r != -ENOENT)
                        return r;
                if (!streq_ptr(status, "disconnected"))
                        n++;
        }

        return n;
}

bool manager_is_docked_or_external_displays(Manager *m) {
        int n;

        /* If we are docked don't react to lid closing */
        if (manager_is_docked(m)) {
                log_debug("System is docked.");
                return true;
        }

        /* If we have more than one display connected,
         * assume that we are docked. */
        n = manager_count_external_displays(m);
        if (n < 0)
                log_warning_errno(n, "Display counting failed: %m");
        else if (n >= 1) {
                log_debug("External (%i) displays connected.", n);
                return true;
        }

        return false;
}

bool manager_is_on_external_power(void) {
        int r;

        /* For now we only check for AC power, but 'external power' can apply to anything that isn't an internal
         * battery */
        r = on_ac_power();
        if (r < 0)
                log_warning_errno(r, "Failed to read AC power status: %m");

        return r != 0; /* Treat failure as 'on AC' */
}

bool manager_all_buttons_ignored(Manager *m) {
        assert(m);

        if (m->handle_power_key != HANDLE_IGNORE)
                return false;
        if (m->handle_power_key_long_press != HANDLE_IGNORE)
                return false;
        if (m->handle_suspend_key != HANDLE_IGNORE)
                return false;
        if (m->handle_suspend_key_long_press != HANDLE_IGNORE)
                return false;
        if (m->handle_hibernate_key != HANDLE_IGNORE)
                return false;
        if (m->handle_hibernate_key_long_press != HANDLE_IGNORE)
                return false;
        if (m->handle_reboot_key != HANDLE_IGNORE)
                return false;
        if (m->handle_reboot_key_long_press != HANDLE_IGNORE)
                return false;
        if (m->handle_lid_switch != HANDLE_IGNORE)
                return false;
        if (!IN_SET(m->handle_lid_switch_ep, _HANDLE_ACTION_INVALID, HANDLE_IGNORE))
                return false;
        if (m->handle_lid_switch_docked != HANDLE_IGNORE)
                return false;
        if (m->handle_secure_attention_key != HANDLE_IGNORE)
                return false;

        return true;
}


int manager_read_efi_boot_loader_entries(Manager *m) {
#if ENABLE_EFI
        int r;

        assert(m);
        if (m->efi_boot_loader_entries_set)
                return 0;

        r = efi_loader_get_entries(&m->efi_boot_loader_entries);
        if (r < 0) {
                if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r)) {
                        log_debug_errno(r, "Boot loader reported no entries.");
                        m->efi_boot_loader_entries_set = true;
                        return 0;
                }
                return log_error_errno(r, "Failed to determine entries reported by boot loader: %m");
        }

        m->efi_boot_loader_entries_set = true;
        return 1;
#else
        return 0;
#endif
}

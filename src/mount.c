/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <stdio.h>
#include <mntent.h>
#include <sys/epoll.h>
#include <signal.h>

#include "unit.h"
#include "mount.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"
#include "strv.h"
#include "mount-setup.h"
#include "unit-name.h"
#include "mount.h"
#include "dbus-mount.h"

static const UnitActiveState state_translation_table[_MOUNT_STATE_MAX] = {
        [MOUNT_DEAD] = UNIT_INACTIVE,
        [MOUNT_MOUNTING] = UNIT_ACTIVATING,
        [MOUNT_MOUNTING_DONE] = UNIT_ACTIVE,
        [MOUNT_MOUNTED] = UNIT_ACTIVE,
        [MOUNT_REMOUNTING] = UNIT_ACTIVE_RELOADING,
        [MOUNT_UNMOUNTING] = UNIT_DEACTIVATING,
        [MOUNT_MOUNTING_SIGTERM] = UNIT_DEACTIVATING,
        [MOUNT_MOUNTING_SIGKILL] = UNIT_DEACTIVATING,
        [MOUNT_REMOUNTING_SIGTERM] = UNIT_ACTIVE_RELOADING,
        [MOUNT_REMOUNTING_SIGKILL] = UNIT_ACTIVE_RELOADING,
        [MOUNT_UNMOUNTING_SIGTERM] = UNIT_DEACTIVATING,
        [MOUNT_UNMOUNTING_SIGKILL] = UNIT_DEACTIVATING,
        [MOUNT_MAINTAINANCE] = UNIT_INACTIVE,
};

static void mount_init(Unit *u) {
        Mount *m = MOUNT(u);

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        m->timeout_usec = DEFAULT_TIMEOUT_USEC;
        exec_context_init(&m->exec_context);

        /* We need to make sure that /bin/mount is always called in
         * the same process group as us, so that the autofs kernel
         * side doesn't send us another mount request while we are
         * already trying to comply its last one. */
        m->exec_context.no_setsid = true;

        m->timer_watch.type = WATCH_INVALID;

        m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
}

static void mount_unwatch_control_pid(Mount *m) {
        assert(m);

        if (m->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(m), m->control_pid);
        m->control_pid = 0;
}

static void mount_parameters_done(MountParameters *p) {
        assert(p);

        free(p->what);
        free(p->options);
        free(p->fstype);

        p->what = p->options = p->fstype = NULL;
}

static void mount_done(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        free(m->where);
        m->where = NULL;

        mount_parameters_done(&m->parameters_etc_fstab);
        mount_parameters_done(&m->parameters_proc_self_mountinfo);
        mount_parameters_done(&m->parameters_fragment);

        exec_context_done(&m->exec_context);
        exec_command_done_array(m->exec_command, _MOUNT_EXEC_COMMAND_MAX);
        m->control_command = NULL;

        mount_unwatch_control_pid(m);

        unit_unwatch_timer(u, &m->timer_watch);
}

static int mount_add_mount_links(Mount *m) {
        Meta *other;
        int r;

        assert(m);

        /* Adds in links to other mount points that might lie below or
         * above us in the hierarchy */

        LIST_FOREACH(units_per_type, other, m->meta.manager->units_per_type[UNIT_MOUNT]) {
                Mount *n = (Mount*) other;

                if (n == m)
                        continue;

                if (n->meta.load_state != UNIT_LOADED)
                        continue;

                if (path_startswith(m->where, n->where)) {

                        if ((r = unit_add_dependency(UNIT(m), UNIT_AFTER, UNIT(n), true)) < 0)
                                return r;

                        if (n->from_etc_fstab || n->from_fragment)
                                if ((r = unit_add_dependency(UNIT(m), UNIT_REQUIRES, UNIT(n), true)) < 0)
                                        return r;

                } else if (path_startswith(n->where, m->where)) {

                        if ((r = unit_add_dependency(UNIT(m), UNIT_BEFORE, UNIT(n), true)) < 0)
                                return r;

                        if (m->from_etc_fstab || m->from_fragment)
                                if ((r = unit_add_dependency(UNIT(n), UNIT_REQUIRES, UNIT(m), true)) < 0)
                                        return r;
                }
        }

        return 0;
}

static int mount_add_swap_links(Mount *m) {
        Meta *other;
        int r;

        assert(m);

        LIST_FOREACH(units_per_type, other, m->meta.manager->units_per_type[UNIT_SWAP])
                if ((r = swap_add_one_mount_link((Swap*) other, m)) < 0)
                        return r;

        return 0;
}

static int mount_add_path_links(Mount *m) {
        Meta *other;
        int r;

        assert(m);

        LIST_FOREACH(units_per_type, other, m->meta.manager->units_per_type[UNIT_PATH])
                if ((r = path_add_one_mount_link((Path*) other, m)) < 0)
                        return r;

        return 0;
}

static int mount_add_automount_links(Mount *m) {
        Meta *other;
        int r;

        assert(m);

        LIST_FOREACH(units_per_type, other, m->meta.manager->units_per_type[UNIT_AUTOMOUNT])
                if ((r = automount_add_one_mount_link((Automount*) other, m)) < 0)
                        return r;

        return 0;
}

static int mount_add_socket_links(Mount *m) {
        Meta *other;
        int r;

        assert(m);

        LIST_FOREACH(units_per_type, other, m->meta.manager->units_per_type[UNIT_SOCKET])
                if ((r = socket_add_one_mount_link((Socket*) other, m)) < 0)
                        return r;

        return 0;
}

static char* mount_test_option(const char *haystack, const char *needle) {
        struct mntent me;

        assert(needle);

        /* Like glibc's hasmntopt(), but works on a string, not a
         * struct mntent */

        if (!haystack)
                return false;

        zero(me);
        me.mnt_opts = (char*) haystack;

        return hasmntopt(&me, needle);
}

static int mount_add_target_links(Mount *m) {
        const char *target;
        MountParameters *p;
        Unit *tu;
        int r;
        bool noauto, handle, automount, user;

        assert(m);

        if (m->from_fragment)
                p = &m->parameters_fragment;
        else if (m->from_etc_fstab)
                p = &m->parameters_etc_fstab;
        else
                return 0;

        noauto = !!mount_test_option(p->options, MNTOPT_NOAUTO);
        user = mount_test_option(p->options, "user") || mount_test_option(p->options, "users");
        handle = !!mount_test_option(p->options, "comment=systemd.mount");
        automount = !!mount_test_option(p->options, "comment=systemd.automount");

        if (mount_test_option(p->options, "_netdev") ||
            fstype_is_network(p->fstype))
                target = SPECIAL_REMOTE_FS_TARGET;
        else
                target = SPECIAL_LOCAL_FS_TARGET;

        if ((r = manager_load_unit(UNIT(m)->meta.manager, target, NULL, &tu)) < 0)
                return r;

        if (automount && m->meta.manager->running_as != MANAGER_SESSION) {
                Unit *am;

                if ((r = unit_load_related_unit(UNIT(m), ".automount", &am)) < 0)
                        return r;

                if ((r = unit_add_dependency(tu, UNIT_WANTS, UNIT(am), true)) < 0)
                        return r;

                return unit_add_dependency(UNIT(am), UNIT_BEFORE, tu, true);

        } else {

                if (!noauto && handle)
                        if (user || m->meta.manager->running_as != MANAGER_SESSION)
                                if ((r = unit_add_dependency(tu, UNIT_WANTS, UNIT(m), true)) < 0)
                                        return r;

                return unit_add_dependency(UNIT(m), UNIT_BEFORE, tu, true);
        }
}

static int mount_verify(Mount *m) {
        bool b;
        char *e;
        assert(m);

        if (m->meta.load_state != UNIT_LOADED)
                return 0;

        if (!m->from_etc_fstab && !m->from_fragment && !m->from_proc_self_mountinfo)
                return -ENOENT;

        if (!(e = unit_name_from_path(m->where, ".mount")))
                return -ENOMEM;

        b = unit_has_name(UNIT(m), e);
        free(e);

        if (!b) {
                log_error("%s's Where setting doesn't match unit name. Refusing.", UNIT(m)->meta.id);
                return -EINVAL;
        }

        if (m->meta.fragment_path && !m->parameters_fragment.what) {
                log_error("%s's What setting is missing. Refusing.", UNIT(m)->meta.id);
                return -EBADMSG;
        }

        return 0;
}

static int mount_load(Unit *u) {
        Mount *m = MOUNT(u);
        int r;

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        if ((r = unit_load_fragment_and_dropin_optional(u)) < 0)
                return r;

        /* This is a new unit? Then let's add in some extras */
        if (u->meta.load_state == UNIT_LOADED) {
                const char *what = NULL;

                if (m->meta.fragment_path)
                        m->from_fragment = true;

                if (!m->where)
                        if (!(m->where = unit_name_to_path(u->meta.id)))
                                return -ENOMEM;

                path_kill_slashes(m->where);

                if (!m->meta.description)
                        if ((r = unit_set_description(u, m->where)) < 0)
                                return r;

                if (m->from_fragment && m->parameters_fragment.what)
                        what = m->parameters_fragment.what;
                else if (m->from_etc_fstab && m->parameters_etc_fstab.what)
                        what = m->parameters_etc_fstab.what;
                else if (m->from_proc_self_mountinfo && m->parameters_proc_self_mountinfo.what)
                        what = m->parameters_proc_self_mountinfo.what;

                if (what)
                        if ((r = unit_add_node_link(u, what,
                                                    (u->meta.manager->running_as == MANAGER_INIT ||
                                                     u->meta.manager->running_as == MANAGER_SYSTEM))) < 0)
                                return r;

                if ((r = mount_add_mount_links(m)) < 0)
                        return r;

                if ((r = mount_add_socket_links(m)) < 0)
                        return r;

                if ((r = mount_add_swap_links(m)) < 0)
                        return r;

                if ((r = mount_add_path_links(m)) < 0)
                        return r;

                if ((r = mount_add_automount_links(m)) < 0)
                        return r;

                if ((r = mount_add_target_links(m)) < 0)
                        return r;

                if ((r = unit_add_default_cgroup(u)) < 0)
                        return r;
        }

        return mount_verify(m);
}

static int mount_notify_automount(Mount *m, int status) {
        Unit *p;
        int r;

        assert(m);

        if ((r = unit_get_related_unit(UNIT(m), ".automount", &p)) < 0)
                return r == -ENOENT ? 0 : r;

        return automount_send_ready(AUTOMOUNT(p), status);
}

static void mount_set_state(Mount *m, MountState state) {
        MountState old_state;
        assert(m);

        old_state = m->state;
        m->state = state;

        if (state != MOUNT_MOUNTING &&
            state != MOUNT_MOUNTING_DONE &&
            state != MOUNT_REMOUNTING &&
            state != MOUNT_UNMOUNTING &&
            state != MOUNT_MOUNTING_SIGTERM &&
            state != MOUNT_MOUNTING_SIGKILL &&
            state != MOUNT_UNMOUNTING_SIGTERM &&
            state != MOUNT_UNMOUNTING_SIGKILL &&
            state != MOUNT_REMOUNTING_SIGTERM &&
            state != MOUNT_REMOUNTING_SIGKILL) {
                unit_unwatch_timer(UNIT(m), &m->timer_watch);
                mount_unwatch_control_pid(m);
                m->control_command = NULL;
                m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
        }

        if (state == MOUNT_MOUNTED ||
            state == MOUNT_REMOUNTING)
                mount_notify_automount(m, 0);
        else if (state == MOUNT_DEAD ||
                 state == MOUNT_UNMOUNTING ||
                 state == MOUNT_MOUNTING_SIGTERM ||
                 state == MOUNT_MOUNTING_SIGKILL ||
                 state == MOUNT_REMOUNTING_SIGTERM ||
                 state == MOUNT_REMOUNTING_SIGKILL ||
                 state == MOUNT_UNMOUNTING_SIGTERM ||
                 state == MOUNT_UNMOUNTING_SIGKILL ||
                 state == MOUNT_MAINTAINANCE)
                mount_notify_automount(m, -ENODEV);

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(m)->meta.id,
                          mount_state_to_string(old_state),
                          mount_state_to_string(state));

        unit_notify(UNIT(m), state_translation_table[old_state], state_translation_table[state]);
}

static int mount_coldplug(Unit *u) {
        Mount *m = MOUNT(u);
        MountState new_state = MOUNT_DEAD;
        int r;

        assert(m);
        assert(m->state == MOUNT_DEAD);

        if (m->deserialized_state != m->state)
                new_state = m->deserialized_state;
        else if (m->from_proc_self_mountinfo)
                new_state = MOUNT_MOUNTED;

        if (new_state != m->state) {

                if (new_state == MOUNT_MOUNTING ||
                    new_state == MOUNT_MOUNTING_DONE ||
                    new_state == MOUNT_REMOUNTING ||
                    new_state == MOUNT_UNMOUNTING ||
                    new_state == MOUNT_MOUNTING_SIGTERM ||
                    new_state == MOUNT_MOUNTING_SIGKILL ||
                    new_state == MOUNT_UNMOUNTING_SIGTERM ||
                    new_state == MOUNT_UNMOUNTING_SIGKILL ||
                    new_state == MOUNT_REMOUNTING_SIGTERM ||
                    new_state == MOUNT_REMOUNTING_SIGKILL) {

                        if (m->control_pid <= 0)
                                return -EBADMSG;

                        if ((r = unit_watch_pid(UNIT(m), m->control_pid)) < 0)
                                return r;

                        if ((r = unit_watch_timer(UNIT(m), m->timeout_usec, &m->timer_watch)) < 0)
                                return r;
                }

                mount_set_state(m, new_state);
        }

        return 0;
}

static void mount_dump(Unit *u, FILE *f, const char *prefix) {
        Mount *m = MOUNT(u);
        MountParameters *p;

        assert(m);
        assert(f);

        if (m->from_proc_self_mountinfo)
                p = &m->parameters_proc_self_mountinfo;
        else if (m->from_fragment)
                p = &m->parameters_fragment;
        else
                p = &m->parameters_etc_fstab;

        fprintf(f,
                "%sMount State: %s\n"
                "%sWhere: %s\n"
                "%sWhat: %s\n"
                "%sFile System Type: %s\n"
                "%sOptions: %s\n"
                "%sFrom /etc/fstab: %s\n"
                "%sFrom /proc/self/mountinfo: %s\n"
                "%sFrom fragment: %s\n"
                "%sKillMode: %s\n",
                prefix, mount_state_to_string(m->state),
                prefix, m->where,
                prefix, strna(p->what),
                prefix, strna(p->fstype),
                prefix, strna(p->options),
                prefix, yes_no(m->from_etc_fstab),
                prefix, yes_no(m->from_proc_self_mountinfo),
                prefix, yes_no(m->from_fragment),
                prefix, kill_mode_to_string(m->kill_mode));

        if (m->control_pid > 0)
                fprintf(f,
                        "%sControl PID: %llu\n",
                        prefix, (unsigned long long) m->control_pid);

        exec_context_dump(&m->exec_context, f, prefix);
}

static int mount_spawn(Mount *m, ExecCommand *c, pid_t *_pid) {
        pid_t pid;
        int r;

        assert(m);
        assert(c);
        assert(_pid);

        if ((r = unit_watch_timer(UNIT(m), m->timeout_usec, &m->timer_watch)) < 0)
                goto fail;

        if ((r = exec_spawn(c,
                            NULL,
                            &m->exec_context,
                            NULL, 0,
                            m->meta.manager->environment,
                            true,
                            true,
                            UNIT(m)->meta.manager->confirm_spawn,
                            UNIT(m)->meta.cgroup_bondings,
                            &pid)) < 0)
                goto fail;

        if ((r = unit_watch_pid(UNIT(m), pid)) < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        unit_unwatch_timer(UNIT(m), &m->timer_watch);

        return r;
}

static void mount_enter_dead(Mount *m, bool success) {
        assert(m);

        if (!success)
                m->failure = true;

        mount_set_state(m, m->failure ? MOUNT_MAINTAINANCE : MOUNT_DEAD);
}

static void mount_enter_mounted(Mount *m, bool success) {
        assert(m);

        if (!success)
                m->failure = true;

        mount_set_state(m, MOUNT_MOUNTED);
}

static void mount_enter_signal(Mount *m, MountState state, bool success) {
        int r;
        bool sent = false;

        assert(m);

        if (!success)
                m->failure = true;

        if (m->kill_mode != KILL_NONE) {
                int sig = (state == MOUNT_MOUNTING_SIGTERM ||
                           state == MOUNT_UNMOUNTING_SIGTERM ||
                           state == MOUNT_REMOUNTING_SIGTERM) ? SIGTERM : SIGKILL;

                if (m->kill_mode == KILL_CONTROL_GROUP) {

                        if ((r = cgroup_bonding_kill_list(UNIT(m)->meta.cgroup_bondings, sig)) < 0) {
                                if (r != -EAGAIN && r != -ESRCH)
                                        goto fail;
                        } else
                                sent = true;
                }

                if (!sent && m->control_pid > 0)
                        if (kill(m->kill_mode == KILL_PROCESS ? m->control_pid : -m->control_pid, sig) < 0 && errno != ESRCH) {
                                r = -errno;
                                goto fail;
                        }
        }

        if (sent) {
                if ((r = unit_watch_timer(UNIT(m), m->timeout_usec, &m->timer_watch)) < 0)
                        goto fail;

                mount_set_state(m, state);
        } else if (state == MOUNT_REMOUNTING_SIGTERM || state == MOUNT_REMOUNTING_SIGKILL)
                mount_enter_mounted(m, true);
        else
                mount_enter_dead(m, true);

        return;

fail:
        log_warning("%s failed to kill processes: %s", UNIT(m)->meta.id, strerror(-r));

        if (state == MOUNT_REMOUNTING_SIGTERM || state == MOUNT_REMOUNTING_SIGKILL)
                mount_enter_mounted(m, false);
        else
                mount_enter_dead(m, false);
}

static void mount_enter_unmounting(Mount *m, bool success) {
        int r;

        assert(m);

        if (!success)
                m->failure = true;

        m->control_command_id = MOUNT_EXEC_UNMOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_UNMOUNT;

        if ((r = exec_command_set(
                             m->control_command,
                             "/bin/umount",
                             m->where,
                             NULL)) < 0)
                goto fail;

        mount_unwatch_control_pid(m);

        if ((r = mount_spawn(m, m->control_command, &m->control_pid)) < 0)
                goto fail;

        mount_set_state(m, MOUNT_UNMOUNTING);

        return;

fail:
        log_warning("%s failed to run umount exectuable: %s", UNIT(m)->meta.id, strerror(-r));
        mount_enter_mounted(m, false);
}

static void mount_enter_mounting(Mount *m) {
        int r;

        assert(m);

        m->control_command_id = MOUNT_EXEC_MOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_MOUNT;

        if (m->from_fragment)
                r = exec_command_set(
                                m->control_command,
                                "/bin/mount",
                                m->parameters_fragment.what,
                                m->where,
                                "-t", m->parameters_fragment.fstype,
                                m->parameters_fragment.options ? "-o" : NULL, m->parameters_fragment.options,
                                NULL);
        else if (m->from_etc_fstab)
                r = exec_command_set(
                                m->control_command,
                                "/bin/mount",
                                m->where,
                                NULL);
        else
                r = -ENOENT;

        if (r < 0)
                goto fail;

        mount_unwatch_control_pid(m);

        if ((r = mount_spawn(m, m->control_command, &m->control_pid)) < 0)
                goto fail;

        mount_set_state(m, MOUNT_MOUNTING);

        return;

fail:
        log_warning("%s failed to run mount exectuable: %s", UNIT(m)->meta.id, strerror(-r));
        mount_enter_dead(m, false);
}

static void mount_enter_mounting_done(Mount *m) {
        assert(m);

        mount_set_state(m, MOUNT_MOUNTING_DONE);
}

static void mount_enter_remounting(Mount *m, bool success) {
        int r;

        assert(m);

        if (!success)
                m->failure = true;

        m->control_command_id = MOUNT_EXEC_REMOUNT;
        m->control_command = m->exec_command + MOUNT_EXEC_REMOUNT;

        if (m->from_fragment) {
                char *buf = NULL;
                const char *o;

                if (m->parameters_fragment.options) {
                        if (!(buf = strappend("remount,", m->parameters_fragment.options))) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        o = buf;
                } else
                        o = "remount";

                r = exec_command_set(
                                m->control_command,
                                "/bin/mount",
                                m->parameters_fragment.what,
                                m->where,
                                "-t", m->parameters_fragment.fstype,
                                "-o", o,
                                NULL);

                free(buf);
        } else if (m->from_etc_fstab)
                r = exec_command_set(
                                m->control_command,
                                "/bin/mount",
                                m->where,
                                "-o", "remount",
                                NULL);
        else
                r = -ENOENT;

        if (r < 0) {
                r = -ENOMEM;
                goto fail;
        }

        mount_unwatch_control_pid(m);

        if ((r = mount_spawn(m, m->control_command, &m->control_pid)) < 0)
                goto fail;

        mount_set_state(m, MOUNT_REMOUNTING);

        return;

fail:
        mount_enter_mounted(m, false);
}

static int mount_start(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (m->state == MOUNT_UNMOUNTING ||
            m->state == MOUNT_UNMOUNTING_SIGTERM ||
            m->state == MOUNT_UNMOUNTING_SIGKILL)
                return -EAGAIN;

        /* Already on it! */
        if (m->state == MOUNT_MOUNTING ||
            m->state == MOUNT_MOUNTING_SIGTERM ||
            m->state == MOUNT_MOUNTING_SIGKILL)
                return 0;

        assert(m->state == MOUNT_DEAD || m->state == MOUNT_MAINTAINANCE);

        m->failure = false;
        mount_enter_mounting(m);
        return 0;
}

static int mount_stop(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        /* Cann't do this right now. */
        if (m->state == MOUNT_MOUNTING ||
            m->state == MOUNT_MOUNTING_DONE ||
            m->state == MOUNT_MOUNTING_SIGTERM ||
            m->state == MOUNT_MOUNTING_SIGKILL ||
            m->state == MOUNT_REMOUNTING ||
            m->state == MOUNT_REMOUNTING_SIGTERM ||
            m->state == MOUNT_REMOUNTING_SIGKILL)
                return -EAGAIN;

        /* Already on it */
        if (m->state == MOUNT_UNMOUNTING ||
            m->state == MOUNT_UNMOUNTING_SIGKILL ||
            m->state == MOUNT_UNMOUNTING_SIGTERM)
                return 0;

        assert(m->state == MOUNT_MOUNTED);

        mount_enter_unmounting(m, true);
        return 0;
}

static int mount_reload(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        if (m->state == MOUNT_MOUNTING_DONE)
                return -EAGAIN;

        assert(m->state == MOUNT_MOUNTED);

        mount_enter_remounting(m, true);
        return 0;
}

static int mount_serialize(Unit *u, FILE *f, FDSet *fds) {
        Mount *m = MOUNT(u);

        assert(m);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", mount_state_to_string(m->state));
        unit_serialize_item(u, f, "failure", yes_no(m->failure));

        if (m->control_pid > 0)
                unit_serialize_item_format(u, f, "control-pid", "%u", (unsigned) m->control_pid);

        if (m->control_command_id >= 0)
                unit_serialize_item(u, f, "control-command", mount_exec_command_to_string(m->control_command_id));

        return 0;
}

static int mount_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Mount *m = MOUNT(u);
        int r;

        assert(u);
        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                MountState state;

                if ((state = mount_state_from_string(value)) < 0)
                        log_debug("Failed to parse state value %s", value);
                else
                        m->deserialized_state = state;
        } else if (streq(key, "failure")) {
                int b;

                if ((b = parse_boolean(value)) < 0)
                        log_debug("Failed to parse failure value %s", value);
                else
                        m->failure = b || m->failure;

        } else if (streq(key, "control-pid")) {
                unsigned pid;

                if ((r = safe_atou(value, &pid)) < 0 || pid <= 0)
                        log_debug("Failed to parse control-pid value %s", value);
                else
                        m->control_pid = (pid_t) pid;
        } else if (streq(key, "control-command")) {
                MountExecCommand id;

                if ((id = mount_exec_command_from_string(value)) < 0)
                        log_debug("Failed to parse exec-command value %s", value);
                else {
                        m->control_command_id = id;
                        m->control_command = m->exec_command + id;
                }

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static UnitActiveState mount_active_state(Unit *u) {
        assert(u);

        return state_translation_table[MOUNT(u)->state];
}

static const char *mount_sub_state_to_string(Unit *u) {
        assert(u);

        return mount_state_to_string(MOUNT(u)->state);
}

static bool mount_check_gc(Unit *u) {
        Mount *m = MOUNT(u);

        assert(m);

        return m->from_etc_fstab || m->from_proc_self_mountinfo;
}

static void mount_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Mount *m = MOUNT(u);
        bool success;

        assert(m);
        assert(pid >= 0);

        success = is_clean_exit(code, status);
        m->failure = m->failure || !success;

        assert(m->control_pid == pid);
        m->control_pid = 0;

        if (m->control_command) {
                exec_status_fill(&m->control_command->exec_status, pid, code, status);
                m->control_command = NULL;
                m->control_command_id = _MOUNT_EXEC_COMMAND_INVALID;
        }

        log_debug("%s control process exited, code=%s status=%i", u->meta.id, sigchld_code_to_string(code), status);

        /* Note that mount(8) returning and the kernel sending us a
         * mount table change event might happen out-of-order. If an
         * operation succeed we assume the kernel will follow soon too
         * and already change into the resulting state.  If it fails
         * we check if the kernel still knows about the mount. and
         * change state accordingly. */

        switch (m->state) {

        case MOUNT_MOUNTING:
        case MOUNT_MOUNTING_DONE:
        case MOUNT_MOUNTING_SIGKILL:
        case MOUNT_MOUNTING_SIGTERM:
        case MOUNT_REMOUNTING:
        case MOUNT_REMOUNTING_SIGKILL:
        case MOUNT_REMOUNTING_SIGTERM:

                if (success)
                        mount_enter_mounted(m, true);
                else if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, false);
                else
                        mount_enter_dead(m, false);
                break;

        case MOUNT_UNMOUNTING:
        case MOUNT_UNMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGTERM:

                if (success)
                        mount_enter_dead(m, true);
                else if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, false);
                else
                        mount_enter_dead(m, false);
                break;

        default:
                assert_not_reached("Uh, control process died at wrong time.");
        }
}

static void mount_timer_event(Unit *u, uint64_t elapsed, Watch *w) {
        Mount *m = MOUNT(u);

        assert(m);
        assert(elapsed == 1);
        assert(w == &m->timer_watch);

        switch (m->state) {

        case MOUNT_MOUNTING:
        case MOUNT_MOUNTING_DONE:
                log_warning("%s mounting timed out. Stopping.", u->meta.id);
                mount_enter_signal(m, MOUNT_MOUNTING_SIGTERM, false);
                break;

        case MOUNT_REMOUNTING:
                log_warning("%s remounting timed out. Stopping.", u->meta.id);
                mount_enter_signal(m, MOUNT_REMOUNTING_SIGTERM, false);
                break;

        case MOUNT_UNMOUNTING:
                log_warning("%s unmounting timed out. Stopping.", u->meta.id);
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGTERM, false);
                break;

        case MOUNT_MOUNTING_SIGTERM:
                log_warning("%s mounting timed out. Killing.", u->meta.id);
                mount_enter_signal(m, MOUNT_MOUNTING_SIGKILL, false);
                break;

        case MOUNT_REMOUNTING_SIGTERM:
                log_warning("%s remounting timed out. Killing.", u->meta.id);
                mount_enter_signal(m, MOUNT_REMOUNTING_SIGKILL, false);
                break;

        case MOUNT_UNMOUNTING_SIGTERM:
                log_warning("%s unmounting timed out. Killing.", u->meta.id);
                mount_enter_signal(m, MOUNT_UNMOUNTING_SIGKILL, false);
                break;

        case MOUNT_MOUNTING_SIGKILL:
        case MOUNT_REMOUNTING_SIGKILL:
        case MOUNT_UNMOUNTING_SIGKILL:
                log_warning("%s mount process still around after SIGKILL. Ignoring.", u->meta.id);

                if (m->from_proc_self_mountinfo)
                        mount_enter_mounted(m, false);
                else
                        mount_enter_dead(m, false);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

static int mount_add_one(
                Manager *m,
                const char *what,
                const char *where,
                const char *options,
                const char *fstype,
                bool from_proc_self_mountinfo,
                bool set_flags) {
        int r;
        Unit *u;
        bool delete;
        char *e, *w = NULL, *o = NULL, *f = NULL;
        MountParameters *p;

        assert(m);
        assert(what);
        assert(where);
        assert(options);
        assert(fstype);

        assert(!set_flags || from_proc_self_mountinfo);

        /* Ignore API mount points. They should never be referenced in
         * dependencies ever. */
        if (mount_point_is_api(where))
                return 0;

        if (streq(fstype, "autofs"))
                return 0;

        /* probably some kind of swap, ignore */
        if (!is_path(where))
                return 0;

        if (!(e = unit_name_from_path(where, ".mount")))
                return -ENOMEM;

        if (!(u = manager_get_unit(m, e))) {
                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }

                r = unit_add_name(u, e);
                free(e);

                if (r < 0)
                        goto fail;

                if (!(MOUNT(u)->where = strdup(where))) {
                        r = -ENOMEM;
                        goto fail;
                }

                unit_add_to_load_queue(u);
        } else {
                delete = false;
                free(e);
        }

        if (!(w = strdup(what)) ||
            !(o = strdup(options)) ||
            !(f = strdup(fstype))) {
                r = -ENOMEM;
                goto fail;
        }

        if (from_proc_self_mountinfo) {
                p = &MOUNT(u)->parameters_proc_self_mountinfo;

                if (set_flags) {
                        MOUNT(u)->is_mounted = true;
                        MOUNT(u)->just_mounted = !MOUNT(u)->from_proc_self_mountinfo;
                        MOUNT(u)->just_changed = !streq_ptr(p->options, o);
                }

                MOUNT(u)->from_proc_self_mountinfo = true;
        } else {
                p = &MOUNT(u)->parameters_etc_fstab;
                MOUNT(u)->from_etc_fstab = true;
        }

        free(p->what);
        p->what = w;

        free(p->options);
        p->options = o;

        free(p->fstype);
        p->fstype = f;

        unit_add_to_dbus_queue(u);

        return 0;

fail:
        free(w);
        free(o);
        free(f);

        if (delete && u)
                unit_free(u);

        return r;
}

static char *fstab_node_to_udev_node(char *p) {
        char *dn, *t;
        int r;

        /* FIXME: to follow udev's logic 100% we need to leave valid
         * UTF8 chars unescaped */

        if (startswith(p, "LABEL=")) {

                if (!(t = xescape(p+6, "/ ")))
                        return NULL;

                r = asprintf(&dn, "/dev/disk/by-label/%s", t);
                free(t);

                if (r < 0)
                        return NULL;

                return dn;
        }

        if (startswith(p, "UUID=")) {

                if (!(t = xescape(p+5, "/ ")))
                        return NULL;

                r = asprintf(&dn, "/dev/disk/by-uuid/%s", ascii_strlower(t));
                free(t);

                if (r < 0)
                        return NULL;

                return dn;
        }

        return strdup(p);
}

static int mount_find_pri(char *options) {
        char *end, *pri;
        unsigned long r;

        if (!(pri = mount_test_option(options, "pri=")))
                return 0;

        pri += 4;

        errno = 0;
        r = strtoul(pri, &end, 10);

        if (errno != 0)
                return -errno;

        if (end == pri || (*end != ',' && *end != 0))
                return -EINVAL;

        return (int) r;
}

static int mount_load_etc_fstab(Manager *m) {
        FILE *f;
        int r;
        struct mntent* me;

        assert(m);

        errno = 0;
        if (!(f = setmntent("/etc/fstab", "r")))
                return -errno;

        while ((me = getmntent(f))) {
                char *where, *what;

                if (!(what = fstab_node_to_udev_node(me->mnt_fsname))) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(where = strdup(me->mnt_dir))) {
                        free(what);
                        r = -ENOMEM;
                        goto finish;
                }

                if (what[0] == '/')
                        path_kill_slashes(what);

                if (where[0] == '/')
                        path_kill_slashes(where);

                if (streq(me->mnt_type, "swap")) {
                        int pri;

                        if ((pri = mount_find_pri(me->mnt_opts)) < 0)
                                r = pri;
                        else
                                r = swap_add_one(m,
                                                 what,
                                                 pri,
                                                 !!mount_test_option(me->mnt_opts, MNTOPT_NOAUTO),
                                                 !!mount_test_option(me->mnt_opts, "comment=systemd.swapon"),
                                                 false);
                } else
                        r = mount_add_one(m, what, where, me->mnt_opts, me->mnt_type, false, false);

                free(what);
                free(where);

                if (r < 0)
                        goto finish;
        }

        r = 0;
finish:

        endmntent(f);
        return r;
}

static int mount_load_proc_self_mountinfo(Manager *m, bool set_flags) {
        int r;
        char *device, *path, *options, *options2, *fstype, *d, *p, *o;

        assert(m);

        rewind(m->proc_self_mountinfo);

        for (;;) {
                int k;

                device = path = options = options2 = fstype = d = p = o = NULL;

                if ((k = fscanf(m->proc_self_mountinfo,
                                "%*s "       /* (1) mount id */
                                "%*s "       /* (2) parent id */
                                "%*s "       /* (3) major:minor */
                                "%*s "       /* (4) root */
                                "%ms "       /* (5) mount point */
                                "%ms"        /* (6) mount options */
                                "%*[^-]"     /* (7) optional fields */
                                "- "         /* (8) seperator */
                                "%ms "       /* (9) file system type */
                                "%ms"        /* (10) mount source */
                                "%ms"        /* (11) mount options 2 */
                                "%*[^\n]",   /* some rubbish at the end */
                                &path,
                                &options,
                                &fstype,
                                &device,
                                &options2)) != 5) {

                        if (k == EOF)
                                break;

                        r = -EBADMSG;
                        goto finish;
                }

                if (asprintf(&o, "%s,%s", options, options2) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(d = cunescape(device)) ||
                    !(p = cunescape(path))) {
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = mount_add_one(m, d, p, o, fstype, true, set_flags)) < 0)
                        goto finish;

                free(device);
                free(path);
                free(options);
                free(options2);
                free(fstype);
                free(d);
                free(p);
                free(o);
        }

        r = 0;

finish:
        free(device);
        free(path);
        free(options);
        free(options2);
        free(fstype);
        free(d);
        free(p);
        free(o);

        return r;
}

static void mount_shutdown(Manager *m) {
        assert(m);

        if (m->proc_self_mountinfo) {
                fclose(m->proc_self_mountinfo);
                m->proc_self_mountinfo = NULL;
        }
}

static int mount_enumerate(Manager *m) {
        int r;
        struct epoll_event ev;
        assert(m);

        if (!m->proc_self_mountinfo) {
                if (!(m->proc_self_mountinfo = fopen("/proc/self/mountinfo", "re")))
                        return -errno;

                m->mount_watch.type = WATCH_MOUNT;
                m->mount_watch.fd = fileno(m->proc_self_mountinfo);

                zero(ev);
                ev.events = EPOLLERR;
                ev.data.ptr = &m->mount_watch;

                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, m->mount_watch.fd, &ev) < 0)
                        return -errno;
        }

        if ((r = mount_load_etc_fstab(m)) < 0)
                goto fail;

        if ((r = mount_load_proc_self_mountinfo(m, false)) < 0)
                goto fail;

        return 0;

fail:
        mount_shutdown(m);
        return r;
}

void mount_fd_event(Manager *m, int events) {
        Meta *meta;
        int r;

        assert(m);
        assert(events == EPOLLERR);

        /* The manager calls this for every fd event happening on the
         * /proc/self/mountinfo file, which informs us about mounting
         * table changes */

        if ((r = mount_load_proc_self_mountinfo(m, true)) < 0) {
                log_error("Failed to reread /proc/self/mountinfo: %s", strerror(errno));

                /* Reset flags, just in case, for later calls */
                LIST_FOREACH(units_per_type, meta, m->units_per_type[UNIT_MOUNT]) {
                        Mount *mount = (Mount*) meta;

                        mount->is_mounted = mount->just_mounted = mount->just_changed = false;
                }

                return;
        }

        manager_dispatch_load_queue(m);

        LIST_FOREACH(units_per_type, meta, m->units_per_type[UNIT_MOUNT]) {
                Mount *mount = (Mount*) meta;

                if (!mount->is_mounted) {
                        /* This has just been unmounted. */

                        mount->from_proc_self_mountinfo = false;

                        switch (mount->state) {

                        case MOUNT_MOUNTED:
                                mount_enter_dead(mount, true);
                                break;

                        default:
                                mount_set_state(mount, mount->state);
                                break;

                        }

                } else if (mount->just_mounted || mount->just_changed) {

                        /* New or changed entrymount */

                        switch (mount->state) {

                        case MOUNT_DEAD:
                        case MOUNT_MAINTAINANCE:
                                mount_enter_mounted(mount, true);
                                break;

                        case MOUNT_MOUNTING:
                                mount_enter_mounting_done(mount);
                                break;

                        default:
                                /* Nothing really changed, but let's
                                 * issue an notification call
                                 * nonetheless, in case somebody is
                                 * waiting for this. (e.g. file system
                                 * ro/rw remounts.) */
                                mount_set_state(mount, mount->state);
                                break;
                        }
                }

                /* Reset the flags for later calls */
                mount->is_mounted = mount->just_mounted = mount->just_changed = false;
        }
}

int mount_path_is_mounted(Manager *m, const char* path) {
        char *t;
        int r;

        assert(m);
        assert(path);

        if (path[0] != '/')
                return 1;

        if (!(t = strdup(path)))
                return -ENOMEM;

        path_kill_slashes(t);

        for (;;) {
                char *e, *slash;
                Unit *u;

                if (!(e = unit_name_from_path(t, ".mount"))) {
                        r = -ENOMEM;
                        goto finish;
                }

                u = manager_get_unit(m, e);
                free(e);

                if (u &&
                    (MOUNT(u)->from_etc_fstab || MOUNT(u)->from_fragment) &&
                    MOUNT(u)->state != MOUNT_MOUNTED) {
                        r = 0;
                        goto finish;
                }

                assert_se(slash = strrchr(t, '/'));

                if (slash == t) {
                        r = 1;
                        goto finish;
                }

                *slash = 0;
        }

        r = 1;

finish:
        free(t);
        return r;
}

static const char* const mount_state_table[_MOUNT_STATE_MAX] = {
        [MOUNT_DEAD] = "dead",
        [MOUNT_MOUNTING] = "mounting",
        [MOUNT_MOUNTING_DONE] = "mounting-done",
        [MOUNT_MOUNTED] = "mounted",
        [MOUNT_REMOUNTING] = "remounting",
        [MOUNT_UNMOUNTING] = "unmounting",
        [MOUNT_MOUNTING_SIGTERM] = "mounting-sigterm",
        [MOUNT_MOUNTING_SIGKILL] = "mounting-sigkill",
        [MOUNT_REMOUNTING_SIGTERM] = "remounting-sigterm",
        [MOUNT_REMOUNTING_SIGKILL] = "remounting-sigkill",
        [MOUNT_UNMOUNTING_SIGTERM] = "unmounting-sigterm",
        [MOUNT_UNMOUNTING_SIGKILL] = "unmounting-sigkill",
        [MOUNT_MAINTAINANCE] = "maintainance"
};

DEFINE_STRING_TABLE_LOOKUP(mount_state, MountState);

static const char* const mount_exec_command_table[_MOUNT_EXEC_COMMAND_MAX] = {
        [MOUNT_EXEC_MOUNT] = "ExecMount",
        [MOUNT_EXEC_UNMOUNT] = "ExecUnmount",
        [MOUNT_EXEC_REMOUNT] = "ExecRemount",
};

DEFINE_STRING_TABLE_LOOKUP(mount_exec_command, MountExecCommand);

const UnitVTable mount_vtable = {
        .suffix = ".mount",

        .no_alias = true,
        .no_instances = true,
        .no_isolate = true,

        .init = mount_init,
        .load = mount_load,
        .done = mount_done,

        .coldplug = mount_coldplug,

        .dump = mount_dump,

        .start = mount_start,
        .stop = mount_stop,
        .reload = mount_reload,

        .serialize = mount_serialize,
        .deserialize_item = mount_deserialize_item,

        .active_state = mount_active_state,
        .sub_state_to_string = mount_sub_state_to_string,

        .check_gc = mount_check_gc,

        .sigchld_event = mount_sigchld_event,
        .timer_event = mount_timer_event,

        .bus_message_handler = bus_mount_message_handler,

        .enumerate = mount_enumerate,
        .shutdown = mount_shutdown
};

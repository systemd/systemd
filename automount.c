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
#include <limits.h>
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <linux/auto_fs4.h>
#include <linux/auto_dev-ioctl.h>

#include "unit.h"
#include "automount.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "unit-name.h"

static const UnitActiveState state_translation_table[_AUTOMOUNT_STATE_MAX] = {
        [AUTOMOUNT_DEAD] = UNIT_INACTIVE,
        [AUTOMOUNT_WAITING] = UNIT_ACTIVE,
        [AUTOMOUNT_RUNNING] = UNIT_ACTIVE,
        [AUTOMOUNT_MAINTAINANCE] = UNIT_INACTIVE,
};

static const char* const state_string_table[_AUTOMOUNT_STATE_MAX] = {
        [AUTOMOUNT_DEAD] = "dead",
        [AUTOMOUNT_WAITING] = "waiting",
        [AUTOMOUNT_RUNNING] = "running",
        [AUTOMOUNT_MAINTAINANCE] = "maintainance"
};

static char *automount_name_from_where(const char *where) {
        assert(where);

        if (streq(where, "/"))
                return strdup("-.automount");

        return unit_name_build_escape(where+1, NULL, ".automount");
}

static void automount_init(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        a->pipe_watch.fd = a->pipe_fd = -1;
}

static void repeat_unmout(const char *path) {
        assert(path);

        for (;;) {

                if (umount2(path, MNT_DETACH) >= 0)
                        continue;

                if (errno != EINVAL)
                        log_error("Failed to unmount: %m");

                break;
        }
}

static void unmount_autofs(Automount *a) {
        assert(a);

        if (a->pipe_fd < 0)
                return;

        automount_send_ready(a, -EHOSTDOWN);

        unit_unwatch_fd(UNIT(a), &a->pipe_watch);
        close_nointr_nofail(a->pipe_fd);
        a->pipe_fd = -1;

        repeat_unmout(a->where);
}

static void automount_done(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        unmount_autofs(a);
        a->mount = NULL;

        if (a->tokens) {
                set_free(a->tokens);
                a->tokens = NULL;
        }
}

static int automount_verify(Automount *a) {
        bool b;
        char *e;
        assert(a);

        if (UNIT(a)->meta.load_state != UNIT_LOADED)
                return 0;

        if (!a->where) {
                log_error("%s lacks Where setting. Refusing.", UNIT(a)->meta.id);
                return -EINVAL;
        }

        path_kill_slashes(a->where);

        if (!(e = automount_name_from_where(a->where)))
                return -ENOMEM;

        b = unit_has_name(UNIT(a), e);
        free(e);

        if (!b) {
                log_error("%s's Where setting doesn't match unit name. Refusing.", UNIT(a)->meta.id);
                return -EINVAL;
        }

        return 0;
}

static int automount_load(Unit *u) {
        int r;
        Automount *a = AUTOMOUNT(u);

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        /* Load a .automount file */
        if ((r = unit_load_fragment_and_dropin_optional(u)) < 0)
                return r;

        if (u->meta.load_state == UNIT_LOADED) {

                if ((r = unit_load_related_unit(u, ".mount", (Unit**) &a->mount)) < 0)
                        return r;

                if ((r = unit_add_dependency(u, UNIT_BEFORE, UNIT(a->mount))) < 0)
                        return r;
        }

        return automount_verify(a);
}

static void automount_set_state(Automount *a, AutomountState state) {
        AutomountState old_state;
        assert(a);

        old_state = a->state;
        a->state = state;

        if (state != AUTOMOUNT_WAITING &&
            state != AUTOMOUNT_RUNNING)
                unmount_autofs(a);

        if (state != old_state)
                log_debug("%s changed %s → %s", UNIT(a)->meta.id, state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(a), state_translation_table[old_state], state_translation_table[state]);
}

static void automount_dump(Unit *u, FILE *f, const char *prefix) {
        Automount *s = AUTOMOUNT(u);

        assert(s);

        fprintf(f,
                "%sAutomount State: %s\n",
                prefix, state_string_table[s->state]);
}

static void automount_enter_dead(Automount *a, bool success) {
        assert(a);

        if (!success)
                a->failure = true;

        automount_set_state(a, a->failure ? AUTOMOUNT_MAINTAINANCE : AUTOMOUNT_DEAD);
}

static int open_dev_autofs(Manager *m) {
        struct autofs_dev_ioctl param;

        assert(m);

        if (m->dev_autofs_fd >= 0)
                return m->dev_autofs_fd;

        if ((m->dev_autofs_fd = open("/dev/autofs", O_RDONLY)) < 0) {
                log_error("Failed to open /dev/autofs: %s", strerror(errno));
                return -errno;
        }

        init_autofs_dev_ioctl(&param);
        if (ioctl(m->dev_autofs_fd, AUTOFS_DEV_IOCTL_VERSION, &param) < 0) {
                close_nointr_nofail(m->dev_autofs_fd);
                m->dev_autofs_fd = -1;
                return -errno;
        }

        log_debug("Autofs kernel version %i.%i", param.ver_major, param.ver_minor);

        return m->dev_autofs_fd;
}

static int open_ioctl_fd(int dev_autofs_fd, const char *where, dev_t devid) {
        struct autofs_dev_ioctl *param;
        size_t l;
        int r;

        assert(dev_autofs_fd >= 0);
        assert(where);

        l = sizeof(struct autofs_dev_ioctl) + strlen(where) + 1;

        if (!(param = malloc(l)))
                return -ENOMEM;

        init_autofs_dev_ioctl(param);
        param->size = l;
        param->ioctlfd = -1;
        param->openmount.devid = devid;
        strcpy(param->path, where);

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_OPENMOUNT, param) < 0) {
                r = -errno;
                goto finish;
        }

        if (param->ioctlfd < 0) {
                r = -EIO;
                goto finish;
        }

        r = param->ioctlfd;

finish:
        free(param);
        return r;
}

static int autofs_protocol(int dev_autofs_fd, int ioctl_fd) {
        uint32_t major, minor;
        struct autofs_dev_ioctl param;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_PROTOVER, &param) < 0)
                return -errno;

        major = param.protover.version;

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_PROTOSUBVER, &param) < 0)
                return -errno;

        minor = param.protosubver.sub_version;

        log_debug("Autofs protocol version %i.%i", major, minor);
        return 0;
}

static int autofs_set_timeout(int dev_autofs_fd, int ioctl_fd, time_t sec) {
        struct autofs_dev_ioctl param;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;
        param.timeout.timeout = sec;

        if (ioctl(dev_autofs_fd, AUTOFS_DEV_IOCTL_TIMEOUT, &param) < 0)
                return -errno;

        return 0;
}

static int autofs_send_ready(int dev_autofs_fd, int ioctl_fd, uint32_t token, int status) {
        struct autofs_dev_ioctl param;

        assert(dev_autofs_fd >= 0);
        assert(ioctl_fd >= 0);

        init_autofs_dev_ioctl(&param);
        param.ioctlfd = ioctl_fd;

        if (status) {
                param.fail.token = token;
                param.fail.status = status;
        } else
                param.ready.token = token;

        if (ioctl(dev_autofs_fd, status ? AUTOFS_DEV_IOCTL_FAIL : AUTOFS_DEV_IOCTL_READY, &param) < 0)
                return -errno;

        return 0;
}

int automount_send_ready(Automount *a, int status) {
        int ioctl_fd, r;
        unsigned token;

        assert(a);
        assert(status <= 0);

        if (set_isempty(a->tokens))
                return 0;

        if ((ioctl_fd = open_ioctl_fd(UNIT(a)->meta.manager->dev_autofs_fd, a->where, a->dev_id)) < 0) {
                r = ioctl_fd;
                goto fail;
        }

        if (status)
                log_debug("Sending failure: %s", strerror(-status));
        else
                log_debug("Sending success.");

        /* Autofs thankfully does not hand out 0 as a token */
        while ((token = PTR_TO_UINT(set_steal_first(a->tokens)))) {
                int k;

                /* Autofs fun fact II:
                 *
                 * if you pass a positive status code here, the kernel will
                 * freeze! Yay! */

                if ((k = autofs_send_ready(UNIT(a)->meta.manager->dev_autofs_fd,
                                           ioctl_fd,
                                           token,
                                           status)) < 0)
                        r = k;
        }

        r = 0;

fail:
        if (ioctl_fd >= 0)
                close_nointr_nofail(ioctl_fd);

        return r;
}

static void automount_enter_waiting(Automount *a) {
        int p[2] = { -1, -1 };
        char name[32], options[128];
        bool mounted = false;
        int r, ioctl_fd = -1, dev_autofs_fd;
        struct stat st;

        assert(a);
        assert(a->pipe_fd < 0);
        assert(a->where);

        if (a->tokens)
                set_clear(a->tokens);
        else if (!(a->tokens = set_new(trivial_hash_func, trivial_compare_func))) {
                r = -ENOMEM;
                goto fail;
        }

        if ((dev_autofs_fd = open_dev_autofs(UNIT(a)->meta.manager)) < 0) {
                r = dev_autofs_fd;
                goto fail;
        }

        /* We knowingly ignore the results of this call */
        mkdir_p(a->where, 0555);

        if (pipe2(p, O_NONBLOCK) < 0) {
                r = -errno;
                goto fail;
        }

        snprintf(options, sizeof(options), "fd=%i,pgrp=%u,minproto=5,maxproto=5,direct", p[1], (unsigned) getpgrp());
        char_array_0(options);

        snprintf(name, sizeof(name), "systemd-%u", (unsigned) getpid());
        char_array_0(name);

        if (mount(name, a->where, "autofs", 0, options) < 0) {
                r = -errno;
                goto fail;
        }

        mounted = true;

        close_nointr_nofail(p[1]);
        p[1] = -1;

        if (stat(a->where, &st) < 0) {
                r = -errno;
                goto fail;
        }

        if ((ioctl_fd = open_ioctl_fd(dev_autofs_fd, a->where, st.st_dev)) < 0) {
                r = ioctl_fd;
                goto fail;
        }

        if ((r = autofs_protocol(dev_autofs_fd, ioctl_fd)) < 0)
                goto fail;

        if ((r = autofs_set_timeout(dev_autofs_fd, ioctl_fd, 300)) < 0)
                goto fail;

        /* Autofs fun fact:
         *
         * Unless we close the ioctl fd here, for some weird reason
         * the direct mount will not receive events from the
         * kernel. */

        close_nointr_nofail(ioctl_fd);
        ioctl_fd = -1;

        if ((r = unit_watch_fd(UNIT(a), p[0], EPOLLIN, &a->pipe_watch)) < 0)
                goto fail;

        a->pipe_fd = p[0];
        a->dev_id = st.st_dev;

        automount_set_state(a, AUTOMOUNT_WAITING);

        return;

fail:
        assert_se(close_pipe(p) == 0);

        if (ioctl_fd >= 0)
                close_nointr_nofail(ioctl_fd);

        if (mounted)
                repeat_unmout(a->where);

        log_error("Failed to initialize automounter: %s", strerror(-r));
        automount_enter_dead(a, false);
}

static void automount_enter_runnning(Automount *a) {
        int r;
        struct stat st;

        assert(a);
        assert(a->mount);

        /* Before we do anything, let's see if somebody is playing games with us? */

        if (stat(a->where, &st) < 0) {
                log_warning("%s failed stat automount point: %m", a->meta.id);
                goto fail;
        }

        if (!S_ISDIR(st.st_mode) || st.st_dev != a->dev_id)
                log_info("%s's automount point already active?", a->meta.id);
        else if ((r = manager_add_job(UNIT(a)->meta.manager, JOB_START, UNIT(a->mount), JOB_REPLACE, true, NULL)) < 0) {
                log_warning("%s failed to queue mount startup job: %s", a->meta.id, strerror(-r));
                goto fail;
        }

        automount_set_state(a, AUTOMOUNT_RUNNING);
        return;

fail:
        automount_enter_dead(a, false);
}

static int automount_start(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        if (path_is_mount_point(a->where)) {
                log_error("Path %s is already a mount point, refusing start for %s", a->where, u->meta.id);
                return -EEXIST;
        }

        assert(a->state == AUTOMOUNT_DEAD || a->state == AUTOMOUNT_MAINTAINANCE);

        a->failure = false;
        automount_enter_waiting(a);
        return 0;
}

static int automount_stop(Unit *u) {
        Automount *a = AUTOMOUNT(u);

        assert(a);

        assert(a->state == AUTOMOUNT_WAITING || a->state == AUTOMOUNT_RUNNING);

        automount_enter_dead(a, true);
        return 0;
}

static UnitActiveState automount_active_state(Unit *u) {

        return state_translation_table[AUTOMOUNT(u)->state];
}

static const char *automount_sub_state_to_string(Unit *u) {
        assert(u);

        return state_string_table[AUTOMOUNT(u)->state];
}

static void automount_fd_event(Unit *u, int fd, uint32_t events, Watch *w) {
        union autofs_v5_packet_union packet;
        ssize_t l;
        int r;

        Automount *a = AUTOMOUNT(u);

        assert(a);
        assert(fd == a->pipe_fd);

        if (events != EPOLLIN) {
                log_error("Got invalid poll event on pipe.");
                goto fail;
        }

        if ((l = loop_read(a->pipe_fd, &packet, sizeof(packet))) != sizeof(packet)) {
                log_error("Invalid read from pipe: %s", l < 0 ? strerror(-l) : "short read");
                goto fail;
        }

        switch (packet.hdr.type) {

        case autofs_ptype_missing_direct:
                log_debug("Got direct mount request for %s", packet.v5_packet.name);

                if ((r = set_put(a->tokens, UINT_TO_PTR(packet.v5_packet.wait_queue_token))) < 0) {
                        log_error("Failed to remember token: %s", strerror(-r));
                        goto fail;
                }

                automount_enter_runnning(a);
                break;

        default:
                log_error("Received unknown automount request %i", packet.hdr.type);
                break;
        }

        return;

fail:
        automount_enter_dead(a, false);
}

static void automount_shutdown(Manager *m) {
        assert(m);

        if (m->dev_autofs_fd >= 0)
                close_nointr_nofail(m->dev_autofs_fd);
}

const UnitVTable automount_vtable = {
        .suffix = ".automount",

        .no_alias = true,
        .no_instances = true,

        .init = automount_init,
        .load = automount_load,
        .done = automount_done,

        .dump = automount_dump,

        .start = automount_start,
        .stop = automount_stop,

        .active_state = automount_active_state,
        .sub_state_to_string = automount_sub_state_to_string,

        .fd_event = automount_fd_event,

        .shutdown = automount_shutdown
};

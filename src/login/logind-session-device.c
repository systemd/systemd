/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 David Herrmann

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

#include <assert.h>
#include <fcntl.h>
#include <libudev.h>
#include <linux/input.h>
#include <linux/ioctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"
#include "missing.h"
#include "bus-util.h"
#include "logind-session-device.h"

enum SessionDeviceNotifications {
        SESSION_DEVICE_RESUME,
        SESSION_DEVICE_TRY_PAUSE,
        SESSION_DEVICE_PAUSE,
        SESSION_DEVICE_RELEASE,
};

static int session_device_notify(SessionDevice *sd, enum SessionDeviceNotifications type) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *path = NULL;
        const char *t = NULL;
        uint32_t major, minor;
        int r;

        assert(sd);

        major = major(sd->dev);
        minor = minor(sd->dev);

        if (!sd->session->controller)
                return 0;

        path = session_bus_path(sd->session);
        if (!path)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        sd->session->manager->bus,
                        &m, path,
                        "org.freedesktop.login1.Session",
                        (type == SESSION_DEVICE_RESUME) ? "ResumeDevice" : "PauseDevice");
        if (!m)
                return r;

        r = sd_bus_message_set_destination(m, sd->session->controller);
        if (r < 0)
                return r;

        switch (type) {
        case SESSION_DEVICE_RESUME:
                r = sd_bus_message_append(m, "uuh", major, minor, sd->fd);
                if (r < 0)
                        return r;
                break;
        case SESSION_DEVICE_TRY_PAUSE:
                t = "pause";
                break;
        case SESSION_DEVICE_PAUSE:
                t = "force";
                break;
        case SESSION_DEVICE_RELEASE:
                t = "gone";
                break;
        default:
                return -EINVAL;
        }

        if (t) {
                r = sd_bus_message_append(m, "uus", major, minor, t);
                if (r < 0)
                        return r;
        }

        return sd_bus_send(sd->session->manager->bus, m, NULL);
}

static int sd_eviocrevoke(int fd) {
        static bool warned;
        int r;

        assert(fd >= 0);

        r = ioctl(fd, EVIOCREVOKE, 1);
        if (r < 0) {
                r = -errno;
                if (r == -EINVAL && !warned) {
                        warned = true;
                        log_warning("kernel does not support evdev-revocation");
                }
        }

        return 0;
}

static int sd_drmsetmaster(int fd) {
        int r;

        assert(fd >= 0);

        r = ioctl(fd, DRM_IOCTL_SET_MASTER, 0);
        if (r < 0)
                return -errno;

        return 0;
}

static int sd_drmdropmaster(int fd) {
        int r;

        assert(fd >= 0);

        r = ioctl(fd, DRM_IOCTL_DROP_MASTER, 0);
        if (r < 0)
                return -errno;

        return 0;
}

static int session_device_open(SessionDevice *sd, bool active) {
        int fd, r;

        assert(sd->type != DEVICE_TYPE_UNKNOWN);

        /* open device and try to get an udev_device from it */
        fd = open(sd->node, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        switch (sd->type) {
        case DEVICE_TYPE_DRM:
                if (active) {
                        /* Weird legacy DRM semantics might return an error
                         * even though we're master. No way to detect that so
                         * fail at all times and let caller retry in inactive
                         * state. */
                        r = sd_drmsetmaster(fd);
                        if (r < 0) {
                                close_nointr(fd);
                                return r;
                        }
                } else {
                        /* DRM-Master is granted to the first user who opens a
                         * device automatically (ughh, racy!). Hence, we just
                         * drop DRM-Master in case we were the first. */
                        sd_drmdropmaster(fd);
                }
                break;
        case DEVICE_TYPE_EVDEV:
                if (!active)
                        sd_eviocrevoke(fd);
                break;
        case DEVICE_TYPE_UNKNOWN:
        default:
                /* fallback for devices wihout synchronizations */
                break;
        }

        return fd;
}

static int session_device_start(SessionDevice *sd) {
        int r;

        assert(sd);
        assert(session_is_active(sd->session));

        if (sd->active)
                return 0;

        switch (sd->type) {
        case DEVICE_TYPE_DRM:
                /* Device is kept open. Simply call drmSetMaster() and hope
                 * there is no-one else. In case it fails, we keep the device
                 * paused. Maybe at some point we have a drmStealMaster(). */
                r = sd_drmsetmaster(sd->fd);
                if (r < 0)
                        return r;
                break;
        case DEVICE_TYPE_EVDEV:
                /* Evdev devices are revoked while inactive. Reopen it and we
                 * are fine. */
                r = session_device_open(sd, true);
                if (r < 0)
                        return r;
                close_nointr(sd->fd);
                sd->fd = r;
                break;
        case DEVICE_TYPE_UNKNOWN:
        default:
                /* fallback for devices wihout synchronizations */
                break;
        }

        sd->active = true;
        return 0;
}

static void session_device_stop(SessionDevice *sd) {
        assert(sd);

        if (!sd->active)
                return;

        switch (sd->type) {
        case DEVICE_TYPE_DRM:
                /* On DRM devices we simply drop DRM-Master but keep it open.
                 * This allows the user to keep resources allocated. The
                 * CAP_SYS_ADMIN restriction to DRM-Master prevents users from
                 * circumventing this. */
                sd_drmdropmaster(sd->fd);
                break;
        case DEVICE_TYPE_EVDEV:
                /* Revoke access on evdev file-descriptors during deactivation.
                 * This will basically prevent any operations on the fd and
                 * cannot be undone. Good side is: it needs no CAP_SYS_ADMIN
                 * protection this way. */
                sd_eviocrevoke(sd->fd);
                break;
        case DEVICE_TYPE_UNKNOWN:
        default:
                /* fallback for devices without synchronization */
                break;
        }

        sd->active = false;
}

static DeviceType detect_device_type(struct udev_device *dev) {
        const char *sysname, *subsystem;
        DeviceType type;

        sysname = udev_device_get_sysname(dev);
        subsystem = udev_device_get_subsystem(dev);
        type = DEVICE_TYPE_UNKNOWN;

        if (streq_ptr(subsystem, "drm")) {
                if (startswith(sysname, "card"))
                        type = DEVICE_TYPE_DRM;
        } else if (streq_ptr(subsystem, "input")) {
                if (startswith(sysname, "event"))
                        type = DEVICE_TYPE_EVDEV;
        }

        return type;
}

static int session_device_verify(SessionDevice *sd) {
        struct udev_device *dev, *p = NULL;
        const char *sp, *node;
        int r;

        dev = udev_device_new_from_devnum(sd->session->manager->udev, 'c', sd->dev);
        if (!dev)
                return -ENODEV;

        sp = udev_device_get_syspath(dev);
        node = udev_device_get_devnode(dev);
        if (!node) {
                r = -EINVAL;
                goto err_dev;
        }

        /* detect device type so we can find the correct sysfs parent */
        sd->type = detect_device_type(dev);
        if (sd->type == DEVICE_TYPE_UNKNOWN) {
                r = -ENODEV;
                goto err_dev;
        } else if (sd->type == DEVICE_TYPE_EVDEV) {
                /* for evdev devices we need the parent node as device */
                p = dev;
                dev = udev_device_get_parent_with_subsystem_devtype(p, "input", NULL);
                if (!dev) {
                        r = -ENODEV;
                        goto err_dev;
                }
                sp = udev_device_get_syspath(dev);
        } else if (sd->type != DEVICE_TYPE_DRM) {
                /* Prevent opening unsupported devices. Especially devices of
                 * subsystem "input" must be opened via the evdev node as
                 * we require EVIOCREVOKE. */
                r = -ENODEV;
                goto err_dev;
        }

        /* search for an existing seat device and return it if available */
        sd->device = hashmap_get(sd->session->manager->devices, sp);
        if (!sd->device) {
                /* The caller might have gotten the udev event before we were
                 * able to process it. Hence, fake the "add" event and let the
                 * logind-manager handle the new device. */
                r = manager_process_seat_device(sd->session->manager, dev);
                if (r < 0)
                        goto err_dev;

                /* if it's still not available, then the device is invalid */
                sd->device = hashmap_get(sd->session->manager->devices, sp);
                if (!sd->device) {
                        r = -ENODEV;
                        goto err_dev;
                }
        }

        if (sd->device->seat != sd->session->seat) {
                r = -EPERM;
                goto err_dev;
        }

        sd->node = strdup(node);
        if (!sd->node) {
                r = -ENOMEM;
                goto err_dev;
        }

        r = 0;
err_dev:
        udev_device_unref(p ? : dev);
        return r;
}

int session_device_new(Session *s, dev_t dev, SessionDevice **out) {
        SessionDevice *sd;
        int r;

        assert(s);
        assert(out);

        if (!s->seat)
                return -EPERM;

        sd = new0(SessionDevice, 1);
        if (!sd)
                return -ENOMEM;

        sd->session = s;
        sd->dev = dev;
        sd->fd = -1;
        sd->type = DEVICE_TYPE_UNKNOWN;

        r = session_device_verify(sd);
        if (r < 0)
                goto error;

        r = hashmap_put(s->devices, &sd->dev, sd);
        if (r < 0) {
                r = -ENOMEM;
                goto error;
        }

        /* Open the device for the first time. We need a valid fd to pass back
         * to the caller. If the session is not active, this _might_ immediately
         * revoke access and thus invalidate the fd. But this is still needed
         * to pass a valid fd back. */
        sd->active = session_is_active(s);
        r = session_device_open(sd, sd->active);
        if (r < 0) {
                /* EINVAL _may_ mean a master is active; retry inactive */
                if (sd->active && r == -EINVAL) {
                        sd->active = false;
                        r = session_device_open(sd, false);
                }
                if (r < 0)
                        goto error;
        }
        sd->fd = r;

        LIST_PREPEND(sd_by_device, sd->device->session_devices, sd);

        *out = sd;
        return 0;

error:
        hashmap_remove(s->devices, &sd->dev);
        free(sd->node);
        free(sd);
        return r;
}

void session_device_free(SessionDevice *sd) {
        assert(sd);

        session_device_stop(sd);
        session_device_notify(sd, SESSION_DEVICE_RELEASE);
        close_nointr(sd->fd);

        LIST_REMOVE(sd_by_device, sd->device->session_devices, sd);

        hashmap_remove(sd->session->devices, &sd->dev);

        free(sd->node);
        free(sd);
}

void session_device_complete_pause(SessionDevice *sd) {
        SessionDevice *iter;
        Iterator i;

        if (!sd->active)
                return;

        session_device_stop(sd);

        /* if not all devices are paused, wait for further completion events */
        HASHMAP_FOREACH(iter, sd->session->devices, i)
                if (iter->active)
                        return;

        /* complete any pending session switch */
        seat_complete_switch(sd->session->seat);
}

void session_device_resume_all(Session *s) {
        SessionDevice *sd;
        Iterator i;
        int r;

        assert(s);

        HASHMAP_FOREACH(sd, s->devices, i) {
                if (!sd->active) {
                        r = session_device_start(sd);
                        if (!r)
                                session_device_notify(sd, SESSION_DEVICE_RESUME);
                }
        }
}

void session_device_pause_all(Session *s) {
        SessionDevice *sd;
        Iterator i;

        assert(s);

        HASHMAP_FOREACH(sd, s->devices, i) {
                if (sd->active) {
                        session_device_stop(sd);
                        session_device_notify(sd, SESSION_DEVICE_PAUSE);
                }
        }
}

unsigned int session_device_try_pause_all(Session *s) {
        SessionDevice *sd;
        Iterator i;
        unsigned int num_pending = 0;

        assert(s);

        HASHMAP_FOREACH(sd, s->devices, i) {
                if (sd->active) {
                        session_device_notify(sd, SESSION_DEVICE_TRY_PAUSE);
                        ++num_pending;
                }
        }

        return num_pending;
}

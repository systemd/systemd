/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "daemon-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "logind.h"
#include "logind-device.h"
#include "logind-seat.h"
#include "logind-session.h"
#include "logind-session-dbus.h"
#include "logind-session-device.h"
#include "missing_drm.h"
#include "string-util.h"

enum SessionDeviceNotifications {
        SESSION_DEVICE_RESUME,
        SESSION_DEVICE_TRY_PAUSE,
        SESSION_DEVICE_PAUSE,
        SESSION_DEVICE_RELEASE,
};

static int session_device_notify(SessionDevice *sd, enum SessionDeviceNotifications type) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
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
                        type == SESSION_DEVICE_RESUME ? "ResumeDevice" : "PauseDevice");
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

static void sd_eviocrevoke(int fd) {
        static bool warned = false;

        assert(fd >= 0);

        if (!warned && ioctl(fd, EVIOCREVOKE, NULL) < 0) {
                if (errno == EINVAL) {
                        log_warning_errno(errno, "Kernel does not support evdev-revocation, continuing without revoking device access: %m");
                        warned = true;
                } else if (errno != ENODEV) {
                        log_warning_errno(errno, "Failed to revoke evdev device, continuing without revoking device access: %m");
                }
        }
}

static void sd_hidiocrevoke(int fd) {
        static bool warned = false;

        assert(fd >= 0);

        if (!warned && ioctl(fd, HIDIOCREVOKE, NULL) < 0) {
                if (errno == EINVAL) {
                        log_warning_errno(errno, "Kernel does not support hidraw-revocation, continuing without revoking device access: %m");
                        warned = true;
                } else if (errno != ENODEV)
                        log_warning_errno(errno, "Failed to revoke hidraw device, continuing without revoking device access: %m");
        }
}

static int sd_drmsetmaster(int fd) {
        assert(fd >= 0);
        return RET_NERRNO(ioctl(fd, DRM_IOCTL_SET_MASTER, 0));
}

static int sd_drmdropmaster(int fd) {
        assert(fd >= 0);
        return RET_NERRNO(ioctl(fd, DRM_IOCTL_DROP_MASTER, 0));
}

static int session_device_open(SessionDevice *sd, bool active) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(sd);
        assert(sd->type != DEVICE_TYPE_UNKNOWN);
        assert(sd->node);

        /* open device and try to get a udev_device from it */
        fd = open(sd->node, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        switch (sd->type) {

        case DEVICE_TYPE_DRM:
                if (active) {
                        /* Weird legacy DRM semantics might return an error even though we're master. No way to detect
                         * that so fail at all times and let caller retry in inactive state. */
                        r = sd_drmsetmaster(fd);
                        if (r < 0)
                                return r;
                } else
                        /* DRM-Master is granted to the first user who opens a device automatically (ughh,
                         * racy!). Hence, we just drop DRM-Master in case we were the first. */
                        (void) sd_drmdropmaster(fd);
                break;

        case DEVICE_TYPE_EVDEV:
                if (!active)
                        sd_eviocrevoke(fd);
                break;

        case DEVICE_TYPE_HIDRAW:
                if (!active)
                        sd_hidiocrevoke(fd);
                break;

        case DEVICE_TYPE_UNKNOWN:
        default:
                /* fallback for devices without synchronizations */
                ;
        }

        return TAKE_FD(fd);
}

static int session_device_start(SessionDevice *sd) {
        int r;

        assert(sd);
        assert(session_is_active(sd->session));

        if (sd->active)
                return 0;

        switch (sd->type) {

        case DEVICE_TYPE_DRM:
                if (sd->fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADF),
                                               "Failed to re-activate DRM fd, as the fd was lost (maybe logind restart went wrong?)");

                /* Device is kept open. Simply call drmSetMaster() and hope there is no-one else. In case it fails, we
                 * keep the device paused. Maybe at some point we have a drmStealMaster(). */
                r = sd_drmsetmaster(sd->fd);
                if (r < 0)
                        return r;
                break;

        case DEVICE_TYPE_EVDEV:
        case DEVICE_TYPE_HIDRAW:
                /* Evdev/hidraw devices are revoked while inactive. Reopen it and we are fine. */
                r = session_device_open(sd, true);
                if (r < 0)
                        return r;

                /* For evdev/hidraw devices, the file descriptor might be left uninitialized. This might happen while resuming
                 * into a session and logind has been restarted right before. */
                close_and_replace(sd->fd, r);
                break;

        case DEVICE_TYPE_UNKNOWN:
        default:
                /* fallback for devices without synchronizations */
                ;
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
                if (sd->fd < 0) {
                        log_error("Failed to de-activate DRM fd, as the fd was lost (maybe logind restart went wrong?)");
                        return;
                }

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

        case DEVICE_TYPE_HIDRAW:
                /* Revoke access on hidraw file-descriptors during deactivation.
                 * This will basically prevent any operations on the fd and
                 * cannot be undone. Good side is: it needs no CAP_SYS_ADMIN
                 * protection this way. */
                sd_hidiocrevoke(sd->fd);
                break;

        case DEVICE_TYPE_UNKNOWN:
        default:
                /* fallback for devices without synchronization */
                ;
        }

        sd->active = false;
}

static DeviceType detect_device_type(sd_device *dev) {
        if (device_in_subsystem(dev, "drm") > 0) {
                if (device_sysname_startswith(dev, "card") > 0)
                        return DEVICE_TYPE_DRM;
                return DEVICE_TYPE_UNKNOWN;
        }

        if (device_in_subsystem(dev, "input") > 0) {
                if (device_sysname_startswith(dev, "event") > 0)
                        return DEVICE_TYPE_EVDEV;
                return DEVICE_TYPE_UNKNOWN;
        }

        if (device_in_subsystem(dev, "hidraw") > 0) {
                if (device_sysname_startswith(dev, "hidraw") > 0)
                        return DEVICE_TYPE_HIDRAW;
                return DEVICE_TYPE_UNKNOWN;
        }

        return DEVICE_TYPE_UNKNOWN;
}

static int session_device_verify(SessionDevice *sd) {
        _cleanup_(sd_device_unrefp) sd_device *p = NULL;
        const char *sp, *node;
        sd_device *dev;
        int r;

        r = sd_device_new_from_devnum(&p, 'c', sd->dev);
        if (r < 0)
                return r;

        dev = p;

        if (sd_device_get_syspath(dev, &sp) < 0 ||
            sd_device_get_devname(dev, &node) < 0)
                return -EINVAL;

        /* detect device type so we can find the correct sysfs parent */
        sd->type = detect_device_type(dev);

        /* Prevent opening unsupported devices. Especially devices of
         * subsystem "input" must be opened via the evdev node as
         * we require EVIOCREVOKE. */
        switch (sd->type) {
        case DEVICE_TYPE_EVDEV:
                /* for evdev devices we need the parent node as device */
                if (sd_device_get_parent_with_subsystem_devtype(p, "input", NULL, &dev) < 0)
                        return -ENODEV;
                if (sd_device_get_syspath(dev, &sp) < 0)
                        return -ENODEV;
                break;

        case DEVICE_TYPE_DRM:
        case DEVICE_TYPE_HIDRAW:
                break;

        case  DEVICE_TYPE_UNKNOWN:
        default:
                return -ENODEV;
        }

        /* search for an existing seat device and return it if available */
        sd->device = hashmap_get(sd->session->manager->devices, sp);
        if (!sd->device) {
                /* The caller might have gotten the udev event before we were
                 * able to process it. Hence, fake the "add" event and let the
                 * logind-manager handle the new device. */
                r = manager_process_seat_device(sd->session->manager, dev);
                if (r < 0)
                        return r;

                /* if it's still not available, then the device is invalid */
                sd->device = hashmap_get(sd->session->manager->devices, sp);
                if (!sd->device)
                        return -ENODEV;
        }

        if (sd->device->seat != sd->session->seat)
                return -EPERM;

        return strdup_to(&sd->node, node);
}

int session_device_new(Session *s, dev_t dev, bool open_device, SessionDevice **ret) {
        SessionDevice *sd;
        int r;

        assert(s);

        if (!s->seat)
                return -EPERM;

        sd = new(SessionDevice, 1);
        if (!sd)
                return -ENOMEM;

        *sd = (SessionDevice) {
                .session = s,
                .dev = dev,
                .fd = -EBADF,
                .type = DEVICE_TYPE_UNKNOWN,
        };

        r = session_device_verify(sd);
        if (r < 0)
                goto error;

        r = hashmap_put(s->devices, &sd->dev, sd);
        if (r < 0)
                goto error;

        if (open_device) {
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
        }

        LIST_PREPEND(sd_by_device, sd->device->session_devices, sd);

        if (ret)
                *ret = sd;

        return 0;

error:
        hashmap_remove(s->devices, &sd->dev);
        free(sd->node);
        free(sd);
        return r;
}

SessionDevice *session_device_free(SessionDevice *sd) {
        if (!sd)
                return NULL;

        /* Make sure to remove the pushed fd. */
        if (sd->pushed_fd)
                (void) notify_remove_fd_warnf("session-%s-device-%u-%u", sd->session->id, major(sd->dev), minor(sd->dev));

        session_device_stop(sd);
        session_device_notify(sd, SESSION_DEVICE_RELEASE);
        safe_close(sd->fd);

        LIST_REMOVE(sd_by_device, sd->device->session_devices, sd);

        hashmap_remove(sd->session->devices, &sd->dev);

        free(sd->node);

        return mfree(sd);
}

void session_device_complete_pause(SessionDevice *sd) {
        SessionDevice *iter;

        if (!sd->active)
                return;

        session_device_stop(sd);

        /* if not all devices are paused, wait for further completion events */
        HASHMAP_FOREACH(iter, sd->session->devices)
                if (iter->active)
                        return;

        /* complete any pending session switch */
        seat_complete_switch(sd->session->seat);
}

void session_device_resume_all(Session *s) {
        SessionDevice *sd;

        assert(s);

        HASHMAP_FOREACH(sd, s->devices) {
                if (sd->active)
                        continue;

                if (session_device_start(sd) < 0)
                        continue;
                if (session_device_save(sd) < 0)
                        continue;

                session_device_notify(sd, SESSION_DEVICE_RESUME);
        }
}

void session_device_pause_all(Session *s) {
        SessionDevice *sd;

        assert(s);

        HASHMAP_FOREACH(sd, s->devices) {
                if (!sd->active)
                        continue;

                session_device_stop(sd);
                session_device_notify(sd, SESSION_DEVICE_PAUSE);
        }
}

unsigned session_device_try_pause_all(Session *s) {
        unsigned num_pending = 0;
        SessionDevice *sd;

        assert(s);

        HASHMAP_FOREACH(sd, s->devices) {
                if (!sd->active)
                        continue;

                session_device_notify(sd, SESSION_DEVICE_TRY_PAUSE);
                num_pending++;
        }

        return num_pending;
}

int session_device_save(SessionDevice *sd) {
        const char *id;
        int r;

        assert(sd);

        /* Store device fd in PID1. It will send it back to us on restart so revocation will continue to work. To make
         * things simple, send fds for all type of devices even if they don't support the revocation mechanism so we
         * don't have to handle them differently later.
         *
         * Note: for device supporting revocation, PID1 will drop a stored fd automatically if the corresponding device
         * is revoked. */

        if (sd->pushed_fd)
                return 0;

        /* Session ID does not contain separators. */
        id = sd->session->id;
        assert(*(id + strcspn(id, "-\n")) == '\0');

        r = notify_push_fdf(sd->fd, "session-%s-device-%u-%u", id, major(sd->dev), minor(sd->dev));
        if (r < 0)
                return r;

        sd->pushed_fd = true;
        return 1;
}

void session_device_attach_fd(SessionDevice *sd, int fd, bool active) {
        assert(fd >= 0);
        assert(sd);
        assert(sd->fd < 0);
        assert(!sd->active);

        sd->fd = fd;
        sd->pushed_fd = true;
        sd->active = active;
}

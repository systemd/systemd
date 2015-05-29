/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <fcntl.h>
#include <libevdev/libevdev.h>
#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include "sd-bus.h"
#include "sd-event.h"
#include "macro.h"
#include "util.h"
#include "bus-util.h"
#include "idev.h"
#include "idev-internal.h"

typedef struct idev_evdev idev_evdev;
typedef struct unmanaged_evdev unmanaged_evdev;
typedef struct managed_evdev managed_evdev;

struct idev_evdev {
        idev_element element;
        struct libevdev *evdev;
        int fd;
        sd_event_source *fd_src;
        sd_event_source *idle_src;

        bool unsync : 1;                /* not in-sync with kernel */
        bool resync : 1;                /* re-syncing with kernel */
        bool running : 1;
};

struct unmanaged_evdev {
        idev_evdev evdev;
        char *devnode;
};

struct managed_evdev {
        idev_evdev evdev;
        dev_t devnum;
        sd_bus_slot *slot_take_device;

        bool requested : 1;             /* TakeDevice() was sent */
        bool acquired : 1;              /* TakeDevice() was successful */
};

#define idev_evdev_from_element(_e) container_of((_e), idev_evdev, element)
#define unmanaged_evdev_from_element(_e) \
        container_of(idev_evdev_from_element(_e), unmanaged_evdev, evdev)
#define managed_evdev_from_element(_e) \
        container_of(idev_evdev_from_element(_e), managed_evdev, evdev)

#define IDEV_EVDEV_INIT(_vtable, _session) ((idev_evdev){ \
                .element = IDEV_ELEMENT_INIT((_vtable), (_session)), \
                .fd = -1, \
        })

#define IDEV_EVDEV_NAME_MAX (8 + DECIMAL_STR_MAX(unsigned) * 2)

static const idev_element_vtable unmanaged_evdev_vtable;
static const idev_element_vtable managed_evdev_vtable;

static int idev_evdev_resume(idev_evdev *evdev, int dev_fd);
static void idev_evdev_pause(idev_evdev *evdev, bool release);

/*
 * Virtual Evdev Element
 * The virtual evdev element is the base class of all other evdev elements. It
 * uses libevdev to access the kernel evdev API. It supports asynchronous
 * access revocation, re-syncing if events got dropped and more.
 * This element cannot be used by itself. There must be a wrapper around it
 * which opens a file-descriptor and passes it to the virtual evdev element.
 */

static void idev_evdev_name(char *out, dev_t devnum) {
        /* @out must be at least of size IDEV_EVDEV_NAME_MAX */
        sprintf(out, "evdev/%u:%u", major(devnum), minor(devnum));
}

static int idev_evdev_feed_resync(idev_evdev *evdev) {
        idev_data data = {
                .type = IDEV_DATA_RESYNC,
                .resync = evdev->resync,
        };

        return idev_element_feed(&evdev->element, &data);
}

static int idev_evdev_feed_evdev(idev_evdev *evdev, struct input_event *event) {
        idev_data data = {
                .type = IDEV_DATA_EVDEV,
                .resync = evdev->resync,
                .evdev = {
                        .event = *event,
                },
        };

        return idev_element_feed(&evdev->element, &data);
}

static void idev_evdev_hup(idev_evdev *evdev) {
        /*
         * On HUP, we close the current fd via idev_evdev_pause(). This drops
         * the event-sources from the main-loop and effectively puts the
         * element asleep. If the HUP is part of a hotplug-event, a following
         * udev-notification will destroy the element. Otherwise, the HUP is
         * either result of access-revokation or a serious error.
         * For unmanaged devices, we should never receive HUP (except for
         * unplug-events). But if we do, something went seriously wrong and we
         * shouldn't try to be clever.
         * Instead, we simply stay asleep and wait for the device to be
         * disabled and then re-enabled (or closed and re-opened). This will
         * re-open the device node and restart the device.
         * For managed devices, a HUP usually means our device-access was
         * revoked. In that case, we simply put the device asleep and wait for
         * logind to notify us once the device is alive again. logind also
         * passes us a new fd. Hence, we don't have to re-enable the device.
         *
         * Long story short: The only thing we have to do here, is close() the
         * file-descriptor and remove it from the main-loop. Everything else is
         * handled via additional events we receive.
         */

        idev_evdev_pause(evdev, true);
}

static int idev_evdev_io(idev_evdev *evdev) {
        idev_element *e = &evdev->element;
        struct input_event ev;
        unsigned int flags;
        int r, error = 0;

        /*
         * Read input-events via libevdev until the input-queue is drained. In
         * case we're disabled, don't do anything. The input-queue might
         * overflow, but we don't care as we have to resync after wake-up,
         * anyway.
         * TODO: libevdev should give us a hint how many events to read. We
         * really want to avoid starvation, so we shouldn't read forever in
         * case we cannot keep up with the kernel.
         * TODO: Make sure libevdev always reports SYN_DROPPED to us, regardless
         * whether any event was synced afterwards.
         */

        flags = LIBEVDEV_READ_FLAG_NORMAL;
        while (e->enabled) {
                if (evdev->unsync) {
                        /* immediately resync, even if in sync right now */
                        evdev->unsync = false;
                        evdev->resync = false;
                        flags = LIBEVDEV_READ_FLAG_NORMAL;
                        r = libevdev_next_event(evdev->evdev, flags | LIBEVDEV_READ_FLAG_FORCE_SYNC, &ev);
                        if (r < 0 && r != -EAGAIN) {
                                r = 0;
                                goto error;
                        } else if (r != LIBEVDEV_READ_STATUS_SYNC) {
                                log_debug("idev-evdev: %s/%s: cannot force resync: %d",
                                          e->session->name, e->name, r);
                        }
                } else {
                        r = libevdev_next_event(evdev->evdev, flags, &ev);
                }

                if (evdev->resync && r == -EAGAIN) {
                        /* end of re-sync */
                        evdev->resync = false;
                        flags = LIBEVDEV_READ_FLAG_NORMAL;
                } else if (r == -EAGAIN) {
                        /* no data available */
                        break;
                } else if (r < 0) {
                        /* read error */
                        goto error;
                } else if (r == LIBEVDEV_READ_STATUS_SYNC) {
                        if (evdev->resync) {
                                /* sync-event */
                                r = idev_evdev_feed_evdev(evdev, &ev);
                                if (r != 0) {
                                        error = r;
                                        break;
                                }
                        } else {
                                /* start of sync */
                                evdev->resync = true;
                                flags = LIBEVDEV_READ_FLAG_SYNC;
                                r = idev_evdev_feed_resync(evdev);
                                if (r != 0) {
                                        error = r;
                                        break;
                                }
                        }
                } else {
                        /* normal event */
                        r = idev_evdev_feed_evdev(evdev, &ev);
                        if (r != 0) {
                                error = r;
                                break;
                        }
                }
        }

        if (error < 0)
                log_debug_errno(error, "idev-evdev: %s/%s: error on data event: %m",
                                e->session->name, e->name);
        return error;

error:
        idev_evdev_hup(evdev);
        return 0; /* idev_evdev_hup() handles the error so discard it */
}

static int idev_evdev_event_fn(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        idev_evdev *evdev = userdata;

        /* fetch data as long as EPOLLIN is signalled */
        if (revents & EPOLLIN)
                return idev_evdev_io(evdev);

        if (revents & (EPOLLHUP | EPOLLERR))
                idev_evdev_hup(evdev);

        return 0;
}

static int idev_evdev_idle_fn(sd_event_source *s, void *userdata) {
        idev_evdev *evdev = userdata;

        /*
         * The idle-event is raised whenever we have to re-sync the libevdev
         * state from the kernel. We simply call into idev_evdev_io() which
         * flushes the state and re-syncs it if @unsync is set.
         * State has to be synced whenever our view of the kernel device is
         * out of date. This is the case when we open the device, if the
         * kernel's receive buffer overflows, or on other exceptional
         * situations. Events during re-syncs must be forwarded to the upper
         * layers so they can update their view of the device. However, such
         * events must only be handled passively, as they might be out-of-order
         * and/or re-ordered. Therefore, we mark them as 'sync' events.
         */

        if (!evdev->unsync)
                return 0;

        return idev_evdev_io(evdev);
}

static void idev_evdev_destroy(idev_evdev *evdev) {
        assert(evdev);
        assert(evdev->fd < 0);

        libevdev_free(evdev->evdev);
        evdev->evdev = NULL;
}

static void idev_evdev_enable(idev_evdev *evdev) {
        assert(evdev);
        assert(evdev->fd_src);
        assert(evdev->idle_src);

        if (evdev->running)
                return;
        if (evdev->fd < 0 || evdev->element.n_open < 1 || !evdev->element.enabled)
                return;

        evdev->running = true;
        sd_event_source_set_enabled(evdev->fd_src, SD_EVENT_ON);
        sd_event_source_set_enabled(evdev->idle_src, SD_EVENT_ONESHOT);
}

static void idev_evdev_disable(idev_evdev *evdev) {
        assert(evdev);
        assert(evdev->fd_src);
        assert(evdev->idle_src);

        if (!evdev->running)
                return;

        evdev->running = false;
        idev_evdev_feed_resync(evdev);
        sd_event_source_set_enabled(evdev->fd_src, SD_EVENT_OFF);
        sd_event_source_set_enabled(evdev->idle_src, SD_EVENT_OFF);
}

static int idev_evdev_resume(idev_evdev *evdev, int dev_fd) {
        idev_element *e = &evdev->element;
        _cleanup_close_ int fd = dev_fd;
        int r, flags;

        if (fd < 0 || evdev->fd == fd) {
                fd = -1;
                idev_evdev_enable(evdev);
                return 0;
        }

        idev_evdev_pause(evdev, true);
        log_debug("idev-evdev: %s/%s: resume", e->session->name, e->name);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = fd_cloexec(fd, true);
        if (r < 0)
                return r;

        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
                return -errno;

        flags &= O_ACCMODE;
        if (flags == O_WRONLY)
                return -EACCES;

        evdev->element.readable = true;
        evdev->element.writable = !(flags & O_RDONLY);

        /*
         * TODO: We *MUST* re-sync the device so we get a delta of the changed
         * state while we didn't read events from the device. This works just
         * fine with libevdev_change_fd(), however, libevdev_new_from_fd() (or
         * libevdev_set_fd()) don't pass us events for the initial device
         * state. So even if we force a re-sync, we will not get the delta for
         * the initial device state.
         * We really need to fix libevdev to support that!
         */
        if (evdev->evdev)
                r = libevdev_change_fd(evdev->evdev, fd);
        else
                r = libevdev_new_from_fd(fd, &evdev->evdev);

        if (r < 0)
                return r;

        r = sd_event_add_io(e->session->context->event,
                            &evdev->fd_src,
                            fd,
                            EPOLLHUP | EPOLLERR | EPOLLIN,
                            idev_evdev_event_fn,
                            evdev);
        if (r < 0)
                return r;

        r = sd_event_add_defer(e->session->context->event,
                               &evdev->idle_src,
                               idev_evdev_idle_fn,
                               evdev);
        if (r < 0) {
                evdev->fd_src = sd_event_source_unref(evdev->fd_src);
                return r;
        }

        sd_event_source_set_enabled(evdev->fd_src, SD_EVENT_OFF);
        sd_event_source_set_enabled(evdev->idle_src, SD_EVENT_OFF);

        evdev->unsync = true;
        evdev->fd = fd;
        fd = -1;

        idev_evdev_enable(evdev);
        return 0;
}

static void idev_evdev_pause(idev_evdev *evdev, bool release) {
        idev_element *e = &evdev->element;

        if (evdev->fd < 0)
                return;

        log_debug("idev-evdev: %s/%s: pause", e->session->name, e->name);

        idev_evdev_disable(evdev);
        if (release) {
                evdev->idle_src = sd_event_source_unref(evdev->idle_src);
                evdev->fd_src = sd_event_source_unref(evdev->fd_src);
                evdev->fd = safe_close(evdev->fd);
        }
}

/*
 * Unmanaged Evdev Element
 * The unmanaged evdev element opens the evdev node for a given input device
 * directly (/dev/input/eventX) and thus needs sufficient privileges. It opens
 * the device only if we really require it and releases it as soon as we're
 * disabled or closed.
 * The unmanaged element can be used in all situations where you have direct
 * access to input device nodes. Unlike managed evdev elements, it can be used
 * outside of user sessions and in emergency situations where logind is not
 * available.
 */

static void unmanaged_evdev_resume(idev_element *e) {
        unmanaged_evdev *eu = unmanaged_evdev_from_element(e);
        int r, fd;

        /*
         * Unmanaged devices can be acquired on-demand. Therefore, don't
         * acquire it unless someone opened the device *and* we're enabled.
         */
        if (e->n_open < 1 || !e->enabled)
                return;

        fd = eu->evdev.fd;
        if (fd < 0) {
                fd = open(eu->devnode, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
                if (fd < 0) {
                        if (errno != EACCES && errno != EPERM) {
                                log_debug_errno(errno, "idev-evdev: %s/%s: cannot open node %s: %m",
                                                e->session->name, e->name, eu->devnode);
                                return;
                        }

                        fd = open(eu->devnode, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
                        if (fd < 0) {
                                log_debug_errno(errno, "idev-evdev: %s/%s: cannot open node %s: %m",
                                                e->session->name, e->name, eu->devnode);
                                return;
                        }

                        e->readable = true;
                        e->writable = false;
                } else {
                        e->readable = true;
                        e->writable = true;
                }
        }

        r = idev_evdev_resume(&eu->evdev, fd);
        if (r < 0)
                log_debug_errno(r, "idev-evdev: %s/%s: cannot resume: %m",
                                e->session->name, e->name);
}

static void unmanaged_evdev_pause(idev_element *e) {
        unmanaged_evdev *eu = unmanaged_evdev_from_element(e);

        /*
         * Release the device if the device is disabled or there is no-one who
         * opened it. This guarantees we stay only available if we're opened
         * *and* enabled.
         */

        idev_evdev_pause(&eu->evdev, true);
}

static int unmanaged_evdev_new(idev_element **out, idev_session *s, struct udev_device *ud) {
        _cleanup_(idev_element_freep) idev_element *e = NULL;
        char name[IDEV_EVDEV_NAME_MAX];
        unmanaged_evdev *eu;
        const char *devnode;
        dev_t devnum;
        int r;

        assert_return(s, -EINVAL);
        assert_return(ud, -EINVAL);

        devnode = udev_device_get_devnode(ud);
        devnum = udev_device_get_devnum(ud);
        if (!devnode || devnum == 0)
                return -ENODEV;

        idev_evdev_name(name, devnum);

        eu = new0(unmanaged_evdev, 1);
        if (!eu)
                return -ENOMEM;

        e = &eu->evdev.element;
        eu->evdev = IDEV_EVDEV_INIT(&unmanaged_evdev_vtable, s);

        eu->devnode = strdup(devnode);
        if (!eu->devnode)
                return -ENOMEM;

        r = idev_element_add(e, name);
        if (r < 0)
                return r;

        if (out)
                *out = e;
        e = NULL;
        return 0;
}

static void unmanaged_evdev_free(idev_element *e) {
        unmanaged_evdev *eu = unmanaged_evdev_from_element(e);

        idev_evdev_destroy(&eu->evdev);
        free(eu->devnode);
        free(eu);
}

static const idev_element_vtable unmanaged_evdev_vtable = {
        .free                   = unmanaged_evdev_free,
        .enable                 = unmanaged_evdev_resume,
        .disable                = unmanaged_evdev_pause,
        .open                   = unmanaged_evdev_resume,
        .close                  = unmanaged_evdev_pause,
};

/*
 * Managed Evdev Element
 * The managed evdev element uses systemd-logind to acquire evdev devices. This
 * means, we do not open the device node /dev/input/eventX directly. Instead,
 * logind passes us a file-descriptor whenever our session is activated. Thus,
 * we don't need access to the device node directly.
 * Furthermore, whenever the session is put asleep, logind revokes the
 * file-descriptor so we loose access to the device.
 * Managed evdev elements should be preferred over unmanaged elements whenever
 * you run inside a user session with exclusive device access.
 */

static int managed_evdev_take_device_fn(sd_bus_message *reply,
                                        void *userdata,
                                        sd_bus_error *ret_error) {
        managed_evdev *em = userdata;
        idev_element *e = &em->evdev.element;
        idev_session *s = e->session;
        int r, paused, fd;

        em->slot_take_device = sd_bus_slot_unref(em->slot_take_device);

        if (sd_bus_message_is_method_error(reply, NULL)) {
                const sd_bus_error *error = sd_bus_message_get_error(reply);

                log_debug("idev-evdev: %s/%s: TakeDevice failed: %s: %s",
                          s->name, e->name, error->name, error->message);
                return 0;
        }

        em->acquired = true;

        r = sd_bus_message_read(reply, "hb", &fd, &paused);
        if (r < 0) {
                log_debug("idev-evdev: %s/%s: erroneous TakeDevice reply", s->name, e->name);
                return 0;
        }

        /* If the device is paused, ignore it; we will get the next fd via
         * ResumeDevice signals. */
        if (paused)
                return 0;

        fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0) {
                log_debug_errno(errno, "idev-evdev: %s/%s: cannot duplicate evdev fd: %m", s->name, e->name);
                return 0;
        }

        r = idev_evdev_resume(&em->evdev, fd);
        if (r < 0)
                log_debug_errno(r, "idev-evdev: %s/%s: cannot resume: %m",
                                s->name, e->name);

        return 0;
}

static void managed_evdev_enable(idev_element *e) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        managed_evdev *em = managed_evdev_from_element(e);
        idev_session *s = e->session;
        idev_context *c = s->context;
        int r;

        /*
         * Acquiring managed devices is heavy, so do it only once we're
         * enabled *and* opened by someone.
         */
        if (e->n_open < 1 || !e->enabled)
                return;

        /* bail out if already pending */
        if (em->requested)
                return;

        r = sd_bus_message_new_method_call(c->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           s->path,
                                           "org.freedesktop.login1.Session",
                                           "TakeDevice");
        if (r < 0)
                goto error;

        r = sd_bus_message_append(m, "uu", major(em->devnum), minor(em->devnum));
        if (r < 0)
                goto error;

        r = sd_bus_call_async(c->sysbus,
                              &em->slot_take_device,
                              m,
                              managed_evdev_take_device_fn,
                              em,
                              0);
        if (r < 0)
                goto error;

        em->requested = true;
        return;

error:
        log_debug_errno(r, "idev-evdev: %s/%s: cannot send TakeDevice request: %m",
                        s->name, e->name);
}

static void managed_evdev_disable(idev_element *e) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        managed_evdev *em = managed_evdev_from_element(e);
        idev_session *s = e->session;
        idev_context *c = s->context;
        int r;

        /*
         * Releasing managed devices is heavy. Once acquired, we get
         * notifications for sleep/wake-up events, so there's no reason to
         * release it if disabled but opened. However, if a device is closed,
         * we release it immediately as we don't care for sleep/wake-up events
         * then (even if we're actually enabled).
         */

        idev_evdev_pause(&em->evdev, false);

        if (e->n_open > 0 || !em->requested)
                return;

        /*
         * If TakeDevice() is pending or was successful, make sure to
         * release the device again. We don't care for return-values,
         * so send it without waiting or callbacks.
         * If a failed TakeDevice() is pending, but someone else took
         * the device on the same bus-connection, we might incorrectly
         * release their device. This is an unlikely race, though.
         * Furthermore, you really shouldn't have two users of the
         * controller-API on the same session, on the same devices, *AND* on
         * the same bus-connection. So we don't care for that race..
         */

        idev_evdev_pause(&em->evdev, true);
        em->requested = false;

        if (!em->acquired && !em->slot_take_device)
                return;

        em->slot_take_device = sd_bus_slot_unref(em->slot_take_device);
        em->acquired = false;

        r = sd_bus_message_new_method_call(c->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           s->path,
                                           "org.freedesktop.login1.Session",
                                           "ReleaseDevice");
        if (r >= 0) {
                r = sd_bus_message_append(m, "uu", major(em->devnum), minor(em->devnum));
                if (r >= 0)
                        r = sd_bus_send(c->sysbus, m, NULL);
        }

        if (r < 0 && r != -ENOTCONN)
                log_debug_errno(r, "idev-evdev: %s/%s: cannot send ReleaseDevice: %m",
                                s->name, e->name);
}

static void managed_evdev_resume(idev_element *e, int fd) {
        managed_evdev *em = managed_evdev_from_element(e);
        idev_session *s = e->session;
        int r;

        /*
         * We get ResumeDevice signals whenever logind resumed a previously
         * paused device. The arguments contain the major/minor number of the
         * related device and a new file-descriptor for the freshly opened
         * device-node. We take the file-descriptor and immediately resume the
         * device.
         */

        fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0) {
                log_debug_errno(errno, "idev-evdev: %s/%s: cannot duplicate evdev fd: %m",
                                s->name, e->name);
                return;
        }

        r = idev_evdev_resume(&em->evdev, fd);
        if (r < 0)
                log_debug_errno(r, "idev-evdev: %s/%s: cannot resume: %m",
                                s->name, e->name);

        return;
}

static void managed_evdev_pause(idev_element *e, const char *mode) {
        managed_evdev *em = managed_evdev_from_element(e);
        idev_session *s = e->session;
        idev_context *c = s->context;
        int r;

        /*
         * We get PauseDevice() signals from logind whenever a device we
         * requested was, or is about to be, paused. Arguments are major/minor
         * number of the device and the mode of the operation.
         * We treat it as asynchronous access-revocation (as if we got HUP on
         * the device fd). Note that we might have already treated the HUP
         * event via EPOLLHUP, whichever comes first.
         *
         * @mode can be one of the following:
         *   "pause": The device is about to be paused. We must react
         *            immediately and respond with PauseDeviceComplete(). Once
         *            we replied, logind will pause the device. Note that
         *            logind might apply any kind of timeout and force pause
         *            the device if we don't respond in a timely manner. In
         *            this case, we will receive a second PauseDevice event
         *            with @mode set to "force" (or similar).
         *   "force": The device was disabled forecfully by logind. Access is
         *            already revoked. This is just an asynchronous
         *            notification so we can put the device asleep (in case
         *            we didn't already notice the access revocation).
         *    "gone": This is like "force" but is sent if the device was
         *            paused due to a device-removal event.
         *
         * We always handle PauseDevice signals as "force" as we properly
         * support asynchronous access revocation, anyway. But in case logind
         * sent mode "pause", we also call PauseDeviceComplete() to immediately
         * acknowledge the request.
         */

        idev_evdev_pause(&em->evdev, true);

        if (streq(mode, "pause")) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                /*
                 * Sending PauseDeviceComplete() is racy if logind triggers the
                 * timeout. That is, if we take too long and logind pauses the
                 * device by sending a forced PauseDevice, our
                 * PauseDeviceComplete call will be stray. That's fine, though.
                 * logind ignores such stray calls. Only if logind also sent a
                 * further PauseDevice() signal, it might match our call
                 * incorrectly to the newer PauseDevice(). That's fine, too, as
                 * we handle that event asynchronously, anyway. Therefore,
                 * whatever happens, we're fine. Yay!
                 */

                r = sd_bus_message_new_method_call(c->sysbus,
                                                   &m,
                                                   "org.freedesktop.login1",
                                                   s->path,
                                                   "org.freedesktop.login1.Session",
                                                   "PauseDeviceComplete");
                if (r >= 0) {
                        r = sd_bus_message_append(m, "uu", major(em->devnum), minor(em->devnum));
                        if (r >= 0)
                                r = sd_bus_send(c->sysbus, m, NULL);
                }

                if (r < 0)
                        log_debug_errno(r, "idev-evdev: %s/%s: cannot send PauseDeviceComplete: %m",
                                        s->name, e->name);
        }
}

static int managed_evdev_new(idev_element **out, idev_session *s, struct udev_device *ud) {
        _cleanup_(idev_element_freep) idev_element *e = NULL;
        char name[IDEV_EVDEV_NAME_MAX];
        managed_evdev *em;
        dev_t devnum;
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->managed, -EINVAL);
        assert_return(s->context->sysbus, -EINVAL);
        assert_return(ud, -EINVAL);

        devnum = udev_device_get_devnum(ud);
        if (devnum == 0)
                return -ENODEV;

        idev_evdev_name(name, devnum);

        em = new0(managed_evdev, 1);
        if (!em)
                return -ENOMEM;

        e = &em->evdev.element;
        em->evdev = IDEV_EVDEV_INIT(&managed_evdev_vtable, s);
        em->devnum = devnum;

        r = idev_element_add(e, name);
        if (r < 0)
                return r;

        if (out)
                *out = e;
        e = NULL;
        return 0;
}

static void managed_evdev_free(idev_element *e) {
        managed_evdev *em = managed_evdev_from_element(e);

        idev_evdev_destroy(&em->evdev);
        free(em);
}

static const idev_element_vtable managed_evdev_vtable = {
        .free                   = managed_evdev_free,
        .enable                 = managed_evdev_enable,
        .disable                = managed_evdev_disable,
        .open                   = managed_evdev_enable,
        .close                  = managed_evdev_disable,
        .resume                 = managed_evdev_resume,
        .pause                  = managed_evdev_pause,
};

/*
 * Generic Constructor
 * Instead of relying on the caller to choose between managed and unmanaged
 * evdev devices, the idev_evdev_new() constructor does that for you (by
 * looking at s->managed).
 */

bool idev_is_evdev(idev_element *e) {
        return e && (e->vtable == &unmanaged_evdev_vtable ||
                     e->vtable == &managed_evdev_vtable);
}

idev_element *idev_find_evdev(idev_session *s, dev_t devnum) {
        char name[IDEV_EVDEV_NAME_MAX];

        assert_return(s, NULL);
        assert_return(devnum != 0, NULL);

        idev_evdev_name(name, devnum);
        return idev_find_element(s, name);
}

int idev_evdev_new(idev_element **out, idev_session *s, struct udev_device *ud) {
        assert_return(s, -EINVAL);
        assert_return(ud, -EINVAL);

        return s->managed ? managed_evdev_new(out, s, ud) : unmanaged_evdev_new(out, s, ud);
}

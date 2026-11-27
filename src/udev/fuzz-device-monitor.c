/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the uevent receive path: the libudev/kernel monitor header and sender validation of
 * sd_device_monitor_receive(), device_new_from_nulstr() and device_verify(), and what udevd does with
 * received devices and with the notifications of its workers: event_queue_insert(), event_find_blocker(),
 * event_enter_locked() via on_worker_notify(), and the requeueing of locked events.
 *
 * The monitor's socket is an AF_UNIX socket. The uevents are sent to it from AF_UNIX sockets bound to
 * addresses that sd_device_monitor_receive() takes for the netlink address of the kernel or of udevd (see
 * fuzz_bind_netlink_address()), with the credentials the kernel attaches (SO_PASSCRED), or explicit ones,
 * which need privileges (CAP_SETUID) for other UIDs than our own. Without them, such uevents are skipped.
 *
 * Worker notifications are sent over an AF_UNIX socketpair to on_worker_notify(), with a fake worker that
 * has our own PID. Notifications that would make udevd add or remove inotify watches (which writes to
 * /run/udev/watch) or broadcast a failed event (which deletes /run/udev/data and /run/udev/tags entries and
 * sends a netlink message) are skipped.
 *
 * Input: one byte of flags (bits 0-6: monitor filters, bit 7: stop the exec queue as with
 * "udevadm control --stop-exec-queue"), then records of [type][length (le16)][payload]. The low three
 * bits of the type select the record kind (see below, modulo _RECORD_MAX); for datagrams bit 3 spoofs the
 * sender's port ID, bits 4-5 select the sender's credentials (the ones the kernel attaches, our own UID,
 * UID 65534, or UID 0, which needs CAP_SETUID unless we are root), and bit 6 sets USEC_INITIALIZED as udevd
 * does for kernel uevents. For requeue records bit 3 lets the requeue interval of all locked events elapse
 * first (see expire_locked_events()). */

#include "sd-event.h"

#include "alloc-util.h"
#include "constants.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fuzz.h"
#include "fuzz-network.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "pidref.h"
#include "prioq.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "unaligned.h"
#include "user-util.h"

/* For its static functions: event_queue_insert(), event_find_blocker(), manager_requeue_locked_events() and
 * on_worker_notify() (see the udev meson.build) */
#include "udev-manager.c"

#define MAX_RECORDS 64U

enum {
        RECORD_KERNEL,          /* multicast from the kernel */
        RECORD_UDEV,            /* multicast from udevd */
        RECORD_NOTIFY,          /* notification from a worker */
        RECORD_REQUEUE,         /* requeue locked events */
        _RECORD_MAX,
};

static void exercise_device(sd_device *dev) {
        sd_device_action_t action;
        const char *s, *nulstr;
        sd_id128_t uuid;
        dev_t devnum;
        size_t n = 0, len;
        char **strv;
        uint64_t u;
        mode_t mode;
        uid_t uid;
        gid_t gid;
        int i;

        /* Getters that work on the data received over the monitor only: none of them reads sysfs or the udev
         * database for a sealed device. sd_device_get_driver() and the sysattr functions would read sysfs,
         * so they are not called. */
        (void) sd_device_get_syspath(dev, &s);
        (void) sd_device_get_devpath(dev, &s);
        (void) sd_device_get_sysname(dev, &s);
        (void) sd_device_get_sysnum(dev, &s);
        (void) sd_device_get_subsystem(dev, &s);
        (void) sd_device_get_driver_subsystem(dev, &s);
        (void) sd_device_get_devtype(dev, &s);
        (void) sd_device_get_devname(dev, &s);
        (void) sd_device_get_devnum(dev, &devnum);
        (void) sd_device_get_ifindex(dev, &i);
        (void) sd_device_get_seqnum(dev, &u);
        (void) sd_device_get_diskseq(dev, &u);
        (void) sd_device_get_device_id(dev, &s);
        (void) sd_device_get_is_initialized(dev);
        (void) sd_device_get_usec_initialized(dev, &u);
        (void) sd_device_get_action(dev, &action);
        (void) sd_device_get_trigger_uuid(dev, &uuid);
        (void) device_get_devnode_mode(dev, &mode);
        (void) device_get_devnode_uid(dev, &uid);
        (void) device_get_devnode_gid(dev, &gid);

        (void) device_get_property_bool(dev, "ID_FOO");
        (void) device_get_property_int(dev, "IFINDEX", &i);
        (void) sd_device_get_property_value(dev, "DEVPATH_OLD", &s);
        (void) sd_device_has_tag(dev, "systemd");
        (void) sd_device_has_current_tag(dev, "systemd");
        (void) device_should_have_db(dev);

        FOREACH_DEVICE_PROPERTY(dev, key, value)
                n += strlen(key) + strlen(value);
        FOREACH_DEVICE_TAG(dev, tag)
                n += strlen(tag);
        FOREACH_DEVICE_CURRENT_TAG(dev, tag)
                n += strlen(tag);
        FOREACH_DEVICE_DEVLINK(dev, devlink)
                n += strlen(devlink);
        DO_NOT_OPTIMIZE(n);

        /* Serialize the device again, as udevd does when it passes it to a worker or stores it in the fd
         * store, and parse the result. */
        if (device_get_properties_nulstr(dev, &nulstr, &len) >= 0 && len > 0) {
                _cleanup_free_ char *copy = ASSERT_NOT_NULL(memdup(nulstr, len));
                _cleanup_(sd_device_unrefp) sd_device *d = NULL;

                (void) device_new_from_nulstr(&d, copy, len);
        }

        if (device_get_properties_strv(dev, &strv) >= 0) {
                _cleanup_strv_free_ char **copy = ASSERT_NOT_NULL(strv_copy(strv));
                _cleanup_(sd_device_unrefp) sd_device *d = NULL;

                if (device_new_from_strv(&d, copy) >= 0) {
                        (void) device_copy_all_tags(d, dev);
                        (void) device_cleanup_tags(d, dev);
                        device_cleanup_devlinks(d);
                }
        }
}

static bool device_needs_sysfs_for_whole_disk(sd_device *dev) {
        /* udev_get_whole_disk() looks up the parent of partitions in sysfs. */
        return device_in_subsystem(dev, "block") > 0 && device_is_devtype(dev, "disk") <= 0;
}

static void find_blockers(Manager *manager) {
        LIST_FOREACH(event, event, manager->events)
                if (event->state == EVENT_QUEUED)
                        event_find_blocker(event);
}

static Event* find_runnable_event(Manager *manager) {
        LIST_FOREACH(event, event, manager->events)
                if (event->state == EVENT_QUEUED && !event->blocker)
                        return event;

        return NULL;
}

static void expire_locked_events(Manager *manager) {
        Event *event;

        /* udevd requeues locked events once EVENT_REQUEUE_INTERVAL_USEC has passed since they were locked,
         * which never happens within the run of one input. Pretend it did. All keys become equal, hence
         * the priority queue stays valid. The requeue timeout is left alone: when it is exceeded,
         * on_worker_notify() broadcasts the failed event, which needs a real monitor and touches
         * /run/udev/. */
        PRIOQ_FOREACH_ITEM(manager->locked_events_by_time, event)
                event->requeue_next_usec = 0;
}

static bool notify_is_safe(const char *text) {
        _cleanup_strv_free_ char **l = NULL;

        /* Mirror the checks in on_worker_notify(): these requests modify /run/udev/ or send netlink
         * messages, which a fuzzer must not do. */
        if (strv_split_newlines_full(&l, text, EXTRACT_RETAIN_ESCAPE) < 0)
                return false;
        if (strv_contains(l, "INOTIFY_WATCH_ADD=1") || strv_contains(l, "INOTIFY_WATCH_REMOVE=1"))
                return false;
        if (strv_contains(l, "TRY_AGAIN=1") && isempty(strv_find_startswith(l, "WHOLE_DISK=")))
                return false;

        return true;
}

static void process_notify(
                Manager *manager,
                Worker *worker,
                const int notify_fds[static 2],
                const uint8_t *p,
                size_t len) {

        _cleanup_free_ char *text = NULL;

        if (len == 0 || len > NOTIFY_BUFFER_MAX)
                return;

        text = ASSERT_NOT_NULL(strndup((const char*) p, len));
        if (!notify_is_safe(text))
                return;

        if (!worker->event) {
                Event *event;

                /* Pretend the worker got an event to process, as worker_attach_event() does. */
                find_blockers(manager);
                event = find_runnable_event(manager);
                if (!event)
                        return;

                worker->state = WORKER_RUNNING;
                worker->event = event;
                event->state = EVENT_RUNNING;
                event->worker = worker;
        }

        if (send(notify_fds[0], p, len, MSG_DONTWAIT) < 0)
                return;

        (void) on_worker_notify(/* s= */ NULL, notify_fds[1], EPOLLIN, manager);

        /* Drain anything on_worker_notify() did not consume. */
        (void) flush_fd(notify_fds[1]);

        /* After a worker finished, on_post() calls event_queue_start(), which looks up the blockers of all
         * queued events again. It does not do that while the queue is stopped (udevadm control
         * --stop-exec-queue, bit 7 of the flags byte). */
        if (!manager->stop_exec_queue)
                find_blockers(manager);
}

static void process_datagram(
                Manager *manager,
                sd_device_monitor *monitor,
                const union sockaddr_union *monitor_address,
                socklen_t monitor_address_size,
                unsigned kind,
                uint8_t type,
                const uint8_t *p,
                size_t len) {

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_close_ int fd = -EBADF;
        bool from_kernel = kind == RECORD_KERNEL, spoofed = FLAGS_SET(type, 1 << 3);
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control = {};
        struct iovec iov = IOVEC_MAKE((void*) p, len);
        struct msghdr mh = {
                .msg_name = (void*) monitor_address,
                .msg_namelen = monitor_address_size,
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        uid_t uid;
        int r;

        /* The kernel sends from port ID 0, udevd from its own, a spoofed sender the other way round */
        fd = ASSERT_OK_ERRNO(socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0));
        ASSERT_OK(fuzz_bind_netlink_address(fd,
                                            /* nl_pid= */ from_kernel != spoofed ? 0 : 4242,
                                            from_kernel ? MONITOR_GROUP_KERNEL : MONITOR_GROUP_UDEV));

        /* By default the kernel attaches our own credentials, which the monitor trusts whether we run as
         * root or not, so that the corpus is fully exercised by unprivileged test runs too. */
        switch ((type >> 4) & 0x03) {
        case 0:
                uid = UID_INVALID;
                break;
        case 1:
                uid = getuid();
                break;
        case 2:
                uid = UID_NOBODY;
                break;
        default:
                uid = 0;
        }

        if (uid_is_valid(uid)) {
                struct cmsghdr *cmsg;

                mh.msg_control = &control;
                mh.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&mh);
                *cmsg = (struct cmsghdr) {
                        .cmsg_level = SOL_SOCKET,
                        .cmsg_type = SCM_CREDENTIALS,
                        .cmsg_len = CMSG_LEN(sizeof(struct ucred)),
                };
                *CMSG_TYPED_DATA(cmsg, struct ucred) = (struct ucred) {
                        .pid = getpid_cached(),
                        .uid = uid,
                        .gid = getgid(),
                };
        }

        if (sendmsg(fd, &mh, MSG_DONTWAIT) < 0)
                return;

        r = sd_device_monitor_receive(monitor, &dev);

        /* Drop the datagram if it wasn't taken */
        (void) flush_fd(sd_device_monitor_get_fd(monitor));

        if (r <= 0)
                return;

        exercise_device(dev);

        if (FLAGS_SET(type, 1 << 6))
                (void) device_ensure_usec_initialized(dev, /* device_old= */ NULL);

        /* This is what udevd does with received uevents, and with events read back from the fd store. */
        if (event_queue_insert(manager, dev) < 0)
                return;

        if (!device_needs_sysfs_for_whole_disk(dev))
                (void) manager_requeue_locked_events_by_device(manager, dev);

        find_blockers(manager);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        _cleanup_close_pair_ int notify_fds[2] = EBADF_PAIR;
        _cleanup_close_ int monitor_fd = -EBADF;
        _cleanup_(worker_freep) Worker *worker = NULL;
        union sockaddr_union monitor_address;
        socklen_t monitor_address_size = sizeof(monitor_address);
        uint8_t flags;

        if (outside_size_range(size, 1, 65536))
                return 0;

        fuzz_forbid_network();
        fuzz_setup_logging();

        flags = data[0];
        data++;
        size--;

        /* The monitor's socket, see above. Its address reads as a netlink address too, as the monitor takes
         * its port ID from it. */
        monitor_fd = ASSERT_OK_ERRNO(socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        ASSERT_OK(setsockopt_int(monitor_fd, SOL_SOCKET, SO_PASSCRED, /* value= */ true));
        ASSERT_OK(fuzz_bind_netlink_address(monitor_fd, /* nl_pid= */ getpid_cached(), MONITOR_GROUP_NONE));
        ASSERT_OK_ERRNO(getsockname(monitor_fd, &monitor_address.sa, &monitor_address_size));
        ASSERT_OK(device_monitor_new_full(&monitor, MONITOR_GROUP_NONE, TAKE_FD(monitor_fd)));

        if (FLAGS_SET(flags, 1 << 0))
                ASSERT_OK(sd_device_monitor_filter_add_match_subsystem_devtype(
                                          monitor, "block", FLAGS_SET(flags, 1 << 1) ? "disk" : NULL));
        if (FLAGS_SET(flags, 1 << 2))
                ASSERT_OK(sd_device_monitor_filter_add_match_subsystem_devtype(
                                monitor, "net", /* devtype= */ NULL));
        if (FLAGS_SET(flags, 1 << 3))
                ASSERT_OK(sd_device_monitor_filter_add_match_tag(monitor, "systemd"));
        if (FLAGS_SET(flags, 1 << 4))
                ASSERT_OK(sd_device_monitor_filter_add_match_tag(monitor, "seat"));
        if (FLAGS_SET(flags, 1 << 5))
                (void) sd_device_monitor_filter_update(monitor);
        if (FLAGS_SET(flags, 1 << 6))
                (void) sd_device_monitor_filter_remove(monitor);

        manager = ASSERT_NOT_NULL(manager_new());
        ASSERT_OK(sd_event_new(&manager->event));
        manager->queue_file_created = true; /* never touch /run/udev/queue */
        manager->stop_exec_queue = FLAGS_SET(flags, 1 << 7);

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, notify_fds));
        ASSERT_OK(setsockopt_int(notify_fds[1], SOL_SOCKET, SO_PASSCRED, /* value= */ true));
        (void) setsockopt_int(notify_fds[1], SOL_SOCKET, SO_PASSPIDFD, /* value= */ true);

        /* A worker with our own PID, so that the notifications we send are attributed to it. Not owned by
         * the hashmap, worker_free() removes it from there and detaches its event. */
        worker = ASSERT_NOT_NULL(new(Worker, 1));
        *worker = (Worker) {
                .manager = manager,
                .pidref = PIDREF_MAKE_FROM_PID(getpid_cached()),
                .state = WORKER_IDLE,
        };
        ASSERT_OK_POSITIVE(hashmap_ensure_put(&manager->workers, &pidref_hash_ops, &worker->pidref, worker));

        for (unsigned n_records = 0; size >= 3 && n_records < MAX_RECORDS; n_records++) {
                uint8_t type = data[0];
                unsigned kind = (type & 0x07) % _RECORD_MAX;
                size_t len = MIN((size_t) unaligned_read_le16(data + 1), size - 3);
                const uint8_t *p = data + 3;

                data += 3 + len;
                size -= 3 + len;

                switch (kind) {
                case RECORD_KERNEL:
                case RECORD_UDEV:
                        process_datagram(manager, monitor, &monitor_address, monitor_address_size,
                                         kind, type, p, len);
                        break;
                case RECORD_NOTIFY:
                        process_notify(manager, worker, notify_fds, p, len);
                        break;
                case RECORD_REQUEUE:
                        if (FLAGS_SET(type, 1 << 3))
                                expire_locked_events(manager);
                        (void) manager_requeue_locked_events(manager);
                        break;
                }
        }

        return 0;
}

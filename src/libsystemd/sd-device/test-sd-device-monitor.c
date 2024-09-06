/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"

#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "io-util.h"
#include "macro.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "virt.h"

static void prepare_loopback(sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class/net/lo"));
        ASSERT_OK(device_add_property(dev, "ACTION", "add"));
        ASSERT_OK(device_add_property(dev, "SEQNUM", "10"));
        ASSERT_OK(device_add_tag(dev, "TEST_SD_DEVICE_MONITOR", true));

        *ret = TAKE_PTR(dev);
}

static int prepare_sda(sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        r = sd_device_new_from_subsystem_sysname(&dev, "block", "sda");
        if (r < 0)
                return r;

        ASSERT_OK(device_add_property(dev, "ACTION", "change"));
        ASSERT_OK(device_add_property(dev, "SEQNUM", "11"));

        *ret = TAKE_PTR(dev);
        return 0;
}

static int monitor_handler(sd_device_monitor *m, sd_device *d, void *userdata) {
        const char *s, *syspath = userdata;

        ASSERT_OK(sd_device_get_syspath(d, &s));
        ASSERT_STREQ(s, syspath);

        return sd_event_exit(sd_device_monitor_get_event(m), 100);
}

static void prepare_monitor(sd_device_monitor **ret_server, sd_device_monitor **ret_client, union sockaddr_union *ret_address) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;

        ASSERT_OK(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1));
        ASSERT_OK(sd_device_monitor_set_description(monitor_server, "sender"));
        ASSERT_OK(sd_device_monitor_start(monitor_server, NULL, NULL));

        ASSERT_OK(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1));
        ASSERT_OK(sd_device_monitor_set_description(monitor_client, "client"));
        ASSERT_OK(device_monitor_allow_unicast_sender(monitor_client, monitor_server));
        ASSERT_OK(device_monitor_get_address(monitor_client, ret_address));

        *ret_server = TAKE_PTR(monitor_server);
        *ret_client = TAKE_PTR(monitor_client);
}

static void send_by_enumerator(
                sd_device_monitor *monitor_server,
                const union sockaddr_union *address,
                sd_device_enumerator *e,
                size_t n,
                const char *syspath_filter) {

        size_t i = 0;

        FOREACH_DEVICE(e, d) {
                const char *p, *s;

                ASSERT_OK(sd_device_get_syspath(d, &p));
                ASSERT_OK(sd_device_get_subsystem(d, &s));

                if (syspath_filter && path_startswith(p, syspath_filter))
                        continue;

                ASSERT_OK(device_add_property(d, "ACTION", "add"));
                ASSERT_OK(device_add_property(d, "SEQNUM", "10"));

                log_device_debug(d, "Sending device subsystem:%s syspath:%s", s, p);
                ASSERT_OK(device_monitor_send(monitor_server, address, d));

                /* The sysattr and parent filters are not implemented in BPF yet. So, sending multiple
                 * devices may fills up buffer and device_monitor_send() may return EAGAIN. Let's send only a
                 * few devices here, which should be filtered out by the receiver. */
                if (n != SIZE_MAX && ++i >= n)
                        break;
        }
}

TEST(sd_device_monitor_is_running) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;

        ASSERT_OK_ZERO(sd_device_monitor_is_running(NULL));

        ASSERT_OK(device_monitor_new_full(&m, MONITOR_GROUP_NONE, -1));
        ASSERT_OK_ZERO(sd_device_monitor_is_running(m));
        ASSERT_OK(sd_device_monitor_start(m, NULL, NULL));
        ASSERT_OK_POSITIVE(sd_device_monitor_is_running(m));
        ASSERT_OK(sd_device_monitor_stop(m));
        ASSERT_OK_ZERO(sd_device_monitor_is_running(m));
}

TEST(sd_device_monitor_start_stop) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        union sockaddr_union sa;
        const char *syspath;

        prepare_loopback(&device);

        ASSERT_OK(sd_device_get_syspath(device, &syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        /* Sending devices before starting client. */
        ASSERT_OK(sd_device_enumerator_new(&e));
        send_by_enumerator(monitor_server, &sa, e, 5, syspath);

        /* sd_device_monitor_start() can be called multiple times. */
        ASSERT_OK(sd_device_monitor_start(monitor_client, NULL, NULL));
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));

        /* Sending devices after client being started. */
        send_by_enumerator(monitor_server, &sa, e, 5, syspath);

        /* sd_device_monitor_stop() can be called multiple times. */
        ASSERT_OK(sd_device_monitor_stop(monitor_client));
        ASSERT_OK(sd_device_monitor_stop(monitor_client));

        /* Sending devices before restarting client. */
        send_by_enumerator(monitor_server, &sa, e, 5, syspath);

        /* Restart monitor, and check if the previously sent devices are ignored. */
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));
        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(refuse_invalid_device) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL;
        union sockaddr_union sa;
        const char *syspath;

        /* Try to send device with invalid action and without seqnum. */
        ASSERT_OK(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo"));
        ASSERT_OK(device_add_property(loopback, "ACTION", "hoge"));

        ASSERT_OK(sd_device_get_syspath(loopback, &syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));
        ASSERT_OK(device_monitor_send(monitor_server, &sa, loopback));
        ASSERT_OK(sd_event_run(sd_device_monitor_get_event(monitor_client), 0));
}

static void test_send_receive_one(sd_device *device, bool subsystem_filter, bool tag_filter, bool use_bpf) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        const char *syspath, *subsystem, *devtype = NULL;
        union sockaddr_union sa;

        log_device_info(device, "/* %s(subsystem_filter=%s, tag_filter=%s, use_bpf=%s) */", __func__,
                        true_false(subsystem_filter), true_false(tag_filter), true_false(use_bpf));

        ASSERT_OK(sd_device_get_syspath(device, &syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        if (subsystem_filter) {
                ASSERT_OK(sd_device_get_subsystem(device, &subsystem));
                (void) sd_device_get_devtype(device, &devtype);
                ASSERT_OK(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, devtype));
        }

        if (tag_filter)
                FOREACH_DEVICE_TAG(device, tag)
                        ASSERT_OK(sd_device_monitor_filter_add_match_tag(monitor_client, tag));

        if ((subsystem_filter || tag_filter) && use_bpf)
                ASSERT_OK(sd_device_monitor_filter_update(monitor_client));

        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));
        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(sd_device_monitor_send_receive) {
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL, *sda = NULL;
        int r;

        prepare_loopback(&loopback);
        test_send_receive_one(loopback, false, false, false);
        test_send_receive_one(loopback,  true, false, false);
        test_send_receive_one(loopback, false,  true, false);
        test_send_receive_one(loopback,  true,  true, false);
        test_send_receive_one(loopback,  true, false,  true);
        test_send_receive_one(loopback, false,  true,  true);
        test_send_receive_one(loopback,  true,  true,  true);

        r = prepare_sda(&sda);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to create sd_device for sda");

        test_send_receive_one(sda, false, false, false);
        test_send_receive_one(sda,  true, false, false);
        test_send_receive_one(sda, false,  true, false);
        test_send_receive_one(sda,  true,  true, false);
        test_send_receive_one(sda,  true, false,  true);
        test_send_receive_one(sda, false,  true,  true);
        test_send_receive_one(sda,  true,  true,  true);
}

TEST(sd_device_monitor_filter_add_match_subsystem_devtype) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *syspath, *subsystem;
        union sockaddr_union sa;

        prepare_loopback(&device);

        ASSERT_OK(sd_device_get_syspath(device, &syspath));
        ASSERT_OK(sd_device_get_subsystem(device, &subsystem));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, NULL));
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, subsystem, false));
        send_by_enumerator(monitor_server, &sa, e, SIZE_MAX, NULL);

        log_device_info(device, "Sending device subsystem:%s syspath:%s", subsystem, syspath);
        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(sd_device_monitor_filter_add_match_tag) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        union sockaddr_union sa;
        const char *syspath;

        prepare_loopback(&device);

        ASSERT_OK(sd_device_get_syspath(device, &syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(sd_device_monitor_filter_add_match_tag(monitor_client, "TEST_SD_DEVICE_MONITOR"));
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));

        ASSERT_OK(sd_device_enumerator_new(&e));
        send_by_enumerator(monitor_server, &sa, e, SIZE_MAX, NULL);

        log_device_info(device, "Sending device syspath:%s", syspath);
        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(sd_device_monitor_filter_add_match_sysattr) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        static const char *sysattr = "ifindex";
        const char *syspath, *sysattr_value;
        union sockaddr_union sa;

        prepare_loopback(&device);

        ASSERT_OK(sd_device_get_syspath(device, &syspath));
        ASSERT_OK(sd_device_get_sysattr_value(device, sysattr, &sysattr_value));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(sd_device_monitor_filter_add_match_sysattr(monitor_client, sysattr, sysattr_value, true));
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, sysattr, sysattr_value, false));
        send_by_enumerator(monitor_server, &sa, e, 5, NULL);

        log_device_info(device, "Sending device syspath:%s", syspath);
        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(sd_device_monitor_add_match_parent) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        const char *syspath, *parent_syspath;
        union sockaddr_union sa;
        sd_device *parent;
        int r;

        r = prepare_sda(&device);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to create sd_device for sda");

        ASSERT_OK(sd_device_get_syspath(device, &syspath));

        r = sd_device_get_parent(device, &parent);
        if (r < 0)
                return (void) log_tests_skipped("sda does not have parent");

        ASSERT_OK(sd_device_get_syspath(parent, &parent_syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(sd_device_monitor_filter_add_match_parent(monitor_client, parent, true));
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));

        ASSERT_OK(sd_device_enumerator_new(&e));
        send_by_enumerator(monitor_server, &sa, e, 5, parent_syspath);

        log_device_info(device, "Sending device syspath:%s", syspath);
        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(sd_device_monitor_filter_remove) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        union sockaddr_union sa;
        const char *syspath;

        prepare_loopback(&device);

        ASSERT_OK(sd_device_get_syspath(device, &syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, "hoge", NULL));
        ASSERT_OK(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath));

        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_OK(sd_event_run(sd_device_monitor_get_event(monitor_client), 0));

        ASSERT_OK(sd_device_monitor_filter_remove(monitor_client));

        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));
        ASSERT_EQ(sd_event_loop(sd_device_monitor_get_event(monitor_client)), 100);
}

TEST(sd_device_monitor_receive) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        union sockaddr_union sa;
        const char *syspath;
        int fd, r;

        prepare_loopback(&device);

        ASSERT_OK(sd_device_get_syspath(device, &syspath));

        prepare_monitor(&monitor_server, &monitor_client, &sa);

        ASSERT_OK(device_monitor_send(monitor_server, &sa, device));

        ASSERT_OK(fd = sd_device_monitor_get_fd(monitor_client));

        for (;;) {
                usec_t timeout;
                int events;

                ASSERT_OK(events = sd_device_monitor_get_events(monitor_client));
                ASSERT_EQ(events, (int) EPOLLIN);
                ASSERT_OK(sd_device_monitor_get_timeout(monitor_client, &timeout));
                ASSERT_EQ(timeout, USEC_INFINITY);

                r = fd_wait_for_event(fd, events, MAX(10 * USEC_PER_SEC, timeout));
                if (r == -EINTR)
                        continue;
                ASSERT_OK_POSITIVE(r);
                break;
        }

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        ASSERT_OK_POSITIVE(sd_device_monitor_receive(monitor_client, &dev));

        const char *s;
        ASSERT_OK(sd_device_get_syspath(dev, &s));
        ASSERT_STREQ(s, syspath);
}

static int intro(void) {
        if (getuid() != 0)
                return log_tests_skipped("not root");

        if (path_is_mount_point("/sys") <= 0)
                return log_tests_skipped("/sys is not mounted");

        if (path_is_read_only_fs("/sys") > 0)
                return log_tests_skipped("Running in container");

        if (access("/sys/class/net/lo", F_OK) < 0)
                return log_tests_skipped_errno(errno, "Loopback network interface 'lo' does not exist");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"

#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "macro.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"
#include "virt.h"

static int monitor_handler(sd_device_monitor *m, sd_device *d, void *userdata) {
        const char *s, *syspath = userdata;

        assert_se(sd_device_get_syspath(d, &s) >= 0);
        assert_se(streq(s, syspath));

        return sd_event_exit(sd_device_monitor_get_event(m), 100);
}

static void test_receive_device_fail(void) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL;
        const char *syspath;

        log_info("/* %s */", __func__);

        /* Try to send device with invalid action and without seqnum. */
        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(device_add_property(loopback, "ACTION", "hoge") >= 0);

        assert_se(sd_device_get_syspath(loopback, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        assert_se(device_monitor_send_device(monitor_server, monitor_client, loopback) >= 0);
        assert_se(sd_event_run(sd_device_monitor_get_event(monitor_client), 0) >= 0);
}

static void test_send_receive_one(sd_device *device, bool subsystem_filter, bool tag_filter, bool use_bpf) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        const char *syspath, *subsystem, *tag, *devtype = NULL;

        log_device_info(device, "/* %s(subsystem_filter=%s, tag_filter=%s, use_bpf=%s) */", __func__,
                        true_false(subsystem_filter), true_false(tag_filter), true_false(use_bpf));

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        if (subsystem_filter) {
                assert_se(sd_device_get_subsystem(device, &subsystem) >= 0);
                (void) sd_device_get_devtype(device, &devtype);
                assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, devtype) >= 0);
        }

        if (tag_filter)
                FOREACH_DEVICE_TAG(device, tag)
                        assert_se(sd_device_monitor_filter_add_match_tag(monitor_client, tag) >= 0);

        if ((subsystem_filter || tag_filter) && use_bpf)
                assert_se(sd_device_monitor_filter_update(monitor_client) >= 0);

        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);
}

static void test_subsystem_filter(sd_device *device) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *syspath, *subsystem;
        sd_device *d;

        log_device_info(device, "/* %s */", __func__);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);
        assert_se(sd_device_get_subsystem(device, &subsystem) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, NULL) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, subsystem, false) >= 0);
        FOREACH_DEVICE(e, d) {
                const char *p, *s;

                assert_se(sd_device_get_syspath(d, &p) >= 0);
                assert_se(sd_device_get_subsystem(d, &s) >= 0);

                assert_se(device_add_property(d, "ACTION", "add") >= 0);
                assert_se(device_add_property(d, "SEQNUM", "10") >= 0);

                log_device_debug(d, "Sending device subsystem:%s syspath:%s", s, p);
                assert_se(device_monitor_send_device(monitor_server, monitor_client, d) >= 0);
        }

        log_device_info(device, "Sending device subsystem:%s syspath:%s", subsystem, syspath);
        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);
}

static void test_tag_filter(sd_device *device) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *syspath;
        sd_device *d;

        log_device_info(device, "/* %s */", __func__);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_filter_add_match_tag(monitor_client, "TEST_SD_DEVICE_MONITOR") >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        FOREACH_DEVICE(e, d) {
                const char *p;

                assert_se(sd_device_get_syspath(d, &p) >= 0);

                assert_se(device_add_property(d, "ACTION", "add") >= 0);
                assert_se(device_add_property(d, "SEQNUM", "10") >= 0);

                log_device_debug(d, "Sending device syspath:%s", p);
                assert_se(device_monitor_send_device(monitor_server, monitor_client, d) >= 0);
        }

        log_device_info(device, "Sending device syspath:%s", syspath);
        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);

}

static void test_sysattr_filter(sd_device *device, const char *sysattr) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *syspath, *sysattr_value;
        sd_device *d;

        log_device_info(device, "/* %s(%s) */", __func__, sysattr);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);
        assert_se(sd_device_get_sysattr_value(device, sysattr, &sysattr_value) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_filter_add_match_sysattr(monitor_client, sysattr, sysattr_value, true) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, sysattr, sysattr_value, false) >= 0);
        FOREACH_DEVICE(e, d) {
                const char *p;

                assert_se(sd_device_get_syspath(d, &p) >= 0);

                assert_se(device_add_property(d, "ACTION", "add") >= 0);
                assert_se(device_add_property(d, "SEQNUM", "10") >= 0);

                log_device_debug(d, "Sending device syspath:%s", p);
                assert_se(device_monitor_send_device(monitor_server, monitor_client, d) >= 0);

                /* The sysattr filter is not implemented in BPF yet. So, sending multiple devices may fills up
                 * buffer and device_monitor_send_device() may return EAGAIN. Let's send one device here,
                 * which should be filtered out by the receiver. */
                break;
        }

        log_device_info(device, "Sending device syspath:%s", syspath);
        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);

}

static void test_parent_filter(sd_device *device) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *syspath, *parent_syspath;
        sd_device *parent, *d;
        int r;

        log_device_info(device, "/* %s */", __func__);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);
        r = sd_device_get_parent(device, &parent);
        if (r < 0)
                return (void) log_device_info(device, "Device does not have parent, skipping.");
        assert_se(sd_device_get_syspath(parent, &parent_syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_filter_add_match_parent(monitor_client, parent, true) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        FOREACH_DEVICE(e, d) {
                const char *p;

                assert_se(sd_device_get_syspath(d, &p) >= 0);
                if (path_startswith(p, parent_syspath))
                        continue;

                assert_se(device_add_property(d, "ACTION", "add") >= 0);
                assert_se(device_add_property(d, "SEQNUM", "10") >= 0);

                log_device_debug(d, "Sending device syspath:%s", p);
                assert_se(device_monitor_send_device(monitor_server, monitor_client, d) >= 0);

                /* The parent filter is not implemented in BPF yet. So, sending multiple devices may fills up
                 * buffer and device_monitor_send_device() may return EAGAIN. Let's send one device here,
                 * which should be filtered out by the receiver. */
                break;
        }

        log_device_info(device, "Sending device syspath:%s", syspath);
        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);

}

static void test_sd_device_monitor_filter_remove(sd_device *device) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        const char *syspath;

        log_device_info(device, "/* %s */", __func__);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_server, "sender") >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_set_description(monitor_client, "receiver") >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);

        assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, "hoge", NULL) >= 0);
        assert_se(sd_device_monitor_filter_update(monitor_client) >= 0);

        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_run(sd_device_monitor_get_event(monitor_client), 0) >= 0);

        assert_se(sd_device_monitor_filter_remove(monitor_client) >= 0);

        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL, *sda = NULL;
        int r;

        test_setup_logging(LOG_INFO);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        if (path_is_read_only_fs("/sys") > 0)
                return log_tests_skipped("Running in container");

        test_receive_device_fail();

        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(device_add_property(loopback, "ACTION", "add") >= 0);
        assert_se(device_add_property(loopback, "SEQNUM", "10") >= 0);
        assert_se(device_add_tag(loopback, "TEST_SD_DEVICE_MONITOR", true) >= 0);

        test_send_receive_one(loopback, false, false, false);
        test_send_receive_one(loopback,  true, false, false);
        test_send_receive_one(loopback, false,  true, false);
        test_send_receive_one(loopback,  true,  true, false);
        test_send_receive_one(loopback,  true, false,  true);
        test_send_receive_one(loopback, false,  true,  true);
        test_send_receive_one(loopback,  true,  true,  true);

        test_subsystem_filter(loopback);
        test_tag_filter(loopback);
        test_sysattr_filter(loopback, "ifindex");
        test_sd_device_monitor_filter_remove(loopback);

        r = sd_device_new_from_subsystem_sysname(&sda, "block", "sda");
        if (r < 0) {
                log_info_errno(r, "Failed to create sd_device for sda, skipping remaining tests: %m");
                return 0;
        }

        assert_se(device_add_property(sda, "ACTION", "change") >= 0);
        assert_se(device_add_property(sda, "SEQNUM", "11") >= 0);

        test_send_receive_one(sda, false, false, false);
        test_send_receive_one(sda,  true, false, false);
        test_send_receive_one(sda, false,  true, false);
        test_send_receive_one(sda,  true,  true, false);
        test_send_receive_one(sda,  true, false,  true);
        test_send_receive_one(sda, false,  true,  true);
        test_send_receive_one(sda,  true,  true,  true);

        test_parent_filter(sda);

        return 0;
}

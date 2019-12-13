/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"

#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "macro.h"
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

static int test_receive_device_fail(void) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL;
        const char *syspath;
        int r;

        log_info("/* %s */", __func__);

        /* Try to send device with invalid action and without seqnum. */
        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(device_add_property(loopback, "ACTION", "hoge") >= 0);

        assert_se(sd_device_get_syspath(loopback, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_server), "sender") >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_client), "receiver") >= 0);

        /* Do not use assert_se() here. */
        r = device_monitor_send_device(monitor_server, monitor_client, loopback);
        if (r < 0)
                return log_error_errno(r, "Failed to send loopback device: %m");

        assert_se(sd_event_run(sd_device_monitor_get_event(monitor_client), 0) >= 0);

        return 0;
}

static void test_send_receive_one(sd_device *device, bool subsystem_filter, bool tag_filter, bool use_bpf) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        const char *syspath, *subsystem, *tag, *devtype = NULL;

        log_device_info(device, "/* %s(subsystem_filter=%s, tag_filter=%s, use_bpf=%s) */", __func__,
                        true_false(subsystem_filter), true_false(tag_filter), true_false(use_bpf));

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_server), "sender") >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_client), "receiver") >= 0);

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
        const char *syspath, *subsystem, *p, *s;
        sd_device *d;

        log_info("/* %s */", __func__);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);
        assert_se(sd_device_get_subsystem(device, &subsystem) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_server), "sender") >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, NULL) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_client), "receiver") >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, subsystem, false) >= 0);
        FOREACH_DEVICE(e, d) {
                assert_se(sd_device_get_syspath(d, &p) >= 0);
                assert_se(sd_device_get_subsystem(d, &s) >= 0);

                log_info("Sending device subsystem:%s syspath:%s", s, p);
                assert_se(device_monitor_send_device(monitor_server, monitor_client, d) >= 0);
        }

        log_info("Sending device subsystem:%s syspath:%s", subsystem, syspath);
        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);
}

static void test_sd_device_monitor_filter_remove(sd_device *device) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        const char *syspath;

        log_device_info(device, "/* %s */", __func__);

        assert_se(sd_device_get_syspath(device, &syspath) >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_server), "sender") >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath) >= 0);
        assert_se(sd_event_source_set_description(sd_device_monitor_get_event_source(monitor_client), "receiver") >= 0);

        assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, "hoge", NULL) >= 0);
        assert_se(sd_device_monitor_filter_update(monitor_client) >= 0);

        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_run(sd_device_monitor_get_event(monitor_client), 0) >= 0);

        assert_se(sd_device_monitor_filter_remove(monitor_client) >= 0);

        assert_se(device_monitor_send_device(monitor_server, monitor_client, device) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 100);
}

static void test_device_copy_properties(sd_device *device) {
        _cleanup_(sd_device_unrefp) sd_device *copy = NULL;

        assert_se(device_shallow_clone(device, &copy) >= 0);
        assert_se(device_copy_properties(copy, device) >= 0);

        test_send_receive_one(copy, false, false, false);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL, *sda = NULL;
        int r;

        test_setup_logging(LOG_INFO);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        r = test_receive_device_fail();
        if (r < 0) {
                assert_se(r == -EPERM && detect_container() > 0);
                return log_tests_skipped("Running in container? Skipping remaining tests");
        }

        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(device_add_property(loopback, "ACTION", "add") >= 0);
        assert_se(device_add_property(loopback, "SEQNUM", "10") >= 0);

        test_send_receive_one(loopback, false, false, false);
        test_send_receive_one(loopback,  true, false, false);
        test_send_receive_one(loopback, false,  true, false);
        test_send_receive_one(loopback,  true,  true, false);
        test_send_receive_one(loopback,  true, false,  true);
        test_send_receive_one(loopback, false,  true,  true);
        test_send_receive_one(loopback,  true,  true,  true);

        test_subsystem_filter(loopback);
        test_sd_device_monitor_filter_remove(loopback);
        test_device_copy_properties(loopback);

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

        return 0;
}

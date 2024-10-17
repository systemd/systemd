/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#include "device-enumerator-private.h"
#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "udev-util.h"

static void test_sd_device_one(sd_device *d) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *syspath, *sysname, *subsystem = NULL, *devname, *val;
        bool is_block = false;
        dev_t devnum;
        usec_t usec;
        int ifindex, r;

        assert_se(sd_device_get_syspath(d, &syspath) >= 0);
        assert_se(path_startswith(syspath, "/sys"));
        assert_se(sd_device_get_sysname(d, &sysname) >= 0);

        log_info("%s(%s)", __func__, syspath);

        assert_se(sd_device_new_from_syspath(&dev, syspath) >= 0);
        assert_se(sd_device_get_syspath(dev, &val) >= 0);
        assert_se(streq(syspath, val));
        dev = sd_device_unref(dev);

        assert_se(sd_device_new_from_path(&dev, syspath) >= 0);
        assert_se(sd_device_get_syspath(dev, &val) >= 0);
        assert_se(streq(syspath, val));
        dev = sd_device_unref(dev);

        r = sd_device_get_ifindex(d, &ifindex);
        if (r >= 0) {
                assert_se(ifindex > 0);

                r = sd_device_new_from_ifindex(&dev, ifindex);
                if (r == -ENODEV)
                        log_device_warning_errno(d, r,
                                                 "Failed to create sd-device object from ifindex %i. "
                                                 "Maybe running on a non-host network namespace.", ifindex);
                else {
                        assert_se(r >= 0);
                        assert_se(sd_device_get_syspath(dev, &val) >= 0);
                        assert_se(streq(syspath, val));
                        dev = sd_device_unref(dev);
                }

                /* This does not require the interface really exists on the network namespace.
                 * Hence, this should always succeed. */
                assert_se(sd_device_new_from_ifname(&dev, sysname) >= 0);
                assert_se(sd_device_get_syspath(dev, &val) >= 0);
                assert_se(streq(syspath, val));
                dev = sd_device_unref(dev);
        } else
                assert_se(r == -ENOENT);

        r = sd_device_get_subsystem(d, &subsystem);
        if (r < 0)
                assert_se(r == -ENOENT);
        else {
                const char *name, *id;

                if (streq(subsystem, "drivers")) {
                        const char *driver_subsystem;
                        ASSERT_OK(sd_device_get_driver_subsystem(d, &driver_subsystem));
                        name = strjoina(driver_subsystem, ":", sysname);
                } else
                        name = sysname;

                r = sd_device_new_from_subsystem_sysname(&dev, subsystem, name);
                if (r >= 0) {
                        assert_se(sd_device_get_syspath(dev, &val) >= 0);
                        assert_se(streq(syspath, val));
                        dev = sd_device_unref(dev);
                } else
                        ASSERT_ERROR(r, ETOOMANYREFS);

                /* The device ID depends on subsystem. */
                assert_se(sd_device_get_device_id(d, &id) >= 0);
                r = sd_device_new_from_device_id(&dev, id);
                if (r == -ENODEV && ifindex > 0)
                        log_device_warning_errno(d, r,
                                                 "Failed to create sd-device object from device ID \"%s\". "
                                                 "Maybe running on a non-host network namespace.", id);
                else if (r >= 0) {
                        assert_se(sd_device_get_syspath(dev, &val) >= 0);
                        assert_se(streq(syspath, val));
                        dev = sd_device_unref(dev);
                } else
                        ASSERT_ERROR(r, ETOOMANYREFS);

                /* These require udev database, and reading database requires device ID. */
                r = sd_device_get_is_initialized(d);
                if (r > 0) {
                        r = sd_device_get_usec_since_initialized(d, &usec);
                        assert_se((r >= 0 && usec > 0) || r == -ENODATA);
                } else
                        assert(r == 0);

                r = sd_device_get_property_value(d, "ID_NET_DRIVER", &val);
                assert_se(r >= 0 || r == -ENOENT);
        }

        is_block = streq_ptr(subsystem, "block");

        r = sd_device_get_devname(d, &devname);
        if (r >= 0) {
                r = sd_device_new_from_devname(&dev, devname);
                if (r >= 0) {
                        assert_se(sd_device_get_syspath(dev, &val) >= 0);
                        assert_se(streq(syspath, val));
                        dev = sd_device_unref(dev);
                } else
                        assert_se(r == -ENODEV || ERRNO_IS_PRIVILEGE(r));

                r = sd_device_new_from_path(&dev, devname);
                if (r >= 0) {
                        assert_se(sd_device_get_syspath(dev, &val) >= 0);
                        assert_se(streq(syspath, val));
                        dev = sd_device_unref(dev);

                        _cleanup_close_ int fd = -EBADF;
                        fd = sd_device_open(d, O_CLOEXEC| O_NONBLOCK | (is_block ? O_RDONLY : O_NOCTTY | O_PATH));
                        assert_se(fd >= 0 || ERRNO_IS_PRIVILEGE(fd));
                } else
                        assert_se(r == -ENODEV || ERRNO_IS_PRIVILEGE(r));
        } else
                assert_se(r == -ENOENT);

        r = sd_device_get_devnum(d, &devnum);
        if (r >= 0) {
                _cleanup_free_ char *p = NULL;

                assert_se(major(devnum) > 0);

                assert_se(sd_device_new_from_devnum(&dev, is_block ? 'b' : 'c', devnum) >= 0);
                assert_se(sd_device_get_syspath(dev, &val) >= 0);
                assert_se(streq(syspath, val));
                dev = sd_device_unref(dev);

                assert_se(asprintf(&p, "/dev/%s/%u:%u", is_block ? "block" : "char", major(devnum), minor(devnum)) >= 0);
                assert_se(sd_device_new_from_devname(&dev, p) >= 0);
                assert_se(sd_device_get_syspath(dev, &val) >= 0);
                assert_se(streq(syspath, val));
                dev = sd_device_unref(dev);

                assert_se(sd_device_new_from_path(&dev, p) >= 0);
                assert_se(sd_device_get_syspath(dev, &val) >= 0);
                assert_se(streq(syspath, val));
                dev = sd_device_unref(dev);
        } else
                assert_se(r == -ENOENT);

        assert_se(sd_device_get_devpath(d, &val) >= 0);

        r = sd_device_get_devtype(d, &val);
        assert_se(r >= 0 || r == -ENOENT);

        r = sd_device_get_driver(d, &val);
        assert_se(r >= 0 || r == -ENOENT);

        r = sd_device_get_sysnum(d, &val);
        if (r >= 0) {
                assert_se(val > sysname);
                assert_se(val < sysname + strlen(sysname));
                assert_se(in_charset(val, DIGITS));
                assert_se(!ascii_isdigit(val[-1]));
        } else
                assert_se(r == -ENOENT);

        r = sd_device_get_sysattr_value(d, "nsid", NULL);
        if (r >= 0) {
                unsigned x;

                assert_se(device_get_sysattr_unsigned(d, "nsid", NULL) >= 0);
                r = device_get_sysattr_unsigned(d, "nsid", &x);
                assert_se(r >= 0);
                assert_se((x > 0) == (r > 0));
        } else
                assert_se(ERRNO_IS_PRIVILEGE(r) || IN_SET(r, -ENOENT, -EINVAL));
}

TEST(sd_device_enumerator_devices) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        /* On some CI environments, it seems some loop block devices and corresponding bdi devices sometimes
         * disappear during running this test. Let's exclude them here for stability. */
        assert_se(sd_device_enumerator_add_match_subsystem(e, "bdi", false) >= 0);
        assert_se(sd_device_enumerator_add_nomatch_sysname(e, "loop*") >= 0);
        /* On CentOS CI, systemd-networkd-tests.py may be running when this test is invoked. The networkd
         * test creates and removes many network interfaces, and may interfere with this test. */
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", false) >= 0);
        FOREACH_DEVICE(e, d)
                test_sd_device_one(d);
}

TEST(sd_device_enumerator_subsystems) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        FOREACH_SUBSYSTEM(e, d)
                test_sd_device_one(d);
}

static void test_sd_device_enumerator_filter_subsystem_one(
                const char *subsystem,
                Hashmap *h,
                unsigned *ret_n_new_dev,
                unsigned *ret_n_removed_dev) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        unsigned n_new_dev = 0, n_removed_dev = 0;
        sd_device *dev;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, subsystem, true) >= 0);
        assert_se(sd_device_enumerator_add_nomatch_sysname(e, "loop*") >= 0);

        FOREACH_DEVICE(e, d) {
                const char *syspath;
                sd_device *t;

                assert_se(sd_device_get_syspath(d, &syspath) >= 0);
                t = hashmap_remove(h, syspath);

                if (!t) {
                        log_warning("New device found: subsystem:%s syspath:%s", subsystem, syspath);
                        n_new_dev++;
                }

                assert_se(!sd_device_unref(t));
        }

        HASHMAP_FOREACH(dev, h) {
                const char *syspath;

                assert_se(sd_device_get_syspath(dev, &syspath) >= 0);
                log_warning("Device removed: subsystem:%s syspath:%s", subsystem, syspath);
                n_removed_dev++;

                assert_se(!sd_device_unref(dev));
        }

        hashmap_free(h);

        *ret_n_new_dev = n_new_dev;
        *ret_n_removed_dev = n_removed_dev;
}

static bool test_sd_device_enumerator_filter_subsystem_trial(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_hashmap_free_ Hashmap *subsystems = NULL;
        unsigned n_new_dev = 0, n_removed_dev = 0;
        Hashmap *h;
        char *s;

        assert_se(subsystems = hashmap_new(&string_hash_ops));
        assert_se(sd_device_enumerator_new(&e) >= 0);
        /* See comments in TEST(sd_device_enumerator_devices). */
        assert_se(sd_device_enumerator_add_match_subsystem(e, "bdi", false) >= 0);
        assert_se(sd_device_enumerator_add_nomatch_sysname(e, "loop*") >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", false) >= 0);

        FOREACH_DEVICE(e, d) {
                const char *syspath, *subsystem;
                int r;

                assert_se(sd_device_get_syspath(d, &syspath) >= 0);

                r = sd_device_get_subsystem(d, &subsystem);
                assert_se(r >= 0 || r == -ENOENT);
                if (r < 0)
                        continue;

                h = hashmap_get(subsystems, subsystem);
                if (!h) {
                        char *str;
                        assert_se(str = strdup(subsystem));
                        assert_se(h = hashmap_new(&string_hash_ops));
                        assert_se(hashmap_put(subsystems, str, h) >= 0);
                }

                assert_se(hashmap_put(h, syspath, d) >= 0);
                assert_se(sd_device_ref(d));

                log_debug("Added subsystem:%s syspath:%s", subsystem, syspath);
        }

        while ((h = hashmap_steal_first_key_and_value(subsystems, (void**) &s))) {
                unsigned n, m;

                test_sd_device_enumerator_filter_subsystem_one(s, TAKE_PTR(h), &n, &m);
                free(s);

                n_new_dev += n;
                n_removed_dev += m;
        }

        if (n_new_dev > 0)
                log_warning("%u new devices are found in re-scan", n_new_dev);
        if (n_removed_dev > 0)
                log_warning("%u devices removed in re-scan", n_removed_dev);

        return n_new_dev + n_removed_dev == 0;
}

static bool test_sd_device_enumerator_filter_subsystem_trial_many(void) {
        for (unsigned i = 0; i < 20; i++) {
                log_debug("%s(): trial %u", __func__, i);
                if (test_sd_device_enumerator_filter_subsystem_trial())
                        return true;
        }

        return false;
}

static int on_inotify(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        if (test_sd_device_enumerator_filter_subsystem_trial_many())
                return sd_event_exit(sd_event_source_get_event(s), 0);

        return sd_event_exit(sd_event_source_get_event(s), -EBUSY);
}

TEST(sd_device_enumerator_filter_subsystem) {
        /* The test test_sd_device_enumerator_filter_subsystem_trial() is quite racy. Let's run the function
         * several times after the udev queue becomes empty. */

        if (!udev_available() || (access("/run/udev", F_OK) < 0 && errno == ENOENT)) {
                assert_se(test_sd_device_enumerator_filter_subsystem_trial_many());
                return;
        }

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        assert_se(sd_event_default(&event) >= 0);
        assert_se(sd_event_add_inotify(event, NULL, "/run/udev" , IN_DELETE, on_inotify, NULL) >= 0);

        if (udev_queue_is_empty() == 0) {
                log_debug("udev queue is not empty, waiting for all queued events to be processed.");
                assert_se(sd_event_loop(event) >= 0);
        } else
                assert_se(test_sd_device_enumerator_filter_subsystem_trial_many());
}

TEST(sd_device_enumerator_add_match_sysattr) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", true) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "1", true) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "hoge", true) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "foo", true) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "bar", false) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "baz", false) >= 0);

        dev = sd_device_enumerator_get_device_first(e);
        assert_se(dev);
        assert_se(sd_device_get_ifindex(dev, &ifindex) >= 0);
        assert_se(ifindex == 1);

        assert_se(!sd_device_enumerator_get_device_next(e));
}

TEST(sd_device_enumerator_add_match_property) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", true) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "1", true) >= 0);
        assert_se(sd_device_enumerator_add_match_property(e, "IFINDE*", "1*") >= 0);
        assert_se(sd_device_enumerator_add_match_property(e, "IFINDE*", "hoge") >= 0);
        assert_se(sd_device_enumerator_add_match_property(e, "IFINDE*", NULL) >= 0);
        assert_se(sd_device_enumerator_add_match_property(e, "AAAAA", "BBBB") >= 0);
        assert_se(sd_device_enumerator_add_match_property(e, "FOOOO", NULL) >= 0);

        dev = sd_device_enumerator_get_device_first(e);
        assert_se(dev);
        assert_se(sd_device_get_ifindex(dev, &ifindex) >= 0);
        assert_se(ifindex == 1);
}

TEST(sd_device_enumerator_add_match_property_required) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", true) >= 0);
        assert_se(sd_device_enumerator_add_match_sysattr(e, "ifindex", "1", true) >= 0);
        assert_se(sd_device_enumerator_add_match_property_required(e, "IFINDE*", "1*") >= 0);

        /* Only one required match which should be satisfied. */
        dev = sd_device_enumerator_get_device_first(e);
        assert_se(dev);
        assert_se(sd_device_get_ifindex(dev, &ifindex) >= 0);
        assert_se(ifindex == 1);

        /* Now let's add a bunch of garbage properties which should not be satisfied. */
        assert_se(sd_device_enumerator_add_match_property_required(e, "IFINDE*", "hoge") >= 0);
        assert_se(sd_device_enumerator_add_match_property_required(e, "IFINDE*", NULL) >= 0);
        assert_se(sd_device_enumerator_add_match_property_required(e, "AAAAA", "BBBB") >= 0);
        assert_se(sd_device_enumerator_add_match_property_required(e, "FOOOO", NULL) >= 0);

        assert_se(!sd_device_enumerator_get_device_first(e));
}

static void check_parent_match(sd_device_enumerator *e, sd_device *dev) {
        const char *syspath;
        bool found = false;

        assert_se(sd_device_get_syspath(dev, &syspath) >= 0);

        FOREACH_DEVICE(e, d) {
                const char *s;

                assert_se(sd_device_get_syspath(d, &s) >= 0);
                if (streq(s, syspath)) {
                        found = true;
                        break;
                }
        }

        if (!found) {
                log_device_debug(dev, "not enumerated, already removed??");
                /* If the original device not found, then the device should be already removed. */
                assert_se(access(syspath, F_OK) < 0);
                assert_se(errno == ENOENT);
        }
}

TEST(sd_device_enumerator_add_match_parent) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        /* See comments in TEST(sd_device_enumerator_devices). */
        assert_se(sd_device_enumerator_add_match_subsystem(e, "bdi", false) >= 0);
        assert_se(sd_device_enumerator_add_nomatch_sysname(e, "loop*") >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", false) >= 0);

        if (!slow_tests_enabled())
                assert_se(sd_device_enumerator_add_match_subsystem(e, "block", true) >= 0);

        FOREACH_DEVICE(e, dev) {
                _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *p = NULL;
                const char *syspath;
                sd_device *parent;

                assert_se(sd_device_get_syspath(dev, &syspath) >= 0);

                r = sd_device_get_parent(dev, &parent);
                if (r < 0) {
                        assert_se(ERRNO_IS_DEVICE_ABSENT(r));
                        continue;
                }

                log_debug("> %s", syspath);

                assert_se(sd_device_enumerator_new(&p) >= 0);
                assert_se(sd_device_enumerator_allow_uninitialized(p) >= 0);
                assert_se(sd_device_enumerator_add_match_parent(p, parent) >= 0);

                check_parent_match(p, dev);

                /* If the device does not have subsystem, then it is not enumerated. */
                r = sd_device_get_subsystem(parent, NULL);
                if (r < 0) {
                        assert_se(r == -ENOENT);
                        continue;
                }
                check_parent_match(p, parent);
        }
}

TEST(sd_device_enumerator_add_all_parents) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        /* STEP 1: enumerate all block devices without all_parents() */
        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));

        /* filter in only a subsystem */
        ASSERT_OK(sd_device_enumerator_add_nomatch_sysname(e, "loop*"));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "block", true));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "DEVTYPE", "partition"));

        unsigned devices_count_with_parents = 0;
        unsigned devices_count_without_parents = 0;
        FOREACH_DEVICE(e, dev) {
                ASSERT_TRUE(device_in_subsystem(dev, "block"));
                ASSERT_TRUE(device_is_devtype(dev, "partition"));
                devices_count_without_parents++;
        }

        log_debug("found %u devices", devices_count_without_parents);

        /* STEP 2: enumerate again with all_parents() */
        ASSERT_OK(sd_device_enumerator_add_all_parents(e) >= 0);

        unsigned not_filtered_parent_count = 0;
        FOREACH_DEVICE(e, dev) {
                if (!device_in_subsystem(dev, "block") || !device_is_devtype(dev, "partition"))
                        not_filtered_parent_count++;
                devices_count_with_parents++;
        }
        log_debug("found %u devices out of %u that would have been excluded without all_parents()",
                  not_filtered_parent_count,
                  devices_count_with_parents);
        ASSERT_EQ(devices_count_with_parents, devices_count_without_parents + not_filtered_parent_count);
}

TEST(sd_device_get_child) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        /* See comments in TEST(sd_device_enumerator_devices). */
        assert_se(sd_device_enumerator_add_match_subsystem(e, "bdi", false) >= 0);
        assert_se(sd_device_enumerator_add_nomatch_sysname(e, "loop*") >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "net", false) >= 0);

        if (!slow_tests_enabled())
                assert_se(sd_device_enumerator_add_match_subsystem(e, "block", true) >= 0);

        FOREACH_DEVICE(e, dev) {
                const char *syspath, *parent_syspath, *expected_suffix, *suffix;
                sd_device *parent;
                bool found = false;

                assert_se(sd_device_get_syspath(dev, &syspath) >= 0);

                r = sd_device_get_parent(dev, &parent);
                if (r < 0) {
                        assert_se(ERRNO_IS_DEVICE_ABSENT(r));
                        continue;
                }

                assert_se(sd_device_get_syspath(parent, &parent_syspath) >= 0);
                assert_se(expected_suffix = path_startswith(syspath, parent_syspath));

                log_debug("> %s", syspath);

                FOREACH_DEVICE_CHILD_WITH_SUFFIX(parent, child, suffix) {
                        const char *s;

                        assert_se(child);
                        assert_se(suffix);

                        if (!streq(suffix, expected_suffix))
                                continue;

                        assert_se(sd_device_get_syspath(child, &s) >= 0);
                        assert_se(streq(s, syspath));
                        found = true;
                        break;
                }
                assert_se(found);
        }
}

TEST(sd_device_new_from_nulstr) {
        const char *devlinks =
                "/dev/disk/by-partuuid/1290d63a-42cc-4c71-b87c-xxxxxxxxxxxx\0"
                "/dev/disk/by-path/pci-0000:00:0f.0-scsi-0:0:0:0-part3\0"
                "/dev/disk/by-label/Arch\\x20Linux\0"
                "/dev/disk/by-uuid/a07b87e5-4af5-4a59-bde9-yyyyyyyyyyyy\0"
                "/dev/disk/by-partlabel/Arch\\x20Linux\0"
                "\0";

        _cleanup_(sd_device_unrefp) sd_device *device = NULL, *from_nulstr = NULL;
        _cleanup_free_ char *nulstr_copy = NULL;
        const char *nulstr;
        size_t len;

        assert_se(sd_device_new_from_syspath(&device, "/sys/class/net/lo") >= 0);

        /* Yeah, of course, setting devlink to the loopback interface is nonsense. But this is just a
         * test for generating and parsing nulstr. For issue #17772. */
        NULSTR_FOREACH(devlink, devlinks) {
                log_device_info(device, "setting devlink: %s", devlink);
                assert_se(device_add_devlink(device, devlink) >= 0);
                assert_se(set_contains(device->devlinks, devlink));
        }

        /* For issue #23799 */
        assert_se(device_add_tag(device, "tag1", false) >= 0);
        assert_se(device_add_tag(device, "tag2", false) >= 0);
        assert_se(device_add_tag(device, "current-tag1", true) >= 0);
        assert_se(device_add_tag(device, "current-tag2", true) >= 0);

        /* These properties are necessary for device_new_from_nulstr(). See device_verify(). */
        assert_se(device_add_property_internal(device, "SEQNUM", "1") >= 0);
        assert_se(device_add_property_internal(device, "ACTION", "change") >= 0);

        assert_se(device_get_properties_nulstr(device, &nulstr, &len) >= 0);
        assert_se(nulstr_copy = newdup(char, nulstr, len));
        assert_se(device_new_from_nulstr(&from_nulstr, nulstr_copy, len) >= 0);

        assert_se(sd_device_has_tag(from_nulstr, "tag1") == 1);
        assert_se(sd_device_has_tag(from_nulstr, "tag2") == 1);
        assert_se(sd_device_has_tag(from_nulstr, "current-tag1") == 1);
        assert_se(sd_device_has_tag(from_nulstr, "current-tag2") == 1);
        assert_se(sd_device_has_current_tag(from_nulstr, "tag1") == 0);
        assert_se(sd_device_has_current_tag(from_nulstr, "tag2") == 0);
        assert_se(sd_device_has_current_tag(from_nulstr, "current-tag1") == 1);
        assert_se(sd_device_has_current_tag(from_nulstr, "current-tag2") == 1);

        NULSTR_FOREACH(devlink, devlinks) {
                log_device_info(from_nulstr, "checking devlink: %s", devlink);
                assert_se(set_contains(from_nulstr->devlinks, devlink));
        }
}

TEST(sd_device_new_from_path) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        int r;

        assert_se(mkdtemp_malloc("/tmp/test-sd-device.XXXXXXX", &tmpdir) >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "block", true) >= 0);
        assert_se(sd_device_enumerator_add_nomatch_sysname(e, "loop*") >= 0);
        assert_se(sd_device_enumerator_add_match_property(e, "DEVNAME", "*") >= 0);

        FOREACH_DEVICE(e, dev) {
                _cleanup_(sd_device_unrefp) sd_device *d = NULL;
                const char *syspath, *devpath, *sysname, *s;
                _cleanup_free_ char *path = NULL;

                assert_se(sd_device_get_sysname(dev, &sysname) >= 0);

                log_debug("%s(%s)", __func__, sysname);

                assert_se(sd_device_get_syspath(dev, &syspath) >= 0);
                assert_se(sd_device_new_from_path(&d, syspath) >= 0);
                assert_se(sd_device_get_syspath(d, &s) >= 0);
                assert_se(streq(s, syspath));
                d = sd_device_unref(d);

                assert_se(sd_device_get_devname(dev, &devpath) >= 0);
                r = sd_device_new_from_path(&d, devpath);
                if (r >= 0) {
                        assert_se(sd_device_get_syspath(d, &s) >= 0);
                        assert_se(streq(s, syspath));
                        d = sd_device_unref(d);
                } else
                        assert_se(r == -ENODEV || ERRNO_IS_PRIVILEGE(r));

                assert_se(path = path_join(tmpdir, sysname));
                assert_se(symlink(syspath, path) >= 0);
                assert_se(sd_device_new_from_path(&d, path) >= 0);
                assert_se(sd_device_get_syspath(d, &s) >= 0);
                assert_se(streq(s, syspath));
        }
}

static void test_devname_from_devnum_one(const char *path) {
        _cleanup_free_ char *resolved = NULL;
        struct stat st;

        log_debug("> %s", path);

        if (stat(path, &st) < 0) {
                assert_se(errno == ENOENT);
                log_notice("Path %s not found, skipping test", path);
                return;
        }

        assert_se(devname_from_devnum(st.st_mode, st.st_rdev, &resolved) >= 0);
        assert_se(path_equal(path, resolved));
        resolved = mfree(resolved);
        assert_se(devname_from_stat_rdev(&st, &resolved) >= 0);
        assert_se(path_equal(path, resolved));
}

TEST(devname_from_devnum) {
        test_devname_from_devnum_one("/dev/null");
        test_devname_from_devnum_one("/dev/zero");
        test_devname_from_devnum_one("/dev/full");
        test_devname_from_devnum_one("/dev/random");
        test_devname_from_devnum_one("/dev/urandom");
        test_devname_from_devnum_one("/dev/tty");

        if (is_device_node("/run/systemd/inaccessible/blk") > 0) {
                test_devname_from_devnum_one("/run/systemd/inaccessible/chr");
                test_devname_from_devnum_one("/run/systemd/inaccessible/blk");
        }
}

static int intro(void) {
        if (path_is_mount_point("/sys") <= 0)
                return log_tests_skipped("/sys is not mounted");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

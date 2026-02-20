/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "capability-util.h"
#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "libmount-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "virt.h"

TEST(mdio_bus) {
        int r;

        /* For issue #37711 */

        if (getuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Running in chroot");

        r = ASSERT_OK(pidref_safe_fork(
                        "(mdio_bus)",
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        NULL));
        if (r == 0) {
                const char *syspath = "/sys/bus/mdio_bus/drivers/Qualcomm Atheros AR8031!AR8033";
                const char *id = "+drivers:mdio_bus:Qualcomm Atheros AR8031!AR8033";

                struct {
                        int (*getter)(sd_device*, const char**);
                        const char *val;
                } table[] = {
                        { sd_device_get_syspath,          syspath                          },
                        { sd_device_get_device_id,        id                               },
                        { sd_device_get_subsystem,        "drivers"                        },
                        { sd_device_get_driver_subsystem, "mdio_bus"                       },
                        { sd_device_get_sysname,          "Qualcomm Atheros AR8031/AR8033" },
                };

                ASSERT_OK_ERRNO(setenv("SYSTEMD_DEVICE_VERIFY_SYSFS", "0", /* overwrite= */ false));
                ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/bus/", "tmpfs", 0, NULL));
                r = mkdir_p(syspath, 0755);
                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        log_tests_skipped("Lacking privileges to create %s", syspath);
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_OK(r);

                _cleanup_free_ char *uevent = path_join(syspath, "uevent");
                ASSERT_NOT_NULL(uevent);
                ASSERT_OK(touch(uevent));

                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
                ASSERT_OK(sd_device_new_from_syspath(&dev, syspath));

                FOREACH_ELEMENT(t, table) {
                        const char *v;

                        ASSERT_OK(t->getter(dev, &v));
                        ASSERT_STREQ(v, t->val);
                }

                dev = sd_device_unref(dev);
                ASSERT_OK(sd_device_new_from_device_id(&dev, id));

                FOREACH_ELEMENT(t, table) {
                        const char *v;

                        ASSERT_OK(t->getter(dev, &v));
                        ASSERT_STREQ(v, t->val);
                }

                _exit(EXIT_SUCCESS);
        }
}

static void test_sd_device_one(sd_device *d) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *syspath, *sysname, *subsystem = NULL, *devname, *val;
        bool is_block = false;
        dev_t devnum;
        usec_t usec;
        int ifindex, r;

        ASSERT_OK(sd_device_get_syspath(d, &syspath));
        ASSERT_NOT_NULL(path_startswith(syspath, "/sys"));
        ASSERT_OK(sd_device_get_sysname(d, &sysname));

        log_info("%s(%s)", __func__, syspath);

        ASSERT_OK(sd_device_new_from_syspath(&dev, syspath));
        ASSERT_OK(sd_device_get_syspath(dev, &val));
        ASSERT_STREQ(syspath, val);
        ASSERT_NULL(dev = sd_device_unref(dev));

        ASSERT_OK(sd_device_new_from_path(&dev, syspath));
        ASSERT_OK(sd_device_get_syspath(dev, &val));
        ASSERT_STREQ(syspath, val);
        ASSERT_NULL(dev = sd_device_unref(dev));

        r = sd_device_get_ifindex(d, &ifindex);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);
        else {
                ASSERT_GT(ifindex, 0);

                const char *ifname;
                ASSERT_OK(device_get_ifname(d, &ifname));
                ASSERT_NOT_NULL(endswith(syspath, ifname));
                if (strchr(sysname, '/'))
                        ASSERT_FALSE(streq(ifname, sysname));
                else
                        ASSERT_STREQ(ifname, sysname);

                r = sd_device_new_from_ifindex(&dev, ifindex);
                if (r < 0) {
                        ASSERT_ERROR(r, ENODEV);
                        log_device_warning_errno(d, r,
                                                 "Failed to create sd-device object from ifindex %i. "
                                                 "Maybe running on a non-host network namespace.", ifindex);
                } else {
                        ASSERT_OK(sd_device_get_syspath(dev, &val));
                        ASSERT_STREQ(syspath, val);
                        ASSERT_NULL(dev = sd_device_unref(dev));
                }

                /* This does not require the interface really exists on the network namespace.
                 * Hence, this should always succeed. */
                ASSERT_OK(sd_device_new_from_ifname(&dev, sysname));
                ASSERT_OK(sd_device_get_syspath(dev, &val));
                ASSERT_STREQ(syspath, val);
                ASSERT_NULL(dev = sd_device_unref(dev));
        }

        r = sd_device_get_subsystem(d, &subsystem);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);
        else {
                const char *name, *id;

                if (streq(subsystem, "drivers")) {
                        const char *driver_subsystem;
                        ASSERT_OK(sd_device_get_driver_subsystem(d, &driver_subsystem));
                        name = strjoina(driver_subsystem, ":", sysname);
                } else
                        name = sysname;

                r = sd_device_new_from_subsystem_sysname(&dev, subsystem, name);
                if (r < 0)
                        ASSERT_ERROR(r, ETOOMANYREFS);
                else {
                        ASSERT_OK(sd_device_get_syspath(dev, &val));
                        ASSERT_STREQ(syspath, val);
                        ASSERT_NULL(dev = sd_device_unref(dev));
                }

                /* The device ID depends on subsystem. */
                ASSERT_OK(sd_device_get_device_id(d, &id));
                r = sd_device_new_from_device_id(&dev, id);
                if (r < 0) {
                        if (r == -ENODEV && ifindex > 0)
                                log_device_warning_errno(d, r,
                                                         "Failed to create sd-device object from device ID \"%s\". "
                                                         "Maybe running on a non-host network namespace.", id);
                        else
                                ASSERT_ERROR(r, ETOOMANYREFS);
                } else {
                        ASSERT_OK(sd_device_get_syspath(dev, &val));
                        ASSERT_STREQ(syspath, val);
                        ASSERT_NULL(dev = sd_device_unref(dev));
                }

                /* These require udev database, and reading database requires device ID. */
                ASSERT_OK(r = sd_device_get_is_initialized(d));
                if (r > 0) {
                        r = sd_device_get_usec_since_initialized(d, &usec);
                        if (r < 0)
                                ASSERT_ERROR(r, ENODATA);
                        else
                                ASSERT_GT(usec, 0U);
                }

                r = sd_device_get_property_value(d, "ID_NET_DRIVER", &val);
                if (r < 0)
                        ASSERT_ERROR(r, ENOENT);
        }

        if (streq(subsystem, "drm")) {
                const char *edid_content;
                size_t edid_size = 0;

                r = sd_device_get_sysattr_value_with_size(d, "edid", &edid_content, &edid_size);
                if (r < 0)
                        ASSERT_ERROR(r, ENOENT);

                /* at least 128 if monitor is connected, otherwise 0 */
                ASSERT_TRUE(edid_size == 0 || edid_size >= 128);
        }

        is_block = streq_ptr(subsystem, "block");

        r = sd_device_get_devname(d, &devname);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);
        else {
                r = sd_device_new_from_devname(&dev, devname);
                if (r < 0)
                        ASSERT_TRUE(r == -ENODEV || ERRNO_IS_NEG_PRIVILEGE(r));
                else {
                        ASSERT_OK(sd_device_get_syspath(dev, &val));
                        ASSERT_STREQ(syspath, val);
                        ASSERT_NULL(dev = sd_device_unref(dev));
                }

                r = sd_device_new_from_path(&dev, devname);
                if (r < 0)
                        ASSERT_TRUE(r == -ENODEV || ERRNO_IS_NEG_PRIVILEGE(r));
                else {
                        ASSERT_OK(sd_device_get_syspath(dev, &val));
                        ASSERT_STREQ(syspath, val);
                        ASSERT_NULL(dev = sd_device_unref(dev));

                        _cleanup_close_ int fd = -EBADF;
                        fd = sd_device_open(d, O_CLOEXEC| O_NONBLOCK | (is_block ? O_RDONLY : O_NOCTTY | O_PATH));
                        ASSERT_TRUE(fd >= 0 || ERRNO_IS_NEG_PRIVILEGE(fd));
                }
        }

        r = sd_device_get_devnum(d, &devnum);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);
        else {
                _cleanup_free_ char *p = NULL;

                ASSERT_GT(major(devnum), 0U);

                ASSERT_OK(sd_device_new_from_devnum(&dev, is_block ? 'b' : 'c', devnum));
                ASSERT_OK(sd_device_get_syspath(dev, &val));
                ASSERT_STREQ(syspath, val);
                ASSERT_NULL(dev = sd_device_unref(dev));

                ASSERT_OK(asprintf(&p, "/dev/%s/%u:%u", is_block ? "block" : "char", major(devnum), minor(devnum)));
                ASSERT_OK(sd_device_new_from_devname(&dev, p));
                ASSERT_OK(sd_device_get_syspath(dev, &val));
                ASSERT_STREQ(syspath, val);
                ASSERT_NULL(dev = sd_device_unref(dev));

                ASSERT_OK(sd_device_new_from_path(&dev, p));
                ASSERT_OK(sd_device_get_syspath(dev, &val));
                ASSERT_STREQ(syspath, val);
                ASSERT_NULL(dev = sd_device_unref(dev));
        }

        ASSERT_OK(sd_device_get_devpath(d, &val));

        r = sd_device_get_devtype(d, NULL);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);

        r = sd_device_get_driver(d, NULL);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);

        r = sd_device_get_sysnum(d, &val);
        if (r < 0)
                ASSERT_ERROR(r, ENOENT);
        else {
                ASSERT_TRUE(val > sysname);
                ASSERT_TRUE(val < sysname + strlen(sysname));
                ASSERT_TRUE(in_charset(val, DIGITS));
                ASSERT_FALSE(ascii_isdigit(val[-1]));

                r = device_get_sysnum_unsigned(d, NULL);
                if (r < 0)
                        ASSERT_ERROR(r, ERANGE); /* sysnum may be too large. */
        }

        r = sd_device_get_sysattr_value(d, "nsid", NULL);
        if (r < 0)
                ASSERT_TRUE(ERRNO_IS_NEG_PRIVILEGE(r) || IN_SET(r, -ENOENT, -EINVAL));
        else {
                unsigned x;
                ASSERT_OK(r = device_get_sysattr_unsigned(d, "nsid", &x));
                ASSERT_EQ(x > 0, r > 0);
        }
}

static void exclude_problematic_devices(sd_device_enumerator *e) {
        /* On some CI environments, it seems some loop block devices and corresponding bdi devices sometimes
         * disappear during running this test. Let's exclude them here for stability. */
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "bdi", false));
        ASSERT_OK(sd_device_enumerator_add_nomatch_sysname(e, "loop*"));
        /* On some CI environments, it seems dm block devices sometimes disappear during running this test.
         * Let's exclude them here for stability. */
        ASSERT_OK(sd_device_enumerator_add_nomatch_sysname(e, "dm-*"));
        /* Several other unit tests create and remove virtual network interfaces, e.g. test-netlink and
         * test-local-addresses. When one of these tests run in parallel with this unit test, the enumerated
         * device may disappear. Let's exclude them here for stability. */
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "net", false));
}

TEST(sd_device_enumerator_devices) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        exclude_problematic_devices(e);

        FOREACH_DEVICE(e, d)
                test_sd_device_one(d);
}

TEST(sd_device_enumerator_subsystems) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
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

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, subsystem, true));
        exclude_problematic_devices(e);

        FOREACH_DEVICE(e, d) {
                const char *syspath;
                sd_device *t;

                ASSERT_OK(sd_device_get_syspath(d, &syspath));
                t = hashmap_remove(h, syspath);

                if (!t) {
                        log_warning("New device found: subsystem:%s syspath:%s", subsystem, syspath);
                        n_new_dev++;
                }

                ASSERT_NULL(sd_device_unref(t));
        }

        HASHMAP_FOREACH(dev, h) {
                const char *syspath;

                ASSERT_OK(sd_device_get_syspath(dev, &syspath));
                log_warning("Device removed: subsystem:%s syspath:%s", subsystem, syspath);
                n_removed_dev++;

                ASSERT_NULL(sd_device_unref(dev));
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

        ASSERT_NOT_NULL((subsystems = hashmap_new(&string_hash_ops)));
        ASSERT_OK(sd_device_enumerator_new(&e));
        exclude_problematic_devices(e);

        FOREACH_DEVICE(e, d) {
                const char *syspath, *subsystem;
                int r;

                ASSERT_OK(sd_device_get_syspath(d, &syspath));

                r = sd_device_get_subsystem(d, &subsystem);
                if (r < 0) {
                        ASSERT_ERROR(r, ENOENT);
                        continue;
                }

                h = hashmap_get(subsystems, subsystem);
                if (!h) {
                        char *str;
                        ASSERT_NOT_NULL((str = strdup(subsystem)));
                        ASSERT_NOT_NULL((h = hashmap_new(&string_hash_ops)));
                        ASSERT_OK(hashmap_put(subsystems, str, h));
                }

                ASSERT_OK(hashmap_put(h, syspath, d));
                ASSERT_NOT_NULL(sd_device_ref(d));

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
                ASSERT_TRUE(test_sd_device_enumerator_filter_subsystem_trial_many());
                return;
        }

        /* The rest of this test depends on a full booted system with a working udev and so on */
        if (!sd_booted())
                return (void) log_tests_skipped("Test requires fully booted system with udev/etc, skipping to avoid hanging forever.");

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_default(&event));
        ASSERT_OK(sd_event_add_inotify(event, NULL, "/run/udev" , IN_DELETE, on_inotify, NULL));

        if (udev_queue_is_empty() == 0) {
                log_debug("udev queue is not empty, waiting for all queued events to be processed.");
                ASSERT_OK(sd_event_loop(event));
        } else
                ASSERT_TRUE(test_sd_device_enumerator_filter_subsystem_trial_many());
}

TEST(sd_device_enumerator_add_match_sysattr) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "net", true));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "1", true));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "hoge", true));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "foo", true));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "bar", false));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "baz", false));

        ASSERT_NOT_NULL((dev = sd_device_enumerator_get_device_first(e)));
        ASSERT_OK(sd_device_get_ifindex(dev, &ifindex));
        ASSERT_EQ(ifindex, 1);

        ASSERT_NULL(sd_device_enumerator_get_device_next(e));
}

TEST(sd_device_enumerator_add_match_property) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "net", true));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "1", true));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "IFINDE*", "1*"));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "IFINDE*", "hoge"));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "IFINDE*", NULL));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "AAAAA", "BBBB"));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "FOOOO", NULL));

        ASSERT_NOT_NULL((dev = sd_device_enumerator_get_device_first(e)));
        ASSERT_OK(sd_device_get_ifindex(dev, &ifindex));
        ASSERT_EQ(ifindex, 1);
}

TEST(sd_device_enumerator_add_match_property_required) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *dev;
        int ifindex;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "net", true));
        ASSERT_OK(sd_device_enumerator_add_match_sysattr(e, "ifindex", "1", true));
        ASSERT_OK(sd_device_enumerator_add_match_property_required(e, "IFINDE*", "1*"));

        /* Only one required match which should be satisfied. */
        ASSERT_NOT_NULL((dev = sd_device_enumerator_get_device_first(e)));
        ASSERT_OK(sd_device_get_ifindex(dev, &ifindex));
        ASSERT_EQ(ifindex, 1);

        /* Now let's add a bunch of garbage properties which should not be satisfied. */
        ASSERT_OK(sd_device_enumerator_add_match_property_required(e, "IFINDE*", "hoge"));
        ASSERT_OK(sd_device_enumerator_add_match_property_required(e, "IFINDE*", NULL));
        ASSERT_OK(sd_device_enumerator_add_match_property_required(e, "AAAAA", "BBBB"));
        ASSERT_OK(sd_device_enumerator_add_match_property_required(e, "FOOOO", NULL));

        ASSERT_NULL(sd_device_enumerator_get_device_first(e));
}

static void check_parent_match(sd_device_enumerator *e, sd_device *dev) {
        const char *syspath;
        bool found = false;

        ASSERT_OK(sd_device_get_syspath(dev, &syspath));

        FOREACH_DEVICE(e, d) {
                const char *s;

                ASSERT_OK(sd_device_get_syspath(d, &s));
                if (streq(s, syspath)) {
                        found = true;
                        break;
                }
        }

        if (!found) {
                log_device_debug(dev, "not enumerated, already removed??");
                /* If the original device not found, then the device should be already removed. */
                ASSERT_FAIL(access(syspath, F_OK));
                ASSERT_EQ(errno, ENOENT);
        }
}

TEST(sd_device_enumerator_add_match_parent) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        /* Some devices have thousands of children. Avoid spending too much time in the double loop below. */
        unsigned iterations = 200;
        int r;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        exclude_problematic_devices(e);

        if (!slow_tests_enabled())
                ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "block", true));

        FOREACH_DEVICE(e, dev) {
                _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *p = NULL;
                const char *syspath;
                sd_device *parent;

                if (iterations-- == 0)
                        break;

                ASSERT_OK(sd_device_get_syspath(dev, &syspath));

                r = sd_device_get_parent(dev, &parent);
                if (r < 0) {
                        ASSERT_TRUE(ERRNO_IS_NEG_DEVICE_ABSENT(r));
                        continue;
                }

                log_debug("> %s", syspath);

                ASSERT_OK(sd_device_enumerator_new(&p));
                ASSERT_OK(sd_device_enumerator_allow_uninitialized(p));
                ASSERT_OK(sd_device_enumerator_add_match_parent(p, parent));

                check_parent_match(p, dev);

                /* If the device does not have subsystem, then it is not enumerated. */
                r = sd_device_get_subsystem(parent, NULL);
                if (r < 0) {
                        ASSERT_ERROR(r, ENOENT);
                        continue;
                }
                check_parent_match(p, parent);
        }
}

TEST(sd_device_enumerator_add_all_parents) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        /* STEP 1: enumerate all block devices without all_parents() */
        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        exclude_problematic_devices(e);

        /* filter in only a subsystem */
        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "block", true));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "DEVTYPE", "partition"));

        unsigned devices_count_with_parents = 0;
        unsigned devices_count_without_parents = 0;
        FOREACH_DEVICE(e, dev) {
                ASSERT_OK_POSITIVE(device_is_subsystem_devtype(dev, "block", "partition"));
                devices_count_without_parents++;
        }

        log_debug("found %u devices", devices_count_without_parents);

        /* STEP 2: enumerate again with all_parents() */
        ASSERT_OK(sd_device_enumerator_add_all_parents(e));

        unsigned not_filtered_parent_count = 0;
        FOREACH_DEVICE(e, dev) {
                ASSERT_OK(r = device_is_subsystem_devtype(dev, "block", "partition"));
                if (r == 0)
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
        /* Some devices have thousands of children. Avoid spending too much time in the double loop below. */
        unsigned iterations = 3000;
        int r;

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        exclude_problematic_devices(e);

        if (!slow_tests_enabled())
                ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "block", true));

        FOREACH_DEVICE(e, dev) {
                const char *syspath, *parent_syspath, *expected_suffix, *suffix;
                sd_device *parent;
                bool found = false;

                ASSERT_OK(sd_device_get_syspath(dev, &syspath));

                r = sd_device_get_parent(dev, &parent);
                if (r < 0) {
                        ASSERT_TRUE(ERRNO_IS_NEG_DEVICE_ABSENT(r));
                        continue;
                }

                ASSERT_OK(sd_device_get_syspath(parent, &parent_syspath));
                ASSERT_NOT_NULL((expected_suffix = path_startswith(syspath, parent_syspath)));

                log_debug("> %s", syspath);

                FOREACH_DEVICE_CHILD_WITH_SUFFIX(parent, child, suffix) {
                        const char *s;

                        if (iterations-- == 0)
                                return;

                        ASSERT_NOT_NULL(child);
                        ASSERT_NOT_NULL(suffix);

                        if (!streq(suffix, expected_suffix))
                                continue;

                        ASSERT_OK(sd_device_get_syspath(child, &s));
                        ASSERT_STREQ(s, syspath);
                        found = true;
                        break;
                }
                ASSERT_TRUE(found);
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

        ASSERT_OK(sd_device_new_from_syspath(&device, "/sys/class/net/lo"));

        /* Yeah, of course, setting devlink to the loopback interface is nonsense. But this is just a
         * test for generating and parsing nulstr. For issue #17772. */
        NULSTR_FOREACH(devlink, devlinks) {
                log_device_info(device, "setting devlink: %s", devlink);
                ASSERT_OK(device_add_devlink(device, devlink));
                ASSERT_TRUE(set_contains(device->devlinks, devlink));
        }

        /* For issue #23799 */
        ASSERT_OK(device_add_tag(device, "tag1", false));
        ASSERT_OK(device_add_tag(device, "tag2", false));
        ASSERT_OK(device_add_tag(device, "current-tag1", true));
        ASSERT_OK(device_add_tag(device, "current-tag2", true));

        /* These properties are necessary for device_new_from_nulstr(). See device_verify(). */
        ASSERT_OK(device_add_property_internal(device, "SEQNUM", "1"));
        ASSERT_OK(device_add_property_internal(device, "ACTION", "change"));

        ASSERT_OK(device_get_properties_nulstr(device, &nulstr, &len));
        ASSERT_NOT_NULL((nulstr_copy = newdup(char, nulstr, len)));
        ASSERT_OK(device_new_from_nulstr(&from_nulstr, nulstr_copy, len));

        ASSERT_OK_POSITIVE(sd_device_has_tag(from_nulstr, "tag1"));
        ASSERT_OK_POSITIVE(sd_device_has_tag(from_nulstr, "tag2"));
        ASSERT_OK_POSITIVE(sd_device_has_tag(from_nulstr, "current-tag1"));
        ASSERT_OK_POSITIVE(sd_device_has_tag(from_nulstr, "current-tag2"));
        ASSERT_OK_ZERO(sd_device_has_current_tag(from_nulstr, "tag1"));
        ASSERT_OK_ZERO(sd_device_has_current_tag(from_nulstr, "tag2"));
        ASSERT_OK_POSITIVE(sd_device_has_current_tag(from_nulstr, "current-tag1"));
        ASSERT_OK_POSITIVE(sd_device_has_current_tag(from_nulstr, "current-tag2"));

        NULSTR_FOREACH(devlink, devlinks) {
                log_device_info(from_nulstr, "checking devlink: %s", devlink);
                ASSERT_TRUE(set_contains(from_nulstr->devlinks, devlink));
        }
}

TEST(sd_device_new_from_path) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-sd-device.XXXXXXX", &tmpdir));

        ASSERT_OK(sd_device_enumerator_new(&e));
        ASSERT_OK(sd_device_enumerator_allow_uninitialized(e));
        exclude_problematic_devices(e);

        ASSERT_OK(sd_device_enumerator_add_match_subsystem(e, "block", true));
        ASSERT_OK(sd_device_enumerator_add_match_property(e, "DEVNAME", "*"));

        FOREACH_DEVICE(e, dev) {
                _cleanup_(sd_device_unrefp) sd_device *d = NULL;
                const char *syspath, *devpath, *sysname, *s;
                _cleanup_free_ char *path = NULL;

                ASSERT_OK(sd_device_get_sysname(dev, &sysname));

                log_debug("%s(%s)", __func__, sysname);

                ASSERT_OK(sd_device_get_syspath(dev, &syspath));
                ASSERT_OK(sd_device_new_from_path(&d, syspath));
                ASSERT_OK(sd_device_get_syspath(d, &s));
                ASSERT_STREQ(s, syspath);
                ASSERT_NULL(d = sd_device_unref(d));

                ASSERT_OK(sd_device_get_devname(dev, &devpath));
                r = sd_device_new_from_path(&d, devpath);
                if (r < 0)
                        ASSERT_TRUE(r == -ENODEV || ERRNO_IS_NEG_PRIVILEGE(r));
                else {
                        ASSERT_OK(sd_device_get_syspath(d, &s));
                        ASSERT_STREQ(s, syspath);
                        ASSERT_NULL(d = sd_device_unref(d));
                }

                ASSERT_NOT_NULL((path = path_join(tmpdir, sysname)));
                ASSERT_OK_ERRNO(symlink(syspath, path));
                ASSERT_OK(sd_device_new_from_path(&d, path));
                ASSERT_OK(sd_device_get_syspath(d, &s));
                ASSERT_STREQ(s, syspath);
        }
}

static void test_devname_from_devnum_one(const char *path) {
        _cleanup_free_ char *resolved = NULL;
        struct stat st;

        log_debug("> %s", path);

        if (stat(path, &st) < 0) {
                log_notice("Path %s not found, skipping test", path);
                return;
        }

        ASSERT_OK(devname_from_devnum(st.st_mode, st.st_rdev, &resolved));
        ASSERT_TRUE(path_equal(path, resolved));
        ASSERT_NULL(resolved = mfree(resolved));
        ASSERT_OK(devname_from_stat_rdev(&st, &resolved));
        ASSERT_TRUE(path_equal(path, resolved));
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
        int r;

        if (path_is_mount_point("/sys") <= 0)
                return log_tests_skipped("/sys/ is not mounted");

        r = dlopen_libmount();
        if (r < 0)
                return log_tests_skipped("libmount not available.");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

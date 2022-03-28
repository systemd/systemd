/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-enumerator-private.h"
#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "hashmap.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

static void test_sd_device_one(sd_device *d) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *syspath, *sysname, *subsystem = NULL, *id, *devname, *val;
        bool is_block = false;
        dev_t devnum;
        usec_t usec;
        int i, r;

        assert_se(sd_device_get_syspath(d, &syspath) >= 0);
        assert_se(path_startswith(syspath, "/sys"));
        assert_se(sd_device_new_from_syspath(&dev, syspath) >= 0);
        assert_se(sd_device_get_syspath(dev, &val) >= 0);
        assert_se(streq(syspath, val));
        dev = sd_device_unref(dev);

        assert_se(sd_device_new_from_path(&dev, syspath) >= 0);
        assert_se(sd_device_get_syspath(dev, &val) >= 0);
        assert_se(streq(syspath, val));
        dev = sd_device_unref(dev);

        assert_se(sd_device_get_sysname(d, &sysname) >= 0);
        r = sd_device_get_subsystem(d, &subsystem);
        if (r >= 0) {
                const char *name;

                if (streq(subsystem, "drivers"))
                        name = strjoina(d->driver_subsystem, ":", sysname);
                else
                        name = sysname;
                assert_se(sd_device_new_from_subsystem_sysname(&dev, subsystem, name) >= 0);
                assert_se(sd_device_get_syspath(dev, &val) >= 0);
                assert_se(streq(syspath, val));
                dev = sd_device_unref(dev);
        } else
                assert_se(r == -ENOENT);

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

        r = sd_device_get_ifindex(d, &i);
        if (r >= 0) {
                assert_se(i > 0);

                assert_se(sd_device_new_from_ifindex(&dev, i) >= 0);
                assert_se(sd_device_get_syspath(dev, &val) >= 0);
                assert_se(streq(syspath, val));
                dev = sd_device_unref(dev);

                assert_se(sd_device_new_from_ifname(&dev, sysname) >= 0);
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
        assert_se(r >= 0 || r == -ENOENT);

        r = sd_device_get_is_initialized(d);
        if (r > 0) {
                r = sd_device_get_usec_since_initialized(d, &usec);
                assert_se((r >= 0 && usec > 0) || r == -ENODATA);
        } else
                assert(r == 0);

        r = sd_device_get_sysattr_value(d, "name_assign_type", &val);
        assert_se(r >= 0 || ERRNO_IS_PRIVILEGE(r) || IN_SET(r, -ENOENT, -EINVAL));

        r = sd_device_get_property_value(d, "ID_NET_DRIVER", &val);
        assert_se(r >= 0 || r == -ENOENT);

        assert_se(device_get_device_id(d, &id) >= 0);
        assert_se(sd_device_new_from_device_id(&dev, id) >= 0);
        assert_se(sd_device_get_syspath(dev, &val) >= 0);
        assert_se(streq(syspath, val));

        log_info("syspath:%s subsystem:%s id:%s initialized:%s", syspath, strna(subsystem), id, yes_no(i));
}

TEST(sd_device_enumerator_devices) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        FOREACH_DEVICE(e, d)
                test_sd_device_one(d);
}

TEST(sd_device_enumerator_subsystems) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        FOREACH_SUBSYSTEM(e, d)
                test_sd_device_one(d);
}

static unsigned test_sd_device_enumerator_filter_subsystem_one(const char *subsystem, Hashmap *h) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d, *t;
        unsigned n_new_dev = 0;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, subsystem, true) >= 0);

        FOREACH_DEVICE(e, d) {
                const char *syspath;

                assert_se(sd_device_get_syspath(d, &syspath) >= 0);
                t = hashmap_remove(h, syspath);
                assert_se(!sd_device_unref(t));

                if (t)
                        log_debug("Removed subsystem:%s syspath:%s", subsystem, syspath);
                else {
                        log_warning("New device found: subsystem:%s syspath:%s", subsystem, syspath);
                        n_new_dev++;
                }
        }

        /* Assume no device is unplugged. */
        assert_se(hashmap_isempty(h));

        return n_new_dev;
}

TEST(sd_device_enumerator_filter_subsystem) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(hashmap_freep) Hashmap *subsystems;
        unsigned n_new_dev = 0;
        sd_device *d;
        Hashmap *h;
        char *s;

        assert_se(subsystems = hashmap_new(&string_hash_ops));
        assert_se(sd_device_enumerator_new(&e) >= 0);

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
                n_new_dev += test_sd_device_enumerator_filter_subsystem_one(s, h);
                hashmap_free(h);
                free(s);
        }

        if (n_new_dev > 0)
                log_warning("%u new device is found in re-scan", n_new_dev);

        /* Assume that not so many devices are plugged. */
        assert_se(n_new_dev <= 10);
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
        _cleanup_free_ uint8_t *nulstr_copy = NULL;
        const char *devlink;
        const uint8_t *nulstr;
        size_t len;

        assert_se(sd_device_new_from_syspath(&device, "/sys/class/net/lo") >= 0);

        /* Yeah, of course, setting devlink to the loopback interface is nonsense. But this is just a
         * test for generating and parsing nulstr. For issue #17772. */
        NULSTR_FOREACH(devlink, devlinks) {
                log_device_info(device, "setting devlink: %s", devlink);
                assert_se(device_add_devlink(device, devlink) >= 0);
                assert_se(set_contains(device->devlinks, devlink));
        }

        /* These properties are necessary for device_new_from_nulstr(). See device_verify(). */
        assert_se(device_add_property_internal(device, "SEQNUM", "1") >= 0);
        assert_se(device_add_property_internal(device, "ACTION", "change") >= 0);

        assert_se(device_get_properties_nulstr(device, &nulstr, &len) >= 0);
        assert_se(nulstr_copy = newdup(uint8_t, nulstr, len));
        assert_se(device_new_from_nulstr(&from_nulstr, nulstr_copy, len) >= 0);

        NULSTR_FOREACH(devlink, devlinks) {
                log_device_info(from_nulstr, "checking devlink: %s", devlink);
                assert_se(set_contains(from_nulstr->devlinks, devlink));
        }
}

DEFINE_TEST_MAIN(LOG_INFO);

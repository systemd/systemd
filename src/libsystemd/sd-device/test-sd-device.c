/* SPDX-License-Identifier: LGPL-2.1+ */

#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-util.h"
#include "hashmap.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

static void test_sd_device_basic(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;

        log_info("/* %s */", __func__);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        FOREACH_DEVICE(e, d) {
                const char *syspath, *subsystem, *val;
                dev_t devnum;
                usec_t usec;
                int i, r;

                assert_se(sd_device_get_syspath(d, &syspath) >= 0);

                r = sd_device_get_subsystem(d, &subsystem);
                assert_se(r >= 0 || r == -ENOENT);

                r = sd_device_get_devtype(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                r = sd_device_get_devnum(d, &devnum);
                assert_se((r >= 0 && major(devnum) > 0) || r == -ENOENT);

                r = sd_device_get_ifindex(d, &i);
                assert_se((r >= 0 && i > 0) || r == -ENOENT);

                r = sd_device_get_driver(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                assert_se(sd_device_get_devpath(d, &val) >= 0);

                r = sd_device_get_devname(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                assert_se(sd_device_get_sysname(d, &val) >= 0);

                r = sd_device_get_sysnum(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                i = sd_device_get_is_initialized(d);
                assert_se(i >= 0);
                if (i > 0) {
                        r = sd_device_get_usec_since_initialized(d, &usec);
                        assert_se((r >= 0 && usec > 0) || r == -ENODATA);
                }

                r = sd_device_get_sysattr_value(d, "name_assign_type", &val);
                assert_se(r >= 0 || IN_SET(r, -ENOENT, -EINVAL));

                r = sd_device_get_property_value(d, "ID_NET_DRIVER", &val);
                assert_se(r >= 0 || r == -ENOENT);

                log_debug("subsystem:%s syspath:%s initialized:%s", strna(subsystem), syspath, yes_no(i));
        }
}

static void test_sd_device_enumerator_filter_subsystem_one(const char *subsystem, Hashmap *h) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d, *t;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, subsystem, true) >= 0);

        FOREACH_DEVICE(e, d) {
                const char *syspath;

                assert_se(sd_device_get_syspath(d, &syspath) >= 0);
                assert_se(t = hashmap_remove(h, syspath));
                assert_se(!sd_device_unref(t));

                log_debug("Removed subsystem:%s syspath:%s", subsystem, syspath);
        }

        assert_se(hashmap_isempty(h));
}

static void test_sd_device_enumerator_filter_subsystem(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(hashmap_freep) Hashmap *subsystems;
        sd_device *d;
        Hashmap *h;
        char *s;

        log_info("/* %s */", __func__);

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
                test_sd_device_enumerator_filter_subsystem_one(s, h);
                hashmap_free(h);
                free(s);
        }
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_sd_device_basic();
        test_sd_device_enumerator_filter_subsystem();

        return 0;
}

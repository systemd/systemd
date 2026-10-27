/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "fd-util.h"
#include "fileio.h"
#include "metrics.h"
#include "path-util.h"
#include "psi-util.h"
#include "report-cgroup.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"

typedef enum TestFamily {
        TEST_AVG10,
        TEST_STALL_SECONDS,
        _TEST_FAMILY_MAX,
} TestFamily;

static const MetricFamily test_metric_family_table[_TEST_FAMILY_MAX] = {
        [TEST_AVG10] = {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "PressureAvg10",
                "Test: pressure stall percentage over the last 10s",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        [TEST_STALL_SECONDS] = {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "PressureStallSeconds",
                "Test: total time stalled in seconds",
                METRIC_FAMILY_TYPE_COUNTER,
        },
};

/* What the pressure attributes in the fake cgroup directory look like. */
typedef enum TestFiles {
        TEST_FILES_COMPLETE,    /* "some" and "full" for every resource */
        TEST_FILES_NO_CPU_FULL, /* kernels before 5.13 emit no "full" line for cpu */
        TEST_FILES_GARBAGE_CPU, /* an unparseable cpu.pressure must not take the scrape down */
        TEST_FILES_NONE,        /* a host without PSI has no pressure attributes at all */
        _TEST_FILES_MAX,
} TestFiles;

typedef struct TestData {
        const char *path;
        unsigned n_units;
        TestFiles files;
        unsigned counts[_PRESSURE_RESOURCE_MAX][_PRESSURE_TYPE_MAX][_TEST_FAMILY_MAX];
} TestData;

static unsigned expected_count(const TestData *data, PressureResource resource, PressureType type) {
        assert(data);

        if (data->files == TEST_FILES_NONE)
                return 0;

        if (resource == PRESSURE_CPU) {
                if (data->files == TEST_FILES_GARBAGE_CPU)
                        return 0;
                if (data->files == TEST_FILES_NO_CPU_FULL && type == PRESSURE_TYPE_FULL)
                        return 0;
        }

        return data->n_units;
}

static int method_pressure(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        TestData *data = ASSERT_PTR(userdata);

        ASSERT_OK(sd_varlink_set_sentinel(link, "io.systemd.Metrics.NoSuchMetric"));
        for (unsigned i = 0; i < data->n_units; i++) {
                ASSERT_OK(report_cgroup_pressure_send(
                                  test_metric_family_table, link, data->path, "test-pressure.service"));
                ASSERT_OK(sd_varlink_flush(link));
        }

        return 0;
}

static int reply_pressure(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        TestData *data = ASSERT_PTR(userdata);

        if (error_id) {
                ASSERT_STREQ(error_id, "io.systemd.Metrics.NoSuchMetric");
                ASSERT_TRUE(data->files == TEST_FILES_NONE);
                goto finish;
        }

        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(parameters, "object")), "test-pressure.service");

        sd_json_variant *fields = sd_json_variant_by_key(parameters, "fields");
        PressureResource resource = pressure_resource_from_string(sd_json_variant_string(sd_json_variant_by_key(fields, "resource")));
        PressureType type = pressure_type_from_string(sd_json_variant_string(sd_json_variant_by_key(fields, "type")));
        ASSERT_GE(resource, 0);
        ASSERT_GE(type, 0);
        ASSERT_GT(expected_count(data, resource, type), 0U);

        const char *name = sd_json_variant_string(sd_json_variant_by_key(parameters, "name"));
        TestFamily family;
        if (streq(name, METRIC_IO_SYSTEMD_CGROUP_PREFIX "PressureAvg10"))
                family = TEST_AVG10;
        else {
                ASSERT_STREQ(name, METRIC_IO_SYSTEMD_CGROUP_PREFIX "PressureStallSeconds");
                family = TEST_STALL_SECONDS;
        }

        sd_json_variant *value = sd_json_variant_by_key(parameters, "value");
        ASSERT_TRUE(sd_json_variant_is_number(value));
        /* Nonzero, exactly representable values catch missing conversion and the wrong divisor. */
        double expected = family == TEST_AVG10 ? (type == PRESSURE_TYPE_SOME ? 12.5 : 6.25) :
                                                 (type == PRESSURE_TYPE_SOME ? 1.25 : 0.5);
        ASSERT_TRUE(fabs(sd_json_variant_real(value) - expected) < 1e-9);
        data->counts[resource][type][family]++;

finish:
        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), 0));

        return 0;
}

static void run_pressure_test(unsigned n_units, TestFiles files) {
        _cleanup_(rm_rf_physical_and_freep) char *path = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *client = NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-report-pressure-XXXXXX", &path));
        if (files != TEST_FILES_NONE)
                FOREACH_STRING(resource, "cpu", "memory", "io") {
                        _cleanup_free_ char *p = path_join(path, strjoina(resource, ".pressure"));
                        ASSERT_NOT_NULL(p);

                        const char *contents;
                        if (streq(resource, "cpu") && files == TEST_FILES_GARBAGE_CPU)
                                contents = "this is not a pressure file\n";
                        else if (streq(resource, "cpu") && files == TEST_FILES_NO_CPU_FULL)
                                contents = "some avg10=12.50 avg60=1.00 avg300=2.00 total=1250000\n";
                        else
                                contents = "some avg10=12.50 avg60=1.00 avg300=2.00 total=1250000\n"
                                           "full avg10=6.25 avg60=0.50 avg300=1.00 total=500000\n";

                        ASSERT_OK(write_string_file(p, contents, WRITE_STRING_FILE_CREATE));
                }

        TestData data = { .path = path, .n_units = n_units, .files = files };
        ASSERT_OK(sd_event_default(&event));
        ASSERT_OK(varlink_server_new(&server, SD_VARLINK_SERVER_INHERIT_USERDATA, &data));
        ASSERT_OK(sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Metrics));
        ASSERT_OK(varlink_server_bind_fiber(server, "io.systemd.Metrics.List", method_pressure));
        ASSERT_OK(sd_varlink_server_attach_event(server, event, 0));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, pair));
        ASSERT_OK(sd_varlink_server_add_connection(server, pair[0], /* ret= */ NULL));
        TAKE_FD(pair[0]);
        ASSERT_OK(sd_varlink_connect_fd(&client, pair[1]));
        TAKE_FD(pair[1]);
        sd_varlink_set_userdata(client, &data);
        ASSERT_OK(sd_varlink_bind_reply(client, reply_pressure));
        ASSERT_OK(sd_varlink_attach_event(client, event, 0));
        ASSERT_OK(sd_varlink_observe(client, "io.systemd.Metrics.List", /* parameters= */ NULL));
        ASSERT_OK(sd_event_loop(event));

        for (PressureResource resource = 0; resource < _PRESSURE_RESOURCE_MAX; resource++)
                for (PressureType type = 0; type < _PRESSURE_TYPE_MAX; type++)
                        for (TestFamily family = 0; family < _TEST_FAMILY_MAX; family++)
                                ASSERT_EQ(data.counts[resource][type][family],
                                          expected_count(&data, resource, type));
}

TEST(pressure) {
        run_pressure_test(1, TEST_FILES_COMPLETE);
}

TEST(pressure_without_cpu_full) {
        run_pressure_test(1, TEST_FILES_NO_CPU_FULL);
}

TEST(pressure_garbage) {
        /* A file we can't parse is ignored like a missing one */
        run_pressure_test(1, TEST_FILES_GARBAGE_CPU);
}

TEST(pressure_unsupported) {
        /* No pressure attributes at all, so no replies, but the scrape itself must still succeed. */
        run_pressure_test(1, TEST_FILES_NONE);
}

TEST(pressure_large_scrape) {
        /* Many more replies than fit the Varlink output buffer */
        run_pressure_test(10000, TEST_FILES_COMPLETE);
}

DEFINE_TEST_MAIN(LOG_INFO);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "psi-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(read_mem_pressure) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/pressurereadtestXXXXXX";
        _cleanup_close_ int fd = -EBADF;
        ResourcePressure rp;

        ASSERT_OK(fd = mkostemp_safe(path));

        ASSERT_LT(read_resource_pressure("/verylikelynonexistentpath", PRESSURE_TYPE_SOME, &rp), 0);
        ASSERT_LT(read_resource_pressure(path, PRESSURE_TYPE_SOME, &rp), 0);

        ASSERT_OK(write_string_file(path, "herpdederp\n", WRITE_STRING_FILE_CREATE));
        ASSERT_LT(read_resource_pressure(path, PRESSURE_TYPE_SOME, &rp), 0);

        /* Pressure file with some invalid values */
        ASSERT_OK(write_string_file(path, "some avg10=0.22=55 avg60=0.17=8 avg300=1.11=00 total=58761459\n"
                                         "full avg10=0.23=55 avg60=0.16=8 avg300=1.08=00 total=58464525", WRITE_STRING_FILE_CREATE));
        ASSERT_LT(read_resource_pressure(path, PRESSURE_TYPE_SOME, &rp), 0);

        /* Same pressure valid values as below but with duplicate avg60 field */
        ASSERT_OK(write_string_file(path, "some avg10=0.22 avg60=0.17 avg60=0.18 avg300=1.11 total=58761459\n"
                                         "full avg10=0.23 avg60=0.16 avg300=1.08 total=58464525", WRITE_STRING_FILE_CREATE));
        ASSERT_LT(read_resource_pressure(path, PRESSURE_TYPE_SOME, &rp), 0);

        ASSERT_OK(write_string_file(path, "some avg10=0.22 avg60=0.17 avg300=1.11 total=58761459\n"
                                         "full avg10=0.23 avg60=0.16 avg300=1.08 total=58464525", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_resource_pressure(path, PRESSURE_TYPE_SOME, &rp));
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg10), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg10), 22U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg60), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg60), 17U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg300), 1U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg300), 11U);
        ASSERT_EQ(rp.total, 58761459U);
        ASSERT_OK(read_resource_pressure(path, PRESSURE_TYPE_FULL, &rp));
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg10), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg10), 23U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg60), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg60), 16U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg300), 1U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg300), 8U);
        ASSERT_EQ(rp.total, 58464525U);

        /* Pressure file with extra unsupported fields */
        ASSERT_OK(write_string_file(path, "some avg5=0.55 avg10=0.22 avg60=0.17 avg300=1.11 total=58761459\n"
                                         "full avg10=0.23 avg60=0.16 avg300=1.08 avg600=2.00 total=58464525", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_resource_pressure(path, PRESSURE_TYPE_SOME, &rp));
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg10), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg10), 22U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg60), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg60), 17U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg300), 1U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg300), 11U);
        ASSERT_EQ(rp.total, 58761459U);
        ASSERT_OK(read_resource_pressure(path, PRESSURE_TYPE_FULL, &rp));
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg10), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg10), 23U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg60), 0U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg60), 16U);
        ASSERT_EQ(LOADAVG_INT_SIDE(rp.avg300), 1U);
        ASSERT_EQ(LOADAVG_DECIMAL_SIDE(rp.avg300), 8U);
        ASSERT_EQ(rp.total, 58464525U);
}

TEST(read_resource_pressure_file) {
        _cleanup_fclose_ FILE *f = NULL;
        ResourcePressure rp;
        char data[] = "some avg10=12.50 avg60=1.00 avg300=2.00 total=1250000\n"
                      "full avg10=6.25 avg60=0.50 avg300=1.00 total=500000\n";

        ASSERT_NOT_NULL(f = fmemopen(data, strlen(data), "r"));
        ASSERT_OK(read_resource_pressure_file(f, PRESSURE_TYPE_SOME, &rp));
        ASSERT_EQ(rp.total, 1250000U);
        ASSERT_EQ(rp.avg10, 12U * LOADAVG_FIXED_POINT_1_0 + LOADAVG_FIXED_POINT_1_0 / 2);
        ASSERT_OK(read_resource_pressure_file(f, PRESSURE_TYPE_FULL, &rp));
        ASSERT_EQ(rp.total, 500000U);
        ASSERT_EQ(rp.avg10, 6U * LOADAVG_FIXED_POINT_1_0 + LOADAVG_FIXED_POINT_1_0 / 4);
        ASSERT_ERROR(read_resource_pressure_file(f, PRESSURE_TYPE_FULL, &rp), ENODATA);

        /* Older kernels provide only the some line for CPU pressure. */
        f = safe_fclose(f);
        char some[] = "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        ASSERT_NOT_NULL(f = fmemopen(some, strlen(some), "r"));
        ASSERT_OK(read_resource_pressure_file(f, PRESSURE_TYPE_SOME, &rp));
        ASSERT_ERROR(read_resource_pressure_file(f, PRESSURE_TYPE_FULL, &rp), ENODATA);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "runtime-measure.h"
#include "tdx-rtmr.h"
#include "tests.h"
#include "tmpfile-util.h"

/* SHA384("abc") */
#define SHA384_ABC_HEX \
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"

/* HMAC-SHA384 test case 2 from RFC 4231: key "Jefe", data "what do ya want for nothing?" */
#define HMAC_JEFE_HEX \
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"

static void setup_rtmrs(const char *dir) {
        for (unsigned i = 0; i < 4; i++) {
                _cleanup_free_ char *p = NULL;

                ASSERT_OK(asprintf(&p, "%s/rtmr%u:sha384", dir, i));
                ASSERT_OK(touch(p));
        }
}

static void check_rtmr(const char *dir, unsigned expect_rtmr, const char *expect_hex) {
        for (unsigned i = 0; i < 4; i++) {
                _cleanup_free_ char *p = NULL, *reg = NULL;
                size_t size;

                ASSERT_OK(asprintf(&p, "%s/rtmr%u:sha384", dir, i));
                ASSERT_OK(read_full_file(p, &reg, &size));

                if (i == expect_rtmr) {
                        _cleanup_free_ char *hex = hexmem(reg, size);
                        ASSERT_NOT_NULL(hex);
                        ASSERT_STREQ(hex, expect_hex);
                } else
                        ASSERT_EQ(size, (size_t) 0);
        }
}

TEST(runtime_measurement_extend_bytes_tdx_rtmr) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *log_path = NULL;
        RuntimeMeasureBackends b = {};

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", d, /* overwrite= */ 1));

        /* Redirect the event log the RTMR backend writes; it's not inspected here. */
        log_path = path_join(d, "cc-measure.log");
        ASSERT_NOT_NULL(log_path);
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_CC_USERSPACE", log_path, /* overwrite= */ 1));

        setup_rtmrs(d);

        /* Without a secret, a plain hash of the data is measured, into the RTMR the PCR maps to */
        ASSERT_OK(runtime_measurement_extend_bytes(&b, /* pcr= */ 11, &IOVEC_MAKE_STRING("abc"),
                                                   /* secret= */ NULL, USERSPACE_MEASUREMENT_EVENT_PHASE, "foobar"));
        check_rtmr(d, 2, SHA384_ABC_HEX);

        /* With a secret, an HMAC keyed by it is measured instead of a plain hash */
        ASSERT_OK(runtime_measurement_extend_bytes(&b, /* pcr= */ 11,
                                                   &IOVEC_MAKE_STRING("what do ya want for nothing?"),
                                                   &IOVEC_MAKE_STRING("Jefe"),
                                                   USERSPACE_MEASUREMENT_EVENT_VOLUME_KEY, "secret"));
        check_rtmr(d, 2, HMAC_JEFE_HEX);

        /* PCRs without an RTMR equivalent aren't measured anywhere */
        ASSERT_ERROR(runtime_measurement_extend_bytes(&b, /* pcr= */ 16, &IOVEC_MAKE_STRING("abc"),
                                                      /* secret= */ NULL, USERSPACE_MEASUREMENT_EVENT_PHASE, "nope"),
                                                      EOPNOTSUPP);
        ASSERT_ERROR(runtime_measurement_extend_bytes(&b, /* pcr= */ 0, &IOVEC_MAKE_STRING("abc"),
                                                      /* secret= */ NULL, USERSPACE_MEASUREMENT_EVENT_PHASE, "nope"),
                                                      EOPNOTSUPP);
        check_rtmr(d, 2, HMAC_JEFE_HEX);
}

TEST(runtime_measurement_extend_nvpcr_tdx_rtmr) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *log_path = NULL;
        RuntimeMeasureBackends b = {};

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", d, /* overwrite= */ 1));

        /* Redirect the event log the RTMR backend writes; it's not inspected here. */
        log_path = path_join(d, "cc-measure.log");
        ASSERT_NOT_NULL(log_path);
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_CC_USERSPACE", log_path, /* overwrite= */ 1));

        setup_rtmrs(d);

        ASSERT_OK(runtime_measurement_extend_nvpcr(&b, "hardware", &IOVEC_MAKE_STRING("abc"),
                                                   /* secret= */ NULL, USERSPACE_MEASUREMENT_EVENT_PRODUCT_ID, "prod"));

        /* NvPCR measurements go to their fixed RTMR... */
        check_rtmr(d, TDX_NVPCR_RTMR, SHA384_ABC_HEX);
}

TEST(runtime_measurement_no_backend) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *log_path = NULL, *missing = NULL;
        RuntimeMeasureBackends b = {};

        ASSERT_OK(mkdtemp_malloc(NULL, &d));

        log_path = path_join(d, "cc-measure.log");
        ASSERT_NOT_NULL(log_path);
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_CC_USERSPACE", log_path, /* overwrite= */ 1));

        /* No TPM2 backend, no RTMR sysfs dir: nothing to measure into */
        missing = path_join(d, "missing");
        ASSERT_NOT_NULL(missing);
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", missing, /* overwrite= */ 1));

        ASSERT_ERROR(runtime_measurement_extend_bytes(&b, /* pcr= */ 11, &IOVEC_MAKE_STRING("abc"),
                                                      /* secret= */ NULL,
                                                      USERSPACE_MEASUREMENT_EVENT_PHASE, "nope"), EOPNOTSUPP);
        ASSERT_ERROR(runtime_measurement_extend_nvpcr(&b, "hardware", &IOVEC_MAKE_STRING("abc"),
                                                      /* secret= */ NULL,
                                                      USERSPACE_MEASUREMENT_EVENT_PRODUCT_ID, "nope"), EOPNOTSUPP);

        /* No backend was ever asked to measure */
        ASSERT_LT(access(log_path, F_OK), 0);

        /* An RTMR sysfs dir without the register attribute is a present but broken backend */
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", d, /* overwrite= */ 1));
        ASSERT_ERROR(runtime_measurement_extend_bytes(&b, /* pcr= */ 11, &IOVEC_MAKE_STRING("abc"),
                                                      /* secret= */ NULL,
                                                      USERSPACE_MEASUREMENT_EVENT_PHASE, "nope"), ENXIO);
}

TEST(runtime_measurements_supported) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", d, /* overwrite= */ 1));

        ASSERT_TRUE(runtime_measurements_supported());

        /* The negative case is deliberately not asserted: on hosts with a real TPM2 the function
         * legitimately returns true regardless of the RTMR sysfs override. */
}

DEFINE_TEST_MAIN(LOG_DEBUG);

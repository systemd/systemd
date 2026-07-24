/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"
#include "sd-json.h"

#include "fileio.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "measurement-log.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tdx-rtmr.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(tdx_pcr_to_rtmr_index) {
        ASSERT_ERROR(tdx_pcr_to_rtmr_index(0), EOPNOTSUPP);
        ASSERT_EQ(tdx_pcr_to_rtmr_index(1), 0);
        for (uint32_t pcr = 2; pcr <= 6; pcr++)
                ASSERT_EQ(tdx_pcr_to_rtmr_index(pcr), 1);
        ASSERT_EQ(tdx_pcr_to_rtmr_index(7), 0);
        for (uint32_t pcr = 8; pcr <= 15; pcr++)
                ASSERT_EQ(tdx_pcr_to_rtmr_index(pcr), 2);
        for (uint32_t pcr = 16; pcr <= 23; pcr++)
                ASSERT_ERROR(tdx_pcr_to_rtmr_index(pcr), EOPNOTSUPP);
        ASSERT_ERROR(tdx_pcr_to_rtmr_index(24), EINVAL);
}

/* An arbitrary but fixed 48-byte extension value. (Happens to be SHA384("abc"), but the extend
 * function treats it as opaque.) */
#define TEST_DIGEST_HEX \
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"

/* Parses the last json-seq record of the log at 'path', and returns the total record count. */
static size_t load_last_record(const char *path, sd_json_variant **ret) {
        _cleanup_free_ char *raw = NULL;
        const char *last = NULL;
        size_t size, n = 0;

        ASSERT_OK(read_full_file(path, &raw, &size));

        for (size_t i = 0; i < size; i++)
                if (raw[i] == 0x1E) {
                        n++;
                        last = raw + i + 1;
                }

        ASSERT_NOT_NULL(last);
        ASSERT_OK(sd_json_parse(last, 0, ret, NULL, NULL));

        return n;
}


TEST(tdx_rtmr_extend_digest) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *rec = NULL;
        _cleanup_free_ char *log_path = NULL, *rtmr_path = NULL, *reg = NULL;
        struct stat st;
        sd_id128_t boot_id;
        size_t reg_size;

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", d, /* overwrite= */ 1));

        log_path = path_join(d, "cc-measure.log");
        ASSERT_NOT_NULL(log_path);
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_CC_USERSPACE", log_path, /* overwrite= */ 1));

        ASSERT_TRUE(tdx_rtmr_supported());

        rtmr_path = path_join(d, "rtmr2:sha384");
        ASSERT_NOT_NULL(rtmr_path);
        ASSERT_OK(touch(rtmr_path));

        DEFINE_HEX_PTR(digest, TEST_DIGEST_HEX);

        /* PCR-flavored measurement */
        ASSERT_OK(tdx_rtmr_extend_digest(/* rtmr= */ 2,
                                         /* digest= */ &IOVEC_MAKE(digest, digest_len),
                                         /* pcr_index= */ 11,
                                         /* nv_index_name= */ NULL,
                                         /* event= */ USERSPACE_MEASUREMENT_EVENT_PHASE,
                                         /* description= */ "foobar"));

        /* The register received the digest verbatim */
        ASSERT_OK(read_full_file(rtmr_path, &reg, &reg_size));
        ASSERT_EQ(reg_size, (size_t) TDX_RTMR_DIGEST_SIZE);
        ASSERT_EQ(memcmp(reg, digest, digest_len), 0);

        /* The log record says what happened */
        ASSERT_EQ(load_last_record(log_path, &rec), 1u);

        sd_json_variant *v;
        v = ASSERT_PTR(sd_json_variant_by_key(rec, "rtmr"));
        ASSERT_EQ(sd_json_variant_unsigned(v), 2u);
        v = ASSERT_PTR(sd_json_variant_by_key(rec, "mapped_pcr"));
        ASSERT_EQ(sd_json_variant_unsigned(v), 11u);
        ASSERT_NULL(sd_json_variant_by_key(rec, "mapped_nv_index"));
        ASSERT_NULL(sd_json_variant_by_key(rec, "pcr"));

        v = ASSERT_PTR(sd_json_variant_by_key(rec, "content_type"));
        ASSERT_STREQ(sd_json_variant_string(v), "systemd");

        sd_json_variant *digests = ASSERT_PTR(sd_json_variant_by_key(rec, "digests"));
        ASSERT_TRUE(sd_json_variant_is_array(digests));
        ASSERT_EQ(sd_json_variant_elements(digests), 1u);
        sd_json_variant *dg = ASSERT_PTR(sd_json_variant_by_index(digests, 0));
        v = ASSERT_PTR(sd_json_variant_by_key(dg, "hashAlg"));
        ASSERT_STREQ(sd_json_variant_string(v), "sha384");
        v = ASSERT_PTR(sd_json_variant_by_key(dg, "digest"));
        ASSERT_STREQ(sd_json_variant_string(v), TEST_DIGEST_HEX);

        sd_json_variant *content = ASSERT_PTR(sd_json_variant_by_key(rec, "content"));
        v = ASSERT_PTR(sd_json_variant_by_key(content, "string"));
        ASSERT_STREQ(sd_json_variant_string(v), "foobar");
        v = ASSERT_PTR(sd_json_variant_by_key(content, "eventType"));
        ASSERT_STREQ(sd_json_variant_string(v),
                userspace_measurement_event_type_to_string(USERSPACE_MEASUREMENT_EVENT_PHASE));
        ASSERT_NULL(sd_json_variant_by_key(content, "nvIndexName"));
        v = ASSERT_PTR(sd_json_variant_by_key(content, "timestamp"));
        ASSERT_TRUE(sd_json_variant_is_unsigned(v));
        ASSERT_OK(sd_id128_get_boot(&boot_id));
        v = ASSERT_PTR(sd_json_variant_by_key(content, "bootId"));
        ASSERT_STREQ(sd_json_variant_string(v), SD_ID128_TO_STRING(boot_id));

        /* The dirty marker is cleared again */
        ASSERT_OK_ERRNO(stat(log_path, &st));
        ASSERT_FALSE(FLAGS_SET(st.st_mode, S_ISVTX));

        /* A second measurement appends, rather than replaces */
        rec = sd_json_variant_unref(rec);
        ASSERT_OK(tdx_rtmr_extend_digest(/* rtmr= */ 2,
                                         /* digest= */ &IOVEC_MAKE(digest, digest_len),
                                         /* pcr_index= */ 11,
                                         /* nv_index_name= */ NULL,
                                         /* event= */ USERSPACE_MEASUREMENT_EVENT_PHASE,
                                         /* description= */ "second"));
        ASSERT_EQ(load_last_record(log_path, &rec), 2u);
        content = ASSERT_PTR(sd_json_variant_by_key(rec, "content"));
        v = ASSERT_PTR(sd_json_variant_by_key(content, "string"));
        ASSERT_STREQ(sd_json_variant_string(v), "second");

        /* NvPCR-flavored measurement */
        rec = sd_json_variant_unref(rec);
        ASSERT_OK(tdx_rtmr_extend_digest(/*rtmr=*/ 2,
                                         /*digest=*/ &IOVEC_MAKE(digest, digest_len),
                                         /* pcr_index= */ UINT_MAX,
                                         /* nv_index_name= */ "hardware",
                                         /* event= */ USERSPACE_MEASUREMENT_EVENT_PRODUCT_ID,
                                         /* description= */ "test"));
        ASSERT_EQ(load_last_record(log_path, &rec), 3u);
        v = ASSERT_PTR(sd_json_variant_by_key(rec, "rtmr"));
        ASSERT_EQ(sd_json_variant_unsigned(v), 2u);
        ASSERT_NULL(sd_json_variant_by_key(rec, "mapped_pcr"));
        content = ASSERT_PTR(sd_json_variant_by_key(rec, "content"));
        v = ASSERT_PTR(sd_json_variant_by_key(content, "nvIndexName"));
        ASSERT_STREQ(sd_json_variant_string(v), "hardware");
        v = ASSERT_PTR(sd_json_variant_by_key(content, "eventType"));
        ASSERT_STREQ(sd_json_variant_string(v),
                userspace_measurement_event_type_to_string(USERSPACE_MEASUREMENT_EVENT_PRODUCT_ID));
}

TEST(tdx_rtmr_extend_digest_failure) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        struct stat st;

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_TDX_MEASUREMENTS_PATH", d, /* overwrite= */ 1));

        _cleanup_free_ char *log_path = path_join(d, "cc-measure.log");
        ASSERT_NOT_NULL(log_path);
        ASSERT_OK_ERRNO(setenv("SYSTEMD_MEASURE_LOG_CC_USERSPACE", log_path, /* overwrite= */ 1));

        DEFINE_HEX_PTR(digest, TEST_DIGEST_HEX);

        /* Missing sysfs attribute fails before the log is marked dirty */
        ASSERT_ERROR(tdx_rtmr_extend_digest(/* rtmr= */ 2,
                                            /* digest= */ &IOVEC_MAKE(digest, digest_len),
                                            /* pcr_index= */ 11,
                                            /* nv_index_name= */ NULL,
                                            /* event= */ USERSPACE_MEASUREMENT_EVENT_PHASE,
                                            /* description= */ "nope"),
                                            ENXIO);
        ASSERT_OK_ERRNO(stat(log_path, &st));  /* the log was created by open()... */
        ASSERT_EQ(st.st_size, (off_t) 0);                /* ...but no record was written... */
        ASSERT_FALSE(FLAGS_SET(st.st_mode, S_ISVTX));    /* ...and it wasn't marked dirty. */

        /* A failing register write leaves the dirty marker behind */
        if (access("/dev/full", W_OK) < 0)
                return (void) log_tests_skipped("/dev/full not available");

        _cleanup_free_ char *rtmr_path = path_join(d, "rtmr2:sha384");
        ASSERT_NOT_NULL(rtmr_path);
        ASSERT_OK_ERRNO(symlink("/dev/full", rtmr_path));
        ASSERT_ERROR(tdx_rtmr_extend_digest(/* rtmr= */ 2,
                                            /* digest= */ &IOVEC_MAKE(digest, digest_len),
                                            /* pcr_index= */ 11,
                                            /* nv_index_name= */ NULL,
                                            /* event= */ USERSPACE_MEASUREMENT_EVENT_PHASE,
                                            /* description= */ "torn"),
                                            ENOSPC);
        ASSERT_OK_ERRNO(stat(log_path, &st));
        ASSERT_TRUE(FLAGS_SET(st.st_mode, S_ISVTX));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

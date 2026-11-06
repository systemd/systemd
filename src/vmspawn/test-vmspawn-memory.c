/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "time-util.h"
#include "vmspawn-memory.h"

TEST(memory_stats_parse) {
        static const struct {
                const char *json;
                int want_error;
                VmspawnMemoryStats want_stats;
        } cases[] = {
                { .json = "{}", .want_error = ENXIO },
                { .json = "[]", .want_error = EINVAL },
                { .json = "{\"stats\":{}}", .want_error = ENXIO },
                { .json = "{\"last-update\":1}", .want_error = ENXIO },
                { .json = "{\"last-update\":0,\"stats\":{}}", .want_error = ENODATA },
                { .json = "{\"last-update\":1,\"stats\":[]}", .want_error = EINVAL },
                { .json = "{\"last-update\":\"1\",\"stats\":{}}", .want_error = EINVAL },
                { .json = "{\"last-update\":-1,\"stats\":{}}", .want_error = EINVAL },
                { .json = "{\"last-update\":288230376151711744,\"stats\":{}}", .want_error = ERANGE },
                { .json = "{\"last-update\":1,\"stats\":{\"stat-total-memory\":1,\"stat-free-memory\":1,\"stat-oom-kills\":-5}}", .want_error = EINVAL },
                { .json = "{\"last-update\":1,\"stats\":{\"stat-total-memory\":1,\"stat-free-memory\":1,\"stat-alloc-stalls\":\"many\"}}", .want_error = EINVAL },
                { .json = "{\"last-update\":0,\"stats\":{\"stat-total-memory\":1,\"stat-free-memory\":1}}", .want_error = ENODATA },
                { .json = "{\"last-update\":1,\"stats\":{}}", .want_error = ENODATA },
                { .json = "{\"last-update\":1,\"stats\":{\"stat-total-memory\":1}}", .want_error = ENODATA },
                { .json = "{\"last-update\":1,\"stats\":{\"stat-free-memory\":1}}", .want_error = ENODATA },
                { .json = "{\"last-update\":1,\"stats\":{\"stat-total-memory\":18446744073709551615,\"stat-free-memory\":1}}", .want_error = ENODATA },
                {
                        .json = "{\"last-update\":1700000000,\"stats\":{"
                                "\"stat-total-memory\":1000,\"stat-free-memory\":1001,"
                                "\"stat-available-memory\":1002,\"stat-disk-caches\":1003,"
                                "\"stat-swap-in\":1004,\"stat-swap-out\":1005,"
                                "\"stat-major-faults\":1006,\"stat-minor-faults\":1007,"
                                "\"stat-htlb-pgalloc\":1008,\"stat-htlb-pgfail\":1009,"
                                "\"stat-oom-kills\":1010,\"stat-alloc-stalls\":1011,"
                                "\"stat-async-scans\":1012,\"stat-direct-scans\":1013,"
                                "\"stat-async-reclaims\":1014,\"stat-direct-reclaims\":1015}}",
                        .want_stats = {
                                .last_update = 1700000000 * USEC_PER_SEC,
                                .total = 1000,
                                .free = 1001,
                                .available = 1002,
                                .disk_caches = 1003,
                                .swap_in = 1004,
                                .swap_out = 1005,
                                .major_faults = 1006,
                                .minor_faults = 1007,
                                .hugetlb_allocations = 1008,
                                .hugetlb_failures = 1009,
                                .oom_kills = 1010,
                                .alloc_stalls = 1011,
                                .async_scans = 1012,
                                .direct_scans = 1013,
                                .async_reclaims = 1014,
                                .direct_reclaims = 1015,
                        },
                },
                {
                        /* Missing and UINT64_MAX stats are not reported, unknown fields are ignored */
                        .json = "{\"last-update\":1,\"future\":1,\"stats\":{"
                                "\"stat-total-memory\":1000,\"stat-free-memory\":0,"
                                "\"stat-available-memory\":18446744073709551615,"
                                "\"stat-swap-in\":0,\"stat-future\":1}}",
                        .want_stats = {
                                .last_update = USEC_PER_SEC,
                                .total = 1000,
                                .free = 0,
                                .available = UINT64_MAX,
                                .disk_caches = UINT64_MAX,
                                .swap_in = 0,
                                .swap_out = UINT64_MAX,
                                .major_faults = UINT64_MAX,
                                .minor_faults = UINT64_MAX,
                                .hugetlb_allocations = UINT64_MAX,
                                .hugetlb_failures = UINT64_MAX,
                                .oom_kills = UINT64_MAX,
                                .alloc_stalls = UINT64_MAX,
                                .async_scans = UINT64_MAX,
                                .direct_scans = UINT64_MAX,
                                .async_reclaims = UINT64_MAX,
                                .direct_reclaims = UINT64_MAX,
                        },
                },
        };

        VmspawnMemoryStats stats;

        /* A QMP reply without "return" has no result */
        ASSERT_ERROR(vmspawn_memory_stats_parse(NULL, &stats), ENXIO);

        FOREACH_ELEMENT(c, cases) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                int r;

                ASSERT_OK(sd_json_parse(c->json, 0, &v, NULL, NULL));
                r = vmspawn_memory_stats_parse(v, &stats);
                if (c->want_error != 0) {
                        ASSERT_ERROR(r, c->want_error);
                        continue;
                }
                ASSERT_OK(r);
                ASSERT_EQ(memcmp(&stats, &c->want_stats, sizeof(stats)), 0);
        }
}

TEST(memory_build_json) {
        static const struct {
                VmspawnMemory memory;
                const char *want_json;
        } cases[] = {
                {
                        .memory = { .configured = 2048, .target = 1024 },
                        .want_json = "{\"configuredBytes\":2048,\"targetBytes\":1024}",
                },
                {
                        .memory = { .configured = 2048, .target = 1024, .actual = 1024 },
                        .want_json = "{\"configuredBytes\":2048,\"targetBytes\":1024,\"actualBytes\":1024}",
                },
                {
                        /* Statistics without a report are not emitted */
                        .memory = { .configured = 2048, .target = 2048, .actual = 2048, .stats = { .total = 1000, .free = 500 } },
                        .want_json = "{\"configuredBytes\":2048,\"targetBytes\":2048,\"actualBytes\":2048}",
                },
                {
                        /* Zero is a reported value and is emitted */
                        .memory = {
                                .configured = 2048,
                                .target = 2048,
                                .actual = 2048,
                                .stats = { .last_update = 5 * USEC_PER_SEC, .total = 1000, .free = 500 },
                        },
                        .want_json = "{\"configuredBytes\":2048,\"targetBytes\":2048,\"actualBytes\":2048,\"stats\":{"
                                     "\"lastUpdateUSec\":5000000,\"totalBytes\":1000,\"freeBytes\":500,"
                                     "\"availableBytes\":0,\"diskCachesBytes\":0,"
                                     "\"swapInBytes\":0,\"swapOutBytes\":0,"
                                     "\"majorFaults\":0,\"minorFaults\":0,"
                                     "\"hugetlbAllocations\":0,\"hugetlbFailures\":0,"
                                     "\"oomKills\":0,\"allocationStalls\":0,"
                                     "\"asyncScansBytes\":0,\"directScansBytes\":0,"
                                     "\"asyncReclaimsBytes\":0,\"directReclaimsBytes\":0}}",
                },
                {
                        /* UINT64_MAX means not reported and is omitted */
                        .memory = {
                                .configured = 2048,
                                .target = 2048,
                                .actual = 2048,
                                .stats = {
                                        .last_update = 5 * USEC_PER_SEC,
                                        .total = 1000,
                                        .free = 500,
                                        .available = UINT64_MAX,
                                        .disk_caches = UINT64_MAX,
                                        .swap_in = UINT64_MAX,
                                        .swap_out = UINT64_MAX,
                                        .major_faults = 7,
                                        .minor_faults = UINT64_MAX,
                                        .hugetlb_allocations = UINT64_MAX,
                                        .hugetlb_failures = UINT64_MAX,
                                        .oom_kills = UINT64_MAX,
                                        .alloc_stalls = UINT64_MAX,
                                        .async_scans = UINT64_MAX,
                                        .direct_scans = UINT64_MAX,
                                        .async_reclaims = UINT64_MAX,
                                        .direct_reclaims = UINT64_MAX,
                                },
                        },
                        .want_json = "{\"configuredBytes\":2048,\"targetBytes\":2048,\"actualBytes\":2048,\"stats\":{"
                                     "\"lastUpdateUSec\":5000000,\"totalBytes\":1000,\"freeBytes\":500,\"majorFaults\":7}}",
                },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *want = NULL;

                ASSERT_OK(sd_json_parse(c->want_json, 0, &want, NULL, NULL));
                ASSERT_OK(vmspawn_memory_build_json(&c->memory, &v));
                ASSERT_TRUE(sd_json_variant_equal(v, want));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "oomd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static char *cgroup = NULL;

STATIC_DESTRUCTOR_REGISTER(cgroup, freep);

static int enter_cgroup_root_cached(void) {
        static int saved_result = 0; /* 0: not entered, 1: success, negative errno: error */
        int r;

        if (saved_result != 0)
                return saved_result;

        r = enter_cgroup_root(&cgroup);
        if (r < 0) {
                log_tests_skipped_errno(r, "Failed to enter a test cgroup scope");
                saved_result = r;
        } else
                saved_result = 1;

        return saved_result;
}

static int fork_and_sleep(unsigned sleep_min) {
        pid_t pid;
        int r;

        ASSERT_OK(r = safe_fork("(test-oom-child)", /* flags = */ 0, &pid));
        if (r == 0) {
                usec_t timeout = usec_add(now(CLOCK_MONOTONIC), sleep_min * USEC_PER_MINUTE);
                for (;;) {
                        usec_t n = now(CLOCK_MONOTONIC);
                        if (timeout < n) {
                                log_error("Child timed out waiting to be killed");
                                abort();
                        }
                        sleep(1);
                }
        }

        return pid;
}

TEST(oomd_cgroup_kill) {
        _cleanup_free_ char *subcgroup = NULL;
        int r;

        if (enter_cgroup_root_cached() < 0)
                return;

        /* Create another cgroup below this one for the pids we forked off. We need this to be managed
         * by the test so that pid1 doesn't delete it before we can read the xattrs. */
        ASSERT_NOT_NULL(subcgroup = path_join(cgroup, "oomdkilltest"));
        /* Always start clean, in case of repeated runs and failures */
        ASSERT_OK(cg_trim(subcgroup, /* delete_root */ true));
        ASSERT_OK(cg_create(subcgroup));

        /* If we don't have permissions to set xattrs we're likely in a userns or missing capabilities */
        r = cg_set_xattr(subcgroup, "user.oomd_test", "test", 4, 0);
        if (ERRNO_IS_PRIVILEGE(r) || ERRNO_IS_NOT_SUPPORTED(r))
                return (void) log_tests_skipped("Cannot set user xattrs");

        /* Do this twice to also check the increment behavior on the xattrs */
        for (size_t i = 0; i < 2; i++) {
                _cleanup_free_ char *v = NULL;
                pid_t pid[2];

                for (size_t j = 0; j < 2; j++) {
                        pid[j] = fork_and_sleep(5);
                        ASSERT_OK(cg_attach(subcgroup, pid[j]));
                }

                ASSERT_OK_POSITIVE(oomd_cgroup_kill(subcgroup, false /* recurse */, false /* dry run */));

                ASSERT_OK(cg_get_xattr(subcgroup, "user.oomd_ooms", &v, /* ret_size= */ NULL));
                ASSERT_STREQ(v, i == 0 ? "1" : "2");
                v = mfree(v);

                /* Wait a bit since processes may take some time to be cleaned up. */
                bool empty = false;
                for (size_t t = 0; t < 100; t++) {
                        usleep_safe(100 * USEC_PER_MSEC);
                        ASSERT_OK(r = cg_is_empty(subcgroup));
                        if (r > 0) {
                                empty = true;
                                break;
                        }
                }
                ASSERT_TRUE(empty);

                ASSERT_OK(cg_get_xattr(subcgroup, "user.oomd_kill", &v, /* ret_size= */ NULL));
                ASSERT_STREQ(v, i == 0 ? "2" : "4");
        }

        ASSERT_OK(cg_trim(subcgroup, /* delete_root */ true));
}

TEST(oomd_cgroup_context_acquire_and_insert) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL, *h2 = NULL;
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *ctx = NULL;
        OomdCGroupContext *c1, *c2;
        CGroupMask mask;

        if (!is_pressure_supported())
                return (void) log_tests_skipped("system does not support pressure");

        if (enter_cgroup_root_cached() < 0)
                return;

        ASSERT_OK(cg_mask_supported(&mask));
        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return (void) log_tests_skipped("cgroup memory controller is not available");

        ASSERT_OK(oomd_cgroup_context_acquire(cgroup, &ctx));

        ASSERT_STREQ(ctx->path, cgroup);
        ASSERT_GT(ctx->current_memory_usage, 0u);
        ASSERT_EQ(ctx->memory_min, 0u);
        ASSERT_EQ(ctx->memory_low, 0u);
        ASSERT_EQ(ctx->swap_usage, 0u);
        ASSERT_EQ(ctx->last_pgscan, 0u);
        ASSERT_EQ(ctx->pgscan, 0u);
        ASSERT_NULL(ctx = oomd_cgroup_context_free(ctx));

        ASSERT_OK(oomd_cgroup_context_acquire("", &ctx));
        ASSERT_STREQ(ctx->path, "/");
        ASSERT_GT(ctx->current_memory_usage, 0u);

        /* Test hashmap inserts */
        ASSERT_NOT_NULL(h1 = hashmap_new(&oomd_cgroup_ctx_hash_ops));
        ASSERT_OK(oomd_insert_cgroup_context(NULL, h1, cgroup));
        ASSERT_NOT_NULL(c1 = hashmap_get(h1, cgroup));
        ASSERT_ERROR(oomd_insert_cgroup_context(NULL, h1, cgroup), EEXIST);

         /* make sure certain values from h1 get updated in h2 */
        c1->pgscan = UINT64_MAX;
        c1->mem_pressure_limit = 6789;
        c1->mem_pressure_limit_hit_start = 42;
        c1->mem_pressure_duration_usec = 1234;
        c1->last_had_mem_reclaim = 888;
        ASSERT_NOT_NULL(h2 = hashmap_new(&oomd_cgroup_ctx_hash_ops));
        ASSERT_OK(oomd_insert_cgroup_context(h1, h2, cgroup));
        ASSERT_NOT_NULL(c1 = hashmap_get(h1, cgroup));
        ASSERT_NOT_NULL(c2 = hashmap_get(h2, cgroup));
        ASSERT_TRUE(c1 != c2);
        ASSERT_EQ(c2->last_pgscan, UINT64_MAX);
        ASSERT_EQ(c2->mem_pressure_limit, 6789u);
        ASSERT_EQ(c2->mem_pressure_limit_hit_start, 42u);
        ASSERT_EQ(c2->mem_pressure_duration_usec, 1234u);
        ASSERT_EQ(c2->last_had_mem_reclaim, 888u); /* assumes the live pgscan is less than UINT64_MAX */
}

TEST(oomd_update_cgroup_contexts_between_hashmaps) {
        _cleanup_hashmap_free_ Hashmap *h_old = NULL, *h_new = NULL;
        OomdCGroupContext *c_old, *c_new;
        char **paths = STRV_MAKE("/0.slice",
                                 "/1.slice");

        OomdCGroupContext ctx_old[2] = {
                { .path = paths[0],
                  .mem_pressure_limit = 5,
                  .mem_pressure_limit_hit_start = 777,
                  .mem_pressure_duration_usec = 111,
                  .last_had_mem_reclaim = 888,
                  .pgscan = 57 },
                { .path = paths[1],
                  .mem_pressure_limit = 6,
                  .mem_pressure_limit_hit_start = 888,
                  .mem_pressure_duration_usec = 222,
                  .last_had_mem_reclaim = 888,
                  .pgscan = 42 },
        };

        OomdCGroupContext ctx_new[2] = {
                { .path = paths[0],
                  .pgscan = 57 },
                { .path = paths[1],
                  .pgscan = 101 },
        };

        ASSERT_NOT_NULL(h_old = hashmap_new(&string_hash_ops));
        ASSERT_OK(hashmap_put(h_old, paths[0], &ctx_old[0]));
        ASSERT_OK(hashmap_put(h_old, paths[1], &ctx_old[1]));

        ASSERT_NOT_NULL(h_new = hashmap_new(&string_hash_ops));
        ASSERT_OK(hashmap_put(h_new, paths[0], &ctx_new[0]));
        ASSERT_OK(hashmap_put(h_new, paths[1], &ctx_new[1]));

        oomd_update_cgroup_contexts_between_hashmaps(h_old, h_new);

        ASSERT_NOT_NULL(c_old = hashmap_get(h_old, "/0.slice"));
        ASSERT_NOT_NULL(c_new = hashmap_get(h_new, "/0.slice"));
        ASSERT_EQ(c_old->pgscan, c_new->last_pgscan);
        ASSERT_EQ(c_old->mem_pressure_limit, c_new->mem_pressure_limit);
        ASSERT_EQ(c_old->mem_pressure_limit_hit_start, c_new->mem_pressure_limit_hit_start);
        ASSERT_EQ(c_old->mem_pressure_duration_usec, c_new->mem_pressure_duration_usec);
        ASSERT_EQ(c_old->last_had_mem_reclaim, c_new->last_had_mem_reclaim);

        ASSERT_NOT_NULL(c_old = hashmap_get(h_old, "/1.slice"));
        ASSERT_NOT_NULL(c_new = hashmap_get(h_new, "/1.slice"));
        ASSERT_EQ(c_old->pgscan, c_new->last_pgscan);
        ASSERT_EQ(c_old->mem_pressure_limit, c_new->mem_pressure_limit);
        ASSERT_EQ(c_old->mem_pressure_limit_hit_start, c_new->mem_pressure_limit_hit_start);
        ASSERT_EQ(c_old->mem_pressure_duration_usec, c_new->mem_pressure_duration_usec);
        ASSERT_LT(c_old->last_had_mem_reclaim, c_new->last_had_mem_reclaim);
}

TEST(oomd_system_context_acquire) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/oomdgetsysctxtestXXXXXX";
        _cleanup_close_ int fd = -EBADF;
        OomdSystemContext ctx;

        ASSERT_OK(fd = mkostemp_safe(path));

        ASSERT_ERROR(oomd_system_context_acquire("/verylikelynonexistentpath", &ctx), ENOENT);

        ASSERT_ERROR(oomd_system_context_acquire(path, &ctx), EINVAL);

        ASSERT_OK(write_string_file(path, "some\nwords\nacross\nmultiple\nlines", WRITE_STRING_FILE_CREATE));
        ASSERT_ERROR(oomd_system_context_acquire(path, &ctx), EINVAL);

        ASSERT_OK(write_string_file(path, "MemTotal:       32495256 kB trailing\n"
                                          "MemFree:         9880512 kB data\n"
                                          "SwapTotal:       8388604 kB is\n"
                                          "SwapFree:           7604 kB bad\n",
                                    WRITE_STRING_FILE_CREATE));
        ASSERT_ERROR(oomd_system_context_acquire(path, &ctx), EINVAL);

        ASSERT_OK(write_string_file(path, "MemTotal:       32495256 kB\n"
                                          "MemFree:         9880512 kB\n"
                                          "MemAvailable:   21777088 kB\n"
                                          "Buffers:            5968 kB\n"
                                          "Cached:         14344796 kB\n"
                                          "Unevictable:      740004 kB\n"
                                          "Mlocked:            4484 kB\n"
                                          "SwapTotal:       8388604 kB\n"
                                          "SwapFree:           7604 kB\n",
                                    WRITE_STRING_FILE_CREATE));
        ASSERT_OK(oomd_system_context_acquire(path, &ctx));
        ASSERT_EQ(ctx.mem_total, 33275142144u);
        ASSERT_EQ(ctx.mem_used, 10975404032u);
        ASSERT_EQ(ctx.swap_total, 8589930496u);
        ASSERT_EQ(ctx.swap_used, 8582144000u);
}

TEST(oomd_pressure_above) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL, *h2 = NULL;
        _cleanup_set_free_ Set *t1 = NULL, *t2 = NULL, *t3 = NULL;
        OomdCGroupContext ctx[2] = {}, *c;
        loadavg_t threshold;

        ASSERT_OK(store_loadavg_fixed_point(80, 0, &threshold));

        /* /herp.slice */
        ASSERT_OK(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg10)));
        ASSERT_OK(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg60)));
        ASSERT_OK(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg300)));
        ctx[0].mem_pressure_limit = threshold;
        /* Set memory pressure duration to 0 since we use the real system monotonic clock
         * in oomd_pressure_above() and we want to avoid this test depending on timing. */
        ctx[0].mem_pressure_duration_usec = 0;

        /* /derp.slice */
        ASSERT_OK(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg10)));
        ASSERT_OK(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg60)));
        ASSERT_OK(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg300)));
        ctx[1].mem_pressure_limit = threshold;
        ctx[1].mem_pressure_duration_usec = 0;

        /* High memory pressure */
        ASSERT_NOT_NULL(h1 = hashmap_new(&string_hash_ops));
        ASSERT_OK(hashmap_put(h1, "/herp.slice", &ctx[0]));
        ASSERT_OK_POSITIVE(oomd_pressure_above(h1, &t1));
        ASSERT_TRUE(set_contains(t1, &ctx[0]));
        ASSERT_NOT_NULL(c = hashmap_get(h1, "/herp.slice"));
        ASSERT_GT(c->mem_pressure_limit_hit_start, 0u);

        /* Low memory pressure */
        ASSERT_NOT_NULL(h2 = hashmap_new(&string_hash_ops));
        ASSERT_OK(hashmap_put(h2, "/derp.slice", &ctx[1]));
        ASSERT_OK_ZERO(oomd_pressure_above(h2, &t2));
        ASSERT_NULL(t2);
        ASSERT_NOT_NULL(c = hashmap_get(h2, "/derp.slice"));
        ASSERT_EQ(c->mem_pressure_limit_hit_start, 0u);

        /* High memory pressure w/ multiple cgroups */
        ASSERT_OK(hashmap_put(h1, "/derp.slice", &ctx[1]));
        ASSERT_OK_POSITIVE(oomd_pressure_above(h1, &t3));
        ASSERT_TRUE(set_contains(t3, &ctx[0]));
        ASSERT_EQ(set_size(t3), 1u);
        ASSERT_NOT_NULL(c = hashmap_get(h1, "/herp.slice"));
        ASSERT_GT(c->mem_pressure_limit_hit_start, 0u);
        ASSERT_NOT_NULL(c = hashmap_get(h1, "/derp.slice"));
        ASSERT_EQ(c->mem_pressure_limit_hit_start, 0u);
}

TEST(oomd_mem_and_swap_free_below) {
        OomdSystemContext ctx = (OomdSystemContext) {
                .mem_total = UINT64_C(20971512) * 1024U,
                .mem_used = UINT64_C(3310136) * 1024U,
                .swap_total = UINT64_C(20971512) * 1024U,
                .swap_used = UINT64_C(20971440) * 1024U,
        };
        ASSERT_FALSE(oomd_mem_available_below(&ctx, 2000));
        ASSERT_TRUE(oomd_swap_free_below(&ctx, 2000));

        ctx = (OomdSystemContext) {
                .mem_total = UINT64_C(20971512) * 1024U,
                .mem_used = UINT64_C(20971440) * 1024U,
                .swap_total = UINT64_C(20971512) * 1024U,
                .swap_used = UINT64_C(3310136) * 1024U,
        };
        ASSERT_TRUE(oomd_mem_available_below(&ctx, 2000));
        ASSERT_FALSE(oomd_swap_free_below(&ctx, 2000));

        ctx = (OomdSystemContext) {
                .mem_total = 0,
                .mem_used = 0,
                .swap_total = 0,
                .swap_used = 0,
        };
        ASSERT_FALSE(oomd_mem_available_below(&ctx, 2000));
        ASSERT_FALSE(oomd_swap_free_below(&ctx, 2000));
}

TEST(oomd_sort_cgroups) {
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        _cleanup_free_ OomdCGroupContext **sorted_cgroups = NULL;
        char **paths = STRV_MAKE("/herp.slice",
                                 "/herp.slice/derp.scope",
                                 "/herp.slice/derp.scope/sheep.service",
                                 "/zupa.slice",
                                 "/boop.slice",
                                 "/omitted.slice",
                                 "/avoid.slice");

        OomdCGroupContext ctx[7] = {
                { .path = paths[0],
                  .swap_usage = 20,
                  .last_pgscan = 0,
                  .pgscan = 33,
                  .current_memory_usage = 10 },
                { .path = paths[1],
                  .swap_usage = 60,
                  .last_pgscan = 33,
                  .pgscan = 1,
                  .current_memory_usage = 20 },
                { .path = paths[2],
                  .swap_usage = 40,
                  .last_pgscan = 1,
                  .pgscan = 33,
                  .current_memory_usage = 40 },
                { .path = paths[3],
                  .swap_usage = 10,
                  .last_pgscan = 33,
                  .pgscan = 2,
                  .current_memory_usage = 10 },
                { .path = paths[4],
                  .swap_usage = 11,
                  .last_pgscan = 33,
                  .pgscan = 33,
                  .current_memory_usage = 10 },
                { .path = paths[5],
                  .swap_usage = 90,
                  .last_pgscan = 0,
                  .pgscan = UINT64_MAX,
                  .preference = MANAGED_OOM_PREFERENCE_OMIT },
                { .path = paths[6],
                  .swap_usage = 99,
                  .last_pgscan = 0,
                  .pgscan = UINT64_MAX,
                  .preference = MANAGED_OOM_PREFERENCE_AVOID },
        };

        ASSERT_NOT_NULL(h = hashmap_new(&string_hash_ops));

        ASSERT_OK(hashmap_put(h, "/herp.slice", &ctx[0]));
        ASSERT_OK(hashmap_put(h, "/herp.slice/derp.scope", &ctx[1]));
        ASSERT_OK(hashmap_put(h, "/herp.slice/derp.scope/sheep.service", &ctx[2]));
        ASSERT_OK(hashmap_put(h, "/zupa.slice", &ctx[3]));
        ASSERT_OK(hashmap_put(h, "/boop.slice", &ctx[4]));
        ASSERT_OK(hashmap_put(h, "/omitted.slice", &ctx[5]));
        ASSERT_OK(hashmap_put(h, "/avoid.slice", &ctx[6]));

        ASSERT_OK_EQ(oomd_sort_cgroup_contexts(h, compare_swap_usage, NULL, &sorted_cgroups), 6);
        ASSERT_PTR_EQ(sorted_cgroups[0], &ctx[1]);
        ASSERT_PTR_EQ(sorted_cgroups[1], &ctx[2]);
        ASSERT_PTR_EQ(sorted_cgroups[2], &ctx[0]);
        ASSERT_PTR_EQ(sorted_cgroups[3], &ctx[4]);
        ASSERT_PTR_EQ(sorted_cgroups[4], &ctx[3]);
        ASSERT_PTR_EQ(sorted_cgroups[5], &ctx[6]);
        sorted_cgroups = mfree(sorted_cgroups);

        ASSERT_OK_EQ(oomd_sort_cgroup_contexts(h, compare_pgscan_rate_and_memory_usage, NULL, &sorted_cgroups), 6);
        ASSERT_PTR_EQ(sorted_cgroups[0], &ctx[0]);
        ASSERT_PTR_EQ(sorted_cgroups[1], &ctx[2]);
        ASSERT_PTR_EQ(sorted_cgroups[2], &ctx[3]);
        ASSERT_PTR_EQ(sorted_cgroups[3], &ctx[1]);
        ASSERT_PTR_EQ(sorted_cgroups[4], &ctx[4]);
        ASSERT_PTR_EQ(sorted_cgroups[5], &ctx[6]);
        sorted_cgroups = mfree(sorted_cgroups);

        ASSERT_OK_EQ(oomd_sort_cgroup_contexts(h, compare_pgscan_rate_and_memory_usage, "/herp.slice/derp.scope", &sorted_cgroups), 2);
        ASSERT_PTR_EQ(sorted_cgroups[0], &ctx[2]);
        ASSERT_PTR_EQ(sorted_cgroups[1], &ctx[1]);
        ASSERT_NULL(sorted_cgroups[2]);
        ASSERT_NULL(sorted_cgroups[3]);
        ASSERT_NULL(sorted_cgroups[4]);
        ASSERT_NULL(sorted_cgroups[5]);
        ASSERT_NULL(sorted_cgroups[6]);
}

TEST(oomd_fetch_cgroup_oom_preference) {
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *ctx = NULL;
        ManagedOOMPreference root_pref;
        CGroupMask mask;
        bool test_xattrs;
        int r;

        if (!is_pressure_supported())
                return (void) log_tests_skipped("system does not support pressure");

        if (enter_cgroup_root_cached() < 0)
                return;

        ASSERT_OK(cg_mask_supported(&mask));
        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return (void) log_tests_skipped("cgroup memory controller is not available");

        ASSERT_OK(oomd_cgroup_context_acquire(cgroup, &ctx));

        /* If we don't have permissions to set xattrs we're likely in a userns or missing capabilities
         * so skip the xattr portions of the test. */
        r = cg_set_xattr(cgroup, "user.oomd_test", "1", 1, 0);
        test_xattrs = !ERRNO_IS_PRIVILEGE(r) && !ERRNO_IS_NOT_SUPPORTED(r);

        if (test_xattrs) {
                ASSERT_OK(oomd_fetch_cgroup_oom_preference(ctx, NULL));
                ASSERT_OK(cg_set_xattr(cgroup, "user.oomd_omit", "1", 1, 0));
                ASSERT_OK(cg_set_xattr(cgroup, "user.oomd_avoid", "1", 1, 0));

                /* omit takes precedence over avoid when both are set to true */
                ASSERT_OK(oomd_fetch_cgroup_oom_preference(ctx, NULL));
                ASSERT_EQ(ctx->preference, geteuid() == 0 ? MANAGED_OOM_PREFERENCE_OMIT : MANAGED_OOM_PREFERENCE_NONE);
        } else {
                ASSERT_FAIL(oomd_fetch_cgroup_oom_preference(ctx, NULL));
                ASSERT_EQ(ctx->preference, MANAGED_OOM_PREFERENCE_NONE);
        }
        ctx = oomd_cgroup_context_free(ctx);

        /* also check when only avoid is set to true */
        if (test_xattrs) {
                ASSERT_OK(cg_set_xattr(cgroup, "user.oomd_omit", "0", 1, 0));
                ASSERT_OK(cg_set_xattr(cgroup, "user.oomd_avoid", "1", 1, 0));
                ASSERT_OK(oomd_cgroup_context_acquire(cgroup, &ctx));
                ASSERT_OK(oomd_fetch_cgroup_oom_preference(ctx, NULL));
                ASSERT_EQ(ctx->preference, geteuid() == 0 ? MANAGED_OOM_PREFERENCE_AVOID : MANAGED_OOM_PREFERENCE_NONE);
                ctx = oomd_cgroup_context_free(ctx);
        }

        /* Test the root cgroup */
        /* Root cgroup is live and not made on demand like the cgroup the test runs in. It can have varying
         * xattrs set already so let's read in the booleans first to get the final preference value. */
        ASSERT_OK(oomd_cgroup_context_acquire("", &ctx));
        root_pref = MANAGED_OOM_PREFERENCE_NONE;
        if (cg_get_xattr_bool("", "user.oomd_avoid") > 0)
                root_pref = MANAGED_OOM_PREFERENCE_AVOID;
        if (cg_get_xattr_bool("", "user.oomd_omit") > 0)
                root_pref = MANAGED_OOM_PREFERENCE_OMIT;
        ASSERT_OK(oomd_fetch_cgroup_oom_preference(ctx, NULL));
        ASSERT_EQ(ctx->preference, root_pref);

        ASSERT_ERROR(oomd_fetch_cgroup_oom_preference(ctx, "/herp.slice/derp.scope"), EINVAL);

        /* Assert that avoid/omit are not set if the cgroup and prefix are not
         * owned by the same user. */
        if (test_xattrs && !empty_or_root(cgroup) && geteuid() == 0) {
                ctx = oomd_cgroup_context_free(ctx);
                ASSERT_OK(cg_set_access(cgroup, 61183, 0));
                ASSERT_OK(oomd_cgroup_context_acquire(cgroup, &ctx));

                ASSERT_OK(oomd_fetch_cgroup_oom_preference(ctx, NULL));
                ASSERT_EQ(ctx->preference, MANAGED_OOM_PREFERENCE_NONE);

                ASSERT_OK(oomd_fetch_cgroup_oom_preference(ctx, ctx->path));
                ASSERT_EQ(ctx->preference, MANAGED_OOM_PREFERENCE_AVOID);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);

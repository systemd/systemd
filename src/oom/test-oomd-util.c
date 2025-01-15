/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "oomd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static int fork_and_sleep(unsigned sleep_min) {
        usec_t n, timeout, ts;

        pid_t pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                timeout = sleep_min * USEC_PER_MINUTE;
                ts = now(CLOCK_MONOTONIC);
                for (;;) {
                        n = now(CLOCK_MONOTONIC);
                        if (ts + timeout < n) {
                                log_error("Child timed out waiting to be killed");
                                abort();
                        }
                        sleep(1);
                }
        }

        return pid;
}

static void test_oomd_cgroup_kill(void) {
        _cleanup_free_ char *cgroup_root = NULL, *cgroup = NULL;
        int pid[2];
        int r;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        if (cg_all_unified() <= 0)
                return (void) log_tests_skipped("cgroups are not running in unified mode");

        assert_se(cg_pid_get_path(NULL, 0, &cgroup_root) >= 0);

        /* Create another cgroup below this one for the pids we forked off. We need this to be managed
         * by the test so that pid1 doesn't delete it before we can read the xattrs. */
        cgroup = path_join(cgroup_root, "oomdkilltest");
        assert_se(cgroup);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, cgroup) >= 0);

        /* If we don't have permissions to set xattrs we're likely in a userns or missing capabilities */
        r = cg_set_xattr(cgroup, "user.oomd_test", "test", 4, 0);
        if (ERRNO_IS_PRIVILEGE(r) || ERRNO_IS_NOT_SUPPORTED(r))
                return (void) log_tests_skipped("Cannot set user xattrs");

        /* Do this twice to also check the increment behavior on the xattrs */
        for (int i = 0; i < 2; i++) {
                _cleanup_free_ char *v = NULL;

                for (int j = 0; j < 2; j++) {
                        pid[j] = fork_and_sleep(5);
                        assert_se(cg_attach(SYSTEMD_CGROUP_CONTROLLER, cgroup, pid[j]) >= 0);
                }

                r = oomd_cgroup_kill(cgroup, false /* recurse */, false /* dry run */);
                if (r <= 0) {
                        log_debug_errno(r, "Failed to kill processes under %s: %m", cgroup);
                        abort();
                }

                assert_se(cg_get_xattr_malloc(cgroup, "user.oomd_ooms", &v) >= 0);
                assert_se(streq(v, i == 0 ? "1" : "2"));
                v = mfree(v);

                /* Wait a bit since processes may take some time to be cleaned up. */
                sleep(2);
                assert_se(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, cgroup) == true);

                assert_se(cg_get_xattr_malloc(cgroup, "user.oomd_kill", &v) >= 0);
                assert_se(streq(v, i == 0 ? "2" : "4"));
        }
}

static void test_oomd_cgroup_context_acquire_and_insert(void) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL, *h2 = NULL;
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *ctx = NULL;
        _cleanup_free_ char *cgroup = NULL;
        OomdCGroupContext *c1, *c2;
        CGroupMask mask;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        if (!is_pressure_supported())
                return (void) log_tests_skipped("system does not support pressure");

        if (cg_all_unified() <= 0)
                return (void) log_tests_skipped("cgroups are not running in unified mode");

        assert_se(cg_mask_supported(&mask) >= 0);

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return (void) log_tests_skipped("cgroup memory controller is not available");

        assert_se(cg_pid_get_path(NULL, 0, &cgroup) >= 0);
        assert_se(oomd_cgroup_context_acquire(cgroup, &ctx) == 0);

        assert_se(streq(ctx->path, cgroup));
        assert_se(ctx->current_memory_usage > 0);
        assert_se(ctx->memory_min == 0);
        assert_se(ctx->memory_low == 0);
        assert_se(ctx->swap_usage == 0);
        assert_se(ctx->last_pgscan == 0);
        assert_se(ctx->pgscan == 0);
        ctx = oomd_cgroup_context_free(ctx);

        assert_se(oomd_cgroup_context_acquire("", &ctx) == 0);
        assert_se(streq(ctx->path, "/"));
        assert_se(ctx->current_memory_usage > 0);

        /* Test hashmap inserts */
        assert_se(h1 = hashmap_new(&oomd_cgroup_ctx_hash_ops));
        assert_se(oomd_insert_cgroup_context(NULL, h1, cgroup) == 0);
        c1 = hashmap_get(h1, cgroup);
        assert_se(c1);
        assert_se(oomd_insert_cgroup_context(NULL, h1, cgroup) == -EEXIST);

         /* make sure certain values from h1 get updated in h2 */
        c1->pgscan = UINT64_MAX;
        c1->mem_pressure_limit = 6789;
        c1->mem_pressure_limit_hit_start = 42;
        c1->mem_pressure_duration_usec = 1234;
        c1->last_had_mem_reclaim = 888;
        assert_se(h2 = hashmap_new(&oomd_cgroup_ctx_hash_ops));
        assert_se(oomd_insert_cgroup_context(h1, h2, cgroup) == 0);
        c1 = hashmap_get(h1, cgroup);
        c2 = hashmap_get(h2, cgroup);
        assert_se(c1);
        assert_se(c2);
        assert_se(c1 != c2);
        assert_se(c2->last_pgscan == UINT64_MAX);
        assert_se(c2->mem_pressure_limit == 6789);
        assert_se(c2->mem_pressure_limit_hit_start == 42);
        assert_se(c2->mem_pressure_duration_usec == 1234);
        assert_se(c2->last_had_mem_reclaim == 888); /* assumes the live pgscan is less than UINT64_MAX */
}

static void test_oomd_update_cgroup_contexts_between_hashmaps(void) {
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

        assert_se(h_old = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h_old, paths[0], &ctx_old[0]) >= 0);
        assert_se(hashmap_put(h_old, paths[1], &ctx_old[1]) >= 0);

        assert_se(h_new = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h_new, paths[0], &ctx_new[0]) >= 0);
        assert_se(hashmap_put(h_new, paths[1], &ctx_new[1]) >= 0);

        oomd_update_cgroup_contexts_between_hashmaps(h_old, h_new);

        assert_se(c_old = hashmap_get(h_old, "/0.slice"));
        assert_se(c_new = hashmap_get(h_new, "/0.slice"));
        assert_se(c_old->pgscan == c_new->last_pgscan);
        assert_se(c_old->mem_pressure_limit == c_new->mem_pressure_limit);
        assert_se(c_old->mem_pressure_limit_hit_start == c_new->mem_pressure_limit_hit_start);
        assert_se(c_old->mem_pressure_duration_usec == c_new->mem_pressure_duration_usec);
        assert_se(c_old->last_had_mem_reclaim == c_new->last_had_mem_reclaim);

        assert_se(c_old = hashmap_get(h_old, "/1.slice"));
        assert_se(c_new = hashmap_get(h_new, "/1.slice"));
        assert_se(c_old->pgscan == c_new->last_pgscan);
        assert_se(c_old->mem_pressure_limit == c_new->mem_pressure_limit);
        assert_se(c_old->mem_pressure_limit_hit_start == c_new->mem_pressure_limit_hit_start);
        assert_se(c_old->mem_pressure_duration_usec == c_new->mem_pressure_duration_usec);
        assert_se(c_new->last_had_mem_reclaim > c_old->last_had_mem_reclaim);
}

static void test_oomd_system_context_acquire(void) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/oomdgetsysctxtestXXXXXX";
        _cleanup_close_ int fd = -EBADF;
        OomdSystemContext ctx;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        assert_se((fd = mkostemp_safe(path)) >= 0);

        assert_se(oomd_system_context_acquire("/verylikelynonexistentpath", &ctx) == -ENOENT);

        assert_se(oomd_system_context_acquire(path, &ctx) == -EINVAL);

        assert_se(write_string_file(path, "some\nwords\nacross\nmultiple\nlines", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(oomd_system_context_acquire(path, &ctx) == -EINVAL);

        assert_se(write_string_file(path, "MemTotal:       32495256 kB trailing\n"
                                          "MemFree:         9880512 kB data\n"
                                          "SwapTotal:       8388604 kB is\n"
                                          "SwapFree:           7604 kB bad\n", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(oomd_system_context_acquire(path, &ctx) == -EINVAL);

        assert_se(write_string_file(path, "MemTotal:       32495256 kB\n"
                                          "MemFree:         9880512 kB\n"
                                          "MemAvailable:   21777088 kB\n"
                                          "Buffers:            5968 kB\n"
                                          "Cached:         14344796 kB\n"
                                          "Unevictable:      740004 kB\n"
                                          "Mlocked:            4484 kB\n"
                                          "SwapTotal:       8388604 kB\n"
                                          "SwapFree:           7604 kB\n", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(oomd_system_context_acquire(path, &ctx) == 0);
        assert_se(ctx.mem_total == 33275142144);
        assert_se(ctx.mem_used == 10975404032);
        assert_se(ctx.swap_total == 8589930496);
        assert_se(ctx.swap_used == 8582144000);
}

static void test_oomd_pressure_above(void) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL, *h2 = NULL;
        _cleanup_set_free_ Set *t1 = NULL, *t2 = NULL, *t3 = NULL;
        OomdCGroupContext ctx[2] = {}, *c;
        loadavg_t threshold;

        assert_se(store_loadavg_fixed_point(80, 0, &threshold) == 0);

        /* /herp.slice */
        assert_se(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg10)) == 0);
        assert_se(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg60)) == 0);
        assert_se(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg300)) == 0);
        ctx[0].mem_pressure_limit = threshold;
        /* Set memory pressure duration to 0 since we use the real system monotonic clock
         * in oomd_pressure_above() and we want to avoid this test depending on timing. */
        ctx[0].mem_pressure_duration_usec = 0;

        /* /derp.slice */
        assert_se(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg10)) == 0);
        assert_se(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg60)) == 0);
        assert_se(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg300)) == 0);
        ctx[1].mem_pressure_limit = threshold;
        ctx[1].mem_pressure_duration_usec = 0;

        /* High memory pressure */
        assert_se(h1 = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h1, "/herp.slice", &ctx[0]) >= 0);
        assert_se(oomd_pressure_above(h1, &t1) == 1);
        assert_se(set_contains(t1, &ctx[0]));
        assert_se(c = hashmap_get(h1, "/herp.slice"));
        assert_se(c->mem_pressure_limit_hit_start > 0);

        /* Low memory pressure */
        assert_se(h2 = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h2, "/derp.slice", &ctx[1]) >= 0);
        assert_se(oomd_pressure_above(h2, &t2) == 0);
        assert_se(!t2);
        assert_se(c = hashmap_get(h2, "/derp.slice"));
        assert_se(c->mem_pressure_limit_hit_start == 0);

        /* High memory pressure w/ multiple cgroups */
        assert_se(hashmap_put(h1, "/derp.slice", &ctx[1]) >= 0);
        assert_se(oomd_pressure_above(h1, &t3) == 1);
        assert_se(set_contains(t3, &ctx[0]));
        assert_se(set_size(t3) == 1);
        assert_se(c = hashmap_get(h1, "/herp.slice"));
        assert_se(c->mem_pressure_limit_hit_start > 0);
        assert_se(c = hashmap_get(h1, "/derp.slice"));
        assert_se(c->mem_pressure_limit_hit_start == 0);
}

static void test_oomd_mem_and_swap_free_below(void) {
        OomdSystemContext ctx = (OomdSystemContext) {
                .mem_total = UINT64_C(20971512) * 1024U,
                .mem_used = UINT64_C(3310136) * 1024U,
                .swap_total = UINT64_C(20971512) * 1024U,
                .swap_used = UINT64_C(20971440) * 1024U,
        };
        assert_se(oomd_mem_available_below(&ctx, 2000) == false);
        assert_se(oomd_swap_free_below(&ctx, 2000) == true);

        ctx = (OomdSystemContext) {
                .mem_total = UINT64_C(20971512) * 1024U,
                .mem_used = UINT64_C(20971440) * 1024U,
                .swap_total = UINT64_C(20971512) * 1024U,
                .swap_used = UINT64_C(3310136) * 1024U,
        };
        assert_se(oomd_mem_available_below(&ctx, 2000) == true);
        assert_se(oomd_swap_free_below(&ctx, 2000) == false);

        ctx = (OomdSystemContext) {
                .mem_total = 0,
                .mem_used = 0,
                .swap_total = 0,
                .swap_used = 0,
        };
        assert_se(oomd_mem_available_below(&ctx, 2000) == false);
        assert_se(oomd_swap_free_below(&ctx, 2000) == false);
}

static void test_oomd_sort_cgroups(void) {
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

        assert_se(h = hashmap_new(&string_hash_ops));

        assert_se(hashmap_put(h, "/herp.slice", &ctx[0]) >= 0);
        assert_se(hashmap_put(h, "/herp.slice/derp.scope", &ctx[1]) >= 0);
        assert_se(hashmap_put(h, "/herp.slice/derp.scope/sheep.service", &ctx[2]) >= 0);
        assert_se(hashmap_put(h, "/zupa.slice", &ctx[3]) >= 0);
        assert_se(hashmap_put(h, "/boop.slice", &ctx[4]) >= 0);
        assert_se(hashmap_put(h, "/omitted.slice", &ctx[5]) >= 0);
        assert_se(hashmap_put(h, "/avoid.slice", &ctx[6]) >= 0);

        assert_se(oomd_sort_cgroup_contexts(h, compare_swap_usage, NULL, &sorted_cgroups) == 6);
        assert_se(sorted_cgroups[0] == &ctx[1]);
        assert_se(sorted_cgroups[1] == &ctx[2]);
        assert_se(sorted_cgroups[2] == &ctx[0]);
        assert_se(sorted_cgroups[3] == &ctx[4]);
        assert_se(sorted_cgroups[4] == &ctx[3]);
        assert_se(sorted_cgroups[5] == &ctx[6]);
        sorted_cgroups = mfree(sorted_cgroups);

        assert_se(oomd_sort_cgroup_contexts(h, compare_pgscan_rate_and_memory_usage, NULL, &sorted_cgroups) == 6);
        assert_se(sorted_cgroups[0] == &ctx[0]);
        assert_se(sorted_cgroups[1] == &ctx[2]);
        assert_se(sorted_cgroups[2] == &ctx[3]);
        assert_se(sorted_cgroups[3] == &ctx[1]);
        assert_se(sorted_cgroups[4] == &ctx[4]);
        assert_se(sorted_cgroups[5] == &ctx[6]);
        sorted_cgroups = mfree(sorted_cgroups);

        assert_se(oomd_sort_cgroup_contexts(h, compare_pgscan_rate_and_memory_usage, "/herp.slice/derp.scope", &sorted_cgroups) == 2);
        assert_se(sorted_cgroups[0] == &ctx[2]);
        assert_se(sorted_cgroups[1] == &ctx[1]);
        ASSERT_NULL(sorted_cgroups[2]);
        ASSERT_NULL(sorted_cgroups[3]);
        ASSERT_NULL(sorted_cgroups[4]);
        ASSERT_NULL(sorted_cgroups[5]);
        ASSERT_NULL(sorted_cgroups[6]);
}

static void test_oomd_fetch_cgroup_oom_preference(void) {
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *ctx = NULL;
        _cleanup_free_ char *cgroup = NULL;
        ManagedOOMPreference root_pref;
        CGroupMask mask;
        bool test_xattrs;
        int root_xattrs, r;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        if (!is_pressure_supported())
                return (void) log_tests_skipped("system does not support pressure");

        if (cg_all_unified() <= 0)
                return (void) log_tests_skipped("cgroups are not running in unified mode");

        assert_se(cg_mask_supported(&mask) >= 0);

        if (!FLAGS_SET(mask, CGROUP_MASK_MEMORY))
                return (void) log_tests_skipped("cgroup memory controller is not available");

        assert_se(cg_pid_get_path(NULL, 0, &cgroup) >= 0);
        assert_se(oomd_cgroup_context_acquire(cgroup, &ctx) == 0);

        /* If we don't have permissions to set xattrs we're likely in a userns or missing capabilities
         * so skip the xattr portions of the test. */
        r = cg_set_xattr(cgroup, "user.oomd_test", "1", 1, 0);
        test_xattrs = !ERRNO_IS_PRIVILEGE(r) && !ERRNO_IS_NOT_SUPPORTED(r);

        if (test_xattrs) {
                assert_se(oomd_fetch_cgroup_oom_preference(ctx, NULL) == 0);
                assert_se(cg_set_xattr(cgroup, "user.oomd_omit", "1", 1, 0) >= 0);
                assert_se(cg_set_xattr(cgroup, "user.oomd_avoid", "1", 1, 0) >= 0);

                /* omit takes precedence over avoid when both are set to true */
                assert_se(oomd_fetch_cgroup_oom_preference(ctx, NULL) == 0);
                assert_se(ctx->preference == MANAGED_OOM_PREFERENCE_OMIT);
        } else {
                assert_se(oomd_fetch_cgroup_oom_preference(ctx, NULL) < 0);
                assert_se(ctx->preference == MANAGED_OOM_PREFERENCE_NONE);
        }
        ctx = oomd_cgroup_context_free(ctx);

        /* also check when only avoid is set to true */
        if (test_xattrs) {
                assert_se(cg_set_xattr(cgroup, "user.oomd_omit", "0", 1, 0) >= 0);
                assert_se(cg_set_xattr(cgroup, "user.oomd_avoid", "1", 1, 0) >= 0);
                assert_se(oomd_cgroup_context_acquire(cgroup, &ctx) == 0);
                assert_se(oomd_fetch_cgroup_oom_preference(ctx, NULL) == 0);
                assert_se(ctx->preference == MANAGED_OOM_PREFERENCE_AVOID);
                ctx = oomd_cgroup_context_free(ctx);
        }

        /* Test the root cgroup */
        /* Root cgroup is live and not made on demand like the cgroup the test runs in. It can have varying
         * xattrs set already so let's read in the booleans first to get the final preference value. */
        assert_se(oomd_cgroup_context_acquire("", &ctx) == 0);
        root_xattrs = cg_get_xattr_bool("", "user.oomd_omit");
        root_pref = root_xattrs > 0 ? MANAGED_OOM_PREFERENCE_OMIT : MANAGED_OOM_PREFERENCE_NONE;
        root_xattrs = cg_get_xattr_bool("", "user.oomd_avoid");
        root_pref = root_xattrs > 0 ? MANAGED_OOM_PREFERENCE_AVOID : MANAGED_OOM_PREFERENCE_NONE;
        assert_se(oomd_fetch_cgroup_oom_preference(ctx, NULL) == 0);
        assert_se(ctx->preference == root_pref);

        assert_se(oomd_fetch_cgroup_oom_preference(ctx, "/herp.slice/derp.scope") == -EINVAL);

        /* Assert that avoid/omit are not set if the cgroup and prefix are not
         * owned by the same user. */
        if (test_xattrs && !empty_or_root(cgroup)) {
                ctx = oomd_cgroup_context_free(ctx);
                assert_se(cg_set_access(SYSTEMD_CGROUP_CONTROLLER, cgroup, 61183, 0) >= 0);
                assert_se(oomd_cgroup_context_acquire(cgroup, &ctx) == 0);

                assert_se(oomd_fetch_cgroup_oom_preference(ctx, NULL) == 0);
                assert_se(ctx->preference == MANAGED_OOM_PREFERENCE_NONE);

                assert_se(oomd_fetch_cgroup_oom_preference(ctx, ctx->path) == 0);
                assert_se(ctx->preference == MANAGED_OOM_PREFERENCE_AVOID);
        }
}

int main(void) {
        int r;

        test_setup_logging(LOG_DEBUG);

        test_oomd_update_cgroup_contexts_between_hashmaps();
        test_oomd_system_context_acquire();
        test_oomd_pressure_above();
        test_oomd_mem_and_swap_free_below();
        test_oomd_sort_cgroups();

        /* The following tests operate on live cgroups */

        r = enter_cgroup_root(NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "failed to enter a test cgroup scope");

        test_oomd_cgroup_kill();
        test_oomd_cgroup_context_acquire_and_insert();
        test_oomd_fetch_cgroup_oom_preference();

        return 0;
}

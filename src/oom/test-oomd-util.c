/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "oomd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static int fork_and_sleep(unsigned sleep_min) {
        usec_t n, timeout, ts;

        pid_t pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                timeout = sleep_min * USEC_PER_MINUTE;
                ts = now(CLOCK_MONOTONIC);
                while (true) {
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
        assert(cgroup);
        assert_se(cg_create(SYSTEMD_CGROUP_CONTROLLER, cgroup) >= 0);

        /* If we don't have permissions to set xattrs we're likely in a userns or missing capabilities */
        r = cg_set_xattr(SYSTEMD_CGROUP_CONTROLLER, cgroup, "user.oomd_test", "test", 4, 0);
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

                /* Wait a bit since processes may take some time to be cleaned up. */
                sleep(2);
                assert_se(cg_is_empty(SYSTEMD_CGROUP_CONTROLLER, cgroup) == true);

                assert_se(cg_get_xattr_malloc(SYSTEMD_CGROUP_CONTROLLER, cgroup, "user.systemd_oomd_kill", &v) >= 0);
                assert_se(memcmp(v, i == 0 ? "2" : "4", 2) == 0);
        }
}

static void test_oomd_cgroup_context_acquire_and_insert(void) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL, *h2 = NULL;
        _cleanup_(oomd_cgroup_context_freep) OomdCGroupContext *ctx = NULL;
        _cleanup_free_ char *cgroup = NULL;
        OomdCGroupContext *c1, *c2;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        if (!is_pressure_supported())
                return (void) log_tests_skipped("system does not support pressure");

        if (cg_all_unified() <= 0)
                return (void) log_tests_skipped("cgroups are not running in unified mode");

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

        /* Test the root cgroup */
        assert_se(oomd_cgroup_context_acquire("", &ctx) == 0);
        assert_se(streq(ctx->path, "/"));
        assert_se(ctx->current_memory_usage > 0);

        /* Test hashmap inserts */
        assert_se(h1 = hashmap_new(&oomd_cgroup_ctx_hash_ops));
        assert_se(oomd_insert_cgroup_context(NULL, h1, cgroup) == 0);
        c1 = hashmap_get(h1, cgroup);
        assert_se(c1);

         /* make sure certain values from h1 get updated in h2 */
        c1->pgscan = 5555;
        c1->mem_pressure_limit = 6789;
        c1->last_hit_mem_pressure_limit = 42;
        assert_se(h2 = hashmap_new(&oomd_cgroup_ctx_hash_ops));
        assert_se(oomd_insert_cgroup_context(h1, h2, cgroup) == 0);
        c1 = hashmap_get(h1, cgroup);
        c2 = hashmap_get(h2, cgroup);
        assert_se(c1);
        assert_se(c2);
        assert_se(c1 != c2);
        assert_se(c2->last_pgscan == 5555);
        assert_se(c2->mem_pressure_limit == 6789);
        assert_se(c2->last_hit_mem_pressure_limit == 42);
}

static void test_oomd_system_context_acquire(void) {
        _cleanup_(unlink_tempfilep) char path[] = "/oomdgetsysctxtestXXXXXX";
        OomdSystemContext ctx;

        if (geteuid() != 0)
                return (void) log_tests_skipped("not root");

        assert_se(mkstemp(path));

        assert_se(oomd_system_context_acquire("/verylikelynonexistentpath", &ctx) == -ENOENT);

        assert_se(oomd_system_context_acquire(path, &ctx) == 0);
        assert_se(ctx.swap_total == 0);
        assert_se(ctx.swap_used == 0);

        assert_se(write_string_file(path, "some\nwords\nacross\nmultiple\nlines", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(oomd_system_context_acquire(path, &ctx) == 0);
        assert_se(ctx.swap_total == 0);
        assert_se(ctx.swap_used == 0);

        assert_se(write_string_file(path, "Filename                                Type            Size    Used    Priority\n"
                                          "/swapvol/swapfile                       file            18971644        0       -3\n"
                                          "/dev/vda2                               partition       1999868 993780  -2", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(oomd_system_context_acquire(path, &ctx) == 0);
        assert_se(ctx.swap_total == 21474828288);
        assert_se(ctx.swap_used == 1017630720);
}

static void test_oomd_pressure_above(void) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL, *h2 = NULL;
        _cleanup_set_free_ Set *t1 = NULL, *t2 = NULL, *t3 = NULL;
        OomdCGroupContext ctx[2], *c;
        loadavg_t threshold;

        assert_se(store_loadavg_fixed_point(80, 0, &threshold) == 0);

        /* /herp.slice */
        assert_se(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg10)) == 0);
        assert_se(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg60)) == 0);
        assert_se(store_loadavg_fixed_point(99, 99, &(ctx[0].memory_pressure.avg300)) == 0);
        ctx[0].mem_pressure_limit = threshold;

        /* /derp.slice */
        assert_se(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg10)) == 0);
        assert_se(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg60)) == 0);
        assert_se(store_loadavg_fixed_point(1, 11, &(ctx[1].memory_pressure.avg300)) == 0);
        ctx[1].mem_pressure_limit = threshold;


        /* High memory pressure */
        assert_se(h1 = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h1, "/herp.slice", &ctx[0]) >= 0);
        assert_se(oomd_pressure_above(h1, 0 /* duration */, &t1) == 1);
        assert_se(set_contains(t1, &ctx[0]) == true);
        assert_se(c = hashmap_get(h1, "/herp.slice"));
        assert_se(c->last_hit_mem_pressure_limit > 0);

        /* Low memory pressure */
        assert_se(h2 = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h2, "/derp.slice", &ctx[1]) >= 0);
        assert_se(oomd_pressure_above(h2, 0 /* duration */, &t2) == 0);
        assert_se(t2 == NULL);
        assert_se(c = hashmap_get(h2, "/derp.slice"));
        assert_se(c->last_hit_mem_pressure_limit == 0);

        /* High memory pressure w/ multiple cgroups */
        assert_se(hashmap_put(h1, "/derp.slice", &ctx[1]) >= 0);
        assert_se(oomd_pressure_above(h1, 0 /* duration */, &t3) == 1);
        assert_se(set_contains(t3, &ctx[0]) == true);
        assert_se(set_size(t3) == 1);
        assert_se(c = hashmap_get(h1, "/herp.slice"));
        assert_se(c->last_hit_mem_pressure_limit > 0);
        assert_se(c = hashmap_get(h1, "/derp.slice"));
        assert_se(c->last_hit_mem_pressure_limit == 0);
}

static void test_oomd_memory_reclaim(void) {
        _cleanup_hashmap_free_ Hashmap *h1 = NULL;
        char **paths = STRV_MAKE("/0.slice",
                                 "/1.slice",
                                 "/2.slice",
                                 "/3.slice",
                                 "/4.slice");

        OomdCGroupContext ctx[5] = {
                { .path = paths[0],
                  .last_pgscan = 100,
                  .pgscan = 100 },
                { .path = paths[1],
                  .last_pgscan = 100,
                  .pgscan = 100 },
                { .path = paths[2],
                  .last_pgscan = 77,
                  .pgscan = 33 },
                { .path = paths[3],
                  .last_pgscan = UINT64_MAX,
                  .pgscan = 100 },
                { .path = paths[4],
                  .last_pgscan = 100,
                  .pgscan = UINT64_MAX },
        };

        assert_se(h1 = hashmap_new(&string_hash_ops));
        assert_se(hashmap_put(h1, paths[0], &ctx[0]) >= 0);
        assert_se(hashmap_put(h1, paths[1], &ctx[1]) >= 0);
        assert_se(oomd_memory_reclaim(h1) == false);

        assert_se(hashmap_put(h1, paths[2], &ctx[2]) >= 0);
        assert_se(oomd_memory_reclaim(h1) == false);

        assert_se(hashmap_put(h1, paths[4], &ctx[4]) >= 0);
        assert_se(oomd_memory_reclaim(h1) == true);

        assert_se(hashmap_put(h1, paths[3], &ctx[3]) >= 0);
        assert_se(oomd_memory_reclaim(h1) == false);
}

static void test_oomd_swap_free_below(void) {
        OomdSystemContext ctx = (OomdSystemContext) {
                .swap_total = 20971512 * 1024U,
                .swap_used = 20971440 * 1024U,
        };
        assert_se(oomd_swap_free_below(&ctx, 20) == true);

        ctx = (OomdSystemContext) {
                .swap_total = 20971512 * 1024U,
                .swap_used = 3310136 * 1024U,
        };
        assert_se(oomd_swap_free_below(&ctx, 20) == false);
}

static void test_oomd_sort_cgroups(void) {
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        _cleanup_free_ OomdCGroupContext **sorted_cgroups;
        char **paths = STRV_MAKE("/herp.slice",
                                 "/herp.slice/derp.scope",
                                 "/herp.slice/derp.scope/sheep.service",
                                 "/zupa.slice");

        OomdCGroupContext ctx[4] = {
                { .path = paths[0],
                  .swap_usage = 20,
                  .pgscan = 60 },
                { .path = paths[1],
                  .swap_usage = 60,
                  .pgscan = 40 },
                { .path = paths[2],
                  .swap_usage = 40,
                  .pgscan = 20 },
                { .path = paths[3],
                  .swap_usage = 10,
                  .pgscan = 80 },
        };

        assert_se(h = hashmap_new(&string_hash_ops));

        assert_se(hashmap_put(h, "/herp.slice", &ctx[0]) >= 0);
        assert_se(hashmap_put(h, "/herp.slice/derp.scope", &ctx[1]) >= 0);
        assert_se(hashmap_put(h, "/herp.slice/derp.scope/sheep.service", &ctx[2]) >= 0);
        assert_se(hashmap_put(h, "/zupa.slice", &ctx[3]) >= 0);

        assert_se(oomd_sort_cgroup_contexts(h, compare_swap_usage, NULL, &sorted_cgroups) == 4);
        assert_se(sorted_cgroups[0] == &ctx[1]);
        assert_se(sorted_cgroups[1] == &ctx[2]);
        assert_se(sorted_cgroups[2] == &ctx[0]);
        assert_se(sorted_cgroups[3] == &ctx[3]);
        sorted_cgroups = mfree(sorted_cgroups);

        assert_se(oomd_sort_cgroup_contexts(h, compare_pgscan, NULL, &sorted_cgroups) == 4);
        assert_se(sorted_cgroups[0] == &ctx[3]);
        assert_se(sorted_cgroups[1] == &ctx[0]);
        assert_se(sorted_cgroups[2] == &ctx[1]);
        assert_se(sorted_cgroups[3] == &ctx[2]);
        sorted_cgroups = mfree(sorted_cgroups);

        assert_se(oomd_sort_cgroup_contexts(h, compare_pgscan, "/herp.slice/derp.scope", &sorted_cgroups) == 2);
        assert_se(sorted_cgroups[0] == &ctx[1]);
        assert_se(sorted_cgroups[1] == &ctx[2]);
        assert_se(sorted_cgroups[2] == 0);
        assert_se(sorted_cgroups[3] == 0);
        sorted_cgroups = mfree(sorted_cgroups);
}

int main(void) {
        int r;

        test_setup_logging(LOG_DEBUG);

        test_oomd_system_context_acquire();
        test_oomd_pressure_above();
        test_oomd_memory_reclaim();
        test_oomd_swap_free_below();
        test_oomd_sort_cgroups();

        /* The following tests operate on live cgroups */

        r = enter_cgroup_root(NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "failed to enter a test cgroup scope");

        test_oomd_cgroup_kill();
        test_oomd_cgroup_context_acquire_and_insert();

        return 0;
}

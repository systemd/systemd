/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "cgroup.h"
#include "cgroup-util.h"
#include "macro.h"
#include "manager.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "unit.h"

#define ASSERT_CGROUP_MASK(got, expected) \
        log_cgroup_mask(got, expected); \
        assert_se(got == expected)

#define ASSERT_CGROUP_MASK_JOINED(got, expected) ASSERT_CGROUP_MASK(got, CGROUP_MASK_EXTEND_JOINED(expected))

static void log_cgroup_mask(CGroupMask got, CGroupMask expected) {
        _cleanup_free_ char *e_store = NULL, *g_store = NULL;

        ASSERT_OK(cg_mask_to_string(expected, &e_store));
        log_info("Expected mask: %s", e_store);
        ASSERT_OK(cg_mask_to_string(got, &g_store));
        log_info("Got mask: %s", g_store);
}

TEST_RET(cgroup_mask, .sd_booted = true) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *son, *daughter, *parent, *root, *grandchild, *parent_deep, *nomem_parent, *nomem_leaf;
        int r;
        CGroupMask cpu_accounting_mask = get_cpu_accounting_mask();

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        /* Prepare the manager. */
        _cleanup_free_ char *unit_dir = NULL;
        ASSERT_OK(get_testdata_dir("units", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        assert_se(runtime_dir = setup_fake_runtime_dir());
        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (IN_SET(r, -EPERM, -EACCES)) {
                log_error_errno(r, "manager_new: %m");
                return log_tests_skipped("cannot create manager");
        }

        assert_se(r >= 0);

        /* Turn off all kinds of default accounting, so that we can
         * verify the masks resulting of our configuration and nothing
         * else. */
        m->defaults.cpu_accounting =
                m->defaults.memory_accounting =
                m->defaults.blockio_accounting =
                m->defaults.io_accounting =
                m->defaults.tasks_accounting = false;
        m->defaults.tasks_max = CGROUP_TASKS_MAX_UNSET;

        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

        /* Load units and verify hierarchy. */
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "parent.slice", NULL, &parent));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "son.service", NULL, &son));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "daughter.service", NULL, &daughter));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "grandchild.service", NULL, &grandchild));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "parent-deep.slice", NULL, &parent_deep));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "nomem.slice", NULL, &nomem_parent));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "nomemleaf.service", NULL, &nomem_leaf));
        assert_se(UNIT_GET_SLICE(son) == parent);
        assert_se(UNIT_GET_SLICE(daughter) == parent);
        assert_se(UNIT_GET_SLICE(parent_deep) == parent);
        assert_se(UNIT_GET_SLICE(grandchild) == parent_deep);
        assert_se(UNIT_GET_SLICE(nomem_leaf) == nomem_parent);
        root = UNIT_GET_SLICE(parent);
        assert_se(UNIT_GET_SLICE(nomem_parent) == root);

        /* Verify per-unit cgroups settings. */
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(son), CGROUP_MASK_CPU);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(daughter), cpu_accounting_mask);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(grandchild), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(parent_deep), CGROUP_MASK_MEMORY);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(parent), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO));
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(nomem_parent), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(nomem_leaf), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_own_mask(root), 0);

        /* Verify aggregation of member masks */
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(son), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(daughter), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(grandchild), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(parent_deep), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(parent), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(nomem_parent), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(nomem_leaf), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_members_mask(root), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of sibling masks. */
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(son), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(daughter), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(grandchild), 0);
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(parent_deep), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(parent), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(nomem_parent), (CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(nomem_leaf), (CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK_JOINED(unit_get_siblings_mask(root), (CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of target masks. */
        ASSERT_CGROUP_MASK(unit_get_target_mask(son), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(daughter), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_target_mask(parent_deep), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(parent), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(nomem_parent), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_IO | CGROUP_MASK_BLKIO) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(nomem_leaf), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_IO | CGROUP_MASK_BLKIO) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(root), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));

        /* Verify aggregation of enable masks. */
        ASSERT_CGROUP_MASK(unit_get_enable_mask(son), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(daughter), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(parent_deep), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(parent), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_enable_mask(nomem_parent), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_IO | CGROUP_MASK_BLKIO) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_enable_mask(nomem_leaf), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(root), (CGROUP_MASK_EXTEND_JOINED(CGROUP_MASK_CPU | cpu_accounting_mask | CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY) & m->cgroup_supported));

        return 0;
}

static void test_cg_mask_to_string_one(CGroupMask mask, const char *t) {
        _cleanup_free_ char *b = NULL;

        assert_se(cg_mask_to_string(mask, &b) >= 0);
        ASSERT_STREQ(b, t);
}

TEST(cg_mask_to_string) {
        test_cg_mask_to_string_one(0, NULL);
        test_cg_mask_to_string_one(_CGROUP_MASK_ALL, "cpu cpuacct cpuset io blkio memory devices pids bpf-firewall bpf-devices bpf-foreign bpf-socket-bind bpf-restrict-network-interfaces");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU, "cpu");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUACCT, "cpuacct");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUSET, "cpuset");
        test_cg_mask_to_string_one(CGROUP_MASK_IO, "io");
        test_cg_mask_to_string_one(CGROUP_MASK_BLKIO, "blkio");
        test_cg_mask_to_string_one(CGROUP_MASK_MEMORY, "memory");
        test_cg_mask_to_string_one(CGROUP_MASK_DEVICES, "devices");
        test_cg_mask_to_string_one(CGROUP_MASK_PIDS, "pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU|CGROUP_MASK_CPUACCT, "cpu cpuacct");
        test_cg_mask_to_string_one(CGROUP_MASK_CPU|CGROUP_MASK_PIDS, "cpu pids");
        test_cg_mask_to_string_one(CGROUP_MASK_CPUACCT|CGROUP_MASK_PIDS, "cpuacct pids");
        test_cg_mask_to_string_one(CGROUP_MASK_DEVICES|CGROUP_MASK_PIDS, "devices pids");
        test_cg_mask_to_string_one(CGROUP_MASK_IO|CGROUP_MASK_BLKIO, "io blkio");
}

static void cgroup_device_permissions_test_normalize(const char *a, const char *b) {
        ASSERT_STREQ(cgroup_device_permissions_to_string(cgroup_device_permissions_from_string(a)), b);
}

TEST(cgroup_device_permissions) {
        for (CGroupDevicePermissions p = 0; p < _CGROUP_DEVICE_PERMISSIONS_MAX; p++) {
                const char *s;

                assert_se(s = cgroup_device_permissions_to_string(p));
                assert_se(cgroup_device_permissions_from_string(s) == p);
        }

        cgroup_device_permissions_test_normalize("", "");
        cgroup_device_permissions_test_normalize("rw", "rw");
        cgroup_device_permissions_test_normalize("wr", "rw");
        cgroup_device_permissions_test_normalize("wwrr", "rw");
        cgroup_device_permissions_test_normalize("mmmmmmmmmmmmmm", "m");
        cgroup_device_permissions_test_normalize("mmmmrrrrmmmwwmwmwmwmwmrmrmr", "rwm");

        assert_se(cgroup_device_permissions_from_string(NULL) == -EINVAL);
        assert_se(cgroup_device_permissions_from_string("rwq") == -EINVAL);
        assert_se(cgroup_device_permissions_from_string("RW") == -EINVAL);
        assert_se(cgroup_device_permissions_from_string("") == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

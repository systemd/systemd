/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "cgroup.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "cpu-set-util.h"
#include "dbus-unit.h"
#include "errno-util.h"
#include "manager.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "unit.h"

#define ASSERT_CGROUP_MASK(got, expected) \
        log_cgroup_mask(got, expected); \
        assert_se(got == expected)

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

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        /* Prepare the manager. */
        _cleanup_free_ char *unit_dir = NULL;
        ASSERT_OK(get_testdata_dir("test-cgroup-mask", &unit_dir));
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
        m->defaults.memory_accounting =
                m->defaults.io_accounting =
                m->defaults.tasks_accounting = false;
        m->defaults.tasks_max = CGROUP_TASKS_MAX_UNSET;

        assert_se(manager_startup(m, NULL, NULL, NULL, NULL) >= 0);

        /* Load units and verify hierarchy. */
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "parent.slice", NULL, LOG_ERR, &parent));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "son.service", NULL, LOG_ERR, &son));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "daughter.service", NULL, LOG_ERR, &daughter));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "grandchild.service", NULL, LOG_ERR, &grandchild));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "parent-deep.slice", NULL, LOG_ERR, &parent_deep));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "nomem.slice", NULL, LOG_ERR, &nomem_parent));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "nomemleaf.service", NULL, LOG_ERR, &nomem_leaf));
        assert_se(UNIT_GET_SLICE(son) == parent);
        assert_se(UNIT_GET_SLICE(daughter) == parent);
        assert_se(UNIT_GET_SLICE(parent_deep) == parent);
        assert_se(UNIT_GET_SLICE(grandchild) == parent_deep);
        assert_se(UNIT_GET_SLICE(nomem_leaf) == nomem_parent);
        root = UNIT_GET_SLICE(parent);
        assert_se(UNIT_GET_SLICE(nomem_parent) == root);

        /* Verify per-unit cgroups settings. */
        ASSERT_CGROUP_MASK(unit_get_own_mask(son), CGROUP_MASK_CPU);
        ASSERT_CGROUP_MASK(unit_get_own_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_own_mask(parent_deep), CGROUP_MASK_MEMORY);
        ASSERT_CGROUP_MASK(unit_get_own_mask(parent), CGROUP_MASK_IO);
        ASSERT_CGROUP_MASK(unit_get_own_mask(nomem_parent), 0);
        ASSERT_CGROUP_MASK(unit_get_own_mask(nomem_leaf), (CGROUP_MASK_IO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_own_mask(root), 0);

        /* Verify aggregation of member masks */
        ASSERT_CGROUP_MASK(unit_get_members_mask(son), 0);
        ASSERT_CGROUP_MASK(unit_get_members_mask(daughter), 0);
        ASSERT_CGROUP_MASK(unit_get_members_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_members_mask(parent_deep), 0);
        ASSERT_CGROUP_MASK(unit_get_members_mask(parent), (CGROUP_MASK_CPU | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_members_mask(nomem_parent), (CGROUP_MASK_IO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_members_mask(nomem_leaf), 0);
        ASSERT_CGROUP_MASK(unit_get_members_mask(root), (CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of sibling masks. */
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(son), (CGROUP_MASK_CPU | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(daughter), (CGROUP_MASK_CPU | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(parent_deep), (CGROUP_MASK_CPU | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(parent), (CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(nomem_parent), (CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(nomem_leaf), (CGROUP_MASK_IO | CGROUP_MASK_MEMORY));
        ASSERT_CGROUP_MASK(unit_get_siblings_mask(root), (CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY));

        /* Verify aggregation of target masks. */
        ASSERT_CGROUP_MASK(unit_get_target_mask(son), ((CGROUP_MASK_CPU | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(daughter), ((CGROUP_MASK_CPU | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_target_mask(parent_deep), ((CGROUP_MASK_CPU | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(parent), ((CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(nomem_parent), ((CGROUP_MASK_CPU | CGROUP_MASK_IO) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(nomem_leaf), (CGROUP_MASK_IO & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_target_mask(root), ((CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY) & m->cgroup_supported));

        /* Verify aggregation of enable masks. */
        ASSERT_CGROUP_MASK(unit_get_enable_mask(son), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(daughter), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(grandchild), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(parent_deep), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(parent), ((CGROUP_MASK_CPU | CGROUP_MASK_MEMORY) & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_enable_mask(nomem_parent), (CGROUP_MASK_IO & m->cgroup_supported));
        ASSERT_CGROUP_MASK(unit_get_enable_mask(nomem_leaf), 0);
        ASSERT_CGROUP_MASK(unit_get_enable_mask(root), ((CGROUP_MASK_CPU | CGROUP_MASK_IO | CGROUP_MASK_MEMORY) & m->cgroup_supported));

        return 0;
}

static void set_allowed_cpus(Unit *u, sd_bus *bus, const CPUSet *cpus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        _cleanup_free_ uint8_t *bits = NULL;
        size_t n;

        ASSERT_OK(cpu_set_to_dbus(cpus, &bits, &n));
        ASSERT_OK(sd_bus_message_new_method_call(
                        bus, &message, "org.freedesktop.systemd1", "/",
                        "org.freedesktop.systemd1.Unit", "SetProperties"));
        ASSERT_OK(sd_bus_message_open_container(message, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_open_container(message, 'r', "sv"));
        ASSERT_OK(sd_bus_message_append(message, "s", "AllowedCPUs"));
        ASSERT_OK(sd_bus_message_open_container(message, 'v', "ay"));
        ASSERT_OK(sd_bus_message_append_array(message, 'y', bits, n));
        ASSERT_OK(sd_bus_message_close_container(message));
        ASSERT_OK(sd_bus_message_close_container(message));
        ASSERT_OK(sd_bus_message_close_container(message));
        ASSERT_OK(sd_bus_message_seal(message, 1, 0));
        ASSERT_OK(sd_bus_message_rewind(message, true));

        /* Exercise the current manager's property setter and cgroup realization, not the host PID1. */
        ASSERT_OK_EQ(bus_unit_set_properties(u, message, UNIT_RUNTIME, true, /* reterr_error= */ NULL), 1);
}

TEST_RET(allowed_cpus_reset, .sd_booted = true) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(cpu_set_done) CPUSet available = {}, limited = {}, affinity = {};
        _cleanup_free_ char *unit_dir = NULL, *test_cgroup = NULL, *init_cgroup = NULL, *parent_cpus = NULL;
        _cleanup_free_ char *configured = NULL, *task_cpus = NULL, *selected = NULL, *scope_name = NULL;
        Unit *u;
        int r;

        if (geteuid() != 0)
                return log_tests_skipped("requires root and a delegated cpuset cgroup");

        r = enter_cgroup_root(&test_cgroup);
        if (r < 0)
                return log_tests_skipped_errno(r, "cannot create a private cgroup subtree");
        ASSERT_OK(path_extract_filename(test_cgroup, &scope_name));
        if (!startswith(scope_name, "test-cgroup-mask-") || !endswith(scope_name, ".scope"))
                return log_tests_skipped("requires a scope dedicated to test-cgroup-mask");
        if (cg_is_delegated(test_cgroup) <= 0)
                return log_tests_skipped("requires a delegated cgroup subtree");

        ASSERT_OK(get_testdata_dir("test-cgroup-mask", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());
        ASSERT_OK(manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m));
        ASSERT_STREQ(m->cgroup_root, test_cgroup);
        if (!FLAGS_SET(m->cgroup_supported, CGROUP_MASK_CPUSET))
                return log_tests_skipped("cpuset controller is unavailable in the test subtree");

        m->defaults.memory_accounting = m->defaults.io_accounting = m->defaults.tasks_accounting = false;
        m->defaults.tasks_max = CGROUP_TASKS_MAX_UNSET;
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL, NULL));
        ASSERT_OK(cg_pid_get_path(0, &init_cgroup));
        ASSERT_OK(cg_get_attribute(m->cgroup_root, "cpuset.cpus.effective", &parent_cpus));
        ASSERT_OK(parse_cpu_set(parent_cpus, &available));
        if (cpu_set_count(&available) < 2)
                return log_tests_skipped("requires at least two available CPUs");
        ASSERT_OK(cpu_set_realloc(&affinity, available.allocated * 8));
        ASSERT_OK_ERRNO(sched_getaffinity(0, affinity.allocated, affinity.set));
        ASSERT_NOT_NULL(task_cpus = cpu_set_to_range_string(&affinity));
        if (!streq(task_cpus, parent_cpus))
                return log_tests_skipped("test process has a separate CPU affinity restriction");
        task_cpus = mfree(task_cpus);

        for (size_t i = 0; i < available.allocated * 8; i++)
                if (CPU_ISSET_S(i, available.allocated, available.set)) {
                        ASSERT_OK(cpu_set_add(&limited, i));
                        break;
                }

        ASSERT_NOT_NULL(selected = cpu_set_to_range_string(&limited));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "son.service", NULL, LOG_ERR, &u));
        ASSERT_OK(sd_bus_default_system(&bus));
        set_allowed_cpus(u, bus, &limited);

        CGroupRuntime *crt = ASSERT_PTR(unit_get_cgroup_runtime(u));
        ASSERT_OK(cg_get_attribute(crt->cgroup_path, "cpuset.cpus", &configured));
        ASSERT_STREQ(configured, selected);
        configured = mfree(configured);
        ASSERT_OK(cg_attach(crt->cgroup_path, 0));
        ASSERT_OK_ERRNO(sched_getaffinity(0, affinity.allocated, affinity.set));
        ASSERT_NOT_NULL(task_cpus = cpu_set_to_range_string(&affinity));
        ASSERT_STREQ(task_cpus, selected);
        task_cpus = mfree(task_cpus);

        set_allowed_cpus(u, bus, &(CPUSet) {});
        ASSERT_NULL(unit_get_cgroup_context(u)->cpuset_cpus.set);

        r = cg_get_attribute(crt->cgroup_path, "cpuset.cpus", &configured);
        ASSERT_TRUE(r >= 0 || r == -ENOENT);
        ASSERT_OK_ERRNO(sched_getaffinity(0, affinity.allocated, affinity.set));
        ASSERT_NOT_NULL(task_cpus = cpu_set_to_range_string(&affinity));

        /* Move out before reporting a failure so the manager can clean up the test unit's cgroup. */
        ASSERT_OK(cg_attach(init_cgroup, 0));
        log_info("AllowedCPUs reset: target CPUSET=%s, configured=%s, task=%s, parent=%s",
                 yes_no(FLAGS_SET(unit_get_target_mask(u), CGROUP_MASK_CPUSET)),
                 configured ?: "<controller absent>", task_cpus, parent_cpus);

        if (!isempty(configured) || !streq(task_cpus, parent_cpus))
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Clearing AllowedCPUs left a CPU restriction.");

        return 0;
}

static void test_cg_mask_to_string_one(CGroupMask mask, const char *t) {
        _cleanup_free_ char *b = NULL;

        assert_se(cg_mask_to_string(mask, &b) >= 0);
        ASSERT_STREQ(b, t);
}

TEST(cg_mask_to_string) {
        test_cg_mask_to_string_one(0, NULL);
        test_cg_mask_to_string_one(_CGROUP_MASK_ALL, "cpu cpuacct cpuset io blkio memory devices pids bpf-firewall bpf-devices bpf-foreign bpf-socket-bind bpf-restrict-network-interfaces bpf-bind-network-interface");
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

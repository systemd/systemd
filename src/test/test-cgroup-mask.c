/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <unistd.h>

#include "sd-bus.h"

#include "cgroup.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "cpu-set-util.h"
#include "dbus-unit.h"
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

static int get_cpu_affinity(CPUSet *ret) {
        _cleanup_(cpu_set_done) CPUSet cpus = {};
        int r;

        assert(ret);

        /* The kernel mask may be larger than the CPUs available to this cgroup. */
        for (size_t n = 16;; n *= 2) {
                r = cpu_set_realloc(&cpus, n);
                if (r < 0)
                        return r;
                if (sched_getaffinity(0, cpus.allocated, cpus.set) >= 0) {
                        cpu_set_done_and_replace(*ret, cpus);
                        return 0;
                }
                if (errno != EINVAL)
                        return -errno;
                if (n > SIZE_MAX / 2)
                        return -EOVERFLOW;
        }
}

TEST(cpu_affinity) {
        _cleanup_(cpu_set_done) CPUSet affinity = {};

        ASSERT_OK(get_cpu_affinity(&affinity));
        int n = ASSERT_OK_POSITIVE(cpus_in_affinity_mask());
        ASSERT_EQ(cpu_set_count(&affinity), (size_t) n);
}

static int probe_populated_cpuset_reset(const char *parent, const char *cpu, const char *restore_cgroup) {
        _cleanup_free_ char *probe = NULL;
        int r;

        ASSERT_NOT_NULL(probe = path_join(parent, "cpuset-reset-probe"));
        ASSERT_OK(cg_create(probe));
        ASSERT_OK(cg_set_attribute(probe, "cpuset.cpus", cpu));
        ASSERT_OK(cg_attach(probe, 0));

        /* Probe the kernel directly: a missing write in systemd must not turn into a skip. */
        r = cg_set_attribute(probe, "cpuset.cpus", "");
        ASSERT_OK(cg_attach(restore_cgroup, 0));
        ASSERT_OK(cg_trim(probe, true));
        return r;
}

static int run_allowed_cpus_reset(bool with_task) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(cpu_set_done) CPUSet available = {}, limited = {}, affinity = {};
        _cleanup_free_ char *unit_dir = NULL, *test_cgroup = NULL, *init_cgroup = NULL, *parent_cpus = NULL;
        _cleanup_free_ char *configured = NULL, *task_cpus = NULL, *selected = NULL, *parent_cgroup = NULL;
        Unit *u;
        int r;

        if (geteuid() != 0)
                return log_tests_skipped("requires root and a delegated cpuset cgroup");

        r = enter_cgroup_subroot(&test_cgroup);
        if (r < 0)
                return log_tests_skipped_errno(r, "cannot create a private cgroup subtree");
        ASSERT_OK(path_extract_directory(test_cgroup, &parent_cgroup));
        if (cg_is_delegated(parent_cgroup) <= 0)
                return log_tests_skipped("requires a delegated parent cgroup");

        /* The helper moved only this process into a private subtree. Do not move other processes in the
         * delegated parent just to enable cpuset: if it is still populated, leave it alone and skip. */
        CGroupMask enabled;
        r = cg_enable(CGROUP_MASK_CPUSET, CGROUP_MASK_CPUSET, parent_cgroup, &enabled);
        if (r < 0)
                return log_tests_skipped_errno(r, "cannot enable cpuset for the private test subtree");
        if (!FLAGS_SET(enabled, CGROUP_MASK_CPUSET))
                return log_tests_skipped("cannot enable cpuset for the private test subtree");

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
        ASSERT_GT(cpu_set_count(&available), 0U);
        if (with_task && cpu_set_count(&available) < 2)
                return log_tests_skipped("requires at least two available CPUs");

        /* Normalize the kernel's comma-separated list before comparing it with our formatter's output. */
        parent_cpus = mfree(parent_cpus);
        ASSERT_NOT_NULL(parent_cpus = cpu_set_to_range_string(&available));
        if (with_task) {
                ASSERT_OK(get_cpu_affinity(&affinity));
                ASSERT_NOT_NULL(task_cpus = cpu_set_to_range_string(&affinity));
                if (!streq(task_cpus, parent_cpus))
                        return log_tests_skipped("test process has a separate CPU affinity restriction");
                task_cpus = mfree(task_cpus);
        }

        for (size_t i = 0; i < available.allocated * 8; i++)
                if (CPU_ISSET_S(i, available.allocated, available.set)) {
                        ASSERT_OK(cpu_set_add(&limited, i));
                        break;
                }

        ASSERT_NOT_NULL(selected = cpu_set_to_range_string(&limited));
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "son.service", NULL, LOG_ERR, &u));
        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_tests_skipped_errno(r, "requires a reachable system bus");
        set_allowed_cpus(u, bus, &limited);

        CGroupRuntime *crt = ASSERT_PTR(unit_get_cgroup_runtime(u));
        ASSERT_OK(cg_get_attribute(crt->cgroup_path, "cpuset.cpus", &configured));
        ASSERT_STREQ(configured, selected);
        configured = mfree(configured);
        if (with_task) {
                /* Older kernels reject clearing a populated cpuset even in cgroup v2. This must not
                 * prevent the separate empty-cgroup regression from checking systemd's reset path. */
                r = probe_populated_cpuset_reset(m->cgroup_root, selected, init_cgroup);
                if (r == -ENOSPC)
                        return log_tests_skipped("kernel cannot clear a populated cpuset");
                ASSERT_OK(r);

                ASSERT_OK(cg_attach(crt->cgroup_path, 0));
                ASSERT_OK(get_cpu_affinity(&affinity));
                ASSERT_NOT_NULL(task_cpus = cpu_set_to_range_string(&affinity));
                ASSERT_STREQ(task_cpus, selected);
                task_cpus = mfree(task_cpus);
        }

        set_allowed_cpus(u, bus, &(CPUSet) {});
        ASSERT_NULL(unit_get_cgroup_context(u)->cpuset_cpus.set);

        if (with_task)
                ASSERT_OK_OR(cg_get_attribute(crt->cgroup_path, "cpuset.cpus", &configured), -ENOENT);
        else
                ASSERT_OK(cg_get_attribute(crt->cgroup_path, "cpuset.cpus", &configured));
        if (with_task) {
                ASSERT_OK(get_cpu_affinity(&affinity));
                ASSERT_NOT_NULL(task_cpus = cpu_set_to_range_string(&affinity));

                /* Move out before reporting a failure so the manager can clean up the unit's cgroup. */
                ASSERT_OK(cg_attach(init_cgroup, 0));
        }
        log_info("AllowedCPUs reset: target CPUSET=%s, configured=%s, task=%s, parent=%s",
                 yes_no(FLAGS_SET(unit_get_target_mask(u), CGROUP_MASK_CPUSET)),
                 configured ?: "<controller absent>", task_cpus ?: "<empty cgroup>", parent_cpus);

        ASSERT_TRUE(isempty(configured));
        if (with_task)
                ASSERT_STREQ(task_cpus, parent_cpus);

        /* A subsequent non-empty setting must still take effect. */
        configured = mfree(configured);
        set_allowed_cpus(u, bus, &limited);
        ASSERT_OK(cg_get_attribute(crt->cgroup_path, "cpuset.cpus", &configured));
        ASSERT_STREQ(configured, selected);

        return 0;
}

TEST(allowed_cpus_reset, .sd_booted = true) {
        ASSERT_OK(run_allowed_cpus_reset(false));
}

TEST(allowed_cpus_reset_running, .sd_booted = true) {
        /* An unsupported live reset must not mark the other cgroup tests as skipped. */
        ASSERT_OK(run_allowed_cpus_reset(true));
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

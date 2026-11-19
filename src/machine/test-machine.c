/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hashmap.h"
#include "machine.h"
#include "machined.h"
#include "path-util.h"
#include "pidref.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void manager_done(Manager *m) {
        Machine *machine;

        while ((machine = hashmap_first(m->machines)))
                machine_free(machine);

        m->machines = hashmap_free(m->machines);
}

static Machine* load_machine(Manager *manager, const char *name) {
        _cleanup_(machine_freep) Machine *m = NULL;

        ASSERT_OK(machine_new(_MACHINE_CLASS_INVALID, name, &m));
        ASSERT_OK(machine_link(manager, m));
        ASSERT_OK(machine_load(m));

        return TAKE_PTR(m);
}

TEST(save_load_subgroup) {
        /* A machine that runs in a subgroup of a unit it doesn't own must still have the subgroup and the
         * cgroup after machined saves and loads its state. Save a machine in a subgroup of
         * user@1000.service without a leader, load it into a second manager that uses the same state
         * directory, and check that the unit, the subgroup and the cgroup are unchanged. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-machine-XXXXXX", &t));

        _cleanup_(manager_done) Manager saver = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(saver.machines = hashmap_new(&string_hash_ops));
        Machine *m;
        ASSERT_OK(machine_new(MACHINE_VM, "foo", &m));
        ASSERT_OK(machine_link(&saver, m));
        ASSERT_NOT_NULL(m->unit = strdup("user@1000.service"));
        ASSERT_NOT_NULL(m->subgroup = strdup("app.slice/vte-spawn-1.scope"));
        ASSERT_NOT_NULL(m->cgroup = strdup("/user.slice/user-1000.slice/user@1000.service/app.slice/vte-spawn-1.scope"));
        m->started = true;
        ASSERT_OK(machine_save(m));

        /* sd_pid_get_machine_name() reads the unit:<unit> symlink. The machine doesn't own
         * user@1000.service, so machine_save() must not create the symlink. */
        _cleanup_free_ char *sl = ASSERT_NOT_NULL(path_join(t, "unit:user@1000.service"));
        ASSERT_ERROR_ERRNO(access(sl, F_OK), ENOENT);

        _cleanup_(manager_done) Manager loader = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(loader.machines = hashmap_new(&string_hash_ops));
        Machine *l = load_machine(&loader, "foo");
        ASSERT_STREQ(l->unit, "user@1000.service");
        ASSERT_STREQ(l->subgroup, "app.slice/vte-spawn-1.scope");
        ASSERT_STREQ(l->cgroup, "/user.slice/user-1000.slice/user@1000.service/app.slice/vte-spawn-1.scope");
        ASSERT_EQ(l->class, MACHINE_VM);
}

TEST(save_load_own_unit) {
        /* A machine that owns a unit other than machine-<name>.scope must still own the unit after machined
         * saves and loads its state, even without a leader. Save a machine that owns
         * systemd-nspawn@foo.service, load it into a second manager that uses the same state directory, and
         * check that the unit is unchanged and the subgroup is unset. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-machine-XXXXXX", &t));

        _cleanup_(manager_done) Manager saver = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(saver.machines = hashmap_new(&string_hash_ops));
        Machine *m;
        ASSERT_OK(machine_new(MACHINE_CONTAINER, "foo", &m));
        ASSERT_OK(machine_link(&saver, m));
        ASSERT_NOT_NULL(m->unit = strdup("systemd-nspawn@foo.service"));
        m->started = true;
        ASSERT_OK(machine_save(m));

        _cleanup_(manager_done) Manager loader = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(loader.machines = hashmap_new(&string_hash_ops));
        Machine *l = load_machine(&loader, "foo");
        ASSERT_STREQ(l->unit, "systemd-nspawn@foo.service");
        ASSERT_NULL(l->subgroup);
}

TEST(load_legacy_machine_scope) {
        /* machined v258 to v262 doesn't write SUBGROUP=. A machine owns the machine-<name>.scope unit that
         * machined starts for it. Write a state file for machine-foo.scope without SUBGROUP= and without a
         * leader, and check that loading it keeps the unit and leaves the subgroup unset. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-machine-XXXXXX", &t));

        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(t, "foo"));
        ASSERT_OK(write_string_file(p, "NAME=foo\nSCOPE=machine-foo.scope\nCLASS=container\n", WRITE_STRING_FILE_CREATE));

        _cleanup_(manager_done) Manager manager = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(manager.machines = hashmap_new(&string_hash_ops));
        Machine *m = load_machine(&manager, "foo");
        ASSERT_STREQ(m->unit, "machine-foo.scope");
        ASSERT_NULL(m->subgroup);
}

TEST(load_legacy_subgroup_without_leader) {
        /* machined v258 to v262 doesn't write SUBGROUP=. After a restart, it creates the unit:<unit> symlink
         * for a machine in a subgroup. Write a state file for user@1000.service without SUBGROUP= and
         * without a leader, and create the symlink. machined can't determine the subgroup without a
         * leader, so loading the state file must drop the unit and mark the machine as stopping. If
         * machined kept the unit, stopping the machine would stop user@1000.service. Loading must also
         * remove the symlink, because sd_pid_get_machine_name() would report the machine for every process
         * in user@1000.service. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-machine-XXXXXX", &t));

        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(t, "foo"));
        ASSERT_OK(write_string_file(p, "NAME=foo\nSCOPE=user@1000.service\nCLASS=vm\n", WRITE_STRING_FILE_CREATE));
        _cleanup_free_ char *sl = ASSERT_NOT_NULL(path_join(t, "unit:user@1000.service"));
        ASSERT_OK_ERRNO(symlink("foo", sl));

        _cleanup_(manager_done) Manager manager = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(manager.machines = hashmap_new(&string_hash_ops));
        Machine *m = load_machine(&manager, "foo");
        ASSERT_NULL(m->unit);
        ASSERT_NULL(m->subgroup);
        ASSERT_TRUE(m->stopping);
        ASSERT_ERROR_ERRNO(access(sl, F_OK), ENOENT);
}

TEST(load_legacy_subgroup_with_leader) {
        /* This test writes a state file without SUBGROUP= like load_legacy_subgroup_without_leader, but
         * with our own process as the leader. Loading the state file must determine the subgroup and the
         * cgroup from the cgroup of the leader. The test moves our process into a new subgroup of its own
         * cgroup, which needs a delegated cgroup. It is skipped if our process doesn't end up in a subgroup
         * of a unit. */
        int r = enter_cgroup_subroot(/* ret_cgroup= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to move into a subgroup, ignoring: %m");

        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        ASSERT_OK(pidref_set_self(&self));

        _cleanup_free_ char *unit = NULL, *subgroup = NULL, *cgroup = NULL;
        if (cg_pidref_get_unit_full(&self, &unit, &subgroup) < 0)
                return (void) log_tests_skipped("Not running in a unit");
        if (!subgroup)
                return (void) log_tests_skipped("Not running in a subgroup of a unit");
        ASSERT_OK(cg_pidref_get_path(&self, &cgroup));

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/test-machine-XXXXXX", &t));

        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(t, "foo"));
        _cleanup_free_ char *s = ASSERT_NOT_NULL(asprintf_safe("NAME=foo\nSCOPE=%s\nCLASS=vm\nLEADER=" PID_FMT "\n", unit, self.pid));
        ASSERT_OK(write_string_file(p, s, WRITE_STRING_FILE_CREATE));

        _cleanup_(manager_done) Manager manager = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .state_dir = t,
        };
        ASSERT_NOT_NULL(manager.machines = hashmap_new(&string_hash_ops));
        Machine *m = load_machine(&manager, "foo");
        ASSERT_STREQ(m->unit, unit);
        ASSERT_STREQ(m->subgroup, subgroup);
        ASSERT_STREQ(m->cgroup, cgroup);
        ASSERT_FALSE(m->stopping);
}

DEFINE_TEST_MAIN(LOG_DEBUG);

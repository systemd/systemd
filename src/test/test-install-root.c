/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "install.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static char *root = NULL;

STATIC_DESTRUCTOR_REGISTER(root, rm_rf_physical_and_freep);

TEST(basic_mask_and_enable) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "g.service", NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "h.service", NULL), -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/a.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/b.service");
        assert_se(symlink("a.service", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        p = strjoina(root, "/usr/lib/systemd/system/c.service");
        assert_se(symlink("/usr/lib/systemd/system/a.service", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        p = strjoina(root, "/usr/lib/systemd/system/d.service");
        assert_se(symlink("c.service", p) >= 0);

        /* This one is interesting, as d follows a relative, then an absolute symlink */
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        assert_se(unit_file_mask(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/dev/null");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/a.service");
        ASSERT_STREQ(changes[0].path, p);

        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        /* Enabling a masked unit should fail! */
        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) == -ERFKILL);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_unmask(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/a.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Enabling it again should succeed but be a NOP */
        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Disabling a disabled unit must succeed but be a NOP */
        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Let's enable this indirectly via a symlink */
        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("d.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/a.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Let's try to reenable */

        assert_se(unit_file_reenable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("b.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/a.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Test masking with relative symlinks */

        p = strjoina(root, "/usr/lib/systemd/system/e.service");
        assert_se(symlink("../../../../../../dev/null", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        assert_se(unlink(p) == 0);
        assert_se(symlink("/usr/../dev/null", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        assert_se(unlink(p) == 0);

        /* Test enabling with unknown dependency target */

        p = strjoina(root, "/usr/lib/systemd/system/f.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=x.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("f.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/f.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/x.target.wants/f.service");
        ASSERT_STREQ(changes[0].path, p);
        assert_se(changes[1].type == INSTALL_CHANGE_DESTINATION_NOT_PRESENT);
        p = strjoina(root, "/usr/lib/systemd/system/f.service");
        ASSERT_STREQ(changes[1].source, p);
        ASSERT_STREQ(changes[1].path, "x.target");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        /* Test enabling units with only Alias= (unit_file_enable should return > 0 to indicate we did
         * something, #33411) */

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR "/g.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "Alias=h.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_GT(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("g.service"), &changes, &n_changes), 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "g.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "h.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
}

TEST(linked_units) {
        const char *p, *q, *s;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0, i;

        /*
         * We'll test three cases here:
         *
         * a) a unit file in /opt, that we use "systemctl link" and
         * "systemctl enable" on to make it available to the system
         *
         * b) a unit file in /opt, that is statically linked into
         * /usr/lib/systemd/system, that "enable" should work on
         * correctly.
         *
         * c) a unit file in /opt, that is linked into
         * /etc/systemd/system, and where "enable" should result in
         * -ELOOP, since using information from /etc to generate
         * information in /etc should not be allowed.
         */

        p = strjoina(root, "/opt/linked.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "Alias=linked-alias.service\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/opt/linked2.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/opt/linked3.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked2.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked3.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/linked2.service");
        assert_se(symlink("/opt/linked2.service", p) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked3.service");
        assert_se(symlink("/opt/linked3.service", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked3.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* First, let's link the unit into the search path */
        assert_se(unit_file_link(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/opt/linked.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* Let's unlink it from the search path again */
        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        /* Now, let's not just link it, but also enable it */
        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 3);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        s = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked-alias.service");
        for (i = 0 ; i < n_changes; i++) {
                assert_se(changes[i].type == INSTALL_CHANGE_SYMLINK);

                if (s && streq(changes[i].path, s))
                        /* The alias symlink should point within the search path. */
                        ASSERT_STREQ(changes[i].source, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
                else
                        ASSERT_STREQ(changes[i].source, "/opt/linked.service");

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else if (s && streq(changes[i].path, s))
                        s = NULL;
                else
                        assert_not_reached();
        }
        assert_se(!p && !q && !s);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked-alias.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* And let's unlink it again */
        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 3);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        s = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked-alias.service");
        for (i = 0; i < n_changes; i++) {
                assert_se(changes[i].type == INSTALL_CHANGE_UNLINK);

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else if (s && streq(changes[i].path, s))
                        s = NULL;
                else
                        assert_not_reached();
        }
        assert_se(!p && !q && !s);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked2.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked2.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked2.service");
        for (i = 0 ; i < n_changes; i++) {
                assert_se(changes[i].type == INSTALL_CHANGE_SYMLINK);
                ASSERT_STREQ(changes[i].source, "/opt/linked2.service");

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else
                        assert_not_reached();
        }
        assert_se(!p && !q);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked3.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(startswith(changes[0].path, root));
        assert_se(endswith(changes[0].path, "linked3.service"));
        ASSERT_STREQ(changes[0].source, "/opt/linked3.service");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

TEST(default) {
        _cleanup_free_ char *def = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;

        p = strjoina(root, "/usr/lib/systemd/system/test-default-real.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/test-default.target");
        assert_se(symlink("test-default-real.target", p) >= 0);

        assert_se(unit_file_get_default(RUNTIME_SCOPE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(RUNTIME_SCOPE_SYSTEM, 0, root, "idontexist.target", &changes, &n_changes) == -ENOENT);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == -ENOENT);
        ASSERT_STREQ(changes[0].path, "idontexist.target");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(RUNTIME_SCOPE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(RUNTIME_SCOPE_SYSTEM, 0, root, "test-default.target", &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/test-default-real.target");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR "/" SPECIAL_DEFAULT_TARGET);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(RUNTIME_SCOPE_SYSTEM, root, &def) >= 0);
        ASSERT_STREQ(def, "test-default-real.target");
}

TEST(add_dependency) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;

        p = strjoina(root, "/usr/lib/systemd/system/real-add-dependency-test-target.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/add-dependency-test-target.target");
        assert_se(symlink("real-add-dependency-test-target.target", p) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/real-add-dependency-test-service.service");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/add-dependency-test-service.service");
        assert_se(symlink("real-add-dependency-test-service.service", p) >= 0);

        assert_se(unit_file_add_dependency(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("add-dependency-test-service.service"), "add-dependency-test-target.target", UNIT_WANTS, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/real-add-dependency-test-service.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/real-add-dependency-test-target.target.wants/real-add-dependency-test-service.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

TEST(template_enable) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        log_info("== %s ==", __func__);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/template@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/template-symlink@.service");
        assert_se(symlink("template@.service", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template@.service enabled ==", __func__);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/template@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@def.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template@foo.service enabled ==", __func__);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/template@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@foo.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template-symlink@quux.service enabled ==", __func__);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("template-symlink@quux.service"), &changes, &n_changes) >= 0);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/template@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@quux.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(indirect) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirecta.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectb.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectc.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/indirecta.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "Also=indirectb.service\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/indirectb.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/indirectc.service");
        assert_se(symlink("indirecta.service", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirecta.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectb.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectc.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/indirectb.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/indirectb.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirecta.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectb.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectc.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/indirectb.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

TEST(preset_and_list) {
        InstallChange *changes = NULL;
        size_t n_changes = 0, i;
        const char *p, *q;
        UnitFileState state;
        bool got_yes = false, got_no = false;
        UnitFileList *fl;
        _cleanup_hashmap_free_ Hashmap *h = NULL;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/preset-no.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/preset-ignore.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        assert_se(write_string_file(p,
                                    "enable *-yes.*\n"
                                    "ignore *-ignore.*\n"
                                    "disable *\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-yes.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/preset-yes.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-yes.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-no.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);

        assert_se(n_changes > 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");

        for (i = 0; i < n_changes; i++) {

                if (changes[i].type == INSTALL_CHANGE_SYMLINK) {
                        ASSERT_STREQ(changes[i].source, "/usr/lib/systemd/system/preset-yes.service");
                        ASSERT_STREQ(changes[i].path, p);
                } else
                        assert_se(changes[i].type == INSTALL_CHANGE_UNLINK);
        }

        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_get_list(RUNTIME_SCOPE_SYSTEM, root, NULL, NULL, &h));

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        q = strjoina(root, "/usr/lib/systemd/system/preset-no.service");

        HASHMAP_FOREACH(fl, h) {
                _cleanup_free_ char *unit_filename = NULL;

                ASSERT_OK(path_extract_filename(fl->path, &unit_filename));
                ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, unit_filename, &state));
                assert_se(fl->state == state);

                if (streq(fl->path, p)) {
                        got_yes = true;
                        assert_se(fl->state == UNIT_FILE_ENABLED);
                } else if (streq(fl->path, q)) {
                        got_no = true;
                        assert_se(fl->state == UNIT_FILE_DISABLED);
                } else
                        assert_se(IN_SET(fl->state, UNIT_FILE_DISABLED, UNIT_FILE_STATIC, UNIT_FILE_INDIRECT, UNIT_FILE_ALIAS));
        }

        assert_se(got_yes && got_no);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-ignore.service"), &changes, &n_changes) >= 0);
        assert_se(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-ignore.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(revert) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "xx.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "yy.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/xx.service");
        assert_se(write_string_file(p, "# Empty\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "xx.service", NULL) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "xx.service", &state) >= 0 && state == UNIT_FILE_STATIC);

        /* Initially there's nothing to revert */
        assert_se(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service");
        assert_se(write_string_file(p, "# Empty override\n", WRITE_STRING_FILE_CREATE) >= 0);

        /* Revert the override file */
        assert_se(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service.d/dropin.conf");
        assert_se(write_string_file(p, "# Empty dropin\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        /* Revert the dropin file */
        assert_se(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service.d");
        assert_se(changes[1].type == INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

/* The enablement symlinks point at paths relative to the image root, so they dangle when inspected from
 * outside of it. Look at the symlink itself rather than at what it resolves to. */
TEST(preset_order) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/prefix-1.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/prefix-2.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        assert_se(write_string_file(p,
                                    "enable prefix-1.service\n"
                                    "disable prefix-*.service\n"
                                    "enable prefix-2.service\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("prefix-1.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/prefix-1.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/prefix-1.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("prefix-2.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
}

TEST(static_instance) {
        UnitFileState state;
        const char *p;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@foo.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@foo.service");
        assert_se(symlink("static-instance@.service", p) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@foo.service", &state) >= 0 && state == UNIT_FILE_STATIC);
}

TEST(with_dropin) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-3.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4a.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-4a.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "Also=with-dropin-4b.service\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4b.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-1.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-1.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-1.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-1.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2.service"), &changes, &n_changes) == 1);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        ASSERT_STREQ(changes[1].source, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-2.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-3.service"), &changes, &n_changes) == 1);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-3.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-3.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-3.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-3.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-4a.service"), &changes, &n_changes) == 2);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-4a.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-4b.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-4a.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-4b.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(with_dropin_template) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@instance-1.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-1\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-2\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-1@instance-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-1@.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-1@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-1@instance-1.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-1@instance-1.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2@instance-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-2@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2@instance-1.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-2@instance-1.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2@instance-2.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2@instance-2.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-3@.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-3@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-3@instance-2.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1@instance-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@instance-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@instance-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@instance-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@instance-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(preset_multiple_instances) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        /* Set up template service files and preset file */
        p = strjoina(root, "/usr/lib/systemd/system/foo@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        assert_se(write_string_file(p,
                                    "enable foo@.service bar0 bar1 bartest\n"
                                    "enable emptylist@.service\n" /* This line ensures the old functionality for templated unit still works */
                                    "disable *\n" , WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        /* Preset a single instantiated unit specified in the list */
        assert_se(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("foo@bar0.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/foo@bar0.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root, STRV_MAKE("foo@bar0.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/foo@bar0.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Check for preset-all case, only instances on the list should be enabled, not including the default instance */
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bartest.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes > 0);

        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bartest.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        install_changes_free(changes, n_changes);
}

TEST(preset_scope) {
        const char *unit, *preset, *link;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* The specifiers in the names an [Install] section asks for are resolved in the scope the caller
         * asked for. %U has no meaning in the global scope, so presetting a unit that uses it has to fail
         * rather than quietly expand it as if this were the system scope. */

        unit = strjoina(root, "/usr/lib/systemd/user/scoped.service");
        ASSERT_OK(mkdir_parents(unit, 0755));
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=target-%U.target\n", WRITE_STRING_FILE_CREATE));

        preset = strjoina(root, "/usr/lib/systemd/user-preset/50-scoped.preset");
        ASSERT_OK(mkdir_parents(preset, 0755));
        ASSERT_OK(write_string_file(preset, "enable scoped.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_ERROR(unit_file_preset(RUNTIME_SCOPE_GLOBAL, 0, root, STRV_MAKE("scoped.service"),
                                      UNIT_FILE_PRESET_FULL, &changes, &n_changes), EINVAL);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        link = strjoina(root, USER_CONFIG_UNIT_DIR"/target-0.target.wants/scoped.service");
        ASSERT_ERROR(is_symlink(link), ENOENT);
}

static void verify_one(
                const InstallInfo *i,
                const char *alias,
                int expected,
                const char *updated_name) {
        int r;
        static const InstallInfo *last_info = NULL;
        _cleanup_free_ char *alias2 = NULL;

        if (i != last_info)
                log_info("-- %s --", (last_info = i)->name);

        r = unit_file_verify_alias(i, alias, &alias2, NULL, NULL);
        log_info_errno(r, "alias %s ← %s: %d/%m (expected %d)%s%s%s",
                       i->name, alias, r, expected,
                       alias2 ? " [" : "", strempty(alias2),
                       alias2 ? "]" : "");
        assert_se(r == expected);

        /* This is test for "instance propagation". This propagation matters mostly for WantedBy= and
         * RequiredBy= settings, and less so for Alias=. The only case where it should happen is when we have
         * an Alias=alias@.service an instantiated template template@instance. In that case the instance name
         * should be propagated into the alias as alias@instance. */
        ASSERT_STREQ(alias2, updated_name);
}

TEST(verify_alias) {
        const InstallInfo
                plain_service    = { .name = (char*) "plain.service" },
                bare_template    = { .name = (char*) "template1@.service" },
                di_template      = { .name = (char*) "template2@.service",
                                     .default_instance = (char*) "di" },
                inst_template    = { .name = (char*) "template3@inst.service" },
                di_inst_template = { .name = (char*) "template4@inst.service",
                                     .default_instance = (char*) "di" };

        verify_one(&plain_service, "alias.service", 0, NULL);
        verify_one(&plain_service, "alias.socket", -EXDEV, NULL);
        verify_one(&plain_service, "alias@.service", -EXDEV, NULL);
        verify_one(&plain_service, "alias@inst.service", -EXDEV, NULL);

        /* Setting WantedBy= and RequiredBy= through Alias= is supported for the sake of backwards
         * compatibility. */
        verify_one(&plain_service, "foo.target.wants/plain.service", 0, NULL);
        verify_one(&plain_service, "foo.target.wants/plain.socket", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.wants/plain@.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.wants/service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.requires/plain.service", 0, NULL);
        verify_one(&plain_service, "foo.target.requires/plain.socket", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.requires/service", -EXDEV, NULL);
        verify_one(&plain_service, "asdf.requires/plain.service", -EXDEV, NULL); /* invalid unit name component */
        /* The newly-added UpheldBy= (.upholds/) and other suffixes should be rejected */
        verify_one(&plain_service, "foo.target.upholds/plain.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.upholds/plain.socket", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.upholds/plain@.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.upholds/service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.service/plain.service", -EXDEV, NULL); /* missing dir suffix */
        verify_one(&plain_service, "foo.target.conf/plain.service", -EXDEV, NULL);

        verify_one(&bare_template, "alias.service", -EXDEV, NULL);
        verify_one(&bare_template, "alias.socket", -EXDEV, NULL);
        verify_one(&bare_template, "alias@.socket", -EXDEV, NULL);
        verify_one(&bare_template, "alias@inst.socket", -EXDEV, NULL);
        /* A general alias alias@.service → template1@.service. */
        verify_one(&bare_template, "alias@.service", 0, NULL);
        /* Only a specific instance is aliased, see the discussion in https://github.com/systemd/systemd/pull/13119. */
        verify_one(&bare_template, "alias@inst.service", 0, NULL);
        verify_one(&bare_template, "foo.target.wants/plain.service", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.wants/plain.socket", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.wants/plain@.service", -EXDEV, NULL);
         /* Name mismatch: we cannot allow this, because plain@foo.service would be pulled in by foo.target,
          * but would not be resolvable on its own, since systemd doesn't know how to load the fragment. */
        verify_one(&bare_template, "foo.target.wants/plain@foo.service", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.wants/template1@foo.service", 0, NULL);
        verify_one(&bare_template, "foo.target.wants/service", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.requires/plain.service", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.requires/plain.socket", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.requires/plain@.service", -EXDEV, NULL); /* instance missing */
        verify_one(&bare_template, "foo.target.requires/template1@inst.service", 0, NULL);
        verify_one(&bare_template, "foo.target.requires/service", -EXDEV, NULL);
        verify_one(&bare_template, "foo.target.conf/plain.service", -EXDEV, NULL);
        verify_one(&bare_template, "FOO@.target.requires/plain@.service", -EXDEV, NULL); /* template name mismatch */
        verify_one(&bare_template, "FOO@inst.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&bare_template, "FOO@inst.target.requires/plain@inst.service", -EXDEV, NULL);
        verify_one(&bare_template, "FOO@.target.requires/template1@.service", 0, NULL); /* instance propagated */
        verify_one(&bare_template, "FOO@inst.target.requires/template1@.service", -EXDEV, NULL); /* instance missing */
        verify_one(&bare_template, "FOO@inst.target.requires/template1@inst.service", 0, NULL); /* instance provided */

        verify_one(&di_template, "alias.service", -EXDEV, NULL);
        verify_one(&di_template, "alias.socket", -EXDEV, NULL);
        verify_one(&di_template, "alias@.socket", -EXDEV, NULL);
        verify_one(&di_template, "alias@inst.socket", -EXDEV, NULL);
        verify_one(&di_template, "alias@inst.service", 0, NULL);
        verify_one(&di_template, "alias@.service", 0, NULL);
        verify_one(&di_template, "alias@di.service", 0, NULL);
        verify_one(&di_template, "foo.target.wants/plain.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.wants/plain.socket", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.wants/plain@.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.wants/plain@di.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.wants/template2@di.service", 0, NULL);
        verify_one(&di_template, "foo.target.wants/service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.requires/plain.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.requires/plain.socket", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.requires/plain@di.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.requires/plain@foo.service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.requires/template2@.service", -EXDEV, NULL); /* instance missing */
        verify_one(&di_template, "foo.target.requires/template2@di.service", 0, NULL);
        verify_one(&di_template, "foo.target.requires/service", -EXDEV, NULL);
        verify_one(&di_template, "foo.target.conf/plain.service", -EXDEV, NULL);

        verify_one(&inst_template, "alias.service", -EXDEV, NULL);
        verify_one(&inst_template, "alias.socket", -EXDEV, NULL);
        verify_one(&inst_template, "alias@.socket", -EXDEV, NULL);
        verify_one(&inst_template, "alias@inst.socket", -EXDEV, NULL);
        verify_one(&inst_template, "alias@inst.service", 0, NULL);
        verify_one(&inst_template, "alias@.service", 0, "alias@inst.service");
        verify_one(&inst_template, "alias@di.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/plain.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/plain.socket", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/plain@.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/plain@di.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/plain@inst.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/template3@foo.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.wants/template3@inst.service", 0, NULL);
        verify_one(&inst_template, "bar.target.wants/service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/plain.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/plain.socket", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/plain@di.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/plain@inst.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/template3@foo.service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.requires/template3@inst.service", 0, NULL);
        verify_one(&inst_template, "bar.target.requires/service", -EXDEV, NULL);
        verify_one(&inst_template, "bar.target.conf/plain.service", -EXDEV, NULL);
        verify_one(&inst_template, "BAR@.target.requires/plain@.service", -EXDEV, NULL); /* template name mismatch */
        verify_one(&inst_template, "BAR@inst.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&inst_template, "BAR@inst.target.requires/plain@inst.service", -EXDEV, NULL);
        verify_one(&inst_template, "BAR@.target.requires/template3@.service", -EXDEV, NULL); /* instance missing */
        verify_one(&inst_template, "BAR@inst.target.requires/template3@.service", -EXDEV, NULL); /* instance missing */
        verify_one(&inst_template, "BAR@inst.target.requires/template3@inst.service", 0, NULL); /* instance provided */
        verify_one(&inst_template, "BAR@inst.target.requires/template3@ins2.service", -EXDEV, NULL); /* instance mismatch */

        /* explicit alias overrides DefaultInstance */
        verify_one(&di_inst_template, "alias.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "alias.socket", -EXDEV, NULL);
        verify_one(&di_inst_template, "alias@.socket", -EXDEV, NULL);
        verify_one(&di_inst_template, "alias@inst.socket", -EXDEV, NULL);
        verify_one(&di_inst_template, "alias@inst.service", 0, NULL);
        verify_one(&di_inst_template, "alias@.service", 0, "alias@inst.service");
        verify_one(&di_inst_template, "alias@di.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain.socket", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain@.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain@di.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/template4@foo.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/template4@inst.service", 0, NULL);
        verify_one(&di_inst_template, "goo.target.wants/template4@di.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.wants/service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain.socket", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain@di.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain@inst.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/template4@foo.service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.requires/template4@inst.service", 0, NULL);
        verify_one(&di_inst_template, "goo.target.requires/service", -EXDEV, NULL);
        verify_one(&di_inst_template, "goo.target.conf/plain.service", -EXDEV, NULL);
}

static bool symlink_exists(const char *path) {
        return is_symlink(path) > 0;
}

static bool is_dependency_mask(const char *path) {
        _cleanup_free_ char *dest = NULL;

        if (readlink_malloc(path, &dest) < 0)
                return false;

        return path_equal(dest, "/dev/null");
}

TEST(vendor_enable) {
        const char *unit, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-enabled.service", NULL), ENOENT);

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-enabled.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-enabled.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* The vendor enables the unit from /usr/, the way distribution packages ship .wants/ symlinks. PID 1
         * acts on those, so we must report the unit as enabled. */
        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-enabled.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-enabled.service", vendor_link));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-enabled.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        /* Disabling it cannot remove the vendor symlink, so it has to shadow it with a symlink to /dev/null
         * in the configuration directory. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-enabled.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1u);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_MASK_DEPENDENCY);

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-enabled.service");
        ASSERT_STREQ(changes[0].path, mask);
        ASSERT_STREQ(changes[0].source, vendor_link);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_TRUE(symlink_exists(vendor_link));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-enabled.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* Disabling twice must not undo the mask. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-enabled.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-enabled.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* Enabling drops the mask again. */
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-enabled.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(symlink_exists(mask));
        ASSERT_FALSE(is_dependency_mask(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-enabled.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(vendor_mask_in_unrelated_target) {
        const char *unit, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* A dependency mask only shadows the entry of the same name in the same .wants/ directory. Masking
         * the unit out of graphical.target must not make it look disabled when the vendor pulls it into
         * multi-user.target. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-two-targets.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-two-targets.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-two-targets.service", vendor_link));

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-two-targets.service");
        ASSERT_OK(mkdir_parents(mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", mask));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-two-targets.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        /* Disabling masks the multi-user.target entry too, and only then is the unit off. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-two-targets.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-two-targets.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* Enabling clears every mask, including the one in the target our [Install] section never mentions. */
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-two-targets.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(is_dependency_mask(mask));
}

TEST(vendor_preset) {
        const char *unit, *preset, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-preset.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/12-vendor.preset");
        ASSERT_OK(write_string_file(preset, "enable vendor-preset.service\n", WRITE_STRING_FILE_CREATE));

        /* "preset --vendor" installs the enablement symlink into the vendor directory, leaving /etc/ empty
         * so that it stays available for the administrator. */
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                   STRV_MAKE("vendor-preset.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-preset.service");
        ASSERT_TRUE(symlink_exists(vendor_link));

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-preset.service");
        ASSERT_FALSE(symlink_exists(mask));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-preset.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        /* Flipping the policy and presetting the vendor directory again removes the symlink rather than
         * masking it: /usr/ is writable at image build time, and a mask there would have nothing to shadow. */
        ASSERT_OK(write_string_file(preset, "disable vendor-preset.service\n",
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                   STRV_MAKE("vendor-preset.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(symlink_exists(vendor_link));
        ASSERT_FALSE(symlink_exists(mask));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-preset.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
}

TEST(vendor_preset_disable_masks_in_etc) {
        const char *unit, *preset, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* A preset policy of "disable" applied to /etc/ must be able to turn off what the vendor enabled,
         * which it can only do by masking. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-preset-off.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-preset-off.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-preset-off.service", vendor_link));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/13-vendor-off.preset");
        ASSERT_OK(write_string_file(preset, "disable vendor-preset-off.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-preset-off.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-preset-off.service");
        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_TRUE(symlink_exists(vendor_link));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-preset-off.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* revert deals with unit files and their drop-ins, not with enablement, so the mask survives it
         * exactly like an ordinary enablement symlink would. */
        ASSERT_OK(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root,
                                   STRV_MAKE("vendor-preset-off.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(is_dependency_mask(mask));

        /* Flipping the policy back is what turns it on again. */
        ASSERT_OK(write_string_file(preset, "enable vendor-preset-off.service\n",
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-preset-off.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(is_dependency_mask(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-preset-off.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(vendor_static_unit_is_not_masked) {
        const char *unit, *preset, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* A unit without an [Install] section is not enabled by a vendor dependency symlink, it is
         * statically wired up by it. Masking that would take it out of the boot, which a catch-all
         * "disable *" preset policy would then do to half the OS. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-static.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Unit]\n"
                                    "Description=no Install section\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-static.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-static.service", vendor_link));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-static.service", &state));
        ASSERT_EQ(state, UNIT_FILE_STATIC);

        preset = strjoina(root, "/usr/lib/systemd/system-preset/14-vendor-static.preset");
        ASSERT_OK(write_string_file(preset, "disable vendor-static.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-static.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-static.service");
        ASSERT_FALSE(symlink_exists(mask));

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-static.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(symlink_exists(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-static.service", &state));
        ASSERT_EQ(state, UNIT_FILE_STATIC);
}

TEST(vendor_alias_only_install) {
        const char *unit, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* Alias= names a unit file, not a dependency symlink, so a vendor .wants/ entry for a unit whose
         * [Install] section has nothing else is static wiring just the same. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-alias-only.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "Alias=vendor-alias-only-alias.service\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-alias-only.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-alias-only.service", vendor_link));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-alias-only.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-alias-only.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-alias-only.service");
        ASSERT_FALSE(symlink_exists(mask));
}

TEST(vendor_preset_all) {
        const char *unit, *preset, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* preset-all is the path distribution tooling actually uses, and it reaches the units by walking the
         * search path rather than by name. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-all.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-all.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-all.service", vendor_link));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/11-vendor-all.preset");
        ASSERT_OK(write_string_file(preset, "disable vendor-all.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL,
                                       &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-all.service");
        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-all.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* Running it again must converge rather than flip-flop. */
        ASSERT_OK(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL,
                                       &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(is_dependency_mask(mask));

        ASSERT_OK(write_string_file(preset, "enable vendor-all.service\n",
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));
        ASSERT_OK(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL,
                                       &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(is_dependency_mask(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-all.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(vendor_requires_and_upholds) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* The three dependency directory kinds go through the same code, but only .wants/ is covered above. */

        FOREACH_STRING(suffix, "requires", "upholds") {
                _cleanup_free_ char *name = NULL, *unit = NULL, *vendor_link = NULL, *mask = NULL;

                ASSERT_NOT_NULL(name = strjoin("vendor-", suffix, ".service"));
                ASSERT_NOT_NULL(unit = strjoin(root, "/usr/lib/systemd/system/", name));
                ASSERT_OK(write_string_file(unit,
                                            "[Install]\n"
                                            "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

                ASSERT_NOT_NULL(vendor_link = strjoin(root, "/usr/lib/systemd/system/multi-user.target.",
                                                      suffix, "/", name));
                ASSERT_OK(mkdir_parents(vendor_link, 0755));
                ASSERT_OK_ERRNO(symlinkat(unit, AT_FDCWD, vendor_link));

                ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, name, &state));
                ASSERT_EQ(state, UNIT_FILE_ENABLED);

                ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                            STRV_MAKE(name), &changes, &n_changes));
                install_changes_free(changes, n_changes);
                changes = NULL; n_changes = 0;

                ASSERT_NOT_NULL(mask = strjoin(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.",
                                               suffix, "/", name));
                ASSERT_TRUE(is_dependency_mask(mask));
                ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, name, &state));
                ASSERT_EQ(state, UNIT_FILE_DISABLED);

                ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                           STRV_MAKE(name), &changes, &n_changes));
                install_changes_free(changes, n_changes);
                changes = NULL; n_changes = 0;

                ASSERT_FALSE(is_dependency_mask(mask));
                ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, name, &state));
                ASSERT_EQ(state, UNIT_FILE_ENABLED);
        }
}

TEST(vendor_template_instance) {
        const char *unit, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* Disabling a template has to mask the vendor's instance symlinks, the same way removal takes away
         * the configured ones. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-tmpl@.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "DefaultInstance=dflt\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-tmpl@inst.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-tmpl@.service", vendor_link));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-tmpl@inst.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        /* Disabling the template must reach the instance the vendor wired up. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-tmpl@.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-tmpl@inst.service");
        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-tmpl@inst.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-tmpl@inst.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(is_dependency_mask(mask));
}

TEST(vendor_also) {
        const char *main_unit, *aux_unit, *vendor_link, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* Enabling has to clear the masks of the Also= units too, and those are only discovered while the
         * symlinks are being applied. */

        main_unit = strjoina(root, "/usr/lib/systemd/system/vendor-also.service");
        ASSERT_OK(write_string_file(main_unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n"
                                    "Also=vendor-also.socket\n", WRITE_STRING_FILE_CREATE));

        aux_unit = strjoina(root, "/usr/lib/systemd/system/vendor-also.socket");
        ASSERT_OK(write_string_file(aux_unit,
                                    "[Install]\n"
                                    "WantedBy=sockets.target\n", WRITE_STRING_FILE_CREATE));

        /* The vendor pulls the auxiliary unit into a target the [Install] section never names. */
        vendor_link = strjoina(root, "/usr/lib/systemd/system/graphical.target.wants/vendor-also.socket");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-also.socket", vendor_link));

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-also.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-also.socket");
        ASSERT_TRUE(is_dependency_mask(mask));

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-also.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(is_dependency_mask(mask));
}

TEST(vendor_mask_shadows_lower_priority_dir) {
        const char *unit, *low_link, *high_mask, *mask;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* An entry in a higher priority directory shadows the one below it, so a vendor that masks its own
         * dependency in /usr/local/ leaves nothing for us to mask in /etc/. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-shadow.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        low_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-shadow.service");
        ASSERT_OK(mkdir_parents(low_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-shadow.service", low_link));

        high_mask = strjoina(root, "/usr/local/lib/systemd/system/multi-user.target.wants/vendor-shadow.service");
        ASSERT_OK(mkdir_parents(high_mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", high_mask));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-shadow.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-shadow.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-shadow.service");
        ASSERT_FALSE(symlink_exists(mask));
}

TEST(vendor_multiple_units) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* Disabling several units at once produces one mask each, and a single enable has to clear all of
         * them, not just the first. */

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service") {
                _cleanup_free_ char *unit = NULL, *vendor_link = NULL;

                ASSERT_NOT_NULL(unit = strjoin(root, "/usr/lib/systemd/system/", name));
                ASSERT_OK(write_string_file(unit,
                                            "[Install]\n"
                                            "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

                /* A target the [Install] section does not name, so that enable has to go through the
                 * unmask pass rather than just overwriting the mask. */
                ASSERT_NOT_NULL(vendor_link = strjoin(root, "/usr/lib/systemd/system/graphical.target.wants/", name));
                ASSERT_OK(mkdir_parents(vendor_link, 0755));
                ASSERT_OK_ERRNO(symlink(strjoina("../", name), vendor_link));
        }

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-multi-a.service",
                                              "vendor-multi-b.service",
                                              "vendor-multi-c.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service") {
                _cleanup_free_ char *mask = NULL;

                ASSERT_NOT_NULL(mask = strjoin(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/", name));
                ASSERT_TRUE(is_dependency_mask(mask));
        }

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-multi-a.service",
                                             "vendor-multi-b.service",
                                             "vendor-multi-c.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service") {
                _cleanup_free_ char *mask = NULL;

                ASSERT_NOT_NULL(mask = strjoin(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/", name));
                ASSERT_FALSE(is_dependency_mask(mask));
        }
}

TEST(vendor_multiple_masks_per_unit) {
        const char *unit, *mask_a, *mask_b;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* One unit wired into several targets: enable has to clear every one of its masks, not just the
         * first one it comes across. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-many-targets.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        FOREACH_STRING(target, "graphical.target", "sockets.target") {
                _cleanup_free_ char *vendor_link = NULL;

                ASSERT_NOT_NULL(vendor_link = strjoin(root, "/usr/lib/systemd/system/", target,
                                                      ".wants/vendor-many-targets.service"));
                ASSERT_OK(mkdir_parents(vendor_link, 0755));
                ASSERT_OK_ERRNO(symlink("../vendor-many-targets.service", vendor_link));
        }

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                    STRV_MAKE("vendor-many-targets.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        mask_a = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-many-targets.service");
        mask_b = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/sockets.target.wants/vendor-many-targets.service");
        ASSERT_TRUE(is_dependency_mask(mask_a));
        ASSERT_TRUE(is_dependency_mask(mask_b));

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-many-targets.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(symlink_exists(mask_a));
        ASSERT_FALSE(symlink_exists(mask_b));
}

TEST(vendor_keeps_symlinks_it_was_not_asked_for) {
        const char *unit, *preset, *compat, *slot, *wiring;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* Distributions ship default.target, the runlevel targets and plenty of other symlinks below /usr/
         * that no [Install] section ever asked for. Presetting into the vendor directories must leave every
         * one of them alone, or building an image with "preset-all --vendor" takes the OS apart. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-named.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "Alias=vendor-named-slot.service\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        /* A name nothing declares, i.e. the vendor's own. */
        compat = strjoina(root, "/usr/lib/systemd/system/vendor-named-compat.service");
        ASSERT_OK_ERRNO(symlink("vendor-named.service", compat));

        /* And the one the [Install] section does declare. */
        slot = strjoina(root, "/usr/lib/systemd/system/vendor-named-slot.service");
        ASSERT_OK_ERRNO(symlink("vendor-named.service", slot));

        wiring = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-named.service");
        ASSERT_OK(mkdir_parents(wiring, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-named.service", wiring));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/19-vendor-named.preset");
        ASSERT_OK(write_string_file(preset, "disable vendor-named.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                   STRV_MAKE("vendor-named.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* The dependency symlink is how the unit was on, so that goes. The names stay: dropping them would
         * not turn anything off, it would take the name away from everything that refers to the unit by
         * it. */
        ASSERT_FALSE(symlink_exists(wiring));
        ASSERT_TRUE(symlink_exists(compat));
        ASSERT_TRUE(symlink_exists(slot));

        /* An explicit disable is a different matter: it may take back what enabling would have created. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                    STRV_MAKE("vendor-named.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(symlink_exists(compat));
        ASSERT_FALSE(symlink_exists(slot));
}

TEST(vendor_disable_keeps_wiring_of_unit_without_install) {
        const char *unit, *compat;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* Same for a unit that cannot be enabled at all: nothing below /usr/ that points at it is ours. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-unnamed.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Unit]\n"
                                    "Description=no Install section\n", WRITE_STRING_FILE_CREATE));

        compat = strjoina(root, "/usr/lib/systemd/system/vendor-unnamed-compat.service");
        ASSERT_OK_ERRNO(symlink("vendor-unnamed.service", compat));

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                    STRV_MAKE("vendor-unnamed.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(symlink_exists(compat));
}

TEST(vendor_disable_removes_linked_unit) {
        const char *unit, *link, *alias;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* A unit file from outside the search path is linked into the vendor directory under its own name,
         * so unlike the symlinks above that one is ours to take back. */

        unit = strjoina(root, "/opt/vendor-linked.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "Alias=vendor-linked-alias.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                   STRV_MAKE("/opt/vendor-linked.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        link = strjoina(root, "/usr/lib/systemd/system/vendor-linked.service");
        alias = strjoina(root, "/usr/lib/systemd/system/vendor-linked-alias.service");
        ASSERT_TRUE(symlink_exists(link));
        ASSERT_TRUE(symlink_exists(alias));

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, root,
                                    STRV_MAKE("vendor-linked.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(symlink_exists(link));
        ASSERT_FALSE(symlink_exists(alias));
}

TEST(vendor_preset_leaves_etc_alone) {
        const char *unit, *preset, *vendor_link, *etc_link;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;

        /* Presetting re-asserts a policy, it is not the administrator saying they want this unit on, so
         * there is nothing to record when the vendor already enables it. An explicit enable does record
         * itself, so that it survives the vendor dropping the symlink later. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-redundant.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-redundant.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-redundant.service", vendor_link));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/15-vendor-redundant.preset");
        ASSERT_OK(write_string_file(preset, "enable vendor-redundant.service\n", WRITE_STRING_FILE_CREATE));

        etc_link = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-redundant.service");

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-redundant.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_FALSE(symlink_exists(etc_link));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-redundant.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        /* An explicit enable writes it out even though it changes nothing right now. */
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-redundant.service"), &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_TRUE(symlink_exists(etc_link));

        /* And that is what makes it survive the vendor changing its mind. */
        ASSERT_OK_ERRNO(unlink(vendor_link));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "vendor-redundant.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(vendor_preset_still_writes_what_is_needed) {
        const char *unit, *preset, *etc_link;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* The skip only applies where the vendor already provides the very same dependency. A target the
         * vendor does not wire up, and a vendor entry that is masked, both still have to be written. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-partial.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE));

        /* The vendor only wires up one of the two targets. */
        const char *vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-partial.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-partial.service", vendor_link));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/16-vendor-partial.preset");
        ASSERT_OK(write_string_file(preset, "enable vendor-partial.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-partial.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        etc_link = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-partial.service");
        ASSERT_FALSE(symlink_exists(etc_link));

        etc_link = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-partial.service");
        ASSERT_TRUE(symlink_exists(etc_link));
        ASSERT_FALSE(is_dependency_mask(etc_link));
}

TEST(vendor_preset_writes_over_transient_and_masked) {
        const char *unit, *preset, *etc_link;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* Only a vendor supplied dependency lets presetting skip the write. An entry in /run/ is gone
         * after a reboot, and a masked one does not establish anything at all, so both still need the
         * persistent symlink. */

        unit = strjoina(root, "/usr/lib/systemd/system/vendor-transient.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        const char *runtime_link = strjoina(root, "/run/systemd/system/multi-user.target.wants/vendor-transient.service");
        ASSERT_OK(mkdir_parents(runtime_link, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-transient.service", runtime_link));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/17-vendor-transient.preset");
        ASSERT_OK(write_string_file(preset, "enable vendor-transient.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-transient.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        etc_link = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-transient.service");
        ASSERT_TRUE(symlink_exists(etc_link));
        ASSERT_FALSE(is_dependency_mask(etc_link));

        /* Now the masked case: the vendor wires it up, but a higher priority vendor directory masks it. */
        unit = strjoina(root, "/usr/lib/systemd/system/vendor-selfmasked.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        const char *vendor_link = strjoina(root, "/usr/lib/systemd/system/multi-user.target.wants/vendor-selfmasked.service");
        ASSERT_OK(mkdir_parents(vendor_link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-selfmasked.service", vendor_link));

        const char *vendor_mask = strjoina(root, "/usr/local/lib/systemd/system/multi-user.target.wants/vendor-selfmasked.service");
        ASSERT_OK(mkdir_parents(vendor_mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", vendor_mask));

        preset = strjoina(root, "/usr/lib/systemd/system-preset/18-vendor-selfmasked.preset");
        ASSERT_OK(write_string_file(preset, "enable vendor-selfmasked.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, root,
                                   STRV_MAKE("vendor-selfmasked.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        etc_link = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/vendor-selfmasked.service");
        ASSERT_TRUE(symlink_exists(etc_link));
        ASSERT_FALSE(is_dependency_mask(etc_link));
}

static int intro(void) {
        const char *p;

        assert_se(mkdtemp_malloc("/tmp/rootXXXXXX", &root) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/run/systemd/system/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/opt/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system-preset/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/multi-user.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/graphical.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

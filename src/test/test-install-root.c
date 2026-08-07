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

/* The vendor tests leave enablement symlinks below /usr/ behind, which a preset-all in any of the other
 * tests would then act on. The order the tests run in is up to the linker, so give them a root of their
 * own rather than depend on it. */
static char *vendor_root = NULL;

STATIC_DESTRUCTOR_REGISTER(root, rm_rf_physical_and_freep);
STATIC_DESTRUCTOR_REGISTER(vendor_root, rm_rf_physical_and_freep);

static void make_root(char **ret) {
        ASSERT_OK(mkdtemp_malloc("/tmp/rootXXXXXX", ret));

        FOREACH_STRING(d, "/usr/lib/systemd/system/", SYSTEM_CONFIG_UNIT_DIR"/", "/run/systemd/system/",
                       "/opt/", "/usr/lib/systemd/system-preset/")
                ASSERT_OK(mkdir_p(strjoina(*ret, d), 0755));

        FOREACH_STRING(t, "multi-user.target", "graphical.target")
                ASSERT_OK(write_string_file(strjoina(*ret, "/usr/lib/systemd/system/", t),
                                            "# pretty much empty", WRITE_STRING_FILE_CREATE));
}

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

        /* A unit a generator produced counts as having a vendor version too, so its override goes as well.
         * The generator directories are root prefixed, so this only works if we look for them as such. */
        p = strjoina(root, "/run/systemd/generator/zz.service");
        assert_se(write_string_file(p, "# Empty\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/zz.service");
        assert_se(write_string_file(p, "# Empty override\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("zz.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* The other tests share this root and the order they run in is up to the linker, so do not leave a
         * generated unit lying around for them to trip over. */
        ASSERT_OK_ERRNO(unlink(strjoina(root, "/run/systemd/generator/zz.service")));
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

static void write_vendor_file(const char *rel, const char *contents) {
        const char *p = strjoina(vendor_root, "/usr/lib/systemd/", rel);

        ASSERT_OK(mkdir_parents(p, 0755));
        ASSERT_OK(write_string_file(p, contents, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));
}

static void write_vendor_symlink(const char *rel, const char *target) {
        const char *p = strjoina(vendor_root, "/usr/lib/systemd/system/", rel);

        ASSERT_OK(mkdir_parents(p, 0755));
        ASSERT_OK_ERRNO(symlink(target, p));
}

static void assert_state(const char *name, UnitFileState expect) {
        UnitFileState state;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, vendor_root, name, &state));
        ASSERT_EQ(state, expect);
}

/* The verbs under test, with the change list of no interest to the caller. The one test that does look at it
 * calls unit_file_disable() directly. */

static void do_enable(UnitFileFlags flags, char * const *names) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, flags, vendor_root, names, &changes, &n_changes));
}

static void do_disable(UnitFileFlags flags, char * const *names) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, flags, vendor_root, names, &changes, &n_changes));
}

static void do_preset(UnitFileFlags flags, char * const *names) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, flags, vendor_root, names, UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
}

static void do_preset_all(UnitFileFlags flags) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);
        ASSERT_OK(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, flags, vendor_root, UNIT_FILE_PRESET_FULL,
                                       &changes, &n_changes));
}

#define VENDOR_WANTS "/usr/lib/systemd/system/multi-user.target.wants/"
#define ETC_WANTS SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/"

#define WANTED_BY_MULTI_USER \
        "[Install]\n"        \
        "WantedBy=multi-user.target\n"

TEST(vendor_enable) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *vendor_link, *mask;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, vendor_root, "vendor-enabled.service", NULL), ENOENT);

        write_vendor_file("system/vendor-enabled.service", WANTED_BY_MULTI_USER);
        assert_state("vendor-enabled.service", UNIT_FILE_DISABLED);

        /* The vendor enables the unit from /usr/, the way distribution packages ship .wants/ symlinks. PID 1
         * acts on those, so we must report the unit as enabled. */
        write_vendor_symlink("multi-user.target.wants/vendor-enabled.service", "../vendor-enabled.service");
        assert_state("vendor-enabled.service", UNIT_FILE_ENABLED);

        /* Disabling it cannot remove the vendor symlink, so it has to shadow it with a symlink to /dev/null
         * in the configuration directory. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, vendor_root,
                                    STRV_MAKE("vendor-enabled.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1u);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_MASK_DEPENDENCY);

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-enabled.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-enabled.service");
        ASSERT_STREQ(changes[0].path, mask);
        ASSERT_STREQ(changes[0].source, vendor_link);

        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_TRUE(symlink_exists(vendor_link));
        assert_state("vendor-enabled.service", UNIT_FILE_DISABLED);

        /* Disabling twice must not undo the mask. */
        do_disable(0, STRV_MAKE("vendor-enabled.service"));
        ASSERT_TRUE(is_dependency_mask(mask));
        assert_state("vendor-enabled.service", UNIT_FILE_DISABLED);

        /* Enabling drops the mask again. */
        do_enable(0, STRV_MAKE("vendor-enabled.service"));
        ASSERT_TRUE(symlink_exists(mask));
        ASSERT_FALSE(is_dependency_mask(mask));
        assert_state("vendor-enabled.service", UNIT_FILE_ENABLED);
}

TEST(vendor_mask_in_unrelated_target) {
        const char *mask;

        /* A dependency mask only shadows the entry of the same name in the same .wants/ directory. Masking
         * the unit out of graphical.target must not make it look disabled when the vendor pulls it into
         * multi-user.target. Enabling then has to clear that mask too, even though the [Install] section
         * never names graphical.target. */

        write_vendor_file("system/vendor-two-targets.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-two-targets.service", "../vendor-two-targets.service");

        mask = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-two-targets.service");
        ASSERT_OK(mkdir_parents(mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", mask));

        assert_state("vendor-two-targets.service", UNIT_FILE_ENABLED);

        do_disable(0, STRV_MAKE("vendor-two-targets.service"));
        assert_state("vendor-two-targets.service", UNIT_FILE_DISABLED);

        do_enable(0, STRV_MAKE("vendor-two-targets.service"));
        ASSERT_FALSE(is_dependency_mask(mask));
}

TEST(vendor_preset) {
        const char *vendor_link, *mask;

        write_vendor_file("system/vendor-preset.service", WANTED_BY_MULTI_USER);
        write_vendor_file("system-preset/12-vendor.preset", "enable vendor-preset.service\n");

        /* "preset --vendor" installs the enablement symlink into the vendor directory, leaving /etc/ empty
         * so that it stays available for the administrator. */
        do_preset(UNIT_FILE_VENDOR, STRV_MAKE("vendor-preset.service"));

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-preset.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-preset.service");
        ASSERT_TRUE(symlink_exists(vendor_link));
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-preset.service", UNIT_FILE_ENABLED);

        /* Flipping the policy and presetting the vendor directory again removes the symlink rather than
         * masking it: /usr/ is writable at image build time, and a mask there would have nothing to shadow. */
        write_vendor_file("system-preset/12-vendor.preset", "disable vendor-preset.service\n");
        do_preset(UNIT_FILE_VENDOR, STRV_MAKE("vendor-preset.service"));

        ASSERT_FALSE(symlink_exists(vendor_link));
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-preset.service", UNIT_FILE_DISABLED);
}

TEST(vendor_preset_leaves_vendor_enablement_alone) {
        const char *vendor_link, *mask;

        /* A preset policy of "disable" does not reach what the vendor enabled below /usr/. Masking it would
         * take units out of the boot on every existing system whose preset files do not name what it wires
         * up, which they never had to. Asking for it by name still works. */

        write_vendor_file("system/vendor-preset-off.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-preset-off.service", "../vendor-preset-off.service");
        write_vendor_file("system-preset/13-vendor-off.preset", "disable vendor-preset-off.service\n");

        do_preset(0, STRV_MAKE("vendor-preset-off.service"));

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-preset-off.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-preset-off.service");
        ASSERT_FALSE(symlink_exists(mask));
        ASSERT_TRUE(symlink_exists(vendor_link));
        assert_state("vendor-preset-off.service", UNIT_FILE_ENABLED);

        /* An explicit disable is a different matter. */
        do_disable(0, STRV_MAKE("vendor-preset-off.service"));
        ASSERT_TRUE(is_dependency_mask(mask));
        assert_state("vendor-preset-off.service", UNIT_FILE_DISABLED);

        /* And presetting it back to "enable" clears that mask again. */
        write_vendor_file("system-preset/13-vendor-off.preset", "enable vendor-preset-off.service\n");
        do_preset(0, STRV_MAKE("vendor-preset-off.service"));

        ASSERT_FALSE(is_dependency_mask(mask));
        assert_state("vendor-preset-off.service", UNIT_FILE_ENABLED);
}

TEST(vendor_not_enableable_is_not_masked) {
        /* A unit that asks for no dependency symlinks is not enabled by a vendor one, it is statically wired
         * up by it. Masking that would take it out of the boot, which a catch-all "disable *" preset policy
         * would then do to half the OS. Alias= names a unit file rather than a dependency symlink, so a unit
         * whose [Install] section has nothing else counts as statically wired up just the same. */

        write_vendor_file("system/vendor-static.service",
                          "[Unit]\n"
                          "Description=no Install section\n");
        write_vendor_file("system/vendor-alias-only.service",
                          "[Install]\n"
                          "Alias=vendor-alias-only-alias.service\n");
        write_vendor_file("system-preset/14-vendor-static.preset",
                          "disable vendor-static.service\n"
                          "disable vendor-alias-only.service\n");

        FOREACH_STRING(name, "vendor-static.service", "vendor-alias-only.service") {
                const char *mask = strjoina(vendor_root, ETC_WANTS, name);

                write_vendor_symlink(strjoina("multi-user.target.wants/", name), strjoina("../", name));
                assert_state(name, streq(name, "vendor-static.service") ? UNIT_FILE_STATIC : UNIT_FILE_DISABLED);

                do_preset(0, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(mask));

                do_disable(0, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(mask));

                /* An administrator who masked it by hand keeps that mask, though. */
                ASSERT_OK_ERRNO(symlink("/dev/null", mask));
                do_enable(0, STRV_MAKE(name));
                ASSERT_TRUE(is_dependency_mask(mask));
                ASSERT_OK_ERRNO(unlink(mask));
        }

        assert_state("vendor-static.service", UNIT_FILE_STATIC);

        /* The protection has to match the way removal does, or an instance of a statically wired template
         * slips through it. A leftover pointing at a unit that no longer exists is not static wiring
         * though, it is rubbish to clean up. */
        write_vendor_file("system/vendor-tmpl-static@.service",
                          "[Unit]\n"
                          "Description=statically wired template\n");
        write_vendor_symlink("multi-user.target.wants/vendor-tmpl-static@one.service",
                             "../vendor-tmpl-static@.service");
        write_vendor_symlink("multi-user.target.wants/vendor-gone.service", "../vendor-gone.service");

        do_preset_all(UNIT_FILE_VENDOR);
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, VENDOR_WANTS"vendor-tmpl-static@one.service")));

        InstallChange *changes = NULL;
        size_t n_changes = 0;
        CLEANUP_ARRAY(changes, n_changes, install_changes_free);
        (void) unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, vendor_root,
                                 STRV_MAKE("vendor-gone.service"), &changes, &n_changes);
        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, VENDOR_WANTS"vendor-gone.service")));
}

TEST(vendor_preset_all) {
        const char *vendor_link, *mask;

        /* preset-all is the path distribution tooling actually uses, and it reaches the units by walking the
         * search path rather than by name. Same rule: it leaves the vendor's enablement where it is, and
         * only presetting the vendor directories takes it away. */

        write_vendor_file("system/vendor-all.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-all.service", "../vendor-all.service");
        write_vendor_file("system-preset/11-vendor-all.preset", "disable vendor-all.service\n");

        do_preset_all(0);

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-all.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-all.service");
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-all.service", UNIT_FILE_ENABLED);

        do_preset_all(UNIT_FILE_VENDOR);
        ASSERT_FALSE(symlink_exists(vendor_link));
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-all.service", UNIT_FILE_DISABLED);

        /* Running it again must converge rather than flip-flop. */
        do_preset_all(UNIT_FILE_VENDOR);
        ASSERT_FALSE(symlink_exists(vendor_link));

        write_vendor_file("system-preset/11-vendor-all.preset", "enable vendor-all.service\n");
        do_preset_all(UNIT_FILE_VENDOR);

        ASSERT_TRUE(symlink_exists(vendor_link));
        assert_state("vendor-all.service", UNIT_FILE_ENABLED);
}

TEST(vendor_requires_and_upholds) {
        /* The three dependency directory kinds go through the same code, but only .wants/ is covered above. */

        FOREACH_STRING(suffix, "requires", "upholds") {
                _cleanup_free_ char *name = NULL, *rel = NULL, *mask = NULL;

                ASSERT_NOT_NULL(name = strjoin("vendor-", suffix, ".service"));
                ASSERT_NOT_NULL(rel = strjoin("multi-user.target.", suffix, "/", name));
                ASSERT_NOT_NULL(mask = strjoin(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.",
                                               suffix, "/", name));

                write_vendor_file(strjoina("system/", name), WANTED_BY_MULTI_USER);
                write_vendor_symlink(rel, strjoina("../", name));
                assert_state(name, UNIT_FILE_ENABLED);

                do_disable(0, STRV_MAKE(name));
                ASSERT_TRUE(is_dependency_mask(mask));
                assert_state(name, UNIT_FILE_DISABLED);

                do_enable(0, STRV_MAKE(name));
                ASSERT_FALSE(is_dependency_mask(mask));
                assert_state(name, UNIT_FILE_ENABLED);
        }
}

TEST(vendor_template_instance) {
        const char *mask;

        /* Disabling a template has to mask the vendor's instance symlinks, the same way removal takes away
         * the configured ones. */

        write_vendor_file("system/vendor-tmpl@.service",
                          "[Install]\n"
                          "DefaultInstance=dflt\n"
                          "WantedBy=multi-user.target\n");
        write_vendor_symlink("multi-user.target.wants/vendor-tmpl@inst.service", "../vendor-tmpl@.service");

        assert_state("vendor-tmpl@inst.service", UNIT_FILE_ENABLED);

        /* Disabling the template must reach the instance the vendor wired up. */
        do_disable(0, STRV_MAKE("vendor-tmpl@.service"));

        mask = strjoina(vendor_root, ETC_WANTS"vendor-tmpl@inst.service");
        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, VENDOR_WANTS"vendor-tmpl@inst.service")));
        assert_state("vendor-tmpl@inst.service", UNIT_FILE_DISABLED);

        do_enable(0, STRV_MAKE("vendor-tmpl@inst.service"));
        ASSERT_FALSE(is_dependency_mask(mask));
}

TEST(vendor_also) {
        const char *mask;

        /* Enabling has to clear the masks of the Also= units too, and those are only discovered while the
         * symlinks are being applied. */

        write_vendor_file("system/vendor-also.service",
                          "[Install]\n"
                          "WantedBy=multi-user.target\n"
                          "Also=vendor-also.socket\n");
        write_vendor_file("system/vendor-also.socket",
                          "[Install]\n"
                          "WantedBy=sockets.target\n");

        /* The vendor pulls the auxiliary unit into a target the [Install] section never names. */
        write_vendor_symlink("graphical.target.wants/vendor-also.socket", "../vendor-also.socket");

        do_disable(0, STRV_MAKE("vendor-also.service"));

        mask = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-also.socket");
        ASSERT_TRUE(is_dependency_mask(mask));

        do_enable(0, STRV_MAKE("vendor-also.service"));
        ASSERT_FALSE(is_dependency_mask(mask));
}

TEST(vendor_mask_shadows_lower_priority_dir) {
        const char *high_mask, *mask;

        /* An entry in a higher priority directory shadows the one below it, so a vendor that masks its own
         * dependency in /usr/local/ leaves nothing for us to mask in /etc/. */

        write_vendor_file("system/vendor-shadow.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-shadow.service", "../vendor-shadow.service");

        high_mask = strjoina(vendor_root, "/usr/local/lib/systemd/system/multi-user.target.wants/vendor-shadow.service");
        ASSERT_OK(mkdir_parents(high_mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", high_mask));

        assert_state("vendor-shadow.service", UNIT_FILE_DISABLED);

        do_disable(0, STRV_MAKE("vendor-shadow.service"));

        mask = strjoina(vendor_root, ETC_WANTS"vendor-shadow.service");
        ASSERT_FALSE(symlink_exists(mask));
}

TEST(vendor_multiple_units) {
        /* Several units at once, each wired into two targets the [Install] section does not name, so that
         * enabling has to go through the unmask pass and clear every one of them rather than stopping at the
         * first unit or the first mask. */

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service") {
                write_vendor_file(strjoina("system/", name), WANTED_BY_MULTI_USER);

                FOREACH_STRING(target, "graphical.target", "sockets.target")
                        write_vendor_symlink(strjoina(target, ".wants/", name), strjoina("../", name));
        }

        do_disable(0, STRV_MAKE("vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service"));

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service")
                FOREACH_STRING(target, "graphical.target", "sockets.target")
                        ASSERT_TRUE(is_dependency_mask(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/", target,
                                                                ".wants/", name)));

        do_enable(0, STRV_MAKE("vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service"));

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service")
                FOREACH_STRING(target, "graphical.target", "sockets.target")
                        ASSERT_FALSE(is_dependency_mask(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/", target,
                                                                 ".wants/", name)));
}

TEST(vendor_entry_kinds) {
        const char *entry;

        /* conf_files_list_strv() lets whatever sits in the higher priority dependency directory win, and
         * PID 1 then ignores anything that is not a symlink. A dependency resolving to an empty file counts
         * as a mask just like one pointing at /dev/null. Our verdict has to agree with all of that. */

        write_vendor_file("system/vendor-kinds.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-kinds.service", "../vendor-kinds.service");
        assert_state("vendor-kinds.service", UNIT_FILE_ENABLED);

        entry = strjoina(vendor_root, ETC_WANTS"vendor-kinds.service");
        ASSERT_OK(mkdir_parents(entry, 0755));

        /* A dangling symlink is still a dependency as far as PID 1 is concerned. */
        ASSERT_OK_ERRNO(symlink("../nope.service", entry));
        assert_state("vendor-kinds.service", UNIT_FILE_ENABLED);
        ASSERT_OK_ERRNO(unlink(entry));

        ASSERT_OK(write_string_file(strjoina(vendor_root, "/etc/empty"), "",
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK_ERRNO(symlink("/etc/empty", entry));
        assert_state("vendor-kinds.service", UNIT_FILE_DISABLED);
        ASSERT_OK_ERRNO(unlink(entry));

        FOREACH_STRING(contents, "", "junk\n") {
                _cleanup_free_ char *back = NULL;

                ASSERT_OK(write_string_file(entry, contents,
                                            WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE|
                                            WRITE_STRING_FILE_AVOID_NEWLINE));
                assert_state("vendor-kinds.service", UNIT_FILE_DISABLED);

                /* Whatever is sitting there already shadows the vendor symlink, so disabling has nothing
                 * left to do and must not replace it: that would destroy it. */
                do_disable(0, STRV_MAKE("vendor-kinds.service"));
                ASSERT_OK(read_full_file(entry, &back, NULL));
                ASSERT_STREQ(back, contents);

                ASSERT_OK_ERRNO(unlink(entry));
        }

        ASSERT_OK_ERRNO(mkdir(entry, 0755));
        assert_state("vendor-kinds.service", UNIT_FILE_DISABLED);

        /* Replacing this one would fail outright rather than quietly. */
        do_disable(0, STRV_MAKE("vendor-kinds.service"));
        ASSERT_OK_ERRNO(rmdir(entry));
}

TEST(vendor_dry_run_writes_nothing) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* "is-enabled --full" drives a dry run through the masking code to list what enables the unit. A
         * regression there would disable units from a read-only query. */

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        write_vendor_file("system/vendor-dry.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-dry.service", "../vendor-dry.service");

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_DRY_RUN, vendor_root,
                                    STRV_MAKE("vendor-dry.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1u);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_MASK_DEPENDENCY);
        ASSERT_STREQ(changes[0].source, strjoina(vendor_root, VENDOR_WANTS"vendor-dry.service"));

        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, ETC_WANTS"vendor-dry.service")));
        assert_state("vendor-dry.service", UNIT_FILE_ENABLED);
}

TEST(vendor_no_pointless_mask_below_the_vendor_directory) {
        /* --vendor operates on /usr/lib/systemd/system/, which is lower priority than /usr/local/lib/. A
         * mask placed there would shadow nothing, so it must not be written at all. */

        write_vendor_file("system/vendor-local.service", WANTED_BY_MULTI_USER);

        const char *high = strjoina(vendor_root, "/usr/local/lib/systemd/system/multi-user.target.wants/vendor-local.service");
        ASSERT_OK(mkdir_parents(high, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-local.service", high));

        do_disable(UNIT_FILE_VENDOR, STRV_MAKE("vendor-local.service"));
        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, VENDOR_WANTS"vendor-local.service")));
}

TEST(vendor_also_keeps_sibling_preset_policy) {
        /* Presetting a unit must not drag its Also= units into the removal set: they have a preset policy of
         * their own, which by then has either already been applied or is yet to be. */

        write_vendor_file("system/vendor-main.service",
                          "[Install]\n"
                          "WantedBy=multi-user.target\n"
                          "Also=vendor-aux.socket\n");
        write_vendor_file("system/vendor-aux.socket",
                          "[Install]\n"
                          "WantedBy=sockets.target\n");
        write_vendor_file("system-preset/20-vendor-mixed.preset",
                          "disable vendor-main.service\n"
                          "enable vendor-aux.socket\n");

        do_enable(0, STRV_MAKE("vendor-aux.socket"));
        assert_state("vendor-aux.socket", UNIT_FILE_ENABLED);

        do_preset(0, STRV_MAKE("vendor-main.service"));
        assert_state("vendor-main.service", UNIT_FILE_DISABLED);
        assert_state("vendor-aux.socket", UNIT_FILE_ENABLED);

        do_preset_all(0);
        assert_state("vendor-main.service", UNIT_FILE_DISABLED);
        assert_state("vendor-aux.socket", UNIT_FILE_ENABLED);
}
TEST(vendor_keeps_symlinks_it_was_not_asked_for) {
        const char *compat, *slot, *wiring;

        /* Distributions ship default.target, the runlevel targets and plenty of other symlinks below /usr/
         * that no [Install] section ever asked for. Presetting into the vendor directories must leave every
         * one of them alone, or building an image with "preset-all --vendor" takes the OS apart. */

        write_vendor_file("system/vendor-named.service",
                          "[Install]\n"
                          "Alias=vendor-named-slot.service\n"
                          "WantedBy=multi-user.target\n");

        /* A name nothing declares, i.e. the vendor's own, and the one the [Install] section does declare. */
        write_vendor_symlink("vendor-named-compat.service", "vendor-named.service");
        write_vendor_symlink("vendor-named-slot.service", "vendor-named.service");
        write_vendor_symlink("multi-user.target.wants/vendor-named.service", "../vendor-named.service");
        write_vendor_file("system-preset/19-vendor-named.preset", "disable vendor-named.service\n");

        do_preset(UNIT_FILE_VENDOR, STRV_MAKE("vendor-named.service"));

        /* The dependency symlink is how the unit was on, so that goes. The names stay: dropping them would
         * not turn anything off, it would take the name away from everything that refers to the unit by
         * it. */
        compat = strjoina(vendor_root, "/usr/lib/systemd/system/vendor-named-compat.service");
        slot = strjoina(vendor_root, "/usr/lib/systemd/system/vendor-named-slot.service");
        wiring = strjoina(vendor_root, VENDOR_WANTS"vendor-named.service");
        ASSERT_FALSE(symlink_exists(wiring));
        ASSERT_TRUE(symlink_exists(compat));
        ASSERT_TRUE(symlink_exists(slot));

        /* An explicit disable is a different matter: it may take back what enabling would have created. */
        do_disable(UNIT_FILE_VENDOR, STRV_MAKE("vendor-named.service"));
        ASSERT_TRUE(symlink_exists(compat));
        ASSERT_FALSE(symlink_exists(slot));

        /* Same for a unit that cannot be enabled at all: nothing below /usr/ that points at it is ours. */
        write_vendor_file("system/vendor-unnamed.service",
                          "[Unit]\n"
                          "Description=no Install section\n");
        write_vendor_symlink("vendor-unnamed-compat.service", "vendor-unnamed.service");

        do_disable(UNIT_FILE_VENDOR, STRV_MAKE("vendor-unnamed.service"));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, "/usr/lib/systemd/system/vendor-unnamed-compat.service")));
}

TEST(vendor_disable_removes_linked_unit) {
        const char *unit, *link, *alias;

        /* A unit file from outside the search path is linked into the vendor directory under its own name,
         * so unlike the symlinks above that one is ours to take back. */

        unit = strjoina(vendor_root, "/opt/vendor-linked.service");
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "Alias=vendor-linked-alias.service\n", WRITE_STRING_FILE_CREATE));

        do_enable(UNIT_FILE_VENDOR, STRV_MAKE("/opt/vendor-linked.service"));

        link = strjoina(vendor_root, "/usr/lib/systemd/system/vendor-linked.service");
        alias = strjoina(vendor_root, "/usr/lib/systemd/system/vendor-linked-alias.service");
        ASSERT_TRUE(symlink_exists(link));
        ASSERT_TRUE(symlink_exists(alias));

        do_disable(UNIT_FILE_VENDOR, STRV_MAKE("vendor-linked.service"));
        ASSERT_FALSE(symlink_exists(link));
        ASSERT_FALSE(symlink_exists(alias));
}

TEST(vendor_preset_leaves_etc_alone) {
        const char *vendor_link, *etc_link;

        /* Presetting re-asserts a policy, it is not the administrator saying they want this unit on, so
         * there is nothing to record when the vendor already enables it. An explicit enable does record
         * itself, so that it survives the vendor dropping the symlink later. */

        write_vendor_file("system/vendor-redundant.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-redundant.service", "../vendor-redundant.service");
        write_vendor_file("system-preset/15-vendor-redundant.preset", "enable vendor-redundant.service\n");

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-redundant.service");
        etc_link = strjoina(vendor_root, ETC_WANTS"vendor-redundant.service");

        do_preset(0, STRV_MAKE("vendor-redundant.service"));
        ASSERT_FALSE(symlink_exists(etc_link));
        assert_state("vendor-redundant.service", UNIT_FILE_ENABLED);

        /* An explicit enable writes it out even though it changes nothing right now, and that is what makes
         * it survive the vendor changing its mind. */
        do_enable(0, STRV_MAKE("vendor-redundant.service"));
        ASSERT_TRUE(symlink_exists(etc_link));

        ASSERT_OK_ERRNO(unlink(vendor_link));
        assert_state("vendor-redundant.service", UNIT_FILE_ENABLED);
}

TEST(vendor_preset_still_writes_what_is_needed) {
        /* The skip only applies where the vendor already provides the very same dependency. A target the
         * vendor does not wire up still has to be written, and so does one whose vendor entry is transient
         * or masked: an entry in /run/ is gone after a reboot and a masked one establishes nothing. */

        write_vendor_file("system/vendor-partial.service",
                          "[Install]\n"
                          "WantedBy=multi-user.target\n"
                          "WantedBy=graphical.target\n"
                          "WantedBy=sockets.target\n"
                          "WantedBy=timers.target\n");

        /* Wired up by the vendor, so nothing to record. */
        write_vendor_symlink("multi-user.target.wants/vendor-partial.service", "../vendor-partial.service");

        /* Wired up in /run/ instead. */
        const char *runtime_link = strjoina(vendor_root, "/run/systemd/system/sockets.target.wants/vendor-partial.service");
        ASSERT_OK(mkdir_parents(runtime_link, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-partial.service", runtime_link));

        /* Wired up by the vendor, but masked by a higher priority vendor directory. */
        write_vendor_symlink("timers.target.wants/vendor-partial.service", "../vendor-partial.service");
        const char *vendor_mask = strjoina(vendor_root, "/usr/local/lib/systemd/system/timers.target.wants/vendor-partial.service");
        ASSERT_OK(mkdir_parents(vendor_mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", vendor_mask));

        write_vendor_file("system-preset/16-vendor-partial.preset", "enable vendor-partial.service\n");
        do_preset(0, STRV_MAKE("vendor-partial.service"));

        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, ETC_WANTS"vendor-partial.service")));

        FOREACH_STRING(target, "graphical.target", "sockets.target", "timers.target") {
                const char *p = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/", target, ".wants/vendor-partial.service");

                ASSERT_TRUE(symlink_exists(p));
                ASSERT_FALSE(is_dependency_mask(p));
        }
}

TEST(vendor_preset_skips_redundant_alias) {
        /* An Alias= symlink the vendor already carries for this very unit is as redundant as a dependency
         * symlink would be, so presetting has nothing to record there either. The name has to point at this
         * unit though: one the vendor carries for somebody else does not satisfy the policy. */

        write_vendor_file("system/vendor-aliased.service",
                          "[Install]\n"
                          "Alias=vendor-aliased-name.service\n"
                          "Alias=vendor-aliased-taken.service\n"
                          "Alias=vendor-aliased-transient.service\n");
        write_vendor_file("system/vendor-aliased-other.service", "[Install]\n");
        write_vendor_symlink("vendor-aliased-name.service", "vendor-aliased.service");
        write_vendor_symlink("vendor-aliased-taken.service", "vendor-aliased-other.service");

        /* And as for dependencies, only a vendor supplied name counts: one in /run/ is gone after a
         * reboot. */
        const char *runtime_alias = strjoina(vendor_root, "/run/systemd/system/vendor-aliased-transient.service");
        ASSERT_OK(mkdir_parents(runtime_alias, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-aliased.service", runtime_alias));

        write_vendor_file("system-preset/21-vendor-aliased.preset", "enable vendor-aliased.service\n");
        do_preset(0, STRV_MAKE("vendor-aliased.service"));

        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-name.service")));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-taken.service")));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-transient.service")));

        /* An explicit enable records itself as always. */
        do_enable(0, STRV_MAKE("vendor-aliased.service"));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-name.service")));
}

static int intro(void) {
        make_root(&root);
        make_root(&vendor_root);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

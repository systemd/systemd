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

/* Tests that use vendor_root leave unit files and enablement symlinks behind. A preset-all in another test
 * would act on the leftover files. The tests run in link order, so with a shared root the result of a
 * test would depend on that order. */
static char *vendor_root = NULL;

STATIC_DESTRUCTOR_REGISTER(root, rm_rf_physical_and_freep);
STATIC_DESTRUCTOR_REGISTER(vendor_root, rm_rf_physical_and_freep);

static void make_root(char **ret) {
        ASSERT_OK(mkdtemp_malloc("/tmp/rootXXXXXX", ret));

        FOREACH_STRING(d, "/usr/lib/systemd/system/", SYSTEM_CONFIG_UNIT_DIR"/", "/run/systemd/system/",
                       "/opt/", "/usr/lib/systemd/system-preset/") {
                _cleanup_free_ char *p = NULL;

                ASSERT_NOT_NULL(p = path_join(*ret, d));
                ASSERT_OK(mkdir_p(p, 0755));
        }

        FOREACH_STRING(t, "multi-user.target", "graphical.target") {
                _cleanup_free_ char *p = NULL;

                ASSERT_NOT_NULL(p = path_join(*ret, "/usr/lib/systemd/system/", t));
                ASSERT_OK(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE));
        }
}

TEST(basic_mask_and_enable) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "g.service", /* ret= */ NULL), -ENOENT);
        ASSERT_EQ(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "h.service", /* ret= */ NULL), -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/a.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/b.service");
        ASSERT_OK_ERRNO(symlink("a.service", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        p = strjoina(root, "/usr/lib/systemd/system/c.service");
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/a.service", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        p = strjoina(root, "/usr/lib/systemd/system/d.service");
        ASSERT_OK_ERRNO(symlink("c.service", p));

        /* This one is interesting, as d follows a relative, then an absolute symlink */
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        ASSERT_OK(unit_file_mask(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/dev/null");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/a.service");
        ASSERT_STREQ(changes[0].path, p);

        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_MASKED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_MASKED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state));
        ASSERT_EQ(state, UNIT_FILE_MASKED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state));
        ASSERT_EQ(state, UNIT_FILE_MASKED);

        /* Enabling a masked unit should fail! */
        ASSERT_ERROR(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes), ERFKILL);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_unmask(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/a.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        /* Enabling it again should succeed but be a NOP */
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 0U);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        /* Disabling a disabled unit must succeed but be a NOP */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("a.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 0U);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Let's enable this indirectly via a symlink */
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("d.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/a.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        /* Let's try to reenable */

        ASSERT_OK(unit_file_reenable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("b.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        ASSERT_STREQ(changes[0].path, p);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/a.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "c.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "d.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        /* Test masking with relative symlinks */

        p = strjoina(root, "/usr/lib/systemd/system/e.service");
        ASSERT_OK_ERRNO(symlink("../../../../../../dev/null", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", &state));
        ASSERT_EQ(state, UNIT_FILE_MASKED);

        ASSERT_OK_ZERO_ERRNO(unlink(p));
        ASSERT_OK_ERRNO(symlink("/usr/../dev/null", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "e.service", &state));
        ASSERT_EQ(state, UNIT_FILE_MASKED);

        ASSERT_OK_ZERO_ERRNO(unlink(p));

        /* Test enabling with unknown dependency target */

        p = strjoina(root, "/usr/lib/systemd/system/f.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=x.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("f.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/f.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/x.target.wants/f.service");
        ASSERT_STREQ(changes[0].path, p);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_DESTINATION_NOT_PRESENT);
        p = strjoina(root, "/usr/lib/systemd/system/f.service");
        ASSERT_STREQ(changes[1].source, p);
        ASSERT_STREQ(changes[1].path, "x.target");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "f.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        /* Test enabling units with only Alias= (unit_file_enable should return > 0 to indicate we did
         * something, #33411) */

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR "/g.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "Alias=h.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_GT(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("g.service"), &changes, &n_changes), 0);
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
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "Alias=linked-alias.service\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/opt/linked2.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/opt/linked3.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", /* ret= */ NULL), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked2.service", /* ret= */ NULL), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked3.service", /* ret= */ NULL), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/linked2.service");
        ASSERT_OK_ERRNO(symlink("/opt/linked2.service", p));

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked3.service");
        ASSERT_OK_ERRNO(symlink("/opt/linked3.service", p));

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", &state), ENOENT);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked3.service", &state));
        ASSERT_EQ(state, UNIT_FILE_LINKED);

        /* First, let's link the unit into the search path */
        ASSERT_OK(unit_file_link(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/opt/linked.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", &state));
        ASSERT_EQ(state, UNIT_FILE_LINKED);

        /* Let's unlink it from the search path again */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("linked.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", /* ret= */ NULL), ENOENT);

        /* Now, let's not just link it, but also enable it */
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 3U);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        s = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked-alias.service");
        for (i = 0 ; i < n_changes; i++) {
                ASSERT_EQ(changes[i].type, INSTALL_CHANGE_SYMLINK);

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
        ASSERT_NULL(p);
        ASSERT_NULL(q);
        ASSERT_NULL(s);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked-alias.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        /* And let's unlink it again */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("linked.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 3U);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        s = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked-alias.service");
        for (i = 0; i < n_changes; i++) {
                ASSERT_EQ(changes[i].type, INSTALL_CHANGE_UNLINK);

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else if (s && streq(changes[i].path, s))
                        s = NULL;
                else
                        assert_not_reached();
        }
        ASSERT_NULL(p);
        ASSERT_NULL(q);
        ASSERT_NULL(s);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "linked.service", /* ret= */ NULL), ENOENT);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("linked2.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 2U);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked2.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked2.service");
        for (i = 0 ; i < n_changes; i++) {
                ASSERT_EQ(changes[i].type, INSTALL_CHANGE_SYMLINK);
                ASSERT_STREQ(changes[i].source, "/opt/linked2.service");

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else
                        assert_not_reached();
        }
        ASSERT_NULL(p);
        ASSERT_NULL(q);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("linked3.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_NOT_NULL(startswith(changes[0].path, root));
        ASSERT_NOT_NULL(endswith(changes[0].path, "linked3.service"));
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
        ASSERT_OK(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/test-default.target");
        ASSERT_OK_ERRNO(symlink("test-default-real.target", p));

        ASSERT_ERROR(unit_file_get_default(RUNTIME_SCOPE_SYSTEM, root, &def), ENOENT);

        ASSERT_ERROR(unit_file_set_default(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, "idontexist.target", &changes, &n_changes), ENOENT);
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, -ENOENT);
        ASSERT_STREQ(changes[0].path, "idontexist.target");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_ERROR(unit_file_get_default(RUNTIME_SCOPE_SYSTEM, root, &def), ENOENT);

        ASSERT_OK(unit_file_set_default(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, "test-default.target", &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/test-default-real.target");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR "/" SPECIAL_DEFAULT_TARGET);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_default(RUNTIME_SCOPE_SYSTEM, root, &def));
        ASSERT_STREQ(def, "test-default-real.target");
}

TEST(add_dependency) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;

        p = strjoina(root, "/usr/lib/systemd/system/real-add-dependency-test-target.target");
        ASSERT_OK(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/add-dependency-test-target.target");
        ASSERT_OK_ERRNO(symlink("real-add-dependency-test-target.target", p));

        p = strjoina(root, "/usr/lib/systemd/system/real-add-dependency-test-service.service");
        ASSERT_OK(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/add-dependency-test-service.service");
        ASSERT_OK_ERRNO(symlink("real-add-dependency-test-service.service", p));

        ASSERT_OK(unit_file_add_dependency(
                                  RUNTIME_SCOPE_SYSTEM,
                                  /* flags= */ 0,
                                  root,
                                  STRV_MAKE("add-dependency-test-service.service"),
                                  "add-dependency-test-target.target",
                                  UNIT_WANTS,
                                  &changes,
                                  &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
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

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/template@.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/template-symlink@.service");
        ASSERT_OK_ERRNO(symlink("template@.service", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        log_info("== %s with template@.service enabled ==", __func__);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("template@.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/template@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@def.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("template@.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        log_info("== %s with template@foo.service enabled ==", __func__);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes));
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/template@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@foo.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_INDIRECT);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@quux.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@quux.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        log_info("== %s with template-symlink@quux.service enabled ==", __func__);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("template-symlink@quux.service"), &changes, &n_changes));
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/template@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@quux.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_INDIRECT);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template@quux.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "template-symlink@quux.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(indirect) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirecta.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectb.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectc.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/indirecta.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "Also=indirectb.service\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/indirectb.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/indirectc.service");
        ASSERT_OK_ERRNO(symlink("indirecta.service", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirecta.service", &state));
        ASSERT_EQ(state, UNIT_FILE_INDIRECT);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectb.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectc.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/indirectb.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/indirectb.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirecta.service", &state));
        ASSERT_EQ(state, UNIT_FILE_INDIRECT);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectb.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "indirectc.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ALIAS);

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
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

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/preset-no.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/preset-ignore.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        ASSERT_OK(write_string_file(p,
                                    "enable *-yes.*\n"
                                    "ignore *-ignore.*\n"
                                    "disable *\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, STRV_MAKE("preset-yes.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/preset-yes.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("preset-yes.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, STRV_MAKE("preset-no.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_EQ(n_changes, 0U);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes));

        ASSERT_GT(n_changes, 0U);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");

        for (i = 0; i < n_changes; i++) {

                if (changes[i].type == INSTALL_CHANGE_SYMLINK) {
                        ASSERT_STREQ(changes[i].source, "/usr/lib/systemd/system/preset-yes.service");
                        ASSERT_STREQ(changes[i].path, p);
                } else
                        ASSERT_EQ(changes[i].type, INSTALL_CHANGE_UNLINK);
        }

        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-yes.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-no.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_get_list(RUNTIME_SCOPE_SYSTEM, root, /* states= */ NULL, /* patterns= */ NULL, &h));

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        q = strjoina(root, "/usr/lib/systemd/system/preset-no.service");

        HASHMAP_FOREACH(fl, h) {
                _cleanup_free_ char *unit_filename = NULL;

                ASSERT_OK(path_extract_filename(fl->path, &unit_filename));
                ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, unit_filename, &state));
                ASSERT_EQ(fl->state, state);

                if (streq(fl->path, p)) {
                        got_yes = true;
                        ASSERT_EQ(fl->state, UNIT_FILE_ENABLED);
                } else if (streq(fl->path, q)) {
                        got_no = true;
                        ASSERT_EQ(fl->state, UNIT_FILE_DISABLED);
                } else
                        ASSERT_TRUE(IN_SET(fl->state, UNIT_FILE_DISABLED, UNIT_FILE_STATIC, UNIT_FILE_INDIRECT, UNIT_FILE_ALIAS));
        }

        ASSERT_TRUE(got_yes);
        ASSERT_TRUE(got_no);

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("preset-ignore.service"), &changes, &n_changes));
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, STRV_MAKE("preset-ignore.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "preset-ignore.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(revert) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "xx.service", /* ret= */ NULL), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "yy.service", /* ret= */ NULL), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/xx.service");
        ASSERT_OK(write_string_file(p, "# Empty\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "xx.service", /* ret= */ NULL));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "xx.service", &state));
        ASSERT_EQ(state, UNIT_FILE_STATIC);

        /* Initially there's nothing to revert */
        ASSERT_OK(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 0U);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service");
        ASSERT_OK(write_string_file(p, "# Empty override\n", WRITE_STRING_FILE_CREATE));

        /* Revert the override file */
        ASSERT_OK(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p, "# Empty dropin\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        /* Revert the dropin file */
        ASSERT_OK(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service.d");
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Reverting only removes a unit file in /etc/ if there's another copy to fall back to, either below
         * /usr/ or written by a generator. Check that a generated copy counts too, when --root= is specified. */
        p = strjoina(root, "/run/systemd/generator/zz.service");
        ASSERT_OK(write_string_file(p, "# Empty\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/zz.service");
        ASSERT_OK(write_string_file(p, "# Empty override\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_revert(RUNTIME_SCOPE_SYSTEM, root, STRV_MAKE("zz.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1u);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_ERRNO(unlink(strjoina(root, "/run/systemd/generator/zz.service")));
}

TEST(preset_order) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/prefix-1.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/prefix-2.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        ASSERT_OK(write_string_file(p,
                                    "enable prefix-1.service\n"
                                    "disable prefix-*.service\n"
                                    "enable prefix-2.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, STRV_MAKE("prefix-1.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/prefix-1.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/prefix-1.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, STRV_MAKE("prefix-2.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_EQ(n_changes, 0U);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "prefix-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
}

TEST(static_instance) {
        UnitFileState state;
        const char *p;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@foo.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@foo.service");
        ASSERT_OK_ERRNO(symlink("static-instance@.service", p));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "static-instance@foo.service", &state));
        ASSERT_EQ(state, UNIT_FILE_STATIC);
}

TEST(with_dropin) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-3.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4a.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-4a.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "Also=with-dropin-4b.service\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4b.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-1.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-1.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-1.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-1.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-1.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-2.service"), &changes, &n_changes), 1);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        ASSERT_STREQ(changes[1].source, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-2.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-3.service"), &changes, &n_changes), 1);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-3.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-3.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-3.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-3.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-4a.service"), &changes, &n_changes), 2);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-4a.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-4b.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-4a.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-4b.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(with_dropin_template) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1@.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@.service", &state), ENOENT);
        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@.service", &state), ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@instance-1.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-1\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service.d/dropin.conf");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-2\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-1@instance-1.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-1@.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-1@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-1@instance-1.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-1@instance-1.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-2@instance-1.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 2U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_EQ(changes[1].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service");
        ASSERT_STREQ(changes[1].source, "/usr/lib/systemd/system/with-dropin-2@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2@instance-1.service");
        ASSERT_STREQ(changes[0].path, p);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-2@instance-1.service");
        ASSERT_STREQ(changes[1].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-2@instance-2.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2@instance-2.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK_EQ(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("with-dropin-3@.service"), &changes, &n_changes), 1);
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        ASSERT_STREQ(changes[0].source, "/usr/lib/systemd/system/with-dropin-3@.service");
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-3@instance-2.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-1@instance-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@instance-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-2@instance-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@instance-1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "with-dropin-3@instance-2.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(preset_multiple_instances) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        /* Set up template service files and preset file */
        p = strjoina(root, "/usr/lib/systemd/system/foo@.service");
        ASSERT_OK(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        ASSERT_OK(write_string_file(p,
                                    "enable foo@.service bar0 bar1 bartest\n"
                                    "enable emptylist@.service\n" /* This line ensures the old functionality for templated unit still works */
                                    "disable *\n" , WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar0.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        /* Preset a single instantiated unit specified in the list */
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, STRV_MAKE("foo@bar0.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar0.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_SYMLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/foo@bar0.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, root, STRV_MAKE("foo@bar0.service"), &changes, &n_changes));
        ASSERT_EQ(n_changes, 1U);
        ASSERT_EQ(changes[0].type, INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/foo@bar0.service");
        ASSERT_STREQ(changes[0].path, p);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Check for preset-all case, only instances on the list should be enabled, not including the default instance */
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bartest.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);

        ASSERT_OK(unit_file_preset_all(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes));
        ASSERT_GT(n_changes, 0U);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@def.service", &state));
        ASSERT_EQ(state, UNIT_FILE_DISABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar0.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bar1.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, root, "foo@bartest.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);

        install_changes_free(changes, n_changes);
}

TEST(preset_scope) {
        const char *unit, *preset, *link;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* %U can't be resolved in the global scope, since there's no user to resolve it to. Make sure
         * presetting in the global scope fails because of that, instead of resolving specifiers in the
         * system scope (where %U is 0) and creating a target-0.target.wants/ symlink. Check both
         * unit_file_preset() and unit_file_preset_all(), they set up their install contexts separately. */

        unit = strjoina(root, "/usr/lib/systemd/user/scoped.service");
        ASSERT_OK(mkdir_parents(unit, 0755));
        ASSERT_OK(write_string_file(unit,
                                    "[Install]\n"
                                    "WantedBy=target-%U.target\n", WRITE_STRING_FILE_CREATE));

        preset = strjoina(root, "/usr/lib/systemd/user-preset/50-scoped.preset");
        ASSERT_OK(mkdir_parents(preset, 0755));
        ASSERT_OK(write_string_file(preset, "enable scoped.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_ERROR(unit_file_preset(RUNTIME_SCOPE_GLOBAL, /* file_flags= */ 0, root, STRV_MAKE("scoped.service"),
                                      UNIT_FILE_PRESET_FULL, &changes, &n_changes), EUNATCH);
        ASSERT_EQ(n_changes, 1u);
        ASSERT_EQ(changes[0].type, -EUNATCH);
        ASSERT_STREQ(changes[0].path, "target-%U.target");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        link = strjoina(root, USER_CONFIG_UNIT_DIR"/target-0.target.wants/scoped.service");
        ASSERT_ERROR(is_symlink(link), ENOENT);

        ASSERT_ERROR(unit_file_preset_all(RUNTIME_SCOPE_GLOBAL, /* file_flags= */ 0, root, UNIT_FILE_PRESET_FULL,
                                          &changes, &n_changes), EUNATCH);
        ASSERT_EQ(n_changes, 1u);
        ASSERT_EQ(changes[0].type, -EUNATCH);
        ASSERT_STREQ(changes[0].path, "target-%U.target");
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

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

        r = unit_file_verify_alias(i, alias, &alias2, /* changes= */ NULL, /* n_changes= */ NULL);
        log_info_errno(r, "alias %s ← %s: %d/%m (expected %d)%s%s%s",
                       i->name, alias, r, expected,
                       alias2 ? " [" : "", strempty(alias2),
                       alias2 ? "]" : "");
        ASSERT_EQ(r, expected);

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

        verify_one(&plain_service, "alias.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&plain_service, "alias.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "alias@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "alias@inst.service", -EXDEV, /* updated_name= */ NULL);

        /* Setting WantedBy= and RequiredBy= through Alias= is supported for the sake of backwards
         * compatibility. */
        verify_one(&plain_service, "foo.target.wants/plain.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.wants/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.wants/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.wants/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.requires/plain.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.requires/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.requires/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "asdf.requires/plain.service", -EXDEV, /* updated_name= */ NULL); /* invalid unit name component */
        /* The newly-added UpheldBy= (.upholds/) and other suffixes should be rejected */
        verify_one(&plain_service, "foo.target.upholds/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.upholds/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.upholds/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.target.upholds/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&plain_service, "foo.service/plain.service", -EXDEV, /* updated_name= */ NULL); /* missing dir suffix */
        verify_one(&plain_service, "foo.target.conf/plain.service", -EXDEV, /* updated_name= */ NULL);

        verify_one(&bare_template, "alias.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "alias.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "alias@.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "alias@inst.socket", -EXDEV, /* updated_name= */ NULL);
        /* A general alias alias@.service → template1@.service. */
        verify_one(&bare_template, "alias@.service", /* expected= */ 0, /* updated_name= */ NULL);
        /* Only a specific instance is aliased, see the discussion in https://github.com/systemd/systemd/pull/13119. */
        verify_one(&bare_template, "alias@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.wants/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.wants/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.wants/plain@.service", -EXDEV, /* updated_name= */ NULL);
         /* Name mismatch: we cannot allow this, because plain@foo.service would be pulled in by foo.target,
          * but would not be resolvable on its own, since systemd doesn't know how to load the fragment. */
        verify_one(&bare_template, "foo.target.wants/plain@foo.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.wants/template1@foo.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.wants/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.requires/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.requires/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL); /* instance missing */
        verify_one(&bare_template, "foo.target.requires/template1@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.requires/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "foo.target.conf/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "FOO@.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL); /* template name mismatch */
        verify_one(&bare_template, "FOO@inst.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "FOO@inst.target.requires/plain@inst.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&bare_template, "FOO@.target.requires/template1@.service", /* expected= */ 0, /* updated_name= */ NULL); /* instance propagated */
        verify_one(&bare_template, "FOO@inst.target.requires/template1@.service", -EXDEV, /* updated_name= */ NULL); /* instance missing */
        verify_one(&bare_template, "FOO@inst.target.requires/template1@inst.service", /* expected= */ 0, /* updated_name= */ NULL); /* instance provided */

        verify_one(&di_template, "alias.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "alias.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "alias@.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "alias@inst.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "alias@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_template, "alias@.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_template, "alias@di.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.wants/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.wants/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.wants/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.wants/plain@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.wants/template2@di.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.wants/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/plain@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/plain@foo.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/template2@.service", -EXDEV, /* updated_name= */ NULL); /* instance missing */
        verify_one(&di_template, "foo.target.requires/template2@di.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.requires/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_template, "foo.target.conf/plain.service", -EXDEV, /* updated_name= */ NULL);

        verify_one(&inst_template, "alias.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "alias.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "alias@.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "alias@inst.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "alias@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&inst_template, "alias@.service", /* expected= */ 0, "alias@inst.service");
        verify_one(&inst_template, "alias@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/plain@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/plain@inst.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/template3@foo.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/template3@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.wants/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/plain@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/plain@inst.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/template3@foo.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/template3@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.requires/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "bar.target.conf/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "BAR@.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL); /* template name mismatch */
        verify_one(&inst_template, "BAR@inst.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "BAR@inst.target.requires/plain@inst.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&inst_template, "BAR@.target.requires/template3@.service", -EXDEV, /* updated_name= */ NULL); /* instance missing */
        verify_one(&inst_template, "BAR@inst.target.requires/template3@.service", -EXDEV, /* updated_name= */ NULL); /* instance missing */
        verify_one(&inst_template, "BAR@inst.target.requires/template3@inst.service", /* expected= */ 0, /* updated_name= */ NULL); /* instance provided */
        verify_one(&inst_template, "BAR@inst.target.requires/template3@ins2.service", -EXDEV, /* updated_name= */ NULL); /* instance mismatch */

        /* explicit alias overrides DefaultInstance */
        verify_one(&di_inst_template, "alias.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "alias.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "alias@.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "alias@inst.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "alias@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "alias@.service", /* expected= */ 0, "alias@inst.service");
        verify_one(&di_inst_template, "alias@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/plain@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/template4@foo.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/template4@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/template4@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.wants/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain.socket", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain@.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain@di.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/plain@inst.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/template4@foo.service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/template4@inst.service", /* expected= */ 0, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.requires/service", -EXDEV, /* updated_name= */ NULL);
        verify_one(&di_inst_template, "goo.target.conf/plain.service", -EXDEV, /* updated_name= */ NULL);
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

TEST(dependency_mask) {
        const char *entry;

        /* A .wants/, .requires/ or .upholds/ entry that resolves to /dev/null tells PID 1 to ignore the
         * dependency, see process_deps(). Disabling must leave the mask alone, because removing it would
         * enable the unit again. */

        write_vendor_file("system/masked-dep.service", WANTED_BY_MULTI_USER);

        do_enable(/* flags= */ 0, STRV_MAKE("masked-dep.service"));
        assert_state("masked-dep.service", UNIT_FILE_ENABLED);

        entry = strjoina(vendor_root, ETC_WANTS"masked-dep.service");
        ASSERT_TRUE(symlink_exists(entry));

        ASSERT_OK_ERRNO(unlink(entry));
        ASSERT_OK_ERRNO(symlink("/dev/null", entry));
        assert_state("masked-dep.service", UNIT_FILE_DISABLED);

        do_disable(/* flags= */ 0, STRV_MAKE("masked-dep.service"));
        ASSERT_TRUE(is_dependency_mask(entry));
        assert_state("masked-dep.service", UNIT_FILE_DISABLED);
}

TEST(dependency_mask_empty_file) {
        _cleanup_free_ char *dest = NULL;
        const char *entry, *empty;

        /* PID 1 checks dependency entries with null_or_empty_path(), so a symlink to an empty file is a mask
         * just like a symlink to /dev/null. */

        write_vendor_file("system/empty-mask-dep.service", WANTED_BY_MULTI_USER);
        empty = strjoina(vendor_root, "/etc/empty-mask");
        ASSERT_OK(touch(empty));

        do_enable(/* flags= */ 0, STRV_MAKE("empty-mask-dep.service"));

        entry = strjoina(vendor_root, ETC_WANTS"empty-mask-dep.service");
        ASSERT_OK_ERRNO(unlink(entry));
        ASSERT_OK_ERRNO(symlink("/etc/empty-mask", entry));
        assert_state("empty-mask-dep.service", UNIT_FILE_DISABLED);

        do_disable(/* flags= */ 0, STRV_MAKE("empty-mask-dep.service"));
        ASSERT_OK(readlink_malloc(entry, &dest));
        ASSERT_STREQ(dest, "/etc/empty-mask");
        assert_state("empty-mask-dep.service", UNIT_FILE_DISABLED);
}

TEST(disable_dependency_with_non_directory_target) {
        const char *entry;

        write_vendor_file("system/non-dir-dep.service", WANTED_BY_MULTI_USER);
        do_enable(/* flags= */ 0, STRV_MAKE("non-dir-dep.service"));

        entry = strjoina(vendor_root, ETC_WANTS"non-dir-dep.service");
        ASSERT_OK_ERRNO(unlink(entry));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/non-dir-dep.service/child", entry));

        do_disable(/* flags= */ 0, STRV_MAKE("non-dir-dep.service"));
        ASSERT_FALSE(symlink_exists(entry));
}

TEST(disable_template_keeps_instance_mask) {
        const char *mask;

        /* Disabling a template removes the symlinks of its instances. A mask of an instance is not an
         * enablement symlink, so disabling must keep it. */

        write_vendor_file("system/masked-tmpl@.service", WANTED_BY_MULTI_USER);

        mask = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/masked-tmpl@inst.service");
        ASSERT_OK_ERRNO(symlink("/dev/null", mask));
        assert_state("masked-tmpl@inst.service", UNIT_FILE_MASKED);

        do_disable(/* flags= */ 0, STRV_MAKE("masked-tmpl@.service"));
        ASSERT_TRUE(symlink_exists(mask));
        assert_state("masked-tmpl@inst.service", UNIT_FILE_MASKED);
}

TEST(dependency_shadow) {
        const char *shadow;

        /* An entry in a higher priority directory hides the entry with the same name in a lower priority
         * directory. PID 1 ignores the entry in /etc/systemd/system.control/ because it is not a symlink.
         * The symlink in /etc/systemd/system/ is hidden, so it does not pull the unit in either. */

        write_vendor_file("system/shadowed-dep.service", WANTED_BY_MULTI_USER);

        do_enable(/* flags= */ 0, STRV_MAKE("shadowed-dep.service"));
        assert_state("shadowed-dep.service", UNIT_FILE_ENABLED);

        shadow = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR".control/multi-user.target.wants/",
                          "shadowed-dep.service");
        ASSERT_OK(mkdir_parents(shadow, 0755));
        ASSERT_OK(write_string_file(shadow, "# not a symlink", WRITE_STRING_FILE_CREATE));
        assert_state("shadowed-dep.service", UNIT_FILE_DISABLED);
}

TEST(dependency_shadow_symlink) {
        const char *link;

        /* PID 1 adds the dependency from the symlink in /run/systemd/system.control/. The symlink in
         * /etc/systemd/system/ is hidden, but it would add the same dependency, so the unit is enabled. */

        write_vendor_file("system/shadow-linked-dep.service", WANTED_BY_MULTI_USER);

        do_enable(/* flags= */ 0, STRV_MAKE("shadow-linked-dep.service"));

        link = strjoina(vendor_root, "/run/systemd/system.control/multi-user.target.wants/",
                        "shadow-linked-dep.service");
        ASSERT_OK(mkdir_parents(link, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/shadow-linked-dep.service", link));
        assert_state("shadow-linked-dep.service", UNIT_FILE_ENABLED);
}

TEST(dependency_dir_not_directory) {
        const char *file;

        /* PID 1 skips a .wants path that is not a directory and uses the entries in the remaining
         * directories. */

        write_vendor_file("system/file-wants-dep.service",
                          "[Install]\n"
                          "WantedBy=file-wants.target\n");

        do_enable(/* flags= */ 0, STRV_MAKE("file-wants-dep.service"));

        file = strjoina(vendor_root, "/run/systemd/system.control/file-wants.target.wants");
        ASSERT_OK(mkdir_parents(file, 0755));
        ASSERT_OK(write_string_file(file, "# not a directory", WRITE_STRING_FILE_CREATE));
        assert_state("file-wants-dep.service", UNIT_FILE_ENABLED);
}

TEST(dependency_unit_dir_symlink) {
        _cleanup_(rm_rf_physical_and_freep) char *linked_root = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *etc, *real, *unit;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        /* /etc/systemd/system can be a symlink to another directory. PID 1 follows the symlink, so the
         * entries below it enable units like the entries in a plain directory. */

        make_root(&linked_root);

        etc = strjoina(linked_root, SYSTEM_CONFIG_UNIT_DIR);
        real = strjoina(linked_root, SYSTEM_CONFIG_UNIT_DIR"-real");
        ASSERT_OK_ERRNO(rename(etc, real));
        ASSERT_OK_ERRNO(symlink("system-real", etc));

        unit = strjoina(linked_root, "/usr/lib/systemd/system/linked-dir-dep.service");
        ASSERT_OK(write_string_file(unit, WANTED_BY_MULTI_USER, WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, linked_root, STRV_MAKE("linked-dir-dep.service"),
                                   &changes, &n_changes));
        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, linked_root, "linked-dir-dep.service", &state));
        ASSERT_EQ(state, UNIT_FILE_ENABLED);
}

TEST(dependency_mask_shadowed_by_symlink) {
        const char *entry, *link;

        /* PID 1 adds the dependency from the symlink in /run/systemd/system.control/ and ignores the mask
         * in /etc/systemd/system/. The unit is enabled in /run/ only, so its state is enabled-runtime. */

        write_vendor_file("system/mask-shadowed-dep.service", WANTED_BY_MULTI_USER);

        do_enable(/* flags= */ 0, STRV_MAKE("mask-shadowed-dep.service"));

        entry = strjoina(vendor_root, ETC_WANTS"mask-shadowed-dep.service");
        ASSERT_OK_ERRNO(unlink(entry));
        ASSERT_OK_ERRNO(symlink("/dev/null", entry));

        link = strjoina(vendor_root, "/run/systemd/system.control/multi-user.target.wants/",
                        "mask-shadowed-dep.service");
        ASSERT_OK(mkdir_parents(link, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/mask-shadowed-dep.service", link));
        assert_state("mask-shadowed-dep.service", UNIT_FILE_ENABLED_RUNTIME);
}

TEST(dependency_shadow_mask) {
        const char *mask;

        write_vendor_file("system/shadow-masked-dep.service", WANTED_BY_MULTI_USER);

        do_enable(/* flags= */ 0, STRV_MAKE("shadow-masked-dep.service"));
        assert_state("shadow-masked-dep.service", UNIT_FILE_ENABLED);

        /* If the mask in /run/ counted as an enablement symlink, the unit would be enabled-runtime. */
        mask = strjoina(vendor_root, "/run/systemd/system.control/multi-user.target.wants/",
                        "shadow-masked-dep.service");
        ASSERT_OK(mkdir_parents(mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", mask));
        assert_state("shadow-masked-dep.service", UNIT_FILE_DISABLED);
}

TEST(vendor_enable) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *vendor_link, *mask;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        ASSERT_ERROR(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, vendor_root, "vendor-enabled.service", /* ret= */ NULL), ENOENT);

        write_vendor_file("system/vendor-enabled.service", WANTED_BY_MULTI_USER);
        assert_state("vendor-enabled.service", UNIT_FILE_DISABLED);

        /* The vendor enables the unit from /usr/, the way distribution packages ship .wants/ symlinks. PID 1
         * acts on those, so we must report the unit as enabled. */
        write_vendor_symlink("multi-user.target.wants/vendor-enabled.service", "../vendor-enabled.service");
        assert_state("vendor-enabled.service", UNIT_FILE_ENABLED);

        /* Disabling it cannot remove the vendor symlink, so it has to shadow it with a symlink to /dev/null
         * in the configuration directory. */
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, vendor_root,
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
        do_disable(/* flags= */ 0, STRV_MAKE("vendor-enabled.service"));
        ASSERT_TRUE(is_dependency_mask(mask));
        assert_state("vendor-enabled.service", UNIT_FILE_DISABLED);

        /* Enabling drops the mask again. */
        do_enable(/* flags= */ 0, STRV_MAKE("vendor-enabled.service"));
        ASSERT_TRUE(symlink_exists(mask));
        ASSERT_FALSE(is_dependency_mask(mask));
        assert_state("vendor-enabled.service", UNIT_FILE_ENABLED);
}

TEST(vendor_mask_in_unrelated_target) {
        const char *mask;

        /* A dependency mask only shadows the entry of the same name in the same .wants/ directory. Masking
         * the unit out of graphical.target must not make it look disabled when the vendor pulls it into
         * multi-user.target. Enabling leaves that mask alone: disabling never creates a mask in a directory
         * the [Install] section does not name, so it is the administrator's. */

        write_vendor_file("system/vendor-two-targets.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-two-targets.service", "../vendor-two-targets.service");

        mask = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/vendor-two-targets.service");
        ASSERT_OK(mkdir_parents(mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", mask));

        assert_state("vendor-two-targets.service", UNIT_FILE_ENABLED);

        do_disable(/* flags= */ 0, STRV_MAKE("vendor-two-targets.service"));
        assert_state("vendor-two-targets.service", UNIT_FILE_DISABLED);

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-two-targets.service"));
        ASSERT_TRUE(is_dependency_mask(mask));
        assert_state("vendor-two-targets.service", UNIT_FILE_ENABLED);
}

TEST(vendor_preset) {
        const char *vendor_link, *mask;

        write_vendor_file("system/vendor-preset.service", WANTED_BY_MULTI_USER);
        write_vendor_file("system-preset/12-vendor.preset", "enable vendor-preset.service\n");

        do_preset(UNIT_FILE_VENDOR, STRV_MAKE("vendor-preset.service"));

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-preset.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-preset.service");
        ASSERT_TRUE(symlink_exists(vendor_link));
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-preset.service", UNIT_FILE_ENABLED);

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

        do_preset(/* flags= */ 0, STRV_MAKE("vendor-preset-off.service"));

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-preset-off.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-preset-off.service");
        ASSERT_FALSE(symlink_exists(mask));
        ASSERT_TRUE(symlink_exists(vendor_link));
        assert_state("vendor-preset-off.service", UNIT_FILE_ENABLED);

        /* An explicit disable is a different matter. */
        do_disable(/* flags= */ 0, STRV_MAKE("vendor-preset-off.service"));
        ASSERT_TRUE(is_dependency_mask(mask));
        assert_state("vendor-preset-off.service", UNIT_FILE_DISABLED);

        /* And presetting it back to "enable" clears that mask again. */
        write_vendor_file("system-preset/13-vendor-off.preset", "enable vendor-preset-off.service\n");
        do_preset(/* flags= */ 0, STRV_MAKE("vendor-preset-off.service"));

        ASSERT_FALSE(is_dependency_mask(mask));
        assert_state("vendor-preset-off.service", UNIT_FILE_ENABLED);
}

TEST(vendor_not_enableable_is_not_masked) {
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

                do_preset(/* flags= */ 0, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(mask));

                do_disable(/* flags= */ 0, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(mask));

                ASSERT_OK(mkdir_parents(mask, 0755));
                ASSERT_OK_ERRNO(symlink("/dev/null", mask));
                do_enable(/* flags= */ 0, STRV_MAKE(name));
                ASSERT_TRUE(is_dependency_mask(mask));
                ASSERT_OK_ERRNO(unlink(mask));
        }

        assert_state("vendor-static.service", UNIT_FILE_STATIC);

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

TEST(vendor_unresolvable_specifier) {
        const char *link, *wiring;

        write_vendor_file("user/vendor-bad-alias.service",
                          "[Install]\n"
                          "WantedBy=multi-user.target %U-foo.target\n"
                          "Alias=%U-vendor-bad-alias.service\n");

        link = strjoina(vendor_root, USER_DATA_UNIT_DIR"/multi-user.target.wants/vendor-bad-alias.service");
        ASSERT_OK(mkdir_parents(link, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-bad-alias.service", link));

        wiring = strjoina(vendor_root, USER_DATA_UNIT_DIR"/foo.target.wants/vendor-bad-alias.service");
        ASSERT_OK(mkdir_parents(wiring, 0755));
        ASSERT_OK_ERRNO(symlink("../vendor-bad-alias.service", wiring));

        InstallChange *changes = NULL;
        size_t n_changes = 0;
        CLEANUP_ARRAY(changes, n_changes, install_changes_free);
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_GLOBAL, UNIT_FILE_VENDOR, vendor_root,
                                    STRV_MAKE("vendor-bad-alias.service"), &changes, &n_changes));
        ASSERT_FALSE(symlink_exists(link));
        ASSERT_TRUE(symlink_exists(wiring));
}

TEST(vendor_is_reported_unsupported_where_there_is_no_vendor_directory) {
        char **names = STRV_MAKE("vendor-enabled.service");

        InstallChange *changes = NULL;
        size_t n_changes = 0;
        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        ASSERT_ERROR(unit_file_enable(RUNTIME_SCOPE_USER, UNIT_FILE_VENDOR, /* root_dir= */ NULL, names,
                                      &changes, &n_changes), EOPNOTSUPP);
        ASSERT_ERROR(unit_file_disable(RUNTIME_SCOPE_USER, UNIT_FILE_VENDOR, /* root_dir= */ NULL, names,
                                       &changes, &n_changes), EOPNOTSUPP);
        ASSERT_ERROR(unit_file_reenable(RUNTIME_SCOPE_USER, UNIT_FILE_VENDOR, /* root_dir= */ NULL, names,
                                        &changes, &n_changes), EOPNOTSUPP);
        ASSERT_ERROR(unit_file_preset(RUNTIME_SCOPE_USER, UNIT_FILE_VENDOR, /* root_dir= */ NULL, names,
                                      UNIT_FILE_PRESET_FULL, &changes, &n_changes), EOPNOTSUPP);
        ASSERT_ERROR(unit_file_preset_all(RUNTIME_SCOPE_USER, UNIT_FILE_VENDOR, /* root_dir= */ NULL,
                                          UNIT_FILE_PRESET_FULL, &changes, &n_changes), EOPNOTSUPP);

        ASSERT_ERROR(unit_file_mask(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, vendor_root, names,
                                    &changes, &n_changes), EOPNOTSUPP);
        ASSERT_ERROR(unit_file_unmask(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, vendor_root, names,
                                      &changes, &n_changes), EOPNOTSUPP);
}

TEST(vendor_symlinked_dependency_dir_is_not_followed) {
        /* A dependency directory that is itself a symlink is not entered. An absolute one would resolve
         * against the host rather than against --root=, which would have us report on and mask in the
         * host's unit tree while operating on an image. */

        write_vendor_file("system/vendor-escape.service", WANTED_BY_MULTI_USER);

        /* The entry lives in a directory whose own name is not a dependency directory name, so it is only
         * ever reachable through the symlink. */
        write_vendor_symlink("stash/vendor-escape.service", "../vendor-escape.service");
        ASSERT_OK_ERRNO(symlink("stash", strjoina(vendor_root, "/usr/lib/systemd/system/escape.target.wants")));

        assert_state("vendor-escape.service", UNIT_FILE_DISABLED);

        do_disable(/* flags= */ 0, STRV_MAKE("vendor-escape.service"));
        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/escape.target.wants/vendor-escape.service")));
}

TEST(vendor_preset_all) {
        const char *vendor_link, *mask;

        write_vendor_file("system/vendor-all.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-all.service", "../vendor-all.service");
        write_vendor_file("system-preset/11-vendor-all.preset", "disable vendor-all.service\n");

        do_preset_all(/* flags= */ 0);

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-all.service");
        mask = strjoina(vendor_root, ETC_WANTS"vendor-all.service");
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-all.service", UNIT_FILE_ENABLED);

        do_preset_all(UNIT_FILE_VENDOR);
        ASSERT_FALSE(symlink_exists(vendor_link));
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-all.service", UNIT_FILE_DISABLED);

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
                _cleanup_free_ char *name = NULL, *rel = NULL, *mask = NULL, *unit = NULL;

                ASSERT_NOT_NULL(name = strjoin("vendor-", suffix, ".service"));
                ASSERT_NOT_NULL(rel = strjoin("multi-user.target.", suffix, "/", name));
                ASSERT_NOT_NULL(mask = strjoin(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.",
                                               suffix, "/", name));
                ASSERT_NOT_NULL(unit = strjoin("[Install]\n",
                                               streq(suffix, "requires") ? "RequiredBy" : "UpheldBy",
                                               "=multi-user.target\n"));

                write_vendor_file(strjoina("system/", name), unit);
                write_vendor_symlink(rel, strjoina("../", name));
                assert_state(name, UNIT_FILE_ENABLED);

                do_disable(/* flags= */ 0, STRV_MAKE(name));
                ASSERT_TRUE(is_dependency_mask(mask));
                assert_state(name, UNIT_FILE_DISABLED);

                do_enable(/* flags= */ 0, STRV_MAKE(name));
                ASSERT_FALSE(is_dependency_mask(mask));
                assert_state(name, UNIT_FILE_ENABLED);
        }
}

TEST(vendor_template_specifier) {
        write_vendor_file("system/vendor-spec@.service",
                          "[Install]\n"
                          "DefaultInstance=dflt\n"
                          "WantedBy=vendor-%i.target\n");
        write_vendor_symlink("vendor-inst.target.wants/vendor-spec@inst.service", "../vendor-spec@.service");
        write_vendor_symlink("vendor-dflt.target.wants/vendor-spec@dflt.service", "../vendor-spec@.service");

        assert_state("vendor-spec@.service", UNIT_FILE_ENABLED);
        assert_state("vendor-spec@inst.service", UNIT_FILE_ENABLED);
        assert_state("vendor-spec@dflt.service", UNIT_FILE_ENABLED);

        write_vendor_symlink("vendor-wrong.target.wants/vendor-spec@wrong-instance.service", "../vendor-spec@.service");
        assert_state("vendor-spec@wrong-instance.service", UNIT_FILE_STATIC);
}

TEST(vendor_template_instance) {
        const char *mask;

        /* Disabling a template has to mask the vendor's instance symlinks, the same way removal takes away
         * the configured ones. Enabling the template only creates the symlink of the default instance, so
         * the masks of the other instances have to be removed separately. */

        write_vendor_file("system/vendor-tmpl@.service",
                          "[Install]\n"
                          "DefaultInstance=dflt\n"
                          "WantedBy=multi-user.target\n");
        write_vendor_symlink("multi-user.target.wants/vendor-tmpl@inst.service", "../vendor-tmpl@.service");

        assert_state("vendor-tmpl@inst.service", UNIT_FILE_ENABLED);

        /* Disabling the template must reach the instance the vendor wired up. */
        do_disable(/* flags= */ 0, STRV_MAKE("vendor-tmpl@.service"));

        mask = strjoina(vendor_root, ETC_WANTS"vendor-tmpl@inst.service");
        ASSERT_TRUE(is_dependency_mask(mask));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, VENDOR_WANTS"vendor-tmpl@inst.service")));
        assert_state("vendor-tmpl@inst.service", UNIT_FILE_DISABLED);

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-tmpl@.service"));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, ETC_WANTS"vendor-tmpl@dflt.service")));
        ASSERT_FALSE(symlink_exists(mask));
        assert_state("vendor-tmpl@inst.service", UNIT_FILE_ENABLED);
}

TEST(vendor_also) {
        const char *mask;

        /* Disabling has to mask the vendor symlinks of the Also= units too, and enabling has to clear them
         * again. Those units are only discovered while the symlinks are being applied. */

        write_vendor_file("system/vendor-also.service",
                          "[Install]\n"
                          "WantedBy=multi-user.target\n"
                          "Also=vendor-also.socket\n");
        write_vendor_file("system/vendor-also.socket",
                          "[Install]\n"
                          "WantedBy=sockets.target\n");
        write_vendor_symlink("sockets.target.wants/vendor-also.socket", "../vendor-also.socket");

        do_disable(/* flags= */ 0, STRV_MAKE("vendor-also.service"));

        mask = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/sockets.target.wants/vendor-also.socket");
        ASSERT_TRUE(is_dependency_mask(mask));
        assert_state("vendor-also.socket", UNIT_FILE_DISABLED);

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-also.service"));
        ASSERT_FALSE(is_dependency_mask(mask));
        assert_state("vendor-also.socket", UNIT_FILE_ENABLED);
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

        do_disable(/* flags= */ 0, STRV_MAKE("vendor-shadow.service"));

        mask = strjoina(vendor_root, ETC_WANTS"vendor-shadow.service");
        ASSERT_FALSE(symlink_exists(mask));
}

TEST(vendor_multiple_units) {
        /* Disabling and enabling several units at once, each with a symlink in two targets, must go
         * through every unit and every mask rather than stop at the first. */

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service") {
                write_vendor_file(strjoina("system/", name),
                                  "[Install]\n"
                                  "WantedBy=multi-user.target graphical.target\n");

                FOREACH_STRING(target, "multi-user.target", "graphical.target")
                        write_vendor_symlink(strjoina(target, ".wants/", name), strjoina("../", name));
        }

        do_disable(/* flags= */ 0, STRV_MAKE("vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service"));

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service")
                FOREACH_STRING(target, "multi-user.target", "graphical.target")
                        ASSERT_TRUE(is_dependency_mask(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/", target,
                                                                ".wants/", name)));

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service"));

        FOREACH_STRING(name, "vendor-multi-a.service", "vendor-multi-b.service", "vendor-multi-c.service")
                FOREACH_STRING(target, "multi-user.target", "graphical.target")
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
                do_disable(/* flags= */ 0, STRV_MAKE("vendor-kinds.service"));
                ASSERT_OK(read_full_file(entry, &back, /* ret_size= */ NULL));
                ASSERT_STREQ(back, contents);

                ASSERT_OK_ERRNO(unlink(entry));
        }

        ASSERT_OK_ERRNO(mkdir(entry, 0755));
        assert_state("vendor-kinds.service", UNIT_FILE_DISABLED);

        /* Replacing this one would fail outright rather than quietly. */
        do_disable(/* flags= */ 0, STRV_MAKE("vendor-kinds.service"));
        ASSERT_OK_ERRNO(rmdir(entry));
}

TEST(vendor_static_dependency) {
        /* systemd installs remote-cryptsetup.target in initrd-root-device.target.wants/, while its [Install]
         * section has WantedBy=multi-user.target. Only a symlink that enabling would create enables the
         * unit. A symlink in a directory the [Install] section does not name, or with a suffix it does not
         * ask for, is a static dependency. */

        write_vendor_file("system/vendor-static-dep.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("initrd-root-device.target.wants/vendor-static-dep.service", "../vendor-static-dep.service");
        write_vendor_symlink("multi-user.target.requires/vendor-static-dep.service", "../vendor-static-dep.service");
        assert_state("vendor-static-dep.service", UNIT_FILE_DISABLED);

        write_vendor_symlink("multi-user.target.wants/vendor-static-dep.service", "../vendor-static-dep.service");
        assert_state("vendor-static-dep.service", UNIT_FILE_ENABLED);

        /* Disabling masks the symlink that enables the unit and leaves the static dependency symlinks alone. */
        do_disable(/* flags= */ 0, STRV_MAKE("vendor-static-dep.service"));
        ASSERT_TRUE(is_dependency_mask(strjoina(vendor_root, ETC_WANTS"vendor-static-dep.service")));
        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/initrd-root-device.target.wants/vendor-static-dep.service")));
        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.requires/vendor-static-dep.service")));
        assert_state("vendor-static-dep.service", UNIT_FILE_DISABLED);

        /* An instance with a static dependency symlink reports as "static", like an instance with an alias
         * symlink below /usr/ does. */
        write_vendor_file("system/vendor-static-dep@.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("initrd-root-device.target.wants/vendor-static-dep@a.service", "../vendor-static-dep@.service");
        assert_state("vendor-static-dep@a.service", UNIT_FILE_STATIC);

        write_vendor_symlink("multi-user.target.wants/vendor-static-dep@b.service", "../vendor-static-dep@.service");
        assert_state("vendor-static-dep@b.service", UNIT_FILE_ENABLED);

        do_disable(/* flags= */ 0, STRV_MAKE("vendor-static-dep@.service"));
        ASSERT_TRUE(is_dependency_mask(strjoina(vendor_root, ETC_WANTS"vendor-static-dep@b.service")));
        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/initrd-root-device.target.wants/vendor-static-dep@a.service")));
        assert_state("vendor-static-dep@a.service", UNIT_FILE_STATIC);
        assert_state("vendor-static-dep@b.service", UNIT_FILE_DISABLED);
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

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-aux.socket"));
        assert_state("vendor-aux.socket", UNIT_FILE_ENABLED);

        do_preset(/* flags= */ 0, STRV_MAKE("vendor-main.service"));
        assert_state("vendor-main.service", UNIT_FILE_DISABLED);
        assert_state("vendor-aux.socket", UNIT_FILE_ENABLED);

        do_preset_all(/* flags= */ 0);
        assert_state("vendor-main.service", UNIT_FILE_DISABLED);
        assert_state("vendor-aux.socket", UNIT_FILE_ENABLED);
}
TEST(vendor_keeps_symlinks_it_was_not_asked_for) {
        const char *compat, *slot, *wiring;

        write_vendor_file("system/vendor-named.service",
                          "[Install]\n"
                          "Alias=vendor-named-slot.service\n"
                          "WantedBy=multi-user.target\n");

        write_vendor_symlink("vendor-named-compat.service", "vendor-named.service");
        write_vendor_symlink("vendor-named-slot.service", "vendor-named.service");
        write_vendor_symlink("multi-user.target.wants/vendor-named.service", "../vendor-named.service");
        write_vendor_file("system-preset/19-vendor-named.preset", "disable vendor-named.service\n");

        do_preset(UNIT_FILE_VENDOR, STRV_MAKE("vendor-named.service"));

        compat = strjoina(vendor_root, "/usr/lib/systemd/system/vendor-named-compat.service");
        slot = strjoina(vendor_root, "/usr/lib/systemd/system/vendor-named-slot.service");
        wiring = strjoina(vendor_root, VENDOR_WANTS"vendor-named.service");
        ASSERT_FALSE(symlink_exists(wiring));
        ASSERT_TRUE(symlink_exists(compat));
        ASSERT_TRUE(symlink_exists(slot));

        do_disable(UNIT_FILE_VENDOR, STRV_MAKE("vendor-named.service"));
        ASSERT_TRUE(symlink_exists(compat));
        ASSERT_FALSE(symlink_exists(slot));

        write_vendor_file("system/vendor-unnamed.service",
                          "[Unit]\n"
                          "Description=no Install section\n");
        write_vendor_symlink("vendor-unnamed-compat.service", "vendor-unnamed.service");

        do_disable(UNIT_FILE_VENDOR, STRV_MAKE("vendor-unnamed.service"));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, "/usr/lib/systemd/system/vendor-unnamed-compat.service")));
}

TEST(vendor_keeps_static_alias_dependencies) {
        FOREACH_STRING(suffix, "wants", "requires", "upholds") {
                const char *name = strjoina("vendor-static-name-", suffix, ".service");
                const char *alias = strjoina("vendor-static-compat-", suffix, ".service");
                const char *directory = strjoina("multi-user.target.", suffix, "/");
                const char *entry = strjoina(vendor_root, SYSTEM_DATA_UNIT_DIR"/", directory, alias);
                const char *enablement = strjoina(vendor_root, SYSTEM_DATA_UNIT_DIR"/", directory, name);
                const char *key = streq(suffix, "wants") ? "WantedBy" :
                                  streq(suffix, "requires") ? "RequiredBy" : "UpheldBy";

                write_vendor_file(strjoina("system/", name), strjoina("[Install]\n", key, "=multi-user.target\n"));
                write_vendor_file(strjoina("system-preset/18-", name, ".preset"), strjoina("disable ", name, "\n"));
                write_vendor_symlink(alias, name);
                write_vendor_symlink(strjoina(directory, alias), strjoina("../", alias));

                do_enable(UNIT_FILE_VENDOR, STRV_MAKE(name));
                ASSERT_TRUE(symlink_exists(enablement));
                do_disable(UNIT_FILE_VENDOR, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(enablement));
                ASSERT_TRUE(symlink_exists(entry));

                do_enable(UNIT_FILE_VENDOR, STRV_MAKE(name));
                do_preset(UNIT_FILE_VENDOR, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(enablement));
                ASSERT_TRUE(symlink_exists(entry));
        }
}

TEST(vendor_directory_symlink_stays_inside_root) {
        _cleanup_(rm_rf_physical_and_freep) char *image = NULL, *outside = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *unit, *vendor, *inside, *dependency, *static_dependency;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-image-XXXXXX", &image));
        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-outside-XXXXXX", &outside));
        unit = strjoina(image, SYSTEM_CONFIG_UNIT_DIR"/contained.service");
        ASSERT_OK(mkdir_parents(unit, 0755));
        ASSERT_OK(write_string_file(unit, WANTED_BY_MULTI_USER, WRITE_STRING_FILE_CREATE));

        vendor = strjoina(image, SYSTEM_DATA_UNIT_DIR);
        ASSERT_OK(mkdir_parents(vendor, 0755));
        ASSERT_OK_ERRNO(symlink(outside, vendor));
        inside = strjoina(image, outside);
        dependency = strjoina(inside, "/multi-user.target.wants/contained.service");

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                   STRV_MAKE("contained.service"), &changes, &n_changes));
        ASSERT_TRUE(symlink_exists(dependency));
        ASSERT_FALSE(symlink_exists(strjoina(outside, "/multi-user.target.wants/contained.service")));

        static_dependency = strjoina(inside, "/initrd-root-device.target.wants/contained.service");
        ASSERT_OK(mkdir_parents(static_dependency, 0755));
        ASSERT_OK_ERRNO(symlink(SYSTEM_CONFIG_UNIT_DIR"/contained.service", static_dependency));

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                    STRV_MAKE("contained.service"), &changes, &n_changes));
        ASSERT_FALSE(symlink_exists(dependency));
        ASSERT_TRUE(symlink_exists(static_dependency));
}

TEST(vendor_dependency_directory_symlink_stays_inside_root) {
        _cleanup_(rm_rf_physical_and_freep) char *image = NULL, *outside = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-image-XXXXXX", &image));
        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-outside-XXXXXX", &outside));

        const char *unit = strjoina(image, SYSTEM_CONFIG_UNIT_DIR"/contained.service");
        ASSERT_OK(mkdir_parents(unit, 0755));
        ASSERT_OK(write_string_file(unit, WANTED_BY_MULTI_USER, WRITE_STRING_FILE_CREATE));

        const char *directory = strjoina(image, SYSTEM_DATA_UNIT_DIR"/multi-user.target.wants");
        ASSERT_OK(mkdir_parents(directory, 0755));
        ASSERT_OK_ERRNO(symlink(outside, directory));
        ASSERT_OK_ERRNO(symlink(".", strjoina(image, SYSTEM_DATA_UNIT_DIR"/cycle.target.wants")));
        ASSERT_OK_ERRNO(symlink("loop.target.wants", strjoina(image, SYSTEM_DATA_UNIT_DIR"/loop.target.wants")));

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                   STRV_MAKE("contained.service"), &changes, &n_changes));
        ASSERT_TRUE(symlink_exists(strjoina(image, outside, "/contained.service")));
        ASSERT_FALSE(symlink_exists(strjoina(outside, "/contained.service")));

        const char *entry = strjoina(image, outside, "/contained.service");
        const char *static_entry = strjoina(image, outside, "/compat.service");
        const char *host_entry = strjoina(outside, "/contained.service");
        ASSERT_OK_ERRNO(symlink("/dev/null", host_entry));
        ASSERT_OK_ERRNO(symlink(SYSTEM_CONFIG_UNIT_DIR"/contained.service", static_entry));

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                    STRV_MAKE("contained.service"), &changes, &n_changes));
        ASSERT_FALSE(symlink_exists(entry));
        ASSERT_TRUE(symlink_exists(static_entry));
        ASSERT_TRUE(symlink_exists(host_entry));

        const char *preset = strjoina(image, "/usr/lib/systemd/system-preset/00-contained.preset");
        ASSERT_OK(mkdir_parents(preset, 0755));
        ASSERT_OK(write_string_file(preset, "disable contained.service\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                   STRV_MAKE("contained.service"), &changes, &n_changes));
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                   STRV_MAKE("contained.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        ASSERT_FALSE(symlink_exists(entry));
        ASSERT_TRUE(symlink_exists(static_entry));
        ASSERT_TRUE(symlink_exists(host_entry));
}

TEST(vendor_legacy_alias_dependency) {
        FOREACH_STRING(suffix, "wants", "requires") {
                const char *name = strjoina("vendor-legacy-", suffix, ".service");
                const char *rel = strjoina("multi-user.target.", suffix, "/", name);
                const char *entry = strjoina(vendor_root, SYSTEM_DATA_UNIT_DIR"/", rel);

                write_vendor_file(strjoina("system/", name), strjoina("[Install]\nAlias=", rel, "\n"));
                do_enable(UNIT_FILE_VENDOR, STRV_MAKE(name));
                ASSERT_TRUE(symlink_exists(entry));
                assert_state(name, UNIT_FILE_ENABLED);

                do_disable(UNIT_FILE_VENDOR, STRV_MAKE(name));
                ASSERT_FALSE(symlink_exists(entry));
                assert_state(name, UNIT_FILE_DISABLED);
        }
}

TEST(vendor_disable_removes_linked_unit) {
        const char *unit, *link, *alias;

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

        write_vendor_file("system/vendor-redundant.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-redundant.service", "../vendor-redundant.service");
        write_vendor_file("system-preset/15-vendor-redundant.preset", "enable vendor-redundant.service\n");

        vendor_link = strjoina(vendor_root, VENDOR_WANTS"vendor-redundant.service");
        etc_link = strjoina(vendor_root, ETC_WANTS"vendor-redundant.service");

        do_preset(/* flags= */ 0, STRV_MAKE("vendor-redundant.service"));
        ASSERT_FALSE(symlink_exists(etc_link));
        assert_state("vendor-redundant.service", UNIT_FILE_ENABLED);

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-redundant.service"));
        ASSERT_TRUE(symlink_exists(etc_link));

        ASSERT_OK_ERRNO(unlink(vendor_link));
        assert_state("vendor-redundant.service", UNIT_FILE_ENABLED);
}

TEST(vendor_preset_relocated_directory) {
        _cleanup_(rm_rf_physical_and_freep) char *image = NULL;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-relocated-XXXXXX", &image));

        const char *unit = strjoina(image, "/opt/units/relocated.service");
        ASSERT_OK(mkdir_parents(unit, 0755));
        ASSERT_OK(write_string_file(unit, WANTED_BY_MULTI_USER, WRITE_STRING_FILE_CREATE));
        const char *vendor = strjoina(image, SYSTEM_DATA_UNIT_DIR);
        ASSERT_OK(mkdir_parents(vendor, 0755));
        ASSERT_OK_ERRNO(symlink("../../../opt/units", vendor));
        const char *preset = strjoina(image, "/usr/lib/systemd/system-preset/00-relocated.preset");
        ASSERT_OK(mkdir_parents(preset, 0755));
        ASSERT_OK(write_string_file(preset, "enable relocated.service\n", WRITE_STRING_FILE_CREATE));

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_VENDOR, image,
                                   STRV_MAKE("relocated.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        ASSERT_TRUE(symlink_exists(strjoina(image, "/opt/units/multi-user.target.wants/relocated.service")));

        const char *entry = strjoina(image, ETC_WANTS"relocated.service");
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, image,
                                   STRV_MAKE("relocated.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        ASSERT_FALSE(symlink_exists(entry));

        const char *local = strjoina(image, "/usr/local/lib/systemd/system/multi-user.target.wants");
        ASSERT_OK(mkdir_parents(local, 0755));
        ASSERT_OK_ERRNO(symlink("/opt/units/multi-user.target.wants", local));
        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, image,
                                   STRV_MAKE("relocated.service"), UNIT_FILE_PRESET_FULL,
                                   &changes, &n_changes));
        ASSERT_TRUE(symlink_exists(entry));
}

TEST(vendor_preset_relocated_dependency_directory) {
        FOREACH_STRING(suffix, "wants", "requires", "upholds")
                FOREACH_STRING(link_type, "absolute", "relative") {
                        _cleanup_(rm_rf_physical_and_freep) char *image = NULL, *outside = NULL;
                        InstallChange *changes = NULL;
                        size_t n_changes = 0;
                        UnitFileState state;

                        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-preset-image-XXXXXX", &image));
                        ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-preset-outside-XXXXXX", &outside));

                        const char *key = streq(suffix, "wants") ? "WantedBy" :
                                          streq(suffix, "requires") ? "RequiredBy" : "UpheldBy";
                        const char *unit = strjoina(image, SYSTEM_DATA_UNIT_DIR"/relocated.service");
                        ASSERT_OK(mkdir_parents(unit, 0755));
                        ASSERT_OK(write_string_file(unit, strjoina("[Install]\n", key, "=multi-user.target\n"),
                                                    WRITE_STRING_FILE_CREATE));
                        const char *preset = strjoina(image, "/usr/lib/systemd/system-preset/00-relocated.preset");
                        ASSERT_OK(mkdir_parents(preset, 0755));
                        ASSERT_OK(write_string_file(preset, "enable relocated.service\n", WRITE_STRING_FILE_CREATE));

                        const char *vendor_entry = strjoina(image, SYSTEM_DATA_UNIT_DIR"/multi-user.target.",
                                                           suffix, "/relocated.service");
                        ASSERT_OK(mkdir_parents(vendor_entry, 0755));
                        ASSERT_OK_ERRNO(symlink("../relocated.service", vendor_entry));

                        const char *directory = strjoina(image, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.", suffix);
                        ASSERT_OK(mkdir_parents(directory, 0755));
                        ASSERT_OK_ERRNO(symlink(streq(link_type, "absolute") ? outside : strjoina("../../..", outside),
                                               directory));
                        const char *entry = strjoina(image, outside, "/relocated.service");
                        ASSERT_OK(mkdir_parents(entry, 0755));
                        ASSERT_OK(write_string_file(entry, "not a mask\n", WRITE_STRING_FILE_CREATE));
                        ASSERT_ERROR(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_FORCE, image,
                                                      STRV_MAKE("relocated.service"), UNIT_FILE_PRESET_FULL,
                                                      &changes, &n_changes), EEXIST);
                        ASSERT_OK_ERRNO(unlink(entry));

                        const char *host_entry = strjoina(outside, "/relocated.service");
                        const char *unrelated = strjoina(image, outside, "/unrelated.service");
                        ASSERT_OK_ERRNO(symlink("/dev/null", host_entry));
                        ASSERT_OK_ERRNO(symlink("/dev/null", unrelated));

                        FOREACH_STRING(mask_type, "symlink", "empty-file") {
                                if (streq(mask_type, "symlink"))
                                        ASSERT_OK_ERRNO(symlink("/dev/null", entry));
                                else
                                        ASSERT_OK(write_string_file(entry, "", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));

                                ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, /* file_flags= */ 0, image,
                                                           STRV_MAKE("relocated.service"), UNIT_FILE_PRESET_FULL,
                                                           &changes, &n_changes));
                                ASSERT_ERROR(access_nofollow(entry, F_OK), ENOENT);
                                ASSERT_TRUE(symlink_exists(host_entry));
                                ASSERT_TRUE(symlink_exists(unrelated));
                                ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, image, "relocated.service", &state));
                                ASSERT_EQ(state, UNIT_FILE_ENABLED);
                        }
                }
}

TEST(vendor_preset_still_writes_what_is_needed) {
        write_vendor_file("system/vendor-partial.service",
                          "[Install]\n"
                          "WantedBy=multi-user.target\n"
                          "WantedBy=graphical.target\n"
                          "WantedBy=sockets.target\n"
                          "WantedBy=timers.target\n"
                          "WantedBy=paths.target\n");

        write_vendor_symlink("multi-user.target.wants/vendor-partial.service", "../vendor-partial.service");

        const char *runtime_link = strjoina(vendor_root, "/run/systemd/system/sockets.target.wants/vendor-partial.service");
        ASSERT_OK(mkdir_parents(runtime_link, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-partial.service", runtime_link));

        write_vendor_symlink("timers.target.wants/vendor-partial.service", "../vendor-partial.service");
        const char *vendor_mask = strjoina(vendor_root, "/usr/local/lib/systemd/system/timers.target.wants/vendor-partial.service");
        ASSERT_OK(mkdir_parents(vendor_mask, 0755));
        ASSERT_OK_ERRNO(symlink("/dev/null", vendor_mask));

        const char *local_link = strjoina(vendor_root, "/usr/local/lib/systemd/system/paths.target.wants/vendor-partial.service");
        ASSERT_OK(mkdir_parents(local_link, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-partial.service", local_link));

        write_vendor_file("system-preset/16-vendor-partial.preset", "enable vendor-partial.service\n");
        do_preset(/* flags= */ 0, STRV_MAKE("vendor-partial.service"));

        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, ETC_WANTS"vendor-partial.service")));

        FOREACH_STRING(target, "graphical.target", "sockets.target", "timers.target", "paths.target") {
                const char *p = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/", target, ".wants/vendor-partial.service");

                ASSERT_TRUE(symlink_exists(p));
                ASSERT_FALSE(is_dependency_mask(p));
        }
}

TEST(vendor_preset_skips_redundant_alias) {
        write_vendor_file("system/vendor-aliased.service",
                          "[Install]\n"
                          "Alias=vendor-aliased-name.service\n"
                          "Alias=vendor-aliased-taken.service\n"
                          "Alias=vendor-aliased-transient.service\n");
        write_vendor_file("system/vendor-aliased-other.service", "[Install]\n");
        write_vendor_symlink("vendor-aliased-name.service", "vendor-aliased.service");
        write_vendor_symlink("vendor-aliased-taken.service", "vendor-aliased-other.service");

        const char *runtime_alias = strjoina(vendor_root, "/run/systemd/system/vendor-aliased-transient.service");
        ASSERT_OK(mkdir_parents(runtime_alias, 0755));
        ASSERT_OK_ERRNO(symlink("/usr/lib/systemd/system/vendor-aliased.service", runtime_alias));

        write_vendor_file("system-preset/21-vendor-aliased.preset", "enable vendor-aliased.service\n");
        do_preset(/* flags= */ 0, STRV_MAKE("vendor-aliased.service"));

        ASSERT_FALSE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-name.service")));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-taken.service")));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-transient.service")));

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-aliased.service"));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-aliased-name.service")));
}

TEST(vendor_preset_relocated_alias_directory) {
        FOREACH_STRING(directory, SYSTEM_CONFIG_UNIT_DIR, "/usr/local/lib/systemd/system") {
                _cleanup_(rm_rf_physical_and_freep) char *image = NULL, *outside = NULL;
                InstallChange *changes = NULL;
                size_t n_changes = 0;

                CLEANUP_ARRAY(changes, n_changes, install_changes_free);

                ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-alias-image-XXXXXX", &image));
                ASSERT_OK(mkdtemp_malloc("/var/tmp/vendor-alias-outside-XXXXXX", &outside));

                const char *unit = strjoina(image, SYSTEM_DATA_UNIT_DIR"/relocated.service");
                ASSERT_OK(mkdir_parents(unit, 0755));
                ASSERT_OK(write_string_file(unit, "[Install]\nAlias=relocated-name.service\n", WRITE_STRING_FILE_CREATE));
                ASSERT_OK(write_string_file(strjoina(image, SYSTEM_DATA_UNIT_DIR"/other.service"),
                                            "[Service]\nExecStart=/bin/true\n", WRITE_STRING_FILE_CREATE));
                ASSERT_OK_ERRNO(symlink("relocated.service", strjoina(image, SYSTEM_DATA_UNIT_DIR"/relocated-name.service")));
                const char *preset = strjoina(image, "/usr/lib/systemd/system-preset/00-relocated.preset");
                ASSERT_OK(mkdir_parents(preset, 0755));
                ASSERT_OK(write_string_file(preset, "enable relocated.service\n", WRITE_STRING_FILE_CREATE));

                const char *lookup = strjoina(image, directory);
                ASSERT_OK(mkdir_parents(lookup, 0755));
                ASSERT_OK_ERRNO(symlink(outside, lookup));
                const char *override = strjoina(image, outside, "/relocated-name.service");
                ASSERT_OK(mkdir_parents(override, 0755));
                const char *alias = path_equal(directory, SYSTEM_CONFIG_UNIT_DIR) ? override :
                                    strjoina(image, SYSTEM_CONFIG_UNIT_DIR"/relocated-name.service");

                FOREACH_STRING(target, "missing.service", SYSTEM_DATA_UNIT_DIR"/other.service") {
                        _cleanup_free_ char *dest = NULL;

                        ASSERT_OK_ERRNO(symlink(target, override));
                        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_FORCE, image,
                                                   STRV_MAKE("relocated.service"), UNIT_FILE_PRESET_FULL,
                                                   &changes, &n_changes));
                        ASSERT_OK(readlink_malloc(alias, &dest));
                        ASSERT_STREQ(dest, SYSTEM_DATA_UNIT_DIR"/relocated.service");
                        ASSERT_FALSE(symlink_exists(strjoina(outside, "/relocated-name.service")));
                        ASSERT_OK_ERRNO(unlink(alias));
                        if (!path_equal(alias, override))
                                ASSERT_OK_ERRNO(unlink(override));
                }
        }
}

TEST(vendor_preset_template_alias) {
        write_vendor_file("system/vendor-alias-template@.service",
                          "[Install]\nAlias=vendor-alias-instance@.service vendor-alias-conflicting@.service\n");
        write_vendor_file("system-preset/20-vendor-template-alias.preset",
                          "enable vendor-alias-template@.service one\n");
        do_preset(UNIT_FILE_VENDOR, STRV_MAKE("vendor-alias-template@.service"));

        const char *vendor_alias = strjoina(vendor_root, SYSTEM_DATA_UNIT_DIR"/vendor-alias-instance@one.service");
        const char *local_alias = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-alias-instance@one.service");
        _cleanup_free_ char *dest = NULL;

        ASSERT_OK(readlink_malloc(vendor_alias, &dest));
        ASSERT_STREQ(dest, SYSTEM_DATA_UNIT_DIR"/vendor-alias-template@.service");

        const char *conflicting = strjoina(vendor_root, SYSTEM_DATA_UNIT_DIR"/vendor-alias-conflicting@one.service");
        ASSERT_OK_ERRNO(unlink(conflicting));
        ASSERT_OK_ERRNO(symlink("vendor-alias-template@two.service", conflicting));
        write_vendor_symlink("vendor-alias-template@two.service", "vendor-alias-template@.service");

        do_preset(/* flags= */ 0, STRV_MAKE("vendor-alias-template@.service"));
        ASSERT_FALSE(symlink_exists(local_alias));
        ASSERT_TRUE(symlink_exists(strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-alias-conflicting@one.service")));

        do_enable(/* flags= */ 0, STRV_MAKE("vendor-alias-template@one.service"));
        ASSERT_TRUE(symlink_exists(local_alias));
}

TEST(vendor_preset_updates_shadowed_alias) {
        const char *alias;

        write_vendor_file("system/vendor-shadowed-alias.service",
                          "[Install]\n"
                          "Alias=vendor-shadowed-name.service\n");
        write_vendor_file("system/vendor-shadowed-other.service", "[Install]\n");
        write_vendor_symlink("vendor-shadowed-name.service", "vendor-shadowed-alias.service");
        write_vendor_file("system-preset/22-vendor-shadowed-alias.preset", "enable vendor-shadowed-alias.service\n");

        alias = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-shadowed-name.service");
        FOREACH_STRING(target, "missing.service", "/usr/lib/systemd/system/vendor-shadowed-other.service") {
                _cleanup_free_ char *dest = NULL;

                ASSERT_OK_ERRNO(symlink(target, alias));
                do_preset(streq(target, "missing.service") ? 0 : UNIT_FILE_FORCE,
                          STRV_MAKE("vendor-shadowed-alias.service"));
                ASSERT_OK(readlink_malloc(alias, &dest));
                ASSERT_STREQ(dest, "/usr/lib/systemd/system/vendor-shadowed-alias.service");
                ASSERT_OK_ERRNO(unlink(alias));
        }
}

TEST(vendor_preset_rejects_local_obstruction) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *entry;

        CLEANUP_ARRAY(changes, n_changes, install_changes_free);

        write_vendor_file("system/vendor-obstructed.service", WANTED_BY_MULTI_USER);
        write_vendor_symlink("multi-user.target.wants/vendor-obstructed.service", "../vendor-obstructed.service");
        write_vendor_file("system-preset/23-vendor-obstructed.preset", "enable vendor-obstructed.service\n");
        entry = strjoina(vendor_root, ETC_WANTS"vendor-obstructed.service");
        ASSERT_OK(mkdir_parents(entry, 0755));
        ASSERT_OK(write_string_file(entry, "not a mask\n", WRITE_STRING_FILE_CREATE));

        ASSERT_ERROR(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_FORCE, vendor_root,
                                      STRV_MAKE("vendor-obstructed.service"), UNIT_FILE_PRESET_FULL,
                                      &changes, &n_changes), EEXIST);
        assert_state("vendor-obstructed.service", UNIT_FILE_DISABLED);
        ASSERT_OK_ERRNO(unlink(entry));

        ASSERT_OK_ERRNO(mkdir(entry, 0755));
        ASSERT_ERROR(unit_file_preset(RUNTIME_SCOPE_SYSTEM, UNIT_FILE_FORCE, vendor_root,
                                      STRV_MAKE("vendor-obstructed.service"), UNIT_FILE_PRESET_FULL,
                                      &changes, &n_changes), EEXIST);
        ASSERT_OK_ERRNO(rmdir(entry));

        ASSERT_OK(write_string_file(entry, "", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        do_preset(/* flags= */ 0, STRV_MAKE("vendor-obstructed.service"));
        ASSERT_ERROR(access_nofollow(entry, F_OK), ENOENT);
        assert_state("vendor-obstructed.service", UNIT_FILE_ENABLED);
}

TEST(vendor_preset_replaces_external_alias) {
        const char *vendor_alias, *config_alias, *external;

        write_vendor_file("system/vendor-external-alias.service",
                          "[Install]\nAlias=vendor-external-name.service\n");
        write_vendor_file("system-preset/24-vendor-external-alias.preset", "enable vendor-external-alias.service\n");
        vendor_alias = strjoina(vendor_root, SYSTEM_DATA_UNIT_DIR"/vendor-external-name.service");
        config_alias = strjoina(vendor_root, SYSTEM_CONFIG_UNIT_DIR"/vendor-external-name.service");
        external = strjoina(vendor_root, "/opt/vendor-external-alias.service");
        ASSERT_OK(write_string_file(external, "[Service]\nExecStart=/bin/false\n", WRITE_STRING_FILE_CREATE));

        FOREACH_STRING(target, "/missing/vendor-external-alias.service", "/opt/vendor-external-alias.service") {
                _cleanup_free_ char *dest = NULL;

                ASSERT_OK_ERRNO(symlink(target, vendor_alias));
                do_preset(/* flags= */ 0, STRV_MAKE("vendor-external-alias.service"));
                ASSERT_OK(readlink_malloc(config_alias, &dest));
                ASSERT_STREQ(dest, SYSTEM_DATA_UNIT_DIR"/vendor-external-alias.service");
                ASSERT_OK_ERRNO(unlink(config_alias));
                ASSERT_OK_ERRNO(unlink(vendor_alias));
        }
}

static int intro(void) {
        make_root(&root);
        make_root(&vendor_root);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);

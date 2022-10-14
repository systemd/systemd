/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "install.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "special.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static char *root = NULL;

STATIC_DESTRUCTOR_REGISTER(root, rm_rf_physical_and_freep);

TEST(basic_mask_and_enable) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "e.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "f.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/a.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/b.service");
        assert_se(symlink("a.service", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        p = strjoina(root, "/usr/lib/systemd/system/c.service");
        assert_se(symlink("/usr/lib/systemd/system/a.service", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        p = strjoina(root, "/usr/lib/systemd/system/d.service");
        assert_se(symlink("c.service", p) >= 0);

        /* This one is interesting, as d follows a relative, then an absolute symlink */
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        assert_se(unit_file_mask(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/dev/null"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/a.service");
        assert_se(streq(changes[0].path, p));

        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        /* Enabling a masked unit should fail! */
        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) == -ERFKILL);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_unmask(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/a.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/a.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Enabling it again should succeed but be a NOP */
        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Disabling a disabled unit must succeed but be a NOP */
        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Let's enable this indirectly via a symlink */
        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("d.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/a.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Let's try to reenable */

        assert_se(unit_file_reenable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("b.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/a.service"));
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        /* Test masking with relative symlinks */

        p = strjoina(root, "/usr/lib/systemd/system/e.service");
        assert_se(symlink("../../../../../../dev/null", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "e.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "e.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        assert_se(unlink(p) == 0);
        assert_se(symlink("/usr/../dev/null", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "e.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "e.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        assert_se(unlink(p) == 0);

        /* Test enabling with unknown dependency target */

        p = strjoina(root, "/usr/lib/systemd/system/f.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=x.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "f.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "f.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("f.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/f.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/x.target.wants/f.service");
        assert_se(streq(changes[0].path, p));
        assert_se(changes[1].type == INSTALL_CHANGE_DESTINATION_NOT_PRESENT);
        p = strjoina(root, "/usr/lib/systemd/system/f.service");
        assert_se(streq(changes[1].source, p));
        assert_se(streq(changes[1].path, "x.target"));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "f.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(linked_units) {
        const char *p, *q;
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
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/opt/linked2.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/opt/linked3.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked2.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked3.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/linked2.service");
        assert_se(symlink("/opt/linked2.service", p) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked3.service");
        assert_se(symlink("/opt/linked3.service", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked3.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* First, let's link the unit into the search path */
        assert_se(unit_file_link(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/opt/linked.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* Let's unlink it from the search path again */
        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        /* Now, let's not just link it, but also enable it */
        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        for (i = 0 ; i < n_changes; i++) {
                assert_se(changes[i].type == INSTALL_CHANGE_SYMLINK);
                assert_se(streq(changes[i].source, "/opt/linked.service"));

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

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        /* And let's unlink it again */
        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked.service");
        for (i = 0; i < n_changes; i++) {
                assert_se(changes[i].type == INSTALL_CHANGE_UNLINK);

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

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked2.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/linked2.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/linked2.service");
        for (i = 0 ; i < n_changes; i++) {
                assert_se(changes[i].type == INSTALL_CHANGE_SYMLINK);
                assert_se(streq(changes[i].source, "/opt/linked2.service"));

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

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("linked3.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(startswith(changes[0].path, root));
        assert_se(endswith(changes[0].path, "linked3.service"));
        assert_se(streq(changes[0].source, "/opt/linked3.service"));
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

        assert_se(unit_file_get_default(LOOKUP_SCOPE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(LOOKUP_SCOPE_SYSTEM, 0, root, "idontexist.target", &changes, &n_changes) == -ENOENT);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == -ENOENT);
        assert_se(streq_ptr(changes[0].path, "idontexist.target"));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(LOOKUP_SCOPE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(LOOKUP_SCOPE_SYSTEM, 0, root, "test-default.target", &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/test-default-real.target"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR "/" SPECIAL_DEFAULT_TARGET);
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(LOOKUP_SCOPE_SYSTEM, root, &def) >= 0);
        assert_se(streq_ptr(def, "test-default-real.target"));
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

        assert_se(unit_file_add_dependency(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("add-dependency-test-service.service"), "add-dependency-test-target.target", UNIT_WANTS, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/real-add-dependency-test-service.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/real-add-dependency-test-target.target.wants/real-add-dependency-test-service.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

TEST(template_enable) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        log_info("== %s ==", __func__);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/template@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/template-symlink@.service");
        assert_se(symlink("template@.service", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template@.service enabled ==", __func__);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@def.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template@foo.service enabled ==", __func__);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@foo.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template-symlink@quux.service enabled ==", __func__);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("template-symlink@quux.service"), &changes, &n_changes) >= 0);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/template@quux.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ALIAS);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(indirect) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirecta.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirectb.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirectc.service", &state) == -ENOENT);

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

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirecta.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirectb.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirectc.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/indirectb.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/indirectb.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirecta.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirectb.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "indirectc.service", &state) >= 0 && state == UNIT_FILE_ALIAS);

        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/indirectb.service");
        assert_se(streq(changes[0].path, p));
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
        Hashmap *h;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-yes.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-no.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/preset-no.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        assert_se(write_string_file(p,
                                    "enable *-yes.*\n"
                                    "disable *\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-yes.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/preset-yes.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-yes.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("preset-no.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(LOOKUP_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);

        assert_se(n_changes > 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/preset-yes.service");

        for (i = 0; i < n_changes; i++) {

                if (changes[i].type == INSTALL_CHANGE_SYMLINK) {
                        assert_se(streq(changes[i].source, "/usr/lib/systemd/system/preset-yes.service"));
                        assert_se(streq(changes[i].path, p));
                } else
                        assert_se(changes[i].type == INSTALL_CHANGE_UNLINK);
        }

        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(h = hashmap_new(&string_hash_ops));
        assert_se(unit_file_get_list(LOOKUP_SCOPE_SYSTEM, root, h, NULL, NULL) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        q = strjoina(root, "/usr/lib/systemd/system/preset-no.service");

        HASHMAP_FOREACH(fl, h) {
                assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, basename(fl->path), &state) >= 0);
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

        unit_file_list_free(h);

        assert_se(got_yes && got_no);
}

TEST(revert) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "xx.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "yy.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/xx.service");
        assert_se(write_string_file(p, "# Empty\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "xx.service", NULL) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "xx.service", &state) >= 0 && state == UNIT_FILE_STATIC);

        /* Initially there's nothing to revert */
        assert_se(unit_file_revert(LOOKUP_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service");
        assert_se(write_string_file(p, "# Empty override\n", WRITE_STRING_FILE_CREATE) >= 0);

        /* Revert the override file */
        assert_se(unit_file_revert(LOOKUP_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service.d/dropin.conf");
        assert_se(write_string_file(p, "# Empty dropin\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        /* Revert the dropin file */
        assert_se(unit_file_revert(LOOKUP_SCOPE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        assert_se(streq(changes[0].path, p));

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/xx.service.d");
        assert_se(changes[1].type == INSTALL_CHANGE_UNLINK);
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

TEST(preset_order) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-1.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-2.service", &state) == -ENOENT);

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

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("prefix-1.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/prefix-1.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/prefix-1.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("prefix-2.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
}

TEST(static_instance) {
        UnitFileState state;
        const char *p;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "static-instance@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "static-instance@foo.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "static-instance@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "static-instance@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@foo.service");
        assert_se(symlink("static-instance@.service", p) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "static-instance@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "static-instance@foo.service", &state) >= 0 && state == UNIT_FILE_STATIC);
}

TEST(with_dropin) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-1.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-3.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4a.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-4a.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "Also=with-dropin-4b.service\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4b.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-1.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-1.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-1.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-1.service");
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2.service"), &changes, &n_changes) == 1);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service"));
        assert_se(streq(changes[1].source, SYSTEM_CONFIG_UNIT_DIR"/with-dropin-2.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-2.service");
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-3.service"), &changes, &n_changes) == 1);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-3.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-3.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-3.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-3.service");
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-4a.service"), &changes, &n_changes) == 2);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-4a.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-4b.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-4a.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-4b.service");
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-4a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-4b.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

TEST(with_dropin_template) {
        const char *p;
        UnitFileState state;
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-1@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3@.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-1@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@instance-1.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-1\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service.d/dropin.conf");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-2\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-1@instance-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-1@.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-1@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-1@instance-1.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-1@instance-1.service");
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2@instance-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(changes[1].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-2@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2@instance-1.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/graphical.target.wants/with-dropin-2@instance-1.service");
        assert_se(streq(changes[1].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2@instance-2.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-2@instance-2.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("with-dropin-3@.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-3@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/with-dropin-3@instance-2.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-1@instance-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2@instance-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-2@instance-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3@instance-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "with-dropin-3@instance-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
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

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        assert_se(write_string_file(p,
                                    "enable foo@.service bar0 bar1 bartest\n"
                                    "enable emptylist@.service\n" /* This line ensures the old functionality for templated unit still works */
                                    "disable *\n" , WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        /* Preset a single instantiated unit specified in the list */
        assert_se(unit_file_preset(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("foo@bar0.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_SYMLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/foo@bar0.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(LOOKUP_SCOPE_SYSTEM, 0, root, STRV_MAKE("foo@bar0.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == INSTALL_CHANGE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_DIR"/multi-user.target.wants/foo@bar0.service");
        assert_se(streq(changes[0].path, p));
        install_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Check for preset-all case, only instances on the list should be enabled, not including the default instance */
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bar1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bartest.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(LOOKUP_SCOPE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes > 0);

        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bar1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(LOOKUP_SCOPE_SYSTEM, root, "foo@bartest.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        install_changes_free(changes, n_changes);
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
        assert_se(streq_ptr(alias2, updated_name));
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
        verify_one(&plain_service, "foo.target.wants/plain.service", 0, NULL);
        verify_one(&plain_service, "foo.target.wants/plain.socket", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.wants/plain@.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.wants/service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.requires/plain.service", 0, NULL);
        verify_one(&plain_service, "foo.target.requires/plain.socket", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.requires/plain@.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.requires/service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.target.conf/plain.service", -EXDEV, NULL);
        verify_one(&plain_service, "foo.service/plain.service", -EXDEV, NULL); /* missing dir suffix */
        verify_one(&plain_service, "asdf.requires/plain.service", -EXDEV, NULL); /* invalid unit name component */

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
          * but would not be resolveable on its own, since systemd doesn't know how to load the fragment. */
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

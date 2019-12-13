/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "install.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "special.h"
#include "string-util.h"
#include "tests.h"

static void test_basic_mask_and_enable(const char *root) {
        const char *p;
        UnitFileState state;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;

        test_setup_logging(LOG_DEBUG);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/a.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", NULL) >= 0);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/b.service");
        assert_se(symlink("a.service", p) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", NULL) >= 0);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/c.service");
        assert_se(symlink("/usr/lib/systemd/system/a.service", p) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", NULL) >= 0);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/d.service");
        assert_se(symlink("c.service", p) >= 0);

        /* This one is interesting, as d follows a relative, then an absolute symlink */
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", NULL) >= 0);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_mask(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/dev/null"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/a.service");
        assert_se(streq(changes[0].path, p));

        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_MASKED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_MASKED);

        /* Enabling a masked unit should fail! */
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) == -ERFKILL);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_unmask(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/a.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/a.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        /* Enabling it again should succeed but be a NOP */
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        /* Disabling a disabled unit must succeed but be a NOP */
        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Let's enable this indirectly via a symlink */
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("d.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/a.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        /* Let's try to reenable */

        assert_se(unit_file_reenable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("b.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/a.service");
        assert_se(streq(changes[0].path, p));
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/a.service"));
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "b.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "c.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "d.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

static void test_linked_units(const char *root) {
        const char *p, *q;
        UnitFileState state;
        UnitFileChange *changes = NULL;
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

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked2.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked3.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/linked2.service");
        assert_se(symlink("/opt/linked2.service", p) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked3.service");
        assert_se(symlink("/opt/linked3.service", p) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked3.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* First, let's link the unit into the search path */
        assert_se(unit_file_link(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/opt/linked.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* Let's unlink it from the search path again */
        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        /* Now, let's not just link it, but also enable it */
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("/opt/linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked.service");
        for (i = 0 ; i < n_changes; i++) {
                assert_se(changes[i].type == UNIT_FILE_SYMLINK);
                assert_se(streq(changes[i].source, "/opt/linked.service"));

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else
                        assert_not_reached("wut?");
        }
        assert(!p && !q);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        /* And let's unlink it again */
        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/linked.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked.service");
        for (i = 0; i < n_changes; i++) {
                assert_se(changes[i].type == UNIT_FILE_UNLINK);

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else
                        assert_not_reached("wut?");
        }
        assert(!p && !q);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("linked2.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/linked2.service");
        q = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked2.service");
        for (i = 0 ; i < n_changes; i++) {
                assert_se(changes[i].type == UNIT_FILE_SYMLINK);
                assert_se(streq(changes[i].source, "/opt/linked2.service"));

                if (p && streq(changes[i].path, p))
                        p = NULL;
                else if (q && streq(changes[i].path, q))
                        q = NULL;
                else
                        assert_not_reached("wut?");
        }
        assert(!p && !q);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("linked3.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(startswith(changes[0].path, root));
        assert_se(endswith(changes[0].path, "linked3.service"));
        assert_se(streq(changes[0].source, "/opt/linked3.service"));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

static void test_default(const char *root) {
        _cleanup_free_ char *def = NULL;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;

        p = strjoina(root, "/usr/lib/systemd/system/test-default-real.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/test-default.target");
        assert_se(symlink("test-default-real.target", p) >= 0);

        assert_se(unit_file_get_default(UNIT_FILE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(UNIT_FILE_SYSTEM, 0, root, "idontexist.target", &changes, &n_changes) == -ENOENT);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == -ENOENT);
        assert_se(streq_ptr(changes[0].path, "idontexist.target"));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(UNIT_FILE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(UNIT_FILE_SYSTEM, 0, root, "test-default.target", &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/test-default-real.target"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH "/" SPECIAL_DEFAULT_TARGET);
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(UNIT_FILE_SYSTEM, root, &def) >= 0);
        assert_se(streq_ptr(def, "test-default-real.target"));
}

static void test_add_dependency(const char *root) {
        UnitFileChange *changes = NULL;
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

        assert_se(unit_file_add_dependency(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("add-dependency-test-service.service"), "add-dependency-test-target.target", UNIT_WANTS, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/real-add-dependency-test-service.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/real-add-dependency-test-target.target.wants/real-add-dependency-test-service.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

static void test_template_enable(const char *root) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        log_info("== %s ==", __func__);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/template@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/template-symlink@.service");
        assert_se(symlink("template@.service", p) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template@.service enabled ==", __func__);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/template@def.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template@foo.service enabled ==", __func__);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/template@foo.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        log_info("== %s with template-symlink@quux.service enabled ==", __func__);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("template-symlink@quux.service"), &changes, &n_changes) >= 0);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/template@quux.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

static void test_indirect(const char *root) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state;
        const char *p;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirecta.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirectb.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirectc.service", &state) == -ENOENT);

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

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirecta.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirectb.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirectc.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/indirectb.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/indirectb.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirecta.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirectb.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "indirectc.service", &state) >= 0 && state == UNIT_FILE_INDIRECT);

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/indirectb.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

static void test_preset_and_list(const char *root) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0, i;
        const char *p, *q;
        UnitFileState state;
        bool got_yes = false, got_no = false;
        Iterator j;
        UnitFileList *fl;
        Hashmap *h;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) == -ENOENT);

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

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("preset-yes.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/preset-yes.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/preset-yes.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("preset-yes.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/preset-yes.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("preset-no.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(UNIT_FILE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);

        assert_se(n_changes > 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/preset-yes.service");

        for (i = 0; i < n_changes; i++) {

                if (changes[i].type == UNIT_FILE_SYMLINK) {
                        assert_se(streq(changes[i].source, "/usr/lib/systemd/system/preset-yes.service"));
                        assert_se(streq(changes[i].path, p));
                } else
                        assert_se(changes[i].type == UNIT_FILE_UNLINK);
        }

        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(h = hashmap_new(&string_hash_ops));
        assert_se(unit_file_get_list(UNIT_FILE_SYSTEM, root, h, NULL, NULL) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/preset-yes.service");
        q = strjoina(root, "/usr/lib/systemd/system/preset-no.service");

        HASHMAP_FOREACH(fl, h, j) {
                assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, basename(fl->path), &state) >= 0);
                assert_se(fl->state == state);

                if (streq(fl->path, p)) {
                        got_yes = true;
                        assert_se(fl->state == UNIT_FILE_ENABLED);
                } else if (streq(fl->path, q)) {
                        got_no = true;
                        assert_se(fl->state == UNIT_FILE_DISABLED);
                } else
                        assert_se(IN_SET(fl->state, UNIT_FILE_DISABLED, UNIT_FILE_STATIC, UNIT_FILE_INDIRECT));
        }

        unit_file_list_free(h);

        assert_se(got_yes && got_no);
}

static void test_revert(const char *root) {
        const char *p;
        UnitFileState state;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;

        assert(root);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "xx.service", NULL) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "yy.service", NULL) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/xx.service");
        assert_se(write_string_file(p, "# Empty\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "xx.service", NULL) >= 0);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "xx.service", &state) >= 0 && state == UNIT_FILE_STATIC);

        /* Initially there's nothing to revert */
        assert_se(unit_file_revert(UNIT_FILE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/xx.service");
        assert_se(write_string_file(p, "# Empty override\n", WRITE_STRING_FILE_CREATE) >= 0);

        /* Revert the override file */
        assert_se(unit_file_revert(UNIT_FILE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/xx.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p, "# Empty dropin\n", WRITE_STRING_FILE_CREATE) >= 0);

        /* Revert the dropin file */
        assert_se(unit_file_revert(UNIT_FILE_SYSTEM, root, STRV_MAKE("xx.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        assert_se(streq(changes[0].path, p));

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/xx.service.d");
        assert_se(changes[1].type == UNIT_FILE_UNLINK);
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

static void test_preset_order(const char *root) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-1.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-2.service", &state) == -ENOENT);

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

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("prefix-1.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/prefix-1.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/prefix-1.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("prefix-2.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "prefix-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
}

static void test_static_instance(const char *root) {
        UnitFileState state;
        const char *p;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "static-instance@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "static-instance@foo.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "static-instance@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "static-instance@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/static-instance@foo.service");
        assert_se(symlink("static-instance@.service", p) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "static-instance@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "static-instance@foo.service", &state) >= 0 && state == UNIT_FILE_STATIC);
}

static void test_with_dropin(const char *root) {
        const char *p;
        UnitFileState state;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-1.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-4a.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-4b.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/with-dropin-2.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/with-dropin-3.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4a.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/with-dropin-4a.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "Also=with-dropin-4b.service\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-4a.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-4b.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-4b.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-1.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-1.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-1.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/graphical.target.wants/with-dropin-1.service");
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2.service"), &changes, &n_changes) == 1);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, SYSTEM_CONFIG_UNIT_PATH"/with-dropin-2.service"));
        assert_se(streq(changes[1].source, SYSTEM_CONFIG_UNIT_PATH"/with-dropin-2.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-2.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/graphical.target.wants/with-dropin-2.service");
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-3.service"), &changes, &n_changes) == 1);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-3.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-3.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-3.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/graphical.target.wants/with-dropin-3.service");
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-4a.service"), &changes, &n_changes) == 2);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-4a.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-4b.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-4a.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-4b.service");
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-4a.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-4b.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

static void test_with_dropin_template(const char *root) {
        const char *p;
        UnitFileState state;
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-1@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2@.service", &state) == -ENOENT);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3@.service", &state) == -ENOENT);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-1@.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-1@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-2@instance-1.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "WantedBy=graphical.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-1\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/with-dropin-3@.service.d/dropin.conf");
        assert_se(mkdir_parents(p, 0755) >= 0);
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=instance-2\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-1@instance-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-1@.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-1@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-1@instance-1.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/graphical.target.wants/with-dropin-1@instance-1.service");
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2@instance-1.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 2);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(changes[1].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service"));
        assert_se(streq(changes[1].source, "/usr/lib/systemd/system/with-dropin-2@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-2@instance-1.service");
        assert_se(streq(changes[0].path, p));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/graphical.target.wants/with-dropin-2@instance-1.service");
        assert_se(streq(changes[1].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-2@instance-2.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-2@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-2@instance-2.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("with-dropin-3@.service"), &changes, &n_changes) == 1);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/with-dropin-3@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/with-dropin-3@instance-2.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-1@instance-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2@instance-1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-2@instance-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3@instance-1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "with-dropin-3@instance-2.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

static void test_preset_multiple_instances(const char *root) {
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        const char *p;
        UnitFileState state;

        /* Set up template service files and preset file */
        p = strjoina(root, "/usr/lib/systemd/system/foo@.service");
        assert_se(write_string_file(p,
                                    "[Install]\n"
                                    "DefaultInstance=def\n"
                                    "WantedBy=multi-user.target\n", WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        p = strjoina(root, "/usr/lib/systemd/system-preset/test.preset");
        assert_se(write_string_file(p,
                                    "enable foo@.service bar0 bar1 bartest\n"
                                    "enable emptylist@.service\n" /* This line ensures the old functionality for templated unit still works */
                                    "disable *\n" , WRITE_STRING_FILE_CREATE) >= 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        /* Preset a single instantiated unit specified in the list */
        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("foo@bar0.service"), UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/foo@bar0.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, 0, root, STRV_MAKE("foo@bar0.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/foo@bar0.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Check for preset-all case, only instances on the list should be enabled, not including the default instance */
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bar1.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bartest.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(UNIT_FILE_SYSTEM, 0, root, UNIT_FILE_PRESET_FULL, &changes, &n_changes) >= 0);
        assert_se(n_changes > 0);

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bar0.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bar1.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "foo@bartest.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        unit_file_changes_free(changes, n_changes);
}

int main(int argc, char *argv[]) {
        char root[] = "/tmp/rootXXXXXX";
        const char *p;

        assert_se(mkdtemp(root));

        p = strjoina(root, "/usr/lib/systemd/system/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/run/systemd/system/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/opt/");
        assert_se(mkdir_p(p, 0755) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system-preset/");
        assert_se(mkdir_p(p, 0755) >= 0);

        test_basic_mask_and_enable(root);
        test_linked_units(root);
        test_default(root);
        test_add_dependency(root);
        test_template_enable(root);
        test_indirect(root);
        test_preset_and_list(root);
        test_preset_order(root);
        test_preset_multiple_instances(root);
        test_revert(root);
        test_static_instance(root);
        test_with_dropin(root);
        test_with_dropin_template(root);

        assert_se(rm_rf(root, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        return 0;
}

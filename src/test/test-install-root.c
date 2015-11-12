/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "fileio.h"
#include "install.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "string-util.h"

static void test_basic_mask_and_enable(const char *root) {
        const char *p;
        UnitFileState state;
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;

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

        assert_se(unit_file_mask(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), false, &changes, &n_changes) >= 0);
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
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), false, &changes, &n_changes) == -ESHUTDOWN);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_unmask(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/a.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), false, &changes, &n_changes) == 1);
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
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), false, &changes, &n_changes) == 1);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
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

        /* Disabling a disabled unit must suceed but be a NOP */
        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("a.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        /* Let's enable this indirectly via a symlink */
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("d.service"), false, &changes, &n_changes) >= 0);
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

        assert_se(unit_file_reenable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("b.service"), false, &changes, &n_changes) >= 0);
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
        unsigned n_changes = 0, i;

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
        assert_se(unit_file_link(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("/opt/linked.service"), false, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/opt/linked.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", &state) >= 0 && state == UNIT_FILE_LINKED);

        /* Let's unlink it from the search path again */
        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/linked.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "linked.service", NULL) == -ENOENT);

        /* Now, let's not just link it, but also enable it */
        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("/opt/linked.service"), false, &changes, &n_changes) >= 0);
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
        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("linked.service"), &changes, &n_changes) >= 0);
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

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("linked2.service"), false, &changes, &n_changes) >= 0);
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

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("linked3.service"), false, &changes, &n_changes) == -ELOOP);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

static void test_default(const char *root) {
        _cleanup_free_ char *def = NULL;
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        const char *p;

        p = strjoina(root, "/usr/lib/systemd/system/test-default-real.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/test-default.target");
        assert_se(symlink("test-default-real.target", p) >= 0);

        assert_se(unit_file_get_default(UNIT_FILE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(UNIT_FILE_SYSTEM, root, "idontexist.target", false, &changes, &n_changes) == -ENOENT);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(UNIT_FILE_SYSTEM, root, &def) == -ENOENT);

        assert_se(unit_file_set_default(UNIT_FILE_SYSTEM, root, "test-default.target", false, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/test-default-real.target"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/default.target");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_default(UNIT_FILE_SYSTEM, root, &def) >= 0);
        assert_se(streq_ptr(def, "test-default-real.target"));
}

static void test_add_dependency(const char *root) {
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
        const char *p;

        p = strjoina(root, "/usr/lib/systemd/system/real-add-dependency-test-target.target");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/add-dependency-test-target.target");
        assert_se(symlink("real-add-dependency-test-target.target", p) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/real-add-dependency-test-service.service");
        assert_se(write_string_file(p, "# pretty much empty", WRITE_STRING_FILE_CREATE) >= 0);

        p = strjoina(root, "/usr/lib/systemd/system/add-dependency-test-service.service");
        assert_se(symlink("real-add-dependency-test-service.service", p) >= 0);

        assert_se(unit_file_add_dependency(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("add-dependency-test-service.service"), "add-dependency-test-target.target", UNIT_WANTS, false, &changes, &n_changes) >= 0);
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
        unsigned n_changes = 0;
        UnitFileState state;
        const char *p;

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

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("template@.service"), false, &changes, &n_changes) >= 0);
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

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("template@.service"), &changes, &n_changes) >= 0);
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

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("template@foo.service"), false, &changes, &n_changes) >= 0);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/template@foo.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_ENABLED);

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("template@foo.service"), &changes, &n_changes) >= 0);
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

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("template-symlink@quux.service"), false, &changes, &n_changes) >= 0);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/template@.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/template@quux.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@def.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@foo.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "template-symlink@quux.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
}

static void test_indirect(const char *root) {
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0;
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

        assert_se(unit_file_enable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("indirectc.service"), false, &changes, &n_changes) >= 0);
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

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("indirectc.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/indirectb.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;
}

static void test_preset_and_list(const char *root) {
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0, i;
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

        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("preset-yes.service"), UNIT_FILE_PRESET_FULL, false, &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_SYMLINK);
        assert_se(streq(changes[0].source, "/usr/lib/systemd/system/preset-yes.service"));
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/preset-yes.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_ENABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_disable(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("preset-yes.service"), &changes, &n_changes) >= 0);
        assert_se(n_changes == 1);
        assert_se(changes[0].type == UNIT_FILE_UNLINK);
        p = strjoina(root, SYSTEM_CONFIG_UNIT_PATH"/multi-user.target.wants/preset-yes.service");
        assert_se(streq(changes[0].path, p));
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset(UNIT_FILE_SYSTEM, false, root, STRV_MAKE("preset-no.service"), UNIT_FILE_PRESET_FULL, false, &changes, &n_changes) >= 0);
        assert_se(n_changes == 0);
        unit_file_changes_free(changes, n_changes);
        changes = NULL; n_changes = 0;

        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-yes.service", &state) >= 0 && state == UNIT_FILE_DISABLED);
        assert_se(unit_file_get_state(UNIT_FILE_SYSTEM, root, "preset-no.service", &state) >= 0 && state == UNIT_FILE_DISABLED);

        assert_se(unit_file_preset_all(UNIT_FILE_SYSTEM, false, root, UNIT_FILE_PRESET_FULL, false, &changes, &n_changes) >= 0);

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
        assert_se(unit_file_get_list(UNIT_FILE_SYSTEM, root, h) >= 0);

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

        assert_se(rm_rf(root, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        return 0;
}

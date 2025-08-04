/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <string.h>

#include "hashmap.h"
#include "install.h"
#include "path-util.h"
#include "tests.h"

static void dump_changes(InstallChange *c, unsigned n) {
        unsigned i;

        assert_se(n == 0 || c);

        for (i = 0; i < n; i++) {
                if (c[i].type == INSTALL_CHANGE_UNLINK)
                        printf("rm '%s'\n", c[i].path);
                else if (c[i].type == INSTALL_CHANGE_SYMLINK)
                        printf("ln -s '%s' '%s'\n", c[i].source, c[i].path);
        }
}

int main(int argc, char* argv[]) {
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        UnitFileList *p;
        int r;
        const char *const files[] = { "avahi-daemon.service", NULL };
        const char *files_name = "avahi-daemon.service";
        const char *const files2[] = { "/home/lennart/test.service", NULL };
        const char *files2_name = "test.service";
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state = 0;

        test_setup_logging(LOG_DEBUG);

        ASSERT_OK(unit_file_get_list(RUNTIME_SCOPE_SYSTEM, NULL, NULL, NULL, &h));

        HASHMAP_FOREACH(p, h) {
                UnitFileState s = _UNIT_FILE_STATE_INVALID;
                _cleanup_free_ char *unit_filename = NULL;

                ASSERT_OK(path_extract_filename(p->path, &unit_filename));
                r = unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, unit_filename, &s);

                assert_se((r < 0 && p->state == UNIT_FILE_BAD) ||
                          (p->state == s));

                fprintf(stderr, "%s (%s)\n",
                        p->path,
                        unit_file_state_to_string(p->state));
        }

        log_info("/*** enable **/");

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        log_info("/*** enable2 **/");

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_ENABLED);

        log_info("/*** disable ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_DISABLED);

        log_info("/*** mask ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_mask(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));
        log_info("/*** mask2 ***/");
        ASSERT_OK(unit_file_mask(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_MASKED);

        log_info("/*** unmask ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_unmask(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));
        log_info("/*** unmask2 ***/");
        ASSERT_OK(unit_file_unmask(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_DISABLED);

        log_info("/*** mask ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_mask(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_MASKED);

        log_info("/*** disable ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));
        log_info("/*** disable2 ***/");
        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_MASKED);

        log_info("/*** umask ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_unmask(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files[0], &state));
        assert_se(state == UNIT_FILE_DISABLED);

        log_info("/*** enable files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_enable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files2, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));
        assert_se(state == UNIT_FILE_ENABLED);

        log_info("/*** disable files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, NULL, STRV_MAKE(files2_name), &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_FAIL(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));

        log_info("/*** link files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_link(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files2, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));
        assert_se(state == UNIT_FILE_LINKED);

        log_info("/*** disable files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, NULL, STRV_MAKE(files2_name), &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_FAIL(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));

        log_info("/*** link files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_link(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files2, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));
        assert_se(state == UNIT_FILE_LINKED);

        log_info("/*** reenable files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_reenable(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files2, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));
        assert_se(state == UNIT_FILE_ENABLED);

        log_info("/*** disable files2 ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_disable(RUNTIME_SCOPE_SYSTEM, 0, NULL, STRV_MAKE(files2_name), &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_FAIL(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files2_name, &state));
        log_info("/*** preset files ***/");
        changes = NULL;
        n_changes = 0;

        ASSERT_OK(unit_file_preset(RUNTIME_SCOPE_SYSTEM, 0, NULL, (char**) files, UNIT_FILE_PRESET_FULL, &changes, &n_changes));

        dump_changes(changes, n_changes);
        install_changes_free(changes, n_changes);

        ASSERT_OK(unit_file_get_state(RUNTIME_SCOPE_SYSTEM, NULL, files_name, &state));
        assert_se(state == UNIT_FILE_ENABLED);

        return 0;
}

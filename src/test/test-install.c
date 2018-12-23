/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <string.h>

#include "install.h"
#include "tests.h"

static void dump_changes(UnitFileChange *c, unsigned n) {
        unsigned i;

        assert_se(n == 0 || c);

        for (i = 0; i < n; i++) {
                if (c[i].type == UNIT_FILE_UNLINK)
                        printf("rm '%s'\n", c[i].path);
                else if (c[i].type == UNIT_FILE_SYMLINK)
                        printf("ln -s '%s' '%s'\n", c[i].source, c[i].path);
        }
}

int main(int argc, char *argv[]) {
        Hashmap *h;
        UnitFileList *p;
        Iterator i;
        int r;
        const char *const files[] = { "avahi-daemon.service", NULL };
        const char *const files2[] = { "/home/lennart/test.service", NULL };
        UnitFileChange *changes = NULL;
        size_t n_changes = 0;
        UnitFileState state = 0;

        test_setup_logging(LOG_DEBUG);

        h = hashmap_new(&string_hash_ops);
        r = unit_file_get_list(UNIT_FILE_SYSTEM, NULL, h, NULL, NULL);
        assert_se(r == 0);

        HASHMAP_FOREACH(p, h, i) {
                UnitFileState s = _UNIT_FILE_STATE_INVALID;

                r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(p->path), &s);

                assert_se((r < 0 && p->state == UNIT_FILE_BAD) || (p->state == s));

                fprintf(stderr, "%s (%s)\n", p->path, unit_file_state_to_string(p->state));
        }

        unit_file_list_free(h);

        log_info("/*** enable **/");

        r = unit_file_enable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        log_info("/*** enable2 **/");

        r = unit_file_enable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_ENABLED);

        log_info("/*** disable ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_disable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_DISABLED);

        log_info("/*** mask ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_mask(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);
        log_info("/*** mask2 ***/");
        r = unit_file_mask(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_MASKED);

        log_info("/*** unmask ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_unmask(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);
        log_info("/*** unmask2 ***/");
        r = unit_file_unmask(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_DISABLED);

        log_info("/*** mask ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_mask(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_MASKED);

        log_info("/*** disable ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_disable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);
        log_info("/*** disable2 ***/");
        r = unit_file_disable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_MASKED);

        log_info("/*** umask ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_unmask(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, files[0], &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_DISABLED);

        log_info("/*** enable files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_enable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files2, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_ENABLED);

        log_info("/*** disable files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_disable(UNIT_FILE_SYSTEM, 0, NULL, STRV_MAKE(basename(files2[0])), &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r < 0);

        log_info("/*** link files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_link(UNIT_FILE_SYSTEM, 0, NULL, (char **) files2, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_LINKED);

        log_info("/*** disable files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_disable(UNIT_FILE_SYSTEM, 0, NULL, STRV_MAKE(basename(files2[0])), &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r < 0);

        log_info("/*** link files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_link(UNIT_FILE_SYSTEM, 0, NULL, (char **) files2, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_LINKED);

        log_info("/*** reenable files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_reenable(UNIT_FILE_SYSTEM, 0, NULL, (char **) files2, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_ENABLED);

        log_info("/*** disable files2 ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_disable(UNIT_FILE_SYSTEM, 0, NULL, STRV_MAKE(basename(files2[0])), &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files2[0]), &state);
        assert_se(r < 0);
        log_info("/*** preset files ***/");
        changes = NULL;
        n_changes = 0;

        r = unit_file_preset(UNIT_FILE_SYSTEM, 0, NULL, (char **) files, UNIT_FILE_PRESET_FULL, &changes, &n_changes);
        assert_se(r >= 0);

        dump_changes(changes, n_changes);
        unit_file_changes_free(changes, n_changes);

        r = unit_file_get_state(UNIT_FILE_SYSTEM, NULL, basename(files[0]), &state);
        assert_se(r >= 0);
        assert_se(state == UNIT_FILE_ENABLED);

        return 0;
}

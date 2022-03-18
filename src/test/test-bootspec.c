/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "fileio.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST_RET(bootspec_sort) {

        static const struct {
                const char *fname;
                const char *contents;
        } entries[] = {
                {
                        .fname = "a-10.conf",
                        .contents =
                        "title A\n"
                        "version 10\n"
                        "machine-id dd235d00696545768f6f693bfd23b15f\n",
                },
                {
                        .fname = "a-5.conf",
                        .contents =
                        "title A\n"
                        "version 5\n"
                        "machine-id dd235d00696545768f6f693bfd23b15f\n",
                },
                {
                        .fname = "b.conf",
                        .contents =
                        "title B\n"
                        "version 3\n"
                        "machine-id b75451ad92f94feeab50b0b442768dbd\n",
                },
                {
                        .fname = "c.conf",
                        .contents =
                        "title C\n"
                        "sort-key xxxx\n"
                        "version 5\n"
                        "machine-id 309de666fd5044268a9a26541ac93176\n",
                },
                {
                        .fname = "cx.conf",
                        .contents =
                        "title C\n"
                        "sort-key xxxx\n"
                        "version 10\n"
                        "machine-id 309de666fd5044268a9a26541ac93176\n",
                },
                {
                        .fname = "d.conf",
                        .contents =
                        "title D\n"
                        "sort-key kkkk\n"
                        "version 100\n"
                        "machine-id 81c6e3147cf544c19006af023e22b292\n",
                },
        };

        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_(boot_config_free) BootConfig config = {};

        assert_se(mkdtemp_malloc("/tmp/bootspec-testXXXXXX", &d) >= 0);

        for (size_t i = 0; i < ELEMENTSOF(entries); i++) {
                _cleanup_free_ char *j = NULL;

                j = path_join(d, "/loader/entries/", entries[i].fname);
                assert_se(j);

                assert_se(write_string_file(j, entries[i].contents, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755) >= 0);
        }

        assert_se(boot_entries_load_config(d, NULL, &config) >= 0);

        assert_se(config.n_entries == 6);

        /* First, because has sort key, and its the lowest one */
        assert_se(streq(config.entries[0].id, "d.conf"));

        /* These two have a sort key, and newest must be first */
        assert_se(streq(config.entries[1].id, "cx.conf"));
        assert_se(streq(config.entries[2].id, "c.conf"));

        /* The following ones have no sort key, hence order by version compared ids, lowest first */
        assert_se(streq(config.entries[3].id, "b.conf"));
        assert_se(streq(config.entries[4].id, "a-10.conf"));
        assert_se(streq(config.entries[5].id, "a-5.conf"));

        return 0;
}

DEFINE_TEST_MAIN(LOG_INFO);

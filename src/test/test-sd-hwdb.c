/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-hwdb.h"

#include "errno-util.h"
#include "fd-util.h"
#include "hwdb-internal.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(failed_enumerate) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *key, *value;

        assert_se(sd_hwdb_new(&hwdb) == 0);

        assert_se(sd_hwdb_seek(hwdb, "no-such-modalias-should-exist") == 0);

        assert_se(sd_hwdb_enumerate(hwdb, &key, &value) == 0);
        ASSERT_RETURN_EXPECTED_SE(sd_hwdb_enumerate(hwdb, &key, NULL) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_hwdb_enumerate(hwdb, NULL, &value) == -EINVAL);
}

#define DELL_MODALIAS \
        "evdev:atkbd:dmi:bvnXXX:bvrYYY:bdZZZ:svnDellXXX:pnYYY:"

TEST(basic_enumerate) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *key, *value;
        size_t len1 = 0, len2 = 0;
        int r;

        assert_se(sd_hwdb_new(&hwdb) == 0);

        assert_se(sd_hwdb_seek(hwdb, DELL_MODALIAS) == 0);

        for (;;) {
                r = sd_hwdb_enumerate(hwdb, &key, &value);
                assert_se(IN_SET(r, 0, 1));
                if (r == 0)
                        break;
                assert_se(key);
                assert_se(value);
                log_debug("A: \"%s\" → \"%s\"", key, value);
                len1 += strlen(key) + strlen(value);
        }

        SD_HWDB_FOREACH_PROPERTY(hwdb, DELL_MODALIAS, key, value) {
                log_debug("B: \"%s\" → \"%s\"", key, value);
                len2 += strlen(key) + strlen(value);
        }

        assert_se(len1 == len2);
}

TEST(sd_hwdb_new_from_path) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        int r;

        ASSERT_RETURN_EXPECTED_SE(sd_hwdb_new_from_path(NULL, &hwdb) == -EINVAL);
        ASSERT_RETURN_EXPECTED_SE(sd_hwdb_new_from_path("", &hwdb) == -EINVAL);
        assert_se(sd_hwdb_new_from_path("/path/that/should/not/exist", &hwdb) < 0);

        NULSTR_FOREACH(hwdb_bin_path, HWDB_BIN_PATHS) {
                r = sd_hwdb_new_from_path(hwdb_bin_path, &hwdb);
                if (r >= 0)
                        break;
        }

        assert_se(r >= 0);
}

static sd_hwdb* hwdb_new_from_blob(const void *data, size_t size) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &tmp));
        _cleanup_free_ char *path = ASSERT_NOT_NULL(path_join(tmp, "hwdb.bin"));

        fd = ASSERT_OK_ERRNO(open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC, 0644));
        ASSERT_OK_EQ_ERRNO(write(fd, data, size), (ssize_t) size);
        fd = safe_close(fd);

        ASSERT_OK(sd_hwdb_new_from_path(path, &hwdb));

        return TAKE_PTR(hwdb);
}

TEST(sd_hwdb_seek_rejects_invalid_fnmatch_child_node) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        struct invalid_hwdb {
                struct trie_header_f header;
                struct trie_node_f root_node;
                struct trie_child_entry_f child1;
                struct trie_node_f mid_node;
                struct trie_child_entry_f child2;
                struct trie_node_f wildcard_node;
                struct trie_child_entry_f child3;
                char strings[STRLEN("usb:") + 1];
        } _packed_ data = {
                .header = {
                        .signature = HWDB_SIG,
                        .tool_version = htole64(PROJECT_VERSION),
                        .file_size = htole64(sizeof(struct invalid_hwdb)),
                        .header_size = htole64(sizeof(struct trie_header_f)),
                        .node_size = htole64(sizeof(struct trie_node_f)),
                        .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                        .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
                        .nodes_root_off = htole64(offsetof(struct invalid_hwdb, root_node)),
                        .nodes_len = htole64(offsetof(struct invalid_hwdb, strings) - offsetof(struct invalid_hwdb, root_node)),
                        .strings_len = htole64(STRLEN("usb:") + 1),
                },
                .root_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings)),
                        .children_count = 1,
                },
                .child1 = {
                        .c = 'v',
                        .child_off = htole64(offsetof(struct invalid_hwdb, mid_node)),
                },
                .mid_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings) + STRLEN("usb:")),
                        .children_count = 1,
                },
                .child2 = {
                        .c = '*',
                        .child_off = htole64(offsetof(struct invalid_hwdb, wildcard_node)),
                },
                .wildcard_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings) + STRLEN("usb:")),
                        .children_count = 1,
                },
                .child3 = {
                        .c = 'x',
                        .child_off = htole64(0xDEAD0000),
                },
                .strings = "usb:",
        };

        hwdb = ASSERT_NOT_NULL(hwdb_new_from_blob(&data, sizeof(data)));

        ASSERT_ERROR(sd_hwdb_seek(hwdb, "usb:vx"), EBADMSG);
}

TEST(sd_hwdb_seek_rejects_invalid_fnmatch_prefix) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        struct invalid_hwdb {
                struct trie_header_f header;
                struct trie_node_f root_node;
                struct trie_child_entry_f child1;
                struct trie_node_f mid_node;
                struct trie_child_entry_f child2;
                struct trie_node_f crash_node;
                char strings[STRLEN("usb:") + 1];
        } _packed_ data = {
                .header = {
                        .signature = HWDB_SIG,
                        .tool_version = htole64(PROJECT_VERSION),
                        .file_size = htole64(sizeof(struct invalid_hwdb)),
                        .header_size = htole64(sizeof(struct trie_header_f)),
                        .node_size = htole64(sizeof(struct trie_node_f)),
                        .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                        .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
                        .nodes_root_off = htole64(offsetof(struct invalid_hwdb, root_node)),
                        .nodes_len = htole64(offsetof(struct invalid_hwdb, strings) - offsetof(struct invalid_hwdb, root_node)),
                        .strings_len = htole64(STRLEN("usb:") + 1),
                },
                .root_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings)),
                        .children_count = 1,
                },
                .child1 = {
                        .c = 'v',
                        .child_off = htole64(offsetof(struct invalid_hwdb, mid_node)),
                },
                .mid_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings) + STRLEN("usb:")),
                        .children_count = 1,
                },
                .child2 = {
                        .c = '*',
                        .child_off = htole64(offsetof(struct invalid_hwdb, crash_node)),
                },
                .crash_node = {
                        .prefix_off = htole64(0xDEAD0000),
                },
                .strings = "usb:",
        };

        hwdb = ASSERT_NOT_NULL(hwdb_new_from_blob(&data, sizeof(data)));

        ASSERT_ERROR(sd_hwdb_seek(hwdb, "usb:v*"), EBADMSG);
}

TEST(sd_hwdb_seek_rejects_invalid_search_prefix) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        struct invalid_hwdb {
                struct trie_header_f header;
                struct trie_node_f root_node;
                char strings[1];
        } _packed_ data = {
                .header = {
                        .signature = HWDB_SIG,
                        .tool_version = htole64(PROJECT_VERSION),
                        .file_size = htole64(sizeof(struct invalid_hwdb)),
                        .header_size = htole64(sizeof(struct trie_header_f)),
                        .node_size = htole64(sizeof(struct trie_node_f)),
                        .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                        .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
                        .nodes_root_off = htole64(offsetof(struct invalid_hwdb, root_node)),
                        .nodes_len = htole64(sizeof(struct trie_node_f)),
                        .strings_len = htole64(1),
                },
                .root_node = {
                        .prefix_off = htole64(0xDEAD0000),
                },
        };

        hwdb = ASSERT_NOT_NULL(hwdb_new_from_blob(&data, sizeof(data)));

        ASSERT_ERROR(sd_hwdb_seek(hwdb, "usb:v1234"), EBADMSG);
}

TEST(sd_hwdb_seek_rejects_truncated_children_array) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        struct invalid_hwdb {
                struct trie_header_f header;
                struct trie_node_f root_node;
        } _packed_ data = {
                .header = {
                        .signature = HWDB_SIG,
                        .tool_version = htole64(PROJECT_VERSION),
                        .file_size = htole64(sizeof(struct invalid_hwdb)),
                        .header_size = htole64(sizeof(struct trie_header_f)),
                        .node_size = htole64(sizeof(struct trie_node_f)),
                        .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                        .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
                        .nodes_root_off = htole64(offsetof(struct invalid_hwdb, root_node)),
                        .nodes_len = htole64(sizeof(struct trie_node_f)),
                },
                .root_node = {
                        .children_count = 1,
                },
        };

        hwdb = ASSERT_NOT_NULL(hwdb_new_from_blob(&data, sizeof(data)));

        ASSERT_ERROR(sd_hwdb_seek(hwdb, "x"), EBADMSG);
}

TEST(sd_hwdb_seek_rejects_invalid_property_key) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        struct invalid_hwdb {
                struct trie_header_f header;
                struct trie_node_f root_node;
                struct trie_value_entry_f value;
                char strings[STRLEN("usb") + 1 + STRLEN("value") + 1];
        } _packed_ data = {
                .header = {
                        .signature = HWDB_SIG,
                        .tool_version = htole64(PROJECT_VERSION),
                        .file_size = htole64(sizeof(struct invalid_hwdb)),
                        .header_size = htole64(sizeof(struct trie_header_f)),
                        .node_size = htole64(sizeof(struct trie_node_f)),
                        .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                        .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
                        .nodes_root_off = htole64(offsetof(struct invalid_hwdb, root_node)),
                        .nodes_len = htole64(offsetof(struct invalid_hwdb, strings) - offsetof(struct invalid_hwdb, root_node)),
                        .strings_len = htole64(STRLEN("usb") + 1 + STRLEN("value") + 1),
                },
                .root_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings)),
                        .values_count = htole64(1),
                },
                .value = {
                        .key_off = htole64(0xDEAD0000),
                        .value_off = htole64(offsetof(struct invalid_hwdb, strings) + STRLEN("usb") + 1),
                },
                .strings = "usb\0value",
        };

        hwdb = ASSERT_NOT_NULL(hwdb_new_from_blob(&data, sizeof(data)));

        ASSERT_ERROR(sd_hwdb_seek(hwdb, "usb"), EBADMSG);
}

TEST(sd_hwdb_seek_rejects_cyclic_trie) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        /* Cyclic trie: the wildcard_node's only child points back to
         * itself, which would drive trie_fnmatch_f() into infinite
         * recursion (stack-overflow CVE-class bug found by CIFuzz).
         * The recursion-depth cap must turn this into a clean -EBADMSG. */
        struct invalid_hwdb {
                struct trie_header_f header;
                struct trie_node_f root_node;
                struct trie_child_entry_f child1;
                struct trie_node_f mid_node;
                struct trie_child_entry_f child2;
                struct trie_node_f wildcard_node;
                struct trie_child_entry_f wildcard_self_child;
                char strings[STRLEN("usb:") + 1];
        } _packed_ data = {
                .header = {
                        .signature = HWDB_SIG,
                        .tool_version = htole64(PROJECT_VERSION),
                        .file_size = htole64(sizeof(struct invalid_hwdb)),
                        .header_size = htole64(sizeof(struct trie_header_f)),
                        .node_size = htole64(sizeof(struct trie_node_f)),
                        .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                        .value_entry_size = htole64(sizeof(struct trie_value_entry_f)),
                        .nodes_root_off = htole64(offsetof(struct invalid_hwdb, root_node)),
                        .nodes_len = htole64(offsetof(struct invalid_hwdb, strings) - offsetof(struct invalid_hwdb, root_node)),
                        .strings_len = htole64(STRLEN("usb:") + 1),
                },
                .root_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings)),
                        .children_count = 1,
                },
                .child1 = {
                        .c = 'v',
                        .child_off = htole64(offsetof(struct invalid_hwdb, mid_node)),
                },
                .mid_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings) + STRLEN("usb:")),
                        .children_count = 1,
                },
                .child2 = {
                        .c = '*',
                        .child_off = htole64(offsetof(struct invalid_hwdb, wildcard_node)),
                },
                .wildcard_node = {
                        .prefix_off = htole64(offsetof(struct invalid_hwdb, strings) + STRLEN("usb:")),
                        .children_count = 1,
                },
                .wildcard_self_child = {
                        .c = 'a',
                        .child_off = htole64(offsetof(struct invalid_hwdb, wildcard_node)),
                },
                .strings = "usb:",
        };

        hwdb = ASSERT_NOT_NULL(hwdb_new_from_blob(&data, sizeof(data)));

        ASSERT_ERROR(sd_hwdb_seek(hwdb, "usb:v*"), EBADMSG);
}

static int intro(void) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        int r;

        r = sd_hwdb_new(&hwdb);
        if (r == -ENOENT || ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped_errno(r, "cannot open hwdb");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);

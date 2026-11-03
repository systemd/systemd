/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "argv-util.h"
#include "bcd.h"
#include "compress.h"
#include "fileio.h"
#include "tests.h"
#include "utf8.h"

/* Include the implementation directly, so we can poke at some internals. */
#include "bcd.c"

static void load_bcd(const char *path, void **ret_bcd, size_t *ret_bcd_len) {
        size_t len;
        _cleanup_free_ char *fn = NULL, *compressed = NULL;

        ASSERT_OK(get_testdata_dir(path, &fn));
        ASSERT_OK(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, SIZE_MAX, /* flags= */ 0, /* bind_name= */ NULL, &compressed, &len));
        ASSERT_OK(decompress_blob(COMPRESSION_ZSTD, compressed, len, ret_bcd, ret_bcd_len, SIZE_MAX));
}

static void test_get_bcd_title_one(
                const char *path,
                const char16_t *title_expect,
                size_t title_len_expect) {

        size_t len;
        _cleanup_free_ void *bcd = NULL;

        log_info("/* %s(%s) */", __func__, path);

        load_bcd(path, &bcd, &len);

        char16_t *title = get_bcd_title(bcd, len);
        if (title_expect) {
                ASSERT_NOT_NULL(title);
                ASSERT_EQ(memcmp(title, title_expect, title_len_expect), 0);
        } else
                ASSERT_NULL(title);
}

TEST(get_bcd_title) {
        test_get_bcd_title_one("test-bcd/win10.bcd.zst", u"Windows 10", sizeof(u"Windows 10"));

        test_get_bcd_title_one("test-bcd/description-bad-type.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/description-empty.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/description-missing.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/description-too-small.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/displayorder-bad-name.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/displayorder-bad-size.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/displayorder-bad-type.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
        test_get_bcd_title_one("test-bcd/empty.bcd.zst", /* title_expect= */ NULL, /* title_len_expect= */ 0);
}

TEST(base_block) {
        size_t len;
        BaseBlock backup;
        uint8_t *bcd_base;
        _cleanup_free_ BaseBlock *bcd = NULL;

        load_bcd("test-bcd/win10.bcd.zst", (void **) &bcd, &len);
        backup = *bcd;
        bcd_base = (uint8_t *) bcd;

        ASSERT_NOT_NULL(get_bcd_title(bcd_base, len));

        /* Try various "corruptions" of the base block. */

        ASSERT_NULL(get_bcd_title(bcd_base, sizeof(BaseBlock) - 1));

        bcd->sig = 0;
        ASSERT_NULL(get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->version_minor = 2;
        ASSERT_NULL(get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->version_major = 4;
        ASSERT_NULL(get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->type = 1;
        ASSERT_NULL(get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->primary_seqnum++;
        ASSERT_NULL(get_bcd_title(bcd_base, len));
        *bcd = backup;
}

TEST(offset_bounds) {
        ASSERT_FALSE(bad_offset(/* offset= */ 0, sizeof(Key), sizeof(Key)));
        ASSERT_FALSE(BAD_STRUCT(Key, 0, sizeof(Key)));
        ASSERT_FALSE(BAD_ARRAY(Key, key_name, 0, 0, sizeof(Key)));

        ASSERT_TRUE(bad_offset(/* offset= */ 0, sizeof(Key) + 1, sizeof(Key)));
        ASSERT_TRUE(bad_offset(sizeof(Key) + 1, /* len= */ 0, sizeof(Key)));
        ASSERT_TRUE(bad_offset(UINT32_MAX, 2, UINT32_MAX));
}

TEST(bad_bcd) {
        size_t len;
        uint8_t *hbins;
        uint32_t offset;
        _cleanup_free_ void *bcd = NULL;

        /* This BCD hive has been manipulated to have bad offsets/sizes at various places. */
        load_bcd("test-bcd/corrupt.bcd.zst", &bcd, &len);

        ASSERT_GE(len, HIVE_CELL_OFFSET);
        hbins = (uint8_t *) bcd + HIVE_CELL_OFFSET;
        len -= HIVE_CELL_OFFSET;
        offset = ((BaseBlock *) bcd)->root_cell_offset;

        const Key *root = ASSERT_NOT_NULL(get_key(hbins, len, offset, "\0"));
        ASSERT_NULL(get_key(hbins, sizeof(Key) - 1, offset, "\0"));

        ASSERT_NULL(get_key(hbins, len, offset, "\0BadOffset\0"));
        ASSERT_NULL(get_key(hbins, len, offset, "\0BadSig\0"));
        ASSERT_NULL(get_key(hbins, len, offset, "\0BadKeyNameLen\0"));
        ASSERT_NULL(get_key(hbins, len, offset, "\0SubkeyBadOffset\0Dummy\0"));
        ASSERT_NULL(get_key(hbins, len, offset, "\0SubkeyBadSig\0Dummy\0"));
        ASSERT_NULL(get_key(hbins, len, offset, "\0SubkeyBadNEntries\0Dummy\0"));

        ASSERT_NULL(get_key_value(hbins, len, root, "Dummy"));

        const Key *kv_bad_offset = ASSERT_NOT_NULL(get_key(hbins, len, offset, "\0KeyValuesBadOffset\0"));
        ASSERT_NULL(get_key_value(hbins, len, kv_bad_offset, "Dummy"));

        const Key *kv_bad_n_key_values =
                ASSERT_NOT_NULL(get_key(hbins, len, offset, "\0KeyValuesBadNKeyValues\0"));
        ASSERT_NULL(get_key_value(hbins, len, kv_bad_n_key_values, "Dummy"));

        const Key *kv = ASSERT_NOT_NULL(get_key(hbins, len, offset, "\0KeyValues\0"));

        ASSERT_NULL(get_key_value(hbins, len, kv, "BadOffset"));
        ASSERT_NULL(get_key_value(hbins, len, kv, "BadSig"));
        ASSERT_NULL(get_key_value(hbins, len, kv, "BadNameLen"));
        ASSERT_NULL(get_key_value(hbins, len, kv, "InlineData"));
        ASSERT_NULL(get_key_value(hbins, len, kv, "BadDataOffset"));
        ASSERT_NULL(get_key_value(hbins, len, kv, "BadDataSize"));
}

TEST(argv_bcds) {
        for (int i = 1; i < saved_argc; i++) {
                size_t len;
                _cleanup_free_ void *bcd = NULL;

                ASSERT_OK(read_full_file_full(
                        AT_FDCWD,
                        saved_argv[i],
                        UINT64_MAX,
                        SIZE_MAX,
                        /* flags= */ 0,
                        /* bind_name= */ NULL,
                        (char **) &bcd,
                        &len));

                char16_t *title = get_bcd_title(bcd, len);
                if (title) {
                        _cleanup_free_ char *title_utf8 = utf16_to_utf8(title, SIZE_MAX);
                        log_info("%s: \"%s\"", saved_argv[i], title_utf8);
                } else
                        log_info("%s: Bad BCD", saved_argv[i]);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);

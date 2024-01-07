/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
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

        assert_se(get_testdata_dir(path, &fn) >= 0);
        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, SIZE_MAX, 0, NULL, &compressed, &len) >= 0);
        assert_se(decompress_blob_zstd(compressed, len, ret_bcd, ret_bcd_len, SIZE_MAX) >= 0);
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
                assert_se(title);
                assert_se(memcmp(title, title_expect, title_len_expect) == 0);
        } else
                assert_se(!title);
}

TEST(get_bcd_title) {
        test_get_bcd_title_one("test-bcd/win10.bcd.zst", u"Windows 10", sizeof(u"Windows 10"));

        test_get_bcd_title_one("test-bcd/description-bad-type.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/description-empty.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/description-missing.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/description-too-small.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/displayorder-bad-name.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/displayorder-bad-size.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/displayorder-bad-type.bcd.zst", NULL, 0);
        test_get_bcd_title_one("test-bcd/empty.bcd.zst", NULL, 0);
}

TEST(base_block) {
        size_t len;
        BaseBlock backup;
        uint8_t *bcd_base;
        BaseBlock *bcd;
        _cleanup_free_ void *bcd_raw = NULL;

        load_bcd("test-bcd/win10.bcd.zst", &bcd_raw, &len);
        bcd = bcd_raw;
        backup = *(BaseBlock *)bcd;
        bcd_base = (uint8_t *) bcd;

        assert_se(get_bcd_title(bcd_base, len));

        /* Try various "corruptions" of the base block. */

        assert_se(!get_bcd_title(bcd_base, sizeof(BaseBlock) - 1));
        bcd->sig = 0;
        assert_se(!get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->version_minor = 2;
        assert_se(!get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->version_major = 4;
        assert_se(!get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->type = 1;
        assert_se(!get_bcd_title(bcd_base, len));
        *bcd = backup;

        bcd->primary_seqnum++;
        assert_se(!get_bcd_title(bcd_base, len));
        *bcd = backup;
}

TEST(bad_bcd) {
        size_t len;
        uint8_t *hbins;
        uint32_t offset;
        _cleanup_free_ void *bcd = NULL;

        /* This BCD hive has been manipulated to have bad offsets/sizes at various places. */
        load_bcd("test-bcd/corrupt.bcd.zst", &bcd, &len);

        assert_se(len >= HIVE_CELL_OFFSET);
        hbins = (uint8_t *) bcd + HIVE_CELL_OFFSET;
        len -= HIVE_CELL_OFFSET;
        offset = ((BaseBlock *) bcd)->root_cell_offset;

        const Key *root = get_key(hbins, len, offset, "\0");
        assert_se(root);
        assert_se(!get_key(hbins, sizeof(Key) - 1, offset, "\0"));

        assert_se(!get_key(hbins, len, offset, "\0BadOffset\0"));
        assert_se(!get_key(hbins, len, offset, "\0BadSig\0"));
        assert_se(!get_key(hbins, len, offset, "\0BadKeyNameLen\0"));
        assert_se(!get_key(hbins, len, offset, "\0SubkeyBadOffset\0Dummy\0"));
        assert_se(!get_key(hbins, len, offset, "\0SubkeyBadSig\0Dummy\0"));
        assert_se(!get_key(hbins, len, offset, "\0SubkeyBadNEntries\0Dummy\0"));

        assert_se(!get_key_value(hbins, len, root, "Dummy"));

        const Key *kv_bad_offset = get_key(hbins, len, offset, "\0KeyValuesBadOffset\0");
        assert_se(kv_bad_offset);
        assert_se(!get_key_value(hbins, len, kv_bad_offset, "Dummy"));

        const Key *kv_bad_n_key_values = get_key(hbins, len, offset, "\0KeyValuesBadNKeyValues\0");
        assert_se(kv_bad_n_key_values);
        assert_se(!get_key_value(hbins, len, kv_bad_n_key_values, "Dummy"));

        const Key *kv = get_key(hbins, len, offset, "\0KeyValues\0");
        assert_se(kv);

        assert_se(!get_key_value(hbins, len, kv, "BadOffset"));
        assert_se(!get_key_value(hbins, len, kv, "BadSig"));
        assert_se(!get_key_value(hbins, len, kv, "BadNameLen"));
        assert_se(!get_key_value(hbins, len, kv, "InlineData"));
        assert_se(!get_key_value(hbins, len, kv, "BadDataOffset"));
        assert_se(!get_key_value(hbins, len, kv, "BadDataSize"));
}

TEST(argv_bcds) {
        for (int i = 1; i < saved_argc; i++) {
                size_t len;
                _cleanup_free_ void *bcd = NULL;
                char *bcd_raw;

                assert_se(read_full_file_full(
                        AT_FDCWD,
                        saved_argv[i],
                        UINT64_MAX,
                        SIZE_MAX,
                        0,
                        NULL,
                        &bcd_raw,
                        &len) >= 0);
                
                bcd = bcd_raw;
                char16_t *title = get_bcd_title(bcd, len);
                if (title) {
                        _cleanup_free_ char *title_utf8 = utf16_to_utf8(title, SIZE_MAX);
                        log_info("%s: \"%s\"", saved_argv[i], title_utf8);
                } else
                        log_info("%s: Bad BCD", saved_argv[i]);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);

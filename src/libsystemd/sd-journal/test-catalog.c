/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "catalog.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "tests.h"
#include "tmpfile-util.h"

static char** catalog_dirs = NULL;
static const char *no_catalog_dirs[] = {
        "/bin/hopefully/with/no/catalog",
        NULL
};

static OrderedHashmap* test_import(const char* contents, ssize_t size, int code) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-catalog.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        OrderedHashmap *h = NULL;

        if (size < 0)
                size = strlen(contents);

        ASSERT_OK(fd = mkostemp_safe(name));
        ASSERT_EQ(write(fd, contents, size), size);

        ASSERT_EQ(catalog_import_file(&h, fd, name), code);

        return h;
}

static void test_catalog_import_invalid(void) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;

        h = test_import("xxx", -1, -EINVAL);
        ASSERT_TRUE(ordered_hashmap_isempty(h));
}

static void test_catalog_import_badid(void) {
        _unused_ _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;
        const char *input =
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededede\n" \
"Subject: message\n" \
"\n" \
"payload\n";
        h = test_import(input, -1, -EINVAL);
}

static void test_catalog_import_one(void) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;
        char *payload;

        const char *input =
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\n" \
"Subject: message\n" \
"\n" \
"payload\n";
        const char *expect =
"Subject: message\n" \
"\n" \
"payload\n";

        h = test_import(input, -1, 0);
        ASSERT_EQ(ordered_hashmap_size(h), 1u);

        ORDERED_HASHMAP_FOREACH(payload, h) {
                printf("expect: %s\n", expect);
                printf("actual: %s\n", payload);
                ASSERT_STREQ(expect, payload);
        }
}

static void test_catalog_import_merge(void) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;
        char *payload;

        const char *input =
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\n" \
"Subject: message\n" \
"Defined-By: me\n" \
"\n" \
"payload\n" \
"\n" \
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\n" \
"Subject: override subject\n" \
"X-Header: hello\n" \
"\n" \
"override payload\n";

        const char *combined =
"Subject: override subject\n" \
"X-Header: hello\n" \
"Subject: message\n" \
"Defined-By: me\n" \
"\n" \
"override payload\n";

        h = test_import(input, -1, 0);
        ASSERT_EQ(ordered_hashmap_size(h), 1u);

        ORDERED_HASHMAP_FOREACH(payload, h)
                ASSERT_STREQ(combined, payload);
}

static void test_catalog_import_merge_no_body(void) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;
        char *payload;

        const char *input =
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\n" \
"Subject: message\n" \
"Defined-By: me\n" \
"\n" \
"payload\n" \
"\n" \
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\n" \
"Subject: override subject\n" \
"X-Header: hello\n" \
"\n";

        const char *combined =
"Subject: override subject\n" \
"X-Header: hello\n" \
"Subject: message\n" \
"Defined-By: me\n" \
"\n" \
"payload\n";

        h = test_import(input, -1, 0);
        ASSERT_EQ(ordered_hashmap_size(h), 1u);

        ORDERED_HASHMAP_FOREACH(payload, h)
                ASSERT_STREQ(combined, payload);
}

static void test_catalog_update(const char *database) {
        /* Test what happens if there are no files. */
        ASSERT_OK_ZERO(catalog_update(database, NULL, NULL));

        /* Test what happens if there are no files in the directory. */
        ASSERT_OK_ZERO(catalog_update(database, NULL, no_catalog_dirs));

        /* Make sure that we at least have some files loaded or the
         * catalog_list below will fail. */
        ASSERT_OK_ZERO(catalog_update(database, NULL, (const char * const *) catalog_dirs));
}

static void test_catalog_file_lang(void) {
        _cleanup_free_ char *lang = NULL, *lang2 = NULL, *lang3 = NULL, *lang4 = NULL;

        ASSERT_EQ(catalog_file_lang("systemd.de_DE.catalog", &lang), 1);
        ASSERT_STREQ(lang, "de_DE");

        ASSERT_OK_ZERO(catalog_file_lang("systemd..catalog", &lang2));
        ASSERT_NULL(lang2);

        ASSERT_EQ(catalog_file_lang("systemd.fr.catalog", &lang2), 1);
        ASSERT_STREQ(lang2, "fr");

        ASSERT_OK_ZERO(catalog_file_lang("systemd.fr.catalog.gz", &lang3));
        ASSERT_NULL(lang3);

        ASSERT_OK_ZERO(catalog_file_lang("systemd.01234567890123456789012345678901.catalog", &lang3));
        ASSERT_NULL(lang3);

        ASSERT_EQ(catalog_file_lang("systemd.0123456789012345678901234567890.catalog", &lang3), 1);
        ASSERT_STREQ(lang3, "0123456789012345678901234567890");

        ASSERT_OK_ZERO(catalog_file_lang("/x/y/systemd.catalog", &lang4));
        ASSERT_NULL(lang4);

        ASSERT_EQ(catalog_file_lang("/x/y/systemd.ru_RU.catalog", &lang4), 1);
        ASSERT_STREQ(lang4, "ru_RU");
}

int main(int argc, char *argv[]) {
        _cleanup_(unlink_tempfilep) char database[] = "/tmp/test-catalog.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *text = NULL;

        setlocale(LC_ALL, "de_DE.UTF-8");

        test_setup_logging(LOG_DEBUG);

        /* If test-catalog is located at the build directory, then use catalogs in that.
         * If it is not, e.g. installed by systemd-tests package, then use installed catalogs. */
        catalog_dirs = STRV_MAKE(get_catalog_dir());

        ASSERT_OK_ERRNO(access(catalog_dirs[0], F_OK));
        log_notice("Using catalog directory '%s'", catalog_dirs[0]);

        test_catalog_file_lang();

        test_catalog_import_invalid();
        test_catalog_import_badid();
        test_catalog_import_one();
        test_catalog_import_merge();
        test_catalog_import_merge_no_body();

        ASSERT_OK(fd = mkostemp_safe(database));

        test_catalog_update(database);

        ASSERT_OK(catalog_list(NULL, database, true));

        ASSERT_OK(catalog_list(NULL, database, false));

        ASSERT_OK(catalog_get(database, SD_MESSAGE_COREDUMP, &text));
        printf(">>>%s<<<\n", text);

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "catalog.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
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

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, contents, size) == size);

        assert_se(catalog_import_file(&h, name) == code);

        return h;
}

static void test_catalog_import_invalid(void) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;

        h = test_import("xxx", -1, -EINVAL);
        assert_se(ordered_hashmap_isempty(h));
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
        assert_se(ordered_hashmap_size(h) == 1);

        ORDERED_HASHMAP_FOREACH(payload, h) {
                printf("expect: %s\n", expect);
                printf("actual: %s\n", payload);
                assert_se(streq(expect, payload));
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
        assert_se(ordered_hashmap_size(h) == 1);

        ORDERED_HASHMAP_FOREACH(payload, h)
                assert_se(streq(combined, payload));
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
        assert_se(ordered_hashmap_size(h) == 1);

        ORDERED_HASHMAP_FOREACH(payload, h)
                assert_se(streq(combined, payload));
}

static void test_catalog_update(const char *database) {
        int r;

        /* Test what happens if there are no files. */
        r = catalog_update(database, NULL, NULL);
        assert_se(r == 0);

        /* Test what happens if there are no files in the directory. */
        r = catalog_update(database, NULL, no_catalog_dirs);
        assert_se(r == 0);

        /* Make sure that we at least have some files loaded or the
         * catalog_list below will fail. */
        r = catalog_update(database, NULL, (const char * const *) catalog_dirs);
        assert_se(r == 0);
}

static void test_catalog_file_lang(void) {
        _cleanup_free_ char *lang = NULL, *lang2 = NULL, *lang3 = NULL, *lang4 = NULL;

        assert_se(catalog_file_lang("systemd.de_DE.catalog", &lang) == 1);
        assert_se(streq(lang, "de_DE"));

        assert_se(catalog_file_lang("systemd..catalog", &lang2) == 0);
        assert_se(lang2 == NULL);

        assert_se(catalog_file_lang("systemd.fr.catalog", &lang2) == 1);
        assert_se(streq(lang2, "fr"));

        assert_se(catalog_file_lang("systemd.fr.catalog.gz", &lang3) == 0);
        assert_se(lang3 == NULL);

        assert_se(catalog_file_lang("systemd.01234567890123456789012345678901.catalog", &lang3) == 0);
        assert_se(lang3 == NULL);

        assert_se(catalog_file_lang("systemd.0123456789012345678901234567890.catalog", &lang3) == 1);
        assert_se(streq(lang3, "0123456789012345678901234567890"));

        assert_se(catalog_file_lang("/x/y/systemd.catalog", &lang4) == 0);
        assert_se(lang4 == NULL);

        assert_se(catalog_file_lang("/x/y/systemd.ru_RU.catalog", &lang4) == 1);
        assert_se(streq(lang4, "ru_RU"));
}

int main(int argc, char *argv[]) {
        _cleanup_(unlink_tempfilep) char database[] = "/tmp/test-catalog.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *text = NULL;
        int r;

        setlocale(LC_ALL, "de_DE.UTF-8");

        test_setup_logging(LOG_DEBUG);

        /* If test-catalog is located at the build directory, then use catalogs in that.
         * If it is not, e.g. installed by systemd-tests package, then use installed catalogs. */
        catalog_dirs = STRV_MAKE(get_catalog_dir());

        assert_se(access(catalog_dirs[0], F_OK) >= 0);
        log_notice("Using catalog directory '%s'", catalog_dirs[0]);

        test_catalog_file_lang();

        test_catalog_import_invalid();
        test_catalog_import_badid();
        test_catalog_import_one();
        test_catalog_import_merge();
        test_catalog_import_merge_no_body();

        assert_se((fd = mkostemp_safe(database)) >= 0);

        test_catalog_update(database);

        r = catalog_list(NULL, database, true);
        assert_se(r >= 0);

        r = catalog_list(NULL, database, false);
        assert_se(r >= 0);

        assert_se(catalog_get(database, SD_MESSAGE_COREDUMP, &text) >= 0);
        printf(">>>%s<<<\n", text);

        return 0;
}

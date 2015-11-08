/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "catalog.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "util.h"

static const char *catalog_dirs[] = {
        CATALOG_DIR,
        NULL,
};

static const char *no_catalog_dirs[] = {
        "/bin/hopefully/with/no/catalog",
        NULL
};

static Hashmap * test_import(const char* contents, ssize_t size, int code) {
        int r;
        char name[] = "/tmp/test-catalog.XXXXXX";
        _cleanup_close_ int fd;
        Hashmap *h;

        if (size < 0)
                size = strlen(contents);

        assert_se(h = hashmap_new(&catalog_hash_ops));

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(write(fd, contents, size) == size);

        r = catalog_import_file(h, name);
        assert_se(r == code);

        unlink(name);

        return h;
}

static void test_catalog_import_invalid(void) {
        _cleanup_hashmap_free_free_free_ Hashmap *h = NULL;

        h = test_import("xxx", -1, -EINVAL);
        assert_se(hashmap_isempty(h));
}

static void test_catalog_import_badid(void) {
        _cleanup_hashmap_free_free_free_ Hashmap *h = NULL;
        const char *input =
"-- 0027229ca0644181a76c4e92458afaff dededededededededededededededede\n" \
"Subject: message\n" \
"\n" \
"payload\n";
        h = test_import(input, -1, -EINVAL);
}

static void test_catalog_import_one(void) {
        _cleanup_hashmap_free_free_free_ Hashmap *h = NULL;
        char *payload;
        Iterator j;

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
        assert_se(hashmap_size(h) == 1);

        HASHMAP_FOREACH(payload, h, j) {
                assert_se(streq(expect, payload));
        }
}

static void test_catalog_import_merge(void) {
        _cleanup_hashmap_free_free_free_ Hashmap *h = NULL;
        char *payload;
        Iterator j;

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
        assert_se(hashmap_size(h) == 1);

        HASHMAP_FOREACH(payload, h, j) {
                assert_se(streq(combined, payload));
        }
}

static void test_catalog_import_merge_no_body(void) {
        _cleanup_hashmap_free_free_free_ Hashmap *h = NULL;
        char *payload;
        Iterator j;

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
        assert_se(hashmap_size(h) == 1);

        HASHMAP_FOREACH(payload, h, j) {
                assert_se(streq(combined, payload));
        }
}

static const char* database = NULL;

static void test_catalog_update(void) {
        static char name[] = "/tmp/test-catalog.XXXXXX";
        int r;

        r = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(r >= 0);

        database = name;

        /* Test what happens if there are no files. */
        r = catalog_update(database, NULL, NULL);
        assert_se(r >= 0);

        /* Test what happens if there are no files in the directory. */
        r = catalog_update(database, NULL, no_catalog_dirs);
        assert_se(r >= 0);

        /* Make sure that we at least have some files loaded or the
           catalog_list below will fail. */
        r = catalog_update(database, NULL, catalog_dirs);
        assert_se(r >= 0);
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
        _cleanup_free_ char *text = NULL;
        int r;

        setlocale(LC_ALL, "de_DE.UTF-8");

        log_parse_environment();
        log_open();

        test_catalog_file_lang();

        test_catalog_import_invalid();
        test_catalog_import_badid();
        test_catalog_import_one();
        test_catalog_import_merge();
        test_catalog_import_merge_no_body();

        test_catalog_update();

        r = catalog_list(stdout, database, true);
        assert_se(r >= 0);

        r = catalog_list(stdout, database, false);
        assert_se(r >= 0);

        assert_se(catalog_get(database, SD_MESSAGE_COREDUMP, &text) >= 0);
        printf(">>>%s<<<\n", text);

        if (database)
                unlink(database);

        return 0;
}

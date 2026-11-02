/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extract-word.h"
#include "tests.h"

TEST(extract_first_word) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "foobar");
        free(t);
        ASSERT_PTR_EQ(p, original + 7);

        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "\"foobar\"");
        free(t);
        ASSERT_PTR_EQ(p, original + 9);

        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "\'waldo\'");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "foobar");
        free(t);
        ASSERT_PTR_EQ(p, original + 9);

        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"";
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), 1);
        ASSERT_STREQ(t, "\"");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE), EINVAL);
        ASSERT_PTR_EQ(p, original + 1);

        p = original = "\'";
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), 1);
        ASSERT_STREQ(t, "\'");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\'";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE), EINVAL);
        ASSERT_PTR_EQ(p, original + 1);

        p = original = "\'fooo";
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), 1);
        ASSERT_STREQ(t, "\'fooo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "KEY=val \"KEY2=val with space\" \"KEY3=val with \\\"quotation\\\"\"";
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE), 1);
        ASSERT_STREQ(t, "KEY=val");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE), 1);
        ASSERT_STREQ(t, "KEY2=val with space");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE), 1);
        ASSERT_STREQ(t, "KEY3=val with \"quotation\"");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "KEY=val \"KEY2=val space\" \"KEY3=val with \\\"quotation\\\"\"";
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_RETAIN_ESCAPE), 1);
        ASSERT_STREQ(t, "KEY=val");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_RETAIN_ESCAPE), 1);
        ASSERT_STREQ(t, "\"KEY2=val");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_RETAIN_ESCAPE), 1);
        ASSERT_STREQ(t, "space\"");
        free(t);
        ASSERT_NOT_NULL(startswith(p, "\"KEY3="));

        p = original = "\'fooo";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "\'fooo";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL,
                                              EXTRACT_UNQUOTE|EXTRACT_RELAX));
        ASSERT_STREQ(t, "fooo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"fooo";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL,
                                              EXTRACT_UNQUOTE|EXTRACT_RELAX));
        ASSERT_STREQ(t, "fooo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "yay\'foo\'bar";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "yay\'foo\'bar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "yay\'foo\'bar";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "yayfoobar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "   foobar   ";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "foobar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "foo\ba\x6ar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "foobax6ar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "    f\\u00f6o \"pi\\U0001F4A9le\"   ";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "föo");
        free(t);
        ASSERT_PTR_EQ(p, original + 13);

        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL,
                                              EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "pi\360\237\222\251le");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_RELAX));
        ASSERT_STREQ(t, "fooo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNESCAPE_RELAX));
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX));
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX));
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foo\\";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "\"foo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL,
                                              EXTRACT_UNQUOTE|EXTRACT_RELAX));
        ASSERT_STREQ(t, "foo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "foo::bar";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", /* flags= */ 0), 1);
        ASSERT_STREQ(t, "foo");
        free(t);
        ASSERT_PTR_EQ(p, original + 5);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", /* flags= */ 0), 1);
        ASSERT_STREQ(t, "bar");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", /* flags= */ 0), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "foo\\:bar::waldo";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", /* flags= */ 0), 1);
        ASSERT_STREQ(t, "foo:bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", /* flags= */ 0), 1);
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", /* flags= */ 0), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foo\\";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_UNESCAPE_RELAX), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "\"foo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX));
        ASSERT_STREQ(t, "foo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foo\\";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX));
        ASSERT_STREQ(t, "foo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_RELAX));
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNESCAPE_RELAX));
        ASSERT_STREQ(t, "fooo\\ bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX));
        ASSERT_STREQ(t, "fooo\\ bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "fooo\\ bar quux";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX));
        ASSERT_STREQ(t, "fooo\\ bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "\\w+@\\K[\\d.]+";
        ASSERT_ERROR(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE), EINVAL);
        ASSERT_PTR_EQ(p, original + 1);

        p = original = "\\w+@\\K[\\d.]+";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX));
        ASSERT_STREQ(t, "\\w+@\\K[\\d.]+");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\\w+\\b";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX));
        ASSERT_STREQ(t, "\\w+\b");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "-N ''";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "-N");
        free(t);
        ASSERT_PTR_EQ(p, original + 3);

        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = ":foo\\:bar::waldo:";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_NOT_NULL(t);
        ASSERT_STREQ(t, "");
        free(t);
        ASSERT_PTR_EQ(p, original + 1);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_STREQ(t, "foo:bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_NOT_NULL(t);
        ASSERT_STREQ(t, "");
        free(t);
        ASSERT_PTR_EQ(p, original + 11);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_PTR_EQ(p, original + 17);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_STREQ(t, "");
        free(t);
        ASSERT_NULL(p);

        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS), 0);
        ASSERT_NULL(t);
        ASSERT_NULL(p);

        p = "foo\\xbar";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "fooxbar");
        free(t);
        ASSERT_NULL(p);

        p = "foo\\xbar";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "foo\\xbar");
        free(t);
        ASSERT_NULL(p);

        p = "\\:";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, ":");
        free(t);
        ASSERT_NULL(p);

        p = "a\\:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a:b");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c";
        ASSERT_OK_EQ(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "c");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c\\x";
        ASSERT_ERROR(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS), EINVAL);

        p = "a\\\\ b:c\\\\x";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a\\ b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "c\\x");
        free(t);
        ASSERT_NULL(p);

        p = "\\:";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, ":");
        free(t);
        ASSERT_NULL(p);

        p = "a\\:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a:b");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c";
        ASSERT_OK_EQ(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "c");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c\\x";
        ASSERT_ERROR(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), EINVAL);

        p = "a\\\\ b:c\\\\x";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a\\ b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "c\\x");
        free(t);
        ASSERT_NULL(p);

        p = "\\:";
        ASSERT_ERROR(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE), EINVAL);

        p = "a\\:b";
        ASSERT_ERROR(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE), EINVAL);
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE), 1);
        ASSERT_STREQ(t, "b");
        free(t);

        p = "a\\ b:c";
        ASSERT_ERROR(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE), EINVAL);
        ASSERT_OK_EQ(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE), 1);
        ASSERT_STREQ(t, "b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE), 1);
        ASSERT_STREQ(t, "c");
        free(t);
        ASSERT_NULL(p);

        p = original = "foobar=\"waldo\"maldo, baldo";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, "=\", ", /* flags= */ 0));
        ASSERT_STREQ(t, "foobar");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, "=\", ", /* flags= */ 0));
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, "=\", ", /* flags= */ 0));
        ASSERT_STREQ(t, "maldo");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, "=\", ", /* flags= */ 0));
        ASSERT_STREQ(t, "baldo");
        free(t);

        p = original = "mode=\"1777\",size=\"10%\",nr_inodes=\"400\"k,uid=\"496,,107\"520,gi\"\"'d=49610,'\"\"7520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(t, "mode=\"1777\"");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(t, "size=\"10%\"");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(t, "nr_inodes=\"400\"k");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(t, "uid=\"496,,107\"520");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(t, "gi\"\"'d=49610,'\"\"7520");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE));
        ASSERT_STREQ(t, "context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"");
        free(t);

        p = original = "mode=\"1777\",size=\"10%\",nr_inodes=\"400\"k,uid=\"496,,107\"520,gi\"\"'d=49610,'\"\"7520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "mode=1777");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "size=10%");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "nr_inodes=400k");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "uid=496,,107520");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "gid=49610,7520");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "context=system_u:object_r:svirt_sandbox_file_t:s0:c0,c1");
        free(t);

        p = "a:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS), 1);
        ASSERT_STREQ(t, "a");
        ASSERT_STREQ(p, ":b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS), 1);
        ASSERT_STREQ(t, "b");
        free(t);

        p = "a>:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS), 1);
        ASSERT_STREQ(t, "a");
        ASSERT_STREQ(p, ">:b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS), 1);
        ASSERT_STREQ(t, "b");
        free(t);

        p = "a>:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS|EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a");
        ASSERT_STREQ(p, ">:b");
        free(t);
        ASSERT_OK_EQ(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS|EXTRACT_DONT_COALESCE_SEPARATORS), 1);
        ASSERT_STREQ(t, "");
        ASSERT_STREQ(p, ">:b");
        free(t);

        p = "a\\:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS|EXTRACT_RETAIN_ESCAPE), 1);
        ASSERT_STREQ(t, "a\\");
        ASSERT_STREQ(p, ":b");
        free(t);

        p = "a\\:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS), 1);
        ASSERT_STREQ(t, "a:b");
        ASSERT_NULL(p);
        free(t);

        p = "a\\:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a:b");
        ASSERT_NULL(p);
        free(t);

        p = "a\\:a:b";
        ASSERT_OK_EQ(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS), 1);
        ASSERT_STREQ(t, "a:a");
        ASSERT_STREQ(p, ":b");
        free(t);

        p = original = "zażółcić 👊🔪💐 가너도루";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "zażółcić");
        free(t);
        ASSERT_PTR_EQ(p, original + 13);

        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "👊🔪💐");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, /* flags= */ 0));
        ASSERT_STREQ(t, "가너도루");
        free(t);
        ASSERT_TRUE(isempty(p));

        /* For issue #16735. */
        p = "test1@foo\\x2dbar\\x2dbaz.service test2@aaa\\x2dbbb\\x2dccc.service test3@escaped-path-like-data.service test4@/pure/path/like/data.service";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test1@foox2dbarx2dbaz.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test2@aaax2dbbbx2dccc.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test3@escaped-path-like-data.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test4@/pure/path/like/data.service");
        free(t);

        p = "test1@foo\\x2dbar\\x2dbaz.service test2@aaa\\x2dbbb\\x2dccc.service test3@escaped-path-like-data.service test4@/pure/path/like/data.service";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test1@foo\\x2dbar\\x2dbaz.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test2@aaa\\x2dbbb\\x2dccc.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test3@escaped-path-like-data.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test4@/pure/path/like/data.service");
        free(t);

        p = "test1@foo\\x2dbar\\x2dbaz.service test2@aaa\\x2dbbb\\x2dccc.service test3@escaped-path-like-data.service test4@/pure/path/like/data.service";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test1@foo-bar-baz.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test2@aaa-bbb-ccc.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test3@escaped-path-like-data.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test4@/pure/path/like/data.service");
        free(t);
}

TEST(extract_first_word_and_warn) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "foobar");
        free(t);
        ASSERT_PTR_EQ(p, original + 7);

        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "foobar");
        free(t);
        ASSERT_PTR_EQ(p, original + 9);

        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "waldo");
        free(t);
        ASSERT_TRUE(isempty(p));

        ASSERT_OK_EQ(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original), 0);
        ASSERT_NULL(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"";
        ASSERT_ERROR(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE, /* unit= */ NULL, "fake", 1, original), EINVAL);
        ASSERT_PTR_EQ(p, original + 1);

        p = original = "\'";
        ASSERT_ERROR(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE, /* unit= */ NULL, "fake", 1, original), EINVAL);
        ASSERT_PTR_EQ(p, original + 1);

        p = original = "\'fooo";
        ASSERT_ERROR(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE, /* unit= */ NULL, "fake", 1, original), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "\'fooo";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "foo\ba\x6ar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "foobax6ar");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "    f\\u00f6o \"pi\\U0001F4A9le\"   ";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "föo");
        free(t);
        ASSERT_PTR_EQ(p, original + 13);

        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "pi\360\237\222\251le");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_RELAX, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foo\\";
        ASSERT_ERROR(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE, /* unit= */ NULL, "fake", 1, original), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "\"foo\\";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "foo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\"foo\\";
        ASSERT_ERROR(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original), EINVAL);
        ASSERT_PTR_EQ(p, original + 5);

        p = original = "\"foo\\";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_RELAX, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "foo");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_RELAX, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, /* flags= */ 0, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "fooo\\ bar quux";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "fooo\\ bar");
        free(t);
        ASSERT_PTR_EQ(p, original + 10);

        p = original = "\\w+@\\K[\\d.]+";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "\\w+@\\K[\\d.]+");
        free(t);
        ASSERT_TRUE(isempty(p));

        p = original = "\\w+\\b";
        ASSERT_OK_POSITIVE(extract_first_word_and_warn(&p, &t, /* separators= */ NULL, EXTRACT_CUNESCAPE, /* unit= */ NULL, "fake", 1, original));
        ASSERT_STREQ(t, "\\w+\b");
        free(t);
        ASSERT_TRUE(isempty(p));
}

TEST(extract_many_words) {
        const char *p, *original;
        char *a, *b, *c, *d, *e, *f;

        p = original = "foobar waldi piep";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0, &a, &b, &c), 3);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, "foobar");
        ASSERT_STREQ(b, "waldi");
        ASSERT_STREQ(c, "piep");
        free(a);
        free(b);
        free(c);

        p = original = "foobar:waldi:piep ba1:ba2";
        ASSERT_OK_EQ(extract_many_words(&p, ":" WHITESPACE, 0, &a, &b, &c), 3);
        ASSERT_FALSE(isempty(p));
        ASSERT_STREQ(a, "foobar");
        ASSERT_STREQ(b, "waldi");
        ASSERT_STREQ(c, "piep");
        ASSERT_OK_EQ(extract_many_words(&p, ":" WHITESPACE, 0, &d, &e, &f), 2);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(d, "ba1");
        ASSERT_STREQ(e, "ba2");
        ASSERT_TRUE(isempty(f));
        free(a);
        free(b);
        free(c);
        free(d);
        free(e);
        free(f);

        p = original = "'foobar' wa\"ld\"i   ";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0, &a, &b, &c), 2);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, "'foobar'");
        ASSERT_STREQ(b, "wa\"ld\"i");
        ASSERT_STREQ(c, NULL);
        free(a);
        free(b);

        p = original = "'foobar' wa\"ld\"i   ";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, EXTRACT_UNQUOTE, &a, &b, &c), 2);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, "foobar");
        ASSERT_STREQ(b, "waldi");
        ASSERT_STREQ(c, NULL);
        free(a);
        free(b);

        p = original = "";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0, &a, &b, &c), 0);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, NULL);
        ASSERT_STREQ(b, NULL);
        ASSERT_STREQ(c, NULL);

        p = original = "  ";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0, &a, &b, &c), 0);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, NULL);
        ASSERT_STREQ(b, NULL);
        ASSERT_STREQ(c, NULL);

        p = original = "foobar";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0), 0);
        ASSERT_PTR_EQ(p, original);

        p = original = "foobar waldi";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0, &a), 1);
        ASSERT_PTR_EQ(p, original+7);
        ASSERT_STREQ(a, "foobar");
        free(a);

        p = original = "     foobar    ";
        ASSERT_OK_EQ(extract_many_words(&p, NULL, 0, &a), 1);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, "foobar");
        free(a);

        p = original = "gęślą:👊🔪💐 가너도루";
        ASSERT_OK_EQ(extract_many_words(&p, ":" WHITESPACE, 0, &a, &b, &c), 3);
        ASSERT_TRUE(isempty(p));
        ASSERT_STREQ(a, "gęślą");
        ASSERT_STREQ(b, "👊🔪💐");
        ASSERT_STREQ(c, "가너도루");
        free(a);
        free(b);
        free(c);
}

DEFINE_TEST_MAIN(LOG_INFO);

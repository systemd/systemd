/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>

#include "extract-word.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

TEST(extract_first_word) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "foobar");
        free(t);
        assert_se(p == original + 7);

        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, NULL, 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "\"foobar\"");
        free(t);
        assert_se(p == original + 9);

        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "\'waldo\'");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, NULL, 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "foobar");
        free(t);
        assert_se(p == original + 9);

        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, NULL, 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"";
        assert_se(extract_first_word(&p, &t, NULL, 0) == 1);
        ASSERT_STREQ(t, "\"");
        free(t);
        assert_se(isempty(p));

        p = original = "\"";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'";
        assert_se(extract_first_word(&p, &t, NULL, 0) == 1);
        ASSERT_STREQ(t, "\'");
        free(t);
        assert_se(isempty(p));

        p = original = "\'";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'fooo";
        assert_se(extract_first_word(&p, &t, NULL, 0) == 1);
        ASSERT_STREQ(t, "\'fooo");
        free(t);
        assert_se(isempty(p));

        p = original = "KEY=val \"KEY2=val with space\" \"KEY3=val with \\\"quotation\\\"\"";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) == 1);
        ASSERT_STREQ(t, "KEY=val");
        free(t);
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) == 1);
        ASSERT_STREQ(t, "KEY2=val with space");
        free(t);
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) == 1);
        ASSERT_STREQ(t, "KEY3=val with \"quotation\"");
        free(t);
        assert_se(isempty(p));

        p = original = "KEY=val \"KEY2=val space\" \"KEY3=val with \\\"quotation\\\"\"";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RETAIN_ESCAPE) == 1);
        ASSERT_STREQ(t, "KEY=val");
        free(t);
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RETAIN_ESCAPE) == 1);
        ASSERT_STREQ(t, "\"KEY2=val");
        free(t);
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RETAIN_ESCAPE) == 1);
        ASSERT_STREQ(t, "space\"");
        free(t);
        assert_se(startswith(p, "\"KEY3="));

        p = original = "\'fooo";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\'fooo";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "fooo");
        free(t);
        assert_se(isempty(p));

        p = original = "\"fooo";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "fooo");
        free(t);
        assert_se(isempty(p));

        p = original = "yay\'foo\'bar";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "yay\'foo\'bar");
        free(t);
        assert_se(isempty(p));

        p = original = "yay\'foo\'bar";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "yayfoobar");
        free(t);
        assert_se(isempty(p));

        p = original = "   foobar   ";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "foobar");
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) > 0);
        ASSERT_STREQ(t, "foo\ba\x6ar");
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "foobax6ar");
        free(t);
        assert_se(isempty(p));

        p = original = "    f\\u00f6o \"pi\\U0001F4A9le\"   ";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) > 0);
        ASSERT_STREQ(t, "föo");
        free(t);
        assert_se(p == original + 13);

        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE) > 0);
        ASSERT_STREQ(t, "pi\360\237\222\251le");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "fooo");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNESCAPE_RELAX) > 0);
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX) > 0);
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, 0) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "foo");
        free(t);
        assert_se(isempty(p));

        p = original = "foo::bar";
        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        ASSERT_STREQ(t, "foo");
        free(t);
        assert_se(p == original + 5);

        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        ASSERT_STREQ(t, "bar");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, ":", 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "foo\\:bar::waldo";
        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        ASSERT_STREQ(t, "foo:bar");
        free(t);
        assert_se(p == original + 10);

        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, ":", 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_UNESCAPE_RELAX) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "foo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "foo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNESCAPE_RELAX) > 0);
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX) > 0);
        ASSERT_STREQ(t, "fooo\\ bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "\\w+@\\K[\\d.]+";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\\w+@\\K[\\d.]+";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX) > 0);
        ASSERT_STREQ(t, "\\w+@\\K[\\d.]+");
        free(t);
        assert_se(isempty(p));

        p = original = "\\w+\\b";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX) > 0);
        ASSERT_STREQ(t, "\\w+\b");
        free(t);
        assert_se(isempty(p));

        p = original = "-N ''";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "-N");
        free(t);
        assert_se(p == original + 3);

        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "");
        free(t);
        assert_se(isempty(p));

        p = original = ":foo\\:bar::waldo:";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(t);
        ASSERT_STREQ(t, "");
        free(t);
        assert_se(p == original + 1);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "foo:bar");
        free(t);
        assert_se(p == original + 10);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(t);
        ASSERT_STREQ(t, "");
        free(t);
        assert_se(p == original + 11);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(p == original + 17);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "");
        free(t);
        ASSERT_NULL(p);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 0);
        assert_se(!t);
        assert_se(!p);

        p = "foo\\xbar";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "fooxbar");
        free(t);
        ASSERT_NULL(p);

        p = "foo\\xbar";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RETAIN_ESCAPE) > 0);
        ASSERT_STREQ(t, "foo\\xbar");
        free(t);
        ASSERT_NULL(p);

        p = "\\:";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, ":");
        free(t);
        ASSERT_NULL(p);

        p = "a\\:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a:b");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c";
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a b");
        free(t);
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "c");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c\\x";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS) == -EINVAL);

        p = "a\\\\ b:c\\\\x";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a\\ b");
        free(t);
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "c\\x");
        free(t);
        ASSERT_NULL(p);

        p = "\\:";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, ":");
        free(t);
        ASSERT_NULL(p);

        p = "a\\:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a:b");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c";
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a b");
        free(t);
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "c");
        free(t);
        ASSERT_NULL(p);

        p = "a\\ b:c\\x";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == -EINVAL);

        p = "a\\\\ b:c\\\\x";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a\\ b");
        free(t);
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "c\\x");
        free(t);
        ASSERT_NULL(p);

        p = "\\:";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE) == -EINVAL);

        p = "a\\:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE) == -EINVAL);
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_CUNESCAPE) == 1);
        ASSERT_STREQ(t, "b");
        free(t);

        p = "a\\ b:c";
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE) == -EINVAL);
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE) == 1);
        ASSERT_STREQ(t, "b");
        free(t);
        assert_se(extract_first_word(&p, &t, WHITESPACE ":", EXTRACT_CUNESCAPE) == 1);
        ASSERT_STREQ(t, "c");
        free(t);
        ASSERT_NULL(p);

        p = original = "foobar=\"waldo\"maldo, baldo";
        assert_se(extract_first_word(&p, &t, "=\", ", 0) > 0);
        ASSERT_STREQ(t, "foobar");
        free(t);
        assert_se(extract_first_word(&p, &t, "=\", ", 0) > 0);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(extract_first_word(&p, &t, "=\", ", 0) > 0);
        ASSERT_STREQ(t, "maldo");
        free(t);
        assert_se(extract_first_word(&p, &t, "=\", ", 0) > 0);
        ASSERT_STREQ(t, "baldo");
        free(t);

        p = original = "mode=\"1777\",size=\"10%\",nr_inodes=\"400\"k,uid=\"496,,107\"520,gi\"\"'d=49610,'\"\"7520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"";
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE) > 0);
        ASSERT_STREQ(t, "mode=\"1777\"");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE) > 0);
        ASSERT_STREQ(t, "size=\"10%\"");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE) > 0);
        ASSERT_STREQ(t, "nr_inodes=\"400\"k");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE) > 0);
        ASSERT_STREQ(t, "uid=\"496,,107\"520");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE) > 0);
        ASSERT_STREQ(t, "gi\"\"'d=49610,'\"\"7520");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_KEEP_QUOTE) > 0);
        ASSERT_STREQ(t, "context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"");
        free(t);

        p = original = "mode=\"1777\",size=\"10%\",nr_inodes=\"400\"k,uid=\"496,,107\"520,gi\"\"'d=49610,'\"\"7520,context=\"system_u:object_r:svirt_sandbox_file_t:s0:c0,c1\"";
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "mode=1777");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "size=10%");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "nr_inodes=400k");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "uid=496,,107520");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "gid=49610,7520");
        free(t);
        assert_se(extract_first_word(&p, &t, ",", EXTRACT_UNQUOTE) > 0);
        ASSERT_STREQ(t, "context=system_u:object_r:svirt_sandbox_file_t:s0:c0,c1");
        free(t);

        p = "a:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a");
        ASSERT_STREQ(p, ":b");
        free(t);
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS) == 1);
        ASSERT_STREQ(t, "b");
        free(t);

        p = "a>:b";
        assert_se(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a");
        ASSERT_STREQ(p, ">:b");
        free(t);
        assert_se(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS) == 1);
        ASSERT_STREQ(t, "b");
        free(t);

        p = "a>:b";
        assert_se(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS|EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a");
        ASSERT_STREQ(p, ">:b");
        free(t);
        assert_se(extract_first_word(&p, &t, ">:", EXTRACT_RETAIN_SEPARATORS|EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "");
        ASSERT_STREQ(p, ">:b");
        free(t);

        p = "a\\:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS|EXTRACT_RETAIN_ESCAPE) == 1);
        ASSERT_STREQ(t, "a\\");
        ASSERT_STREQ(p, ":b");
        free(t);

        p = "a\\:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a:b");
        assert_se(!p);
        free(t);

        p = "a\\:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a:b");
        assert_se(!p);
        free(t);

        p = "a\\:a:b";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_RETAIN_SEPARATORS|EXTRACT_UNESCAPE_SEPARATORS) == 1);
        ASSERT_STREQ(t, "a:a");
        ASSERT_STREQ(p, ":b");
        free(t);

        p = original = "zażółcić 👊🔪💐 가너도루";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "zażółcić");
        free(t);
        assert_se(p == original + 13);

        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "👊🔪💐");
        free(t);
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        ASSERT_STREQ(t, "가너도루");
        free(t);
        assert_se(isempty(p));

        /* For issue #16735. */
        p = "test1@foo\\x2dbar\\x2dbaz.service test2@aaa\\x2dbbb\\x2dccc.service test3@escaped-path-like-data.service test4@/pure/path/like/data.service";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test1@foox2dbarx2dbaz.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test2@aaax2dbbbx2dccc.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test3@escaped-path-like-data.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE));
        ASSERT_STREQ(t, "test4@/pure/path/like/data.service");
        free(t);

        p = "test1@foo\\x2dbar\\x2dbaz.service test2@aaa\\x2dbbb\\x2dccc.service test3@escaped-path-like-data.service test4@/pure/path/like/data.service";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test1@foo\\x2dbar\\x2dbaz.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test2@aaa\\x2dbbb\\x2dccc.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test3@escaped-path-like-data.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_RETAIN_ESCAPE));
        ASSERT_STREQ(t, "test4@/pure/path/like/data.service");
        free(t);

        p = "test1@foo\\x2dbar\\x2dbaz.service test2@aaa\\x2dbbb\\x2dccc.service test3@escaped-path-like-data.service test4@/pure/path/like/data.service";
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test1@foo-bar-baz.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test2@aaa-bbb-ccc.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test3@escaped-path-like-data.service");
        free(t);
        ASSERT_OK_POSITIVE(extract_first_word(&p, &t, NULL, EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE));
        ASSERT_STREQ(t, "test4@/pure/path/like/data.service");
        free(t);
}

TEST(extract_first_word_and_warn) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "foobar");
        free(t);
        assert_se(p == original + 7);

        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "foobar");
        free(t);
        assert_se(p == original + 9);

        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "waldo");
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'fooo";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\'fooo";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo");
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "foo\ba\x6ar");
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "foobax6ar");
        free(t);
        assert_se(isempty(p));

        p = original = "    f\\u00f6o \"pi\\U0001F4A9le\"   ";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "föo");
        free(t);
        assert_se(p == original + 13);

        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "pi\360\237\222\251le");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo\\");
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "foo");
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "foo");
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "fooo\\ bar");
        free(t);
        assert_se(p == original + 10);

        p = original = "\\w+@\\K[\\d.]+";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "\\w+@\\K[\\d.]+");
        free(t);
        assert_se(isempty(p));

        p = original = "\\w+\\b";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        ASSERT_STREQ(t, "\\w+\b");
        free(t);
        assert_se(isempty(p));
}

TEST(extract_many_words) {
        const char *p, *original;
        char *a, *b, *c, *d, *e, *f;

        p = original = "foobar waldi piep";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c) == 3);
        assert_se(isempty(p));
        ASSERT_STREQ(a, "foobar");
        ASSERT_STREQ(b, "waldi");
        ASSERT_STREQ(c, "piep");
        free(a);
        free(b);
        free(c);

        p = original = "foobar:waldi:piep ba1:ba2";
        assert_se(extract_many_words(&p, ":" WHITESPACE, 0, &a, &b, &c) == 3);
        assert_se(!isempty(p));
        ASSERT_STREQ(a, "foobar");
        ASSERT_STREQ(b, "waldi");
        ASSERT_STREQ(c, "piep");
        assert_se(extract_many_words(&p, ":" WHITESPACE, 0, &d, &e, &f) == 2);
        assert_se(isempty(p));
        ASSERT_STREQ(d, "ba1");
        ASSERT_STREQ(e, "ba2");
        assert_se(isempty(f));
        free(a);
        free(b);
        free(c);
        free(d);
        free(e);
        free(f);

        p = original = "'foobar' wa\"ld\"i   ";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c) == 2);
        assert_se(isempty(p));
        ASSERT_STREQ(a, "'foobar'");
        ASSERT_STREQ(b, "wa\"ld\"i");
        ASSERT_STREQ(c, NULL);
        free(a);
        free(b);

        p = original = "'foobar' wa\"ld\"i   ";
        assert_se(extract_many_words(&p, NULL, EXTRACT_UNQUOTE, &a, &b, &c) == 2);
        assert_se(isempty(p));
        ASSERT_STREQ(a, "foobar");
        ASSERT_STREQ(b, "waldi");
        ASSERT_STREQ(c, NULL);
        free(a);
        free(b);

        p = original = "";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c) == 0);
        assert_se(isempty(p));
        ASSERT_STREQ(a, NULL);
        ASSERT_STREQ(b, NULL);
        ASSERT_STREQ(c, NULL);

        p = original = "  ";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c) == 0);
        assert_se(isempty(p));
        ASSERT_STREQ(a, NULL);
        ASSERT_STREQ(b, NULL);
        ASSERT_STREQ(c, NULL);

        p = original = "foobar";
        assert_se(extract_many_words(&p, NULL, 0) == 0);
        assert_se(p == original);

        p = original = "foobar waldi";
        assert_se(extract_many_words(&p, NULL, 0, &a) == 1);
        assert_se(p == original+7);
        ASSERT_STREQ(a, "foobar");
        free(a);

        p = original = "     foobar    ";
        assert_se(extract_many_words(&p, NULL, 0, &a) == 1);
        assert_se(isempty(p));
        ASSERT_STREQ(a, "foobar");
        free(a);

        p = original = "gęślą:👊🔪💐 가너도루";
        assert_se(extract_many_words(&p, ":" WHITESPACE, 0, &a, &b, &c) == 3);
        assert_se(isempty(p));
        ASSERT_STREQ(a, "gęślą");
        ASSERT_STREQ(b, "👊🔪💐");
        ASSERT_STREQ(c, "가너도루");
        free(a);
        free(b);
        free(c);
}

DEFINE_TEST_MAIN(LOG_INFO);

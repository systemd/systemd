/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Thomas H.P. Andersen

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

#include <stdlib.h>
#include <string.h>

#include "extract-word.h"
#include "log.h"
#include "string-util.h"

static void test_extract_first_word(void) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 7);

        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, NULL, 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "\"foobar\""));
        free(t);
        assert_se(p == original + 9);

        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "\'waldo\'"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, NULL, 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 9);

        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) > 0);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, NULL, 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"";
        assert_se(extract_first_word(&p, &t, NULL, 0) == 1);
        assert_se(streq(t, "\""));
        free(t);
        assert_se(isempty(p));

        p = original = "\"";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'";
        assert_se(extract_first_word(&p, &t, NULL, 0) == 1);
        assert_se(streq(t, "\'"));
        free(t);
        assert_se(isempty(p));

        p = original = "\'";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'fooo";
        assert_se(extract_first_word(&p, &t, NULL, 0) == 1);
        assert_se(streq(t, "\'fooo"));
        free(t);
        assert_se(isempty(p));

        p = original = "\'fooo";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\'fooo";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "fooo"));
        free(t);
        assert_se(isempty(p));

        p = original = "\"fooo";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "fooo"));
        free(t);
        assert_se(isempty(p));

        p = original = "yay\'foo\'bar";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "yay\'foo\'bar"));
        free(t);
        assert_se(isempty(p));

        p = original = "yay\'foo\'bar";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) > 0);
        assert_se(streq(t, "yayfoobar"));
        free(t);
        assert_se(isempty(p));

        p = original = "   foobar   ";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) > 0);
        assert_se(streq(t, "foo\ba\x6ar"));
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "foobax6ar"));
        free(t);
        assert_se(isempty(p));

        p = original = "    f\\u00f6o \"pi\\U0001F4A9le\"   ";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) > 0);
        assert_se(streq(t, "föo"));
        free(t);
        assert_se(p == original + 13);

        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE) > 0);
        assert_se(streq(t, "pi\360\237\222\251le"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RELAX) > 0);
        assert_se(streq(t, "fooo"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE_RELAX) > 0);
        assert_se(streq(t, "fooo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "fooo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_CUNESCAPE_RELAX) > 0);
        assert_se(streq(t, "fooo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, 0) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "foo"));
        free(t);
        assert_se(isempty(p));

        p = original = "foo::bar";
        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        assert_se(streq(t, "foo"));
        free(t);
        assert_se(p == original + 5);

        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        assert_se(streq(t, "bar"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, ":", 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "foo\\:bar::waldo";
        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        assert_se(streq(t, "foo:bar"));
        free(t);
        assert_se(p == original + 10);

        assert_se(extract_first_word(&p, &t, ":", 0) == 1);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word(&p, &t, ":", 0) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE_RELAX) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "foo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE|EXTRACT_CUNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "foo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RELAX) > 0);
        assert_se(streq(t, "fooo bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE_RELAX) > 0);
        assert_se(streq(t, "fooo bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE_RELAX|EXTRACT_RELAX) > 0);
        assert_se(streq(t, "fooo bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_CUNESCAPE_RELAX) > 0);
        assert_se(streq(t, "fooo\\ bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "\\w+@\\K[\\d.]+";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\\w+@\\K[\\d.]+";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_CUNESCAPE_RELAX) > 0);
        assert_se(streq(t, "\\w+@\\K[\\d.]+"));
        free(t);
        assert_se(isempty(p));

        p = original = "\\w+\\b";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_CUNESCAPE|EXTRACT_CUNESCAPE_RELAX) > 0);
        assert_se(streq(t, "\\w+\b"));
        free(t);
        assert_se(isempty(p));

        p = original = "-N ''";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) > 0);
        assert_se(streq(t, "-N"));
        free(t);
        assert_se(p == original + 3);

        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_QUOTES) > 0);
        assert_se(streq(t, ""));
        free(t);
        assert_se(isempty(p));

        p = original = ":foo\\:bar::waldo:";
        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(t);
        assert_se(streq(t, ""));
        free(t);
        assert_se(p == original + 1);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(streq(t, "foo:bar"));
        free(t);
        assert_se(p == original + 10);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(t);
        assert_se(streq(t, ""));
        free(t);
        assert_se(p == original + 11);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(p == original + 17);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 1);
        assert_se(streq(t, ""));
        free(t);
        assert_se(p == NULL);

        assert_se(extract_first_word(&p, &t, ":", EXTRACT_DONT_COALESCE_SEPARATORS) == 0);
        assert_se(!t);
        assert_se(!p);

        p = "foo\\xbar";
        assert_se(extract_first_word(&p, &t, NULL, 0) > 0);
        assert_se(streq(t, "fooxbar"));
        free(t);
        assert_se(p == NULL);

        p = "foo\\xbar";
        assert_se(extract_first_word(&p, &t, NULL, EXTRACT_RETAIN_ESCAPE) > 0);
        assert_se(streq(t, "foo\\xbar"));
        free(t);
        assert_se(p == NULL);
}

static void test_extract_first_word_and_warn(void) {
        const char *p, *original;
        char *t;

        p = original = "foobar waldo";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 7);

        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"foobar\" \'waldo\'";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "foobar"));
        free(t);
        assert_se(p == original + 9);

        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "waldo"));
        free(t);
        assert_se(isempty(p));

        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) == 0);
        assert_se(!t);
        assert_se(isempty(p));

        p = original = "\"";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 1);

        p = original = "\'fooo";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\'fooo";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo"));
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "foo\ba\x6ar"));
        free(t);
        assert_se(isempty(p));

        p = original = " foo\\ba\\x6ar ";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "foobax6ar"));
        free(t);
        assert_se(isempty(p));

        p = original = "    f\\u00f6o \"pi\\U0001F4A9le\"   ";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "föo"));
        free(t);
        assert_se(p == original + 13);

        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "pi\360\237\222\251le"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo\\"));
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "foo"));
        free(t);
        assert_se(isempty(p));

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE, NULL, "fake", 1, original) == -EINVAL);
        assert_se(p == original + 5);

        p = original = "\"foo\\";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_QUOTES|EXTRACT_CUNESCAPE|EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "foo"));
        free(t);
        assert_se(isempty(p));

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_RELAX, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, 0, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "fooo\\ bar quux";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "fooo\\ bar"));
        free(t);
        assert_se(p == original + 10);

        p = original = "\\w+@\\K[\\d.]+";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "\\w+@\\K[\\d.]+"));
        free(t);
        assert_se(isempty(p));

        p = original = "\\w+\\b";
        assert_se(extract_first_word_and_warn(&p, &t, NULL, EXTRACT_CUNESCAPE, NULL, "fake", 1, original) > 0);
        assert_se(streq(t, "\\w+\b"));
        free(t);
        assert_se(isempty(p));
}

static void test_extract_many_words(void) {
        const char *p, *original;
        char *a, *b, *c;

        p = original = "foobar waldi piep";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c, NULL) == 3);
        assert_se(isempty(p));
        assert_se(streq_ptr(a, "foobar"));
        assert_se(streq_ptr(b, "waldi"));
        assert_se(streq_ptr(c, "piep"));
        free(a);
        free(b);
        free(c);

        p = original = "'foobar' wa\"ld\"i   ";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c, NULL) == 2);
        assert_se(isempty(p));
        assert_se(streq_ptr(a, "'foobar'"));
        assert_se(streq_ptr(b, "wa\"ld\"i"));
        assert_se(streq_ptr(c, NULL));
        free(a);
        free(b);

        p = original = "'foobar' wa\"ld\"i   ";
        assert_se(extract_many_words(&p, NULL, EXTRACT_QUOTES, &a, &b, &c, NULL) == 2);
        assert_se(isempty(p));
        assert_se(streq_ptr(a, "foobar"));
        assert_se(streq_ptr(b, "waldi"));
        assert_se(streq_ptr(c, NULL));
        free(a);
        free(b);

        p = original = "";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c, NULL) == 0);
        assert_se(isempty(p));
        assert_se(streq_ptr(a, NULL));
        assert_se(streq_ptr(b, NULL));
        assert_se(streq_ptr(c, NULL));

        p = original = "  ";
        assert_se(extract_many_words(&p, NULL, 0, &a, &b, &c, NULL) == 0);
        assert_se(isempty(p));
        assert_se(streq_ptr(a, NULL));
        assert_se(streq_ptr(b, NULL));
        assert_se(streq_ptr(c, NULL));

        p = original = "foobar";
        assert_se(extract_many_words(&p, NULL, 0, NULL) == 0);
        assert_se(p == original);

        p = original = "foobar waldi";
        assert_se(extract_many_words(&p, NULL, 0, &a, NULL) == 1);
        assert_se(p == original+7);
        assert_se(streq_ptr(a, "foobar"));
        free(a);

        p = original = "     foobar    ";
        assert_se(extract_many_words(&p, NULL, 0, &a, NULL) == 1);
        assert_se(isempty(p));
        assert_se(streq_ptr(a, "foobar"));
        free(a);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_extract_first_word();
        test_extract_first_word_and_warn();
        test_extract_many_words();

        return 0;
}

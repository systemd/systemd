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

#include <string.h>

#include "util.h"

static void test_streq_ptr(void) {
        assert(streq_ptr(NULL, NULL));
        assert(!streq_ptr("abc", "cdef"));
}

static void test_first_word(void) {
        assert(first_word("Hello", ""));
        assert(first_word("Hello", "Hello"));
        assert(first_word("Hello world", "Hello"));
        assert(first_word("Hello\tworld", "Hello"));
        assert(first_word("Hello\nworld", "Hello"));
        assert(first_word("Hello\rworld", "Hello"));
        assert(first_word("Hello ", "Hello"));

        assert(!first_word("Hello", "Hellooo"));
        assert(!first_word("Hello", "xxxxx"));
        assert(!first_word("Hellooo", "Hello"));
}

static void test_foreach_word_quoted(void) {
        char *w, *state;
        size_t l;
        const char test[] = "test a b c 'd' e '' '' hhh '' ''";
        printf("<%s>\n", test);
        FOREACH_WORD_QUOTED(w, l, test, state) {
                char *t;

                assert_se(t = strndup(w, l));
                printf("<%s>\n", t);
                free(t);
        }
}

static void test_default_term_for_tty(void) {
        puts(default_term_for_tty("/dev/tty23"));
        puts(default_term_for_tty("/dev/ttyS23"));
        puts(default_term_for_tty("/dev/tty0"));
        puts(default_term_for_tty("/dev/pty0"));
        puts(default_term_for_tty("/dev/pts/0"));
        puts(default_term_for_tty("/dev/console"));
        puts(default_term_for_tty("tty23"));
        puts(default_term_for_tty("ttyS23"));
        puts(default_term_for_tty("tty0"));
        puts(default_term_for_tty("pty0"));
        puts(default_term_for_tty("pts/0"));
        puts(default_term_for_tty("console"));
}

int main(int argc, char *argv[]) {
        test_streq_ptr();
        test_first_word();
        test_default_term_for_tty();
        test_foreach_word_quoted();

        return 0;
}

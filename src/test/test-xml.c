/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <stdarg.h>

#include "alloc-util.h"
#include "string-util.h"
#include "util.h"
#include "xml.h"

static void test_one(const char *data, ...) {
        void *state = NULL;
        va_list ap;

        va_start(ap, data);

        for (;;) {
                _cleanup_free_ char *name = NULL;
                int t, tt;
                const char *nn;

                t = xml_tokenize(&data, &name, &state, NULL);
                assert_se(t >= 0);

                tt = va_arg(ap, int);
                assert_se(tt >= 0);

                assert_se(t == tt);
                if (t == XML_END)
                        break;

                nn = va_arg(ap, const char *);
                assert_se(streq_ptr(nn, name));
        }

        va_end(ap);
}

int main(int argc, char *argv[]) {

        test_one("", XML_END);

        test_one("<foo></foo>",
                 XML_TAG_OPEN, "foo",
                 XML_TAG_CLOSE, "foo",
                 XML_END);

        test_one("<foo waldo=piep meh=\"huhu\"/>",
                 XML_TAG_OPEN, "foo",
                 XML_ATTRIBUTE_NAME, "waldo",
                 XML_ATTRIBUTE_VALUE, "piep",
                 XML_ATTRIBUTE_NAME, "meh",
                 XML_ATTRIBUTE_VALUE, "huhu",
                 XML_TAG_CLOSE_EMPTY, NULL,
                 XML_END);

        test_one("xxxx\n"
                 "<foo><?xml foo?>     <!-- zzzz -->  </foo>",
                 XML_TEXT, "xxxx\n",
                 XML_TAG_OPEN, "foo",
                 XML_TEXT, "     ",
                 XML_TEXT, "  ",
                 XML_TAG_CLOSE, "foo",
                 XML_END);

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>

#include "alloc-util.h"
#include "string-util.h"
#include "tests.h"
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
                ASSERT_STREQ(nn, name);
        }

        va_end(ap);
}

int main(int argc, char *argv[]) {

        test_setup_logging(LOG_DEBUG);

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

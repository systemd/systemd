/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "macro.h"
#include "string-util.h"
#include "xml.h"

enum {
        STATE_NULL,
        STATE_TEXT,
        STATE_TAG,
        STATE_ATTRIBUTE,
};

static void inc_lines(unsigned *line, const char *s, size_t n) {
        const char *p = s;

        if (!line)
                return;

        for (;;) {
                const char *f;

                f = memchr(p, '\n', n);
                if (!f)
                        return;

                n -= (f - p) + 1;
                p = f + 1;
                (*line)++;
        }
}

/* We don't actually do real XML here. We only read a simplistic
 * subset, that is a bit less strict that XML and lacks all the more
 * complex features, like entities, or namespaces. However, we do
 * support some HTML5-like simplifications */

int xml_tokenize(const char **p, char **name, void **state, unsigned *line) {
        const char *c, *e, *b;
        char *ret;
        int t;

        assert(p);
        assert(*p);
        assert(name);
        assert(state);

        t = PTR_TO_INT(*state);
        c = *p;

        if (t == STATE_NULL) {
                if (line)
                        *line = 1;
                t = STATE_TEXT;
        }

        for (;;) {
                if (*c == 0)
                        return XML_END;

                switch (t) {

                case STATE_TEXT: {
                        int x;

                        e = strchrnul(c, '<');
                        if (e > c) {
                                /* More text... */
                                ret = strndup(c, e - c);
                                if (!ret)
                                        return -ENOMEM;

                                inc_lines(line, c, e - c);

                                *name = ret;
                                *p = e;
                                *state = INT_TO_PTR(STATE_TEXT);

                                return XML_TEXT;
                        }

                        assert(*e == '<');
                        b = c + 1;

                        if (startswith(b, "!--")) {
                                /* A comment */
                                e = strstr(b + 3, "-->");
                                if (!e)
                                        return -EINVAL;

                                inc_lines(line, b, e + 3 - b);

                                c = e + 3;
                                continue;
                        }

                        if (*b == '?') {
                                /* Processing instruction */

                                e = strstr(b + 1, "?>");
                                if (!e)
                                        return -EINVAL;

                                inc_lines(line, b, e + 2 - b);

                                c = e + 2;
                                continue;
                        }

                        if (*b == '!') {
                                /* DTD */

                                e = strchr(b + 1, '>');
                                if (!e)
                                        return -EINVAL;

                                inc_lines(line, b, e + 1 - b);

                                c = e + 1;
                                continue;
                        }

                        if (*b == '/') {
                                /* A closing tag */
                                x = XML_TAG_CLOSE;
                                b++;
                        } else
                                x = XML_TAG_OPEN;

                        e = strpbrk(b, WHITESPACE "/>");
                        if (!e)
                                return -EINVAL;

                        ret = strndup(b, e - b);
                        if (!ret)
                                return -ENOMEM;

                        *name = ret;
                        *p = e;
                        *state = INT_TO_PTR(STATE_TAG);

                        return x;
                }

                case STATE_TAG:

                        b = c + strspn(c, WHITESPACE);
                        if (*b == 0)
                                return -EINVAL;

                        inc_lines(line, c, b - c);

                        e = b + strcspn(b, WHITESPACE "=/>");
                        if (e > b) {
                                /* An attribute */

                                ret = strndup(b, e - b);
                                if (!ret)
                                        return -ENOMEM;

                                *name = ret;
                                *p = e;
                                *state = INT_TO_PTR(STATE_ATTRIBUTE);

                                return XML_ATTRIBUTE_NAME;
                        }

                        if (startswith(b, "/>")) {
                                /* An empty tag */

                                *name = NULL; /* For empty tags we return a NULL name, the caller must be prepared for that */
                                *p = b + 2;
                                *state = INT_TO_PTR(STATE_TEXT);

                                return XML_TAG_CLOSE_EMPTY;
                        }

                        if (*b != '>')
                                return -EINVAL;

                        c = b + 1;
                        t = STATE_TEXT;
                        continue;

                case STATE_ATTRIBUTE:

                        if (*c == '=') {
                                c++;

                                if (IN_SET(*c, '\'', '\"')) {
                                        /* Tag with a quoted value */

                                        e = strchr(c+1, *c);
                                        if (!e)
                                                return -EINVAL;

                                        inc_lines(line, c, e - c);

                                        ret = strndup(c+1, e - c - 1);
                                        if (!ret)
                                                return -ENOMEM;

                                        *name = ret;
                                        *p = e + 1;
                                        *state = INT_TO_PTR(STATE_TAG);

                                        return XML_ATTRIBUTE_VALUE;

                                }

                                /* Tag with a value without quotes */

                                b = strpbrk(c, WHITESPACE ">");
                                if (!b)
                                        b = c;

                                ret = strndup(c, b - c);
                                if (!ret)
                                        return -ENOMEM;

                                *name = ret;
                                *p = b;
                                *state = INT_TO_PTR(STATE_TAG);
                                return XML_ATTRIBUTE_VALUE;
                        }

                        t = STATE_TAG;
                        continue;
                }

        }

        assert_not_reached("Bad state");
}

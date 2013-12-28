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

#include <string.h>

#include "util.h"
#include "xml.h"

enum {
        STATE_TEXT,
        STATE_TAG,
        STATE_ATTRIBUTE,
};

/* We don't actually do real XML here. We only read a simplistic
 * subset, that is a bit less strict that XML and lacks all the more
 * complex features, like entities, or namespaces. However, we do
 * support some HTML5-like simplifications */

int xml_tokenize(const char **p, char **name, void **state) {
        const char *c, *e, *b;
        char *ret;
        int t;

        assert(p);
        assert(*p);
        assert(name);
        assert(state);

        t = PTR_TO_INT(*state);
        c = *p;

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

                                c = e + 3;
                                continue;
                        }

                        if (*b == '?') {
                                /* Processing instruction */

                                e = strstr(b + 1, "?>");
                                if (!e)
                                        return -EINVAL;

                                c = e + 2;
                                continue;
                        }

                        if (*b == '!') {
                                /* DTD */

                                e = strchr(b + 1, '>');
                                if (!e)
                                        return -EINVAL;

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

                                if (*c == '\'' || *c == '\"') {
                                        /* Tag with a quoted value */

                                        e = strchr(c+1, *c);
                                        if (!e)
                                                return -EINVAL;

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

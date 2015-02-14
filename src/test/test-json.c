/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <math.h>

#include "util.h"
#include "json.h"

static void test_one(const char *data, ...) {
        void *state = NULL;
        va_list ap;

        va_start(ap, data);

        for (;;) {
                _cleanup_free_ char *str = NULL;
                union json_value v = {};
                int t, tt;

                t = json_tokenize(&data, &str, &v, &state, NULL);
                tt = va_arg(ap, int);

                assert_se(t == tt);

                if (t == JSON_END || t < 0)
                        break;

                else if (t == JSON_STRING) {
                        const char *nn;

                        nn = va_arg(ap, const char *);
                        assert_se(streq_ptr(nn, str));

                } else if (t == JSON_REAL) {
                        double d;

                        d = va_arg(ap, double);
                        assert_se(fabs(d - v.real) < 0.001);

                } else if (t == JSON_INTEGER) {
                        intmax_t i;

                        i = va_arg(ap, intmax_t);
                        assert_se(i == v.integer);

                } else if (t == JSON_BOOLEAN) {
                        bool b;

                        b = va_arg(ap, int);
                        assert_se(b == v.boolean);
                }
        }

        va_end(ap);
}

int main(int argc, char *argv[]) {

        test_one("x", -EINVAL);
        test_one("", JSON_END);
        test_one(" ", JSON_END);
        test_one("0", JSON_INTEGER, (intmax_t) 0, JSON_END);
        test_one("1234", JSON_INTEGER, (intmax_t) 1234, JSON_END);
        test_one("3.141", JSON_REAL, 3.141, JSON_END);
        test_one("0.0", JSON_REAL, 0.0, JSON_END);
        test_one("7e3", JSON_REAL, 7e3, JSON_END);
        test_one("-7e-3", JSON_REAL, -7e-3, JSON_END);
        test_one("true", JSON_BOOLEAN, true, JSON_END);
        test_one("false", JSON_BOOLEAN, false, JSON_END);
        test_one("null", JSON_NULL, JSON_END);
        test_one("{}", JSON_OBJECT_OPEN, JSON_OBJECT_CLOSE, JSON_END);
        test_one("\t {\n} \n", JSON_OBJECT_OPEN, JSON_OBJECT_CLOSE, JSON_END);
        test_one("[]", JSON_ARRAY_OPEN, JSON_ARRAY_CLOSE, JSON_END);
        test_one("\t [] \n\n", JSON_ARRAY_OPEN, JSON_ARRAY_CLOSE, JSON_END);
        test_one("\"\"", JSON_STRING, "", JSON_END);
        test_one("\"foo\"", JSON_STRING, "foo", JSON_END);
        test_one("\"foo\\nfoo\"", JSON_STRING, "foo\nfoo", JSON_END);
        test_one("{\"foo\" : \"bar\"}", JSON_OBJECT_OPEN, JSON_STRING, "foo", JSON_COLON, JSON_STRING, "bar", JSON_OBJECT_CLOSE, JSON_END);
        test_one("{\"foo\" : [true, false]}", JSON_OBJECT_OPEN, JSON_STRING, "foo", JSON_COLON, JSON_ARRAY_OPEN, JSON_BOOLEAN, true, JSON_COMMA, JSON_BOOLEAN, false, JSON_ARRAY_CLOSE, JSON_OBJECT_CLOSE, JSON_END);
        test_one("\"\xef\xbf\xbd\"", JSON_STRING, "\xef\xbf\xbd", JSON_END);
        test_one("\"\\ufffd\"", JSON_STRING, "\xef\xbf\xbd", JSON_END);
        test_one("\"\\uf\"", -EINVAL);
        test_one("\"\\ud800a\"", -EINVAL);
        test_one("\"\\udc00\\udc00\"", -EINVAL);
        test_one("\"\\ud801\\udc37\"", JSON_STRING, "\xf0\x90\x90\xb7", JSON_END);

        return 0;
}

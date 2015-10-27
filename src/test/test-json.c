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

#include "alloc-util.h"
#include "json.h"
#include "string-util.h"
#include "util.h"

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

typedef void (*Test)(JsonVariant *);

static void test_file(const char *data, Test test) {
        _cleanup_json_variant_unref_ JsonVariant *v = NULL;
        int r;

        r = json_parse(data, &v);
        assert_se(r == 0);
        assert_se(v != NULL);
        assert_se(v->type == JSON_VARIANT_OBJECT);

        if (test)
                test(v);
}

static void test_1(JsonVariant *v) {
        JsonVariant *p, *q;
        unsigned i;

        /* 3 keys + 3 values */
        assert_se(v->size == 6);

        /* has k */
        p = json_variant_value(v, "k");
        assert_se(p && p->type == JSON_VARIANT_STRING);

        /* k equals v */
        assert_se(streq(json_variant_string(p), "v"));

        /* has foo */
        p = json_variant_value(v, "foo");
        assert_se(p && p->type == JSON_VARIANT_ARRAY && p->size == 3);

        /* check  foo[0] = 1, foo[1] = 2, foo[2] = 3 */
        for (i = 0; i < 3; ++i) {
                q = json_variant_element(p, i);
                assert_se(q && q->type == JSON_VARIANT_INTEGER && json_variant_integer(q) == (i+1));
        }

        /* has bar */
        p = json_variant_value(v, "bar");
        assert_se(p && p->type == JSON_VARIANT_OBJECT && p->size == 2);

        /* zap is null */
        q = json_variant_value(p, "zap");
        assert_se(q && q->type == JSON_VARIANT_NULL);
}

static void test_2(JsonVariant *v) {
        JsonVariant *p, *q;

        /* 2 keys + 2 values */
        assert_se(v->size == 4);

        /* has mutant */
        p = json_variant_value(v, "mutant");
        assert_se(p && p->type == JSON_VARIANT_ARRAY && p->size == 4);

        /* mutant[0] == 1 */
        q = json_variant_element(p, 0);
        assert_se(q && q->type == JSON_VARIANT_INTEGER && json_variant_integer(q) == 1);

        /* mutant[1] == null */
        q = json_variant_element(p, 1);
        assert_se(q && q->type == JSON_VARIANT_NULL);

        /* mutant[2] == "1" */
        q = json_variant_element(p, 2);
        assert_se(q && q->type == JSON_VARIANT_STRING && streq(json_variant_string(q), "1"));

        /* mutant[3] == JSON_VARIANT_OBJECT */
        q = json_variant_element(p, 3);
        assert_se(q && q->type == JSON_VARIANT_OBJECT && q->size == 2);

        /* has 1 */
        p = json_variant_value(q, "1");
        assert_se(p && p->type == JSON_VARIANT_ARRAY && p->size == 2);

        /* "1"[0] == 1 */
        q = json_variant_element(p, 0);
        assert_se(q && q->type == JSON_VARIANT_INTEGER && json_variant_integer(q) == 1);

        /* "1"[1] == "1" */
        q = json_variant_element(p, 1);
        assert_se(q && q->type == JSON_VARIANT_STRING && streq(json_variant_string(q), "1"));

        /* has blah */
        p = json_variant_value(v, "blah");
        assert_se(p && p->type == JSON_VARIANT_REAL && fabs(json_variant_real(p) - 1.27) < 0.001);
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

        test_one("[1, 2]", JSON_ARRAY_OPEN, JSON_INTEGER, (intmax_t) 1, JSON_COMMA, JSON_INTEGER, (intmax_t) 2, JSON_ARRAY_CLOSE, JSON_END);

        test_file("{\"k\": \"v\", \"foo\": [1, 2, 3], \"bar\": {\"zap\": null}}", test_1);
        test_file("{\"mutant\": [1, null, \"1\", {\"1\": [1, \"1\"]}], \"blah\": 1.27}", test_2);

        return 0;
}

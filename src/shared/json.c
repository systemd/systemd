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

#include <sys/types.h>
#include <math.h>
#include "macro.h"
#include "utf8.h"
#include "json.h"

int json_variant_new(JsonVariant **ret, JsonVariantType type) {
        JsonVariant *v;

        v = new0(JsonVariant, 1);
        if (!v)
                return -ENOMEM;
        v->type = type;
        *ret = v;
        return 0;
}

static int json_variant_deep_copy(JsonVariant *ret, JsonVariant *variant) {
        int r;

        assert(ret);
        assert(variant);

        ret->type = variant->type;
        ret->size = variant->size;

        if (variant->type == JSON_VARIANT_STRING) {
                ret->string = memdup(variant->string, variant->size+1);
                if (!ret->string)
                        return -ENOMEM;
        } else if (variant->type == JSON_VARIANT_ARRAY || variant->type == JSON_VARIANT_OBJECT) {
                size_t i;

                ret->objects = new0(JsonVariant, variant->size);
                if (!ret->objects)
                        return -ENOMEM;

                for (i = 0; i < variant->size; ++i) {
                        r = json_variant_deep_copy(&ret->objects[i], &variant->objects[i]);
                        if (r < 0)
                                return r;
                }
        } else
                ret->value = variant->value;

        return 0;
}

static JsonVariant *json_object_unref(JsonVariant *variant);

static JsonVariant *json_variant_unref_inner(JsonVariant *variant) {
        if (!variant)
                return NULL;

        if (variant->type == JSON_VARIANT_ARRAY || variant->type == JSON_VARIANT_OBJECT)
                return json_object_unref(variant);
        else if (variant->type == JSON_VARIANT_STRING)
                free(variant->string);

        return NULL;
}

static JsonVariant *json_raw_unref(JsonVariant *variant, size_t size) {
        if (!variant)
                return NULL;

        for (size_t i = 0; i < size; ++i)
                json_variant_unref_inner(&variant[i]);

        free(variant);
        return NULL;
}

static JsonVariant *json_object_unref(JsonVariant *variant) {
        size_t i;

        assert(variant);

        if (!variant->objects)
                return NULL;

        for (i = 0; i < variant->size; ++i)
                json_variant_unref_inner(&variant->objects[i]);

        free(variant->objects);
        return NULL;
}

static JsonVariant **json_variant_array_unref(JsonVariant **variant) {
        size_t i = 0;
        JsonVariant *p = NULL;

        if (!variant)
                return NULL;

        while((p = (variant[i++])) != NULL) {
                if (p->type == JSON_VARIANT_STRING)
                       free(p->string);
                free(p);
        }

        free(variant);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonVariant **, json_variant_array_unref);

JsonVariant *json_variant_unref(JsonVariant *variant) {
        if (!variant)
                return NULL;

        if (variant->type == JSON_VARIANT_ARRAY || variant->type == JSON_VARIANT_OBJECT)
                json_object_unref(variant);
        else if (variant->type == JSON_VARIANT_STRING)
                free(variant->string);

        free(variant);

        return NULL;
}

char *json_variant_string(JsonVariant *variant){
        assert(variant);
        assert(variant->type == JSON_VARIANT_STRING);

        return variant->string;
}

bool json_variant_bool(JsonVariant *variant) {
        assert(variant);
        assert(variant->type == JSON_VARIANT_BOOLEAN);

        return variant->value.boolean;
}

intmax_t json_variant_integer(JsonVariant *variant) {
        assert(variant);
        assert(variant->type == JSON_VARIANT_INTEGER);

        return variant->value.integer;
}

double json_variant_real(JsonVariant *variant) {
        assert(variant);
        assert(variant->type == JSON_VARIANT_REAL);

        return variant->value.real;
}

JsonVariant *json_variant_element(JsonVariant *variant, unsigned index) {
        assert(variant);
        assert(variant->type == JSON_VARIANT_ARRAY || variant->type == JSON_VARIANT_OBJECT);
        assert(index < variant->size);
        assert(variant->objects);

        return &variant->objects[index];
}

JsonVariant *json_variant_value(JsonVariant *variant, const char *key) {
        size_t i;

        assert(variant);
        assert(variant->type == JSON_VARIANT_OBJECT);
        assert(variant->objects);

        for (i = 0; i < variant->size; i += 2) {
                JsonVariant *p = &variant->objects[i];
                if (p->type == JSON_VARIANT_STRING && streq(key, p->string))
                        return &variant->objects[i + 1];
        }

        return NULL;
}

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

static int unhex_ucs2(const char *c, uint16_t *ret) {
        int aa, bb, cc, dd;
        uint16_t x;

        assert(c);
        assert(ret);

        aa = unhexchar(c[0]);
        if (aa < 0)
                return -EINVAL;

        bb = unhexchar(c[1]);
        if (bb < 0)
                return -EINVAL;

        cc = unhexchar(c[2]);
        if (cc < 0)
                return -EINVAL;

        dd = unhexchar(c[3]);
        if (dd < 0)
                return -EINVAL;

        x =     ((uint16_t) aa << 12) |
                ((uint16_t) bb << 8) |
                ((uint16_t) cc << 4) |
                ((uint16_t) dd);

        if (x <= 0)
                return -EINVAL;

        *ret = x;

        return 0;
}

static int json_parse_string(const char **p, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t n = 0, allocated = 0;
        const char *c;

        assert(p);
        assert(*p);
        assert(ret);

        c = *p;

        if (*c != '"')
                return -EINVAL;

        c++;

        for (;;) {
                int len;

                /* Check for EOF */
                if (*c == 0)
                        return -EINVAL;

                /* Check for control characters 0x00..0x1f */
                if (*c > 0 && *c < ' ')
                        return -EINVAL;

                /* Check for control character 0x7f */
                if (*c == 0x7f)
                        return -EINVAL;

                if (*c == '"') {
                        if (!s) {
                                s = strdup("");
                                if (!s)
                                        return -ENOMEM;
                        } else
                                s[n] = 0;

                        *p = c + 1;

                        *ret = s;
                        s = NULL;
                        return JSON_STRING;
                }

                if (*c == '\\') {
                        char ch = 0;
                        c++;

                        if (*c == 0)
                                return -EINVAL;

                        if (IN_SET(*c, '"', '\\', '/'))
                                ch = *c;
                        else if (*c == 'b')
                                ch = '\b';
                        else if (*c == 'f')
                                ch = '\f';
                        else if (*c == 'n')
                                ch = '\n';
                        else if (*c == 'r')
                                ch = '\r';
                        else if (*c == 't')
                                ch = '\t';
                        else if (*c == 'u') {
                                uint16_t x;
                                int r;

                                r = unhex_ucs2(c + 1, &x);
                                if (r < 0)
                                        return r;

                                c += 5;

                                if (!GREEDY_REALLOC(s, allocated, n + 4))
                                        return -ENOMEM;

                                if (!utf16_is_surrogate(x))
                                        n += utf8_encode_unichar(s + n, x);
                                else if (utf16_is_trailing_surrogate(x))
                                        return -EINVAL;
                                else {
                                        uint16_t y;

                                        if (c[0] != '\\' || c[1] != 'u')
                                                return -EINVAL;

                                        r = unhex_ucs2(c + 2, &y);
                                        if (r < 0)
                                                return r;

                                        c += 6;

                                        if (!utf16_is_trailing_surrogate(y))
                                                return -EINVAL;

                                        n += utf8_encode_unichar(s + n, utf16_surrogate_pair_to_unichar(x, y));
                                }

                                continue;
                        } else
                                return -EINVAL;

                        if (!GREEDY_REALLOC(s, allocated, n + 2))
                                return -ENOMEM;

                        s[n++] = ch;
                        c ++;
                        continue;
                }

                len = utf8_encoded_valid_unichar(c);
                if (len < 0)
                        return len;

                if (!GREEDY_REALLOC(s, allocated, n + len + 1))
                        return -ENOMEM;

                memcpy(s + n, c, len);
                n += len;
                c += len;
        }
}

static int json_parse_number(const char **p, union json_value *ret) {
        bool negative = false, exponent_negative = false, is_double = false;
        double x = 0.0, y = 0.0, exponent = 0.0, shift = 1.0;
        intmax_t i = 0;
        const char *c;

        assert(p);
        assert(*p);
        assert(ret);

        c = *p;

        if (*c == '-') {
                negative = true;
                c++;
        }

        if (*c == '0')
                c++;
        else {
                if (!strchr("123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        if (!is_double) {
                                int64_t t;

                                t = 10 * i + (*c - '0');
                                if (t < i) /* overflow */
                                        is_double = false;
                                else
                                        i = t;
                        }

                        x = 10.0 * x + (*c - '0');
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (*c == '.') {
                is_double = true;
                c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        y = 10.0 * y + (*c - '0');
                        shift = 10.0 * shift;
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (*c == 'e' || *c == 'E') {
                is_double = true;
                c++;

                if (*c == '-') {
                        exponent_negative = true;
                        c++;
                } else if (*c == '+')
                        c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        exponent = 10.0 * exponent + (*c - '0');
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        *p = c;

        if (is_double) {
                ret->real = ((negative ? -1.0 : 1.0) * (x + (y / shift))) * exp10((exponent_negative ? -1.0 : 1.0) * exponent);
                return JSON_REAL;
        } else {
                ret->integer = negative ? -i : i;
                return JSON_INTEGER;
        }
}

int json_tokenize(
                const char **p,
                char **ret_string,
                union json_value *ret_value,
                void **state,
                unsigned *line) {

        const char *c;
        int t;
        int r;

        enum {
                STATE_NULL,
                STATE_VALUE,
                STATE_VALUE_POST,
        };

        assert(p);
        assert(*p);
        assert(ret_string);
        assert(ret_value);
        assert(state);

        t = PTR_TO_INT(*state);
        c = *p;

        if (t == STATE_NULL) {
                if (line)
                        *line = 1;
                t = STATE_VALUE;
        }

        for (;;) {
                const char *b;

                b = c + strspn(c, WHITESPACE);
                if (*b == 0)
                        return JSON_END;

                inc_lines(line, c, b - c);
                c = b;

                switch (t) {

                case STATE_VALUE:

                        if (*c == '{') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_OBJECT_OPEN;

                        } else if (*c == '}') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_OBJECT_CLOSE;

                        } else if (*c == '[') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_ARRAY_OPEN;

                        } else if (*c == ']') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_ARRAY_CLOSE;

                        } else if (*c == '"') {
                                r = json_parse_string(&c, ret_string);
                                if (r < 0)
                                        return r;

                                *ret_value = JSON_VALUE_NULL;
                                *p = c;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return r;

                        } else if (strchr("-0123456789", *c)) {
                                r = json_parse_number(&c, ret_value);
                                if (r < 0)
                                        return r;

                                *ret_string = NULL;
                                *p = c;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return r;

                        } else if (startswith(c, "true")) {
                                *ret_string = NULL;
                                ret_value->boolean = true;
                                *p = c + 4;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_BOOLEAN;

                        } else if (startswith(c, "false")) {
                                *ret_string = NULL;
                                ret_value->boolean = false;
                                *p = c + 5;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_BOOLEAN;

                        } else if (startswith(c, "null")) {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 4;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_NULL;

                        } else
                                return -EINVAL;

                case STATE_VALUE_POST:

                        if (*c == ':') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_COLON;
                        } else if (*c == ',') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE);
                                return JSON_COMMA;
                        } else if (*c == '}') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_OBJECT_CLOSE;
                        } else if (*c == ']') {
                                *ret_string = NULL;
                                *ret_value = JSON_VALUE_NULL;
                                *p = c + 1;
                                *state = INT_TO_PTR(STATE_VALUE_POST);
                                return JSON_ARRAY_CLOSE;
                        } else
                                return -EINVAL;
                }

        }
}

static bool json_is_value(JsonVariant *var) {
        assert(var);

        return var->type != JSON_VARIANT_CONTROL;
}

static int json_scoped_parse(JsonVariant **tokens, size_t *i, size_t n, JsonVariant *scope) {
        bool arr = scope->type == JSON_VARIANT_ARRAY;
        int terminator = arr ? JSON_ARRAY_CLOSE : JSON_OBJECT_CLOSE;
        size_t allocated = 0, size = 0;
        JsonVariant *key = NULL, *value = NULL, *var = NULL, *items = NULL;
        enum {
                STATE_KEY,
                STATE_COLON,
                STATE_COMMA,
                STATE_VALUE
        } state = arr ? STATE_VALUE : STATE_KEY;

        assert(tokens);
        assert(i);
        assert(scope);

        while((var = *i < n ? tokens[(*i)++] : NULL) != NULL) {
                bool stopper;
                int r;

                stopper = !json_is_value(var) && var->value.integer == terminator;

                if (stopper) {
                        if (state != STATE_COMMA && size > 0)
                                goto error;

                        goto out;
                }

                if (state == STATE_KEY) {
                        if (var->type != JSON_VARIANT_STRING)
                                goto error;
                        else {
                                key = var;
                                state = STATE_COLON;
                        }
                }
                else if (state == STATE_COLON) {
                        if (key == NULL)
                                goto error;

                        if (json_is_value(var))
                                goto error;

                        if (var->value.integer != JSON_COLON)
                                goto error;

                        state = STATE_VALUE;
                }
                else if (state == STATE_VALUE) {
                        _cleanup_json_variant_unref_ JsonVariant *v = NULL;
                        size_t toadd = arr ? 1 : 2;

                        if (!json_is_value(var)) {
                                int type = (var->value.integer == JSON_ARRAY_OPEN) ? JSON_VARIANT_ARRAY : JSON_VARIANT_OBJECT;

                                r = json_variant_new(&v, type);
                                if (r < 0)
                                        goto error;

                                r = json_scoped_parse(tokens, i, n, v);
                                if (r < 0)
                                        goto error;

                                value = v;
                        }
                        else
                                value = var;

                        if(!GREEDY_REALLOC(items, allocated, size + toadd))
                                goto error;

                        if (arr) {
                                r = json_variant_deep_copy(&items[size], value);
                                if (r < 0)
                                        goto error;
                        } else {
                                r = json_variant_deep_copy(&items[size], key);
                                if (r < 0)
                                        goto error;

                                r = json_variant_deep_copy(&items[size+1], value);
                                if (r < 0)
                                        goto error;
                        }

                        size += toadd;
                        state = STATE_COMMA;
                }
                else if (state == STATE_COMMA) {
                        if (json_is_value(var))
                                goto error;

                        if (var->value.integer != JSON_COMMA)
                                goto error;

                        key = NULL;
                        value = NULL;

                        state = arr ? STATE_VALUE : STATE_KEY;
                }
        }

error:
        json_raw_unref(items, size);
        return -EBADMSG;

out:
        scope->size = size;
        scope->objects = items;

        return scope->type;
}

static int json_parse_tokens(JsonVariant **tokens, size_t ntokens, JsonVariant **rv) {
        size_t it = 0;
        int r;
        JsonVariant *e;
        _cleanup_json_variant_unref_ JsonVariant *p = NULL;

        assert(tokens);
        assert(ntokens);

        e = tokens[it++];
        r = json_variant_new(&p, JSON_VARIANT_OBJECT);
        if (r < 0)
                return r;

        if (e->type != JSON_VARIANT_CONTROL && e->value.integer != JSON_OBJECT_OPEN)
                return -EBADMSG;

        r = json_scoped_parse(tokens, &it, ntokens, p);
        if (r < 0)
                return r;

        *rv = p;
        p = NULL;

        return 0;
}

static int json_tokens(const char *string, size_t size, JsonVariant ***tokens, size_t *n) {
        _cleanup_free_ char *buf = NULL;
        _cleanup_(json_variant_array_unrefp) JsonVariant **items = NULL;
        union json_value v = {};
        void *json_state = NULL;
        const char *p;
        int t, r;
        size_t allocated = 0, s = 0;

        assert(string);
        assert(n);

        if (size <= 0)
                return -EBADMSG;

        buf = strndup(string, size);
        if (!buf)
                return -ENOMEM;

        p = buf;
        for (;;) {
                _cleanup_json_variant_unref_ JsonVariant *var = NULL;
                _cleanup_free_ char *rstr = NULL;

                t = json_tokenize(&p, &rstr, &v, &json_state, NULL);

                if (t < 0)
                        return t;
                else if (t == JSON_END)
                        break;

                if (t <= JSON_ARRAY_CLOSE) {
                        r = json_variant_new(&var, JSON_VARIANT_CONTROL);
                        if (r < 0)
                                return r;
                        var->value.integer = t;
                } else {
                        switch (t) {
                        case JSON_STRING:
                                r = json_variant_new(&var, JSON_VARIANT_STRING);
                                if (r < 0)
                                        return r;
                                var->size = strlen(rstr);
                                var->string = strdup(rstr);
                                if (!var->string) {
                                        return -ENOMEM;
                                }
                                break;
                        case JSON_INTEGER:
                                r = json_variant_new(&var, JSON_VARIANT_INTEGER);
                                if (r < 0)
                                        return r;
                                var->value = v;
                                break;
                        case JSON_REAL:
                                r = json_variant_new(&var, JSON_VARIANT_REAL);
                                if (r < 0)
                                        return r;
                                var->value = v;
                                break;
                        case JSON_BOOLEAN:
                                r = json_variant_new(&var, JSON_VARIANT_BOOLEAN);
                                if (r < 0)
                                        return r;
                                var->value = v;
                                break;
                        case JSON_NULL:
                                r = json_variant_new(&var, JSON_VARIANT_NULL);
                                if (r < 0)
                                        return r;
                                break;
                        }
                }

                if (!GREEDY_REALLOC(items, allocated, s+2))
                        return -ENOMEM;

                items[s++] = var;
                items[s] = NULL;
                var = NULL;
        }

        *n = s;
        *tokens = items;
        items = NULL;

        return 0;
}

int json_parse(const char *string, JsonVariant **rv) {
        _cleanup_(json_variant_array_unrefp) JsonVariant **s = NULL;
        JsonVariant *v = NULL;
        size_t n = 0;
        int r;

        assert(string);
        assert(rv);

        r = json_tokens(string, strlen(string), &s, &n);
        if (r < 0)
                return r;

        r = json_parse_tokens(s, n, &v);
        if (r < 0)
                return r;

        *rv = v;
        return 0;
}

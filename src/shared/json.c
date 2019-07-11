/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "float.h"
#include "hexdecoct.h"
#include "json-internal.h"
#include "json.h"
#include "macro.h"
#include "memory-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "utf8.h"

/* Refuse putting together variants with a larger depth than 4K by default (as a protection against overflowing stacks
 * if code processes JSON objects recursively. Note that we store the depth in an uint16_t, hence make sure this
 * remains under 2^16.
 * The value was 16k, but it was discovered to be too high on llvm/x86-64. See also the issue #10738. */
#define DEPTH_MAX (4U*1024U)
assert_cc(DEPTH_MAX <= UINT16_MAX);

typedef struct JsonSource {
        /* When we parse from a file or similar, encodes the filename, to indicate the source of a json variant */
        size_t n_ref;
        unsigned max_line;
        unsigned max_column;
        char name[];
} JsonSource;

/* On x86-64 this whole structure should have a size of 6 * 64 bit = 48 bytes */
struct JsonVariant {
        union {
                /* We either maintain a reference counter for this variant itself, or we are embedded into an
                 * array/object, in which case only that surrounding object is ref-counted. (If 'embedded' is false,
                 * see below.) */
                size_t n_ref;

                /* If this JsonVariant is part of an array/object, then this field points to the surrounding
                 * JSON_VARIANT_ARRAY/JSON_VARIANT_OBJECT object. (If 'embedded' is true, see below.) */
                JsonVariant *parent;
        };

        /* If this was parsed from some file or buffer, this stores where from, as well as the source line/column */
        JsonSource *source;
        unsigned line, column;

        JsonVariantType type:5;

        /* A marker whether this variant is embedded into in array/object or not. If true, the 'parent' pointer above
         * is valid. If false, the 'n_ref' field above is valid instead. */
        bool is_embedded:1;

        /* In some conditions (for example, if this object is part of an array of strings or objects), we don't store
         * any data inline, but instead simply reference an external object and act as surrogate of it. In that case
         * this bool is set, and the external object is referenced through the .reference field below. */
        bool is_reference:1;

        /* While comparing two arrays, we use this for marking what we already have seen */
        bool is_marked:1;

        /* The current 'depth' of the JsonVariant, i.e. how many levels of member variants this has */
        uint16_t depth;

        union {
                /* For simple types we store the value in-line. */
                JsonValue value;

                /* For objects and arrays we store the number of elements immediately following */
                size_t n_elements;

                /* If is_reference as indicated above is set, this is where the reference object is actually stored. */
                JsonVariant *reference;

                /* Strings are placed immediately after the structure. Note that when this is a JsonVariant embedded
                 * into an array we might encode strings up to INLINE_STRING_LENGTH characters directly inside the
                 * element, while longer strings are stored as references. When this object is not embedded into an
                 * array, but stand-alone we allocate the right size for the whole structure, i.e. the array might be
                 * much larger than INLINE_STRING_LENGTH.
                 *
                 * Note that because we want to allocate arrays of the JsonVariant structure we specify [0] here,
                 * rather than the prettier []. If we wouldn't, then this char array would have undefined size, and so
                 * would the union and then the struct this is included in. And of structures with undefined size we
                 * can't allocate arrays (at least not easily). */
                char string[0];
        };
};

/* Inside string arrays we have a series of JasonVariant structures one after the other. In this case, strings longer
 * than INLINE_STRING_MAX are stored as references, and all shorter ones inline. (This means — on x86-64 — strings up
 * to 15 chars are stored within the array elements, and all others in separate allocations) */
#define INLINE_STRING_MAX (sizeof(JsonVariant) - offsetof(JsonVariant, string) - 1U)

/* Let's make sure this structure isn't increased in size accidentally. This check is only for our most relevant arch
 * (x86-64). */
#ifdef __x86_64__
assert_cc(sizeof(JsonVariant) == 48U);
assert_cc(INLINE_STRING_MAX == 15U);
#endif

static JsonSource* json_source_new(const char *name) {
        JsonSource *s;

        assert(name);

        s = malloc(offsetof(JsonSource, name) + strlen(name) + 1);
        if (!s)
                return NULL;

        *s = (JsonSource) {
                .n_ref = 1,
        };
        strcpy(s->name, name);

        return s;
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(JsonSource, json_source, mfree);

static bool json_source_equal(JsonSource *a, JsonSource *b) {
        if (a == b)
                return true;

        if (!a || !b)
                return false;

        return streq(a->name, b->name);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JsonSource*, json_source_unref);

/* There are four kind of JsonVariant* pointers:
 *
 *    1. NULL
 *    2. A 'regular' one, i.e. pointing to malloc() memory
 *    3. A 'magic' one, i.e. one of the special JSON_VARIANT_MAGIC_XYZ values, that encode a few very basic values directly in the pointer.
 *    4. A 'const string' one, i.e. a pointer to a const string.
 *
 * The four kinds of pointers can be discerned like this:
 *
 *    Detecting #1 is easy, just compare with NULL. Detecting #3 is similarly easy: all magic pointers are below
 *    _JSON_VARIANT_MAGIC_MAX (which is pretty low, within the first memory page, which is special on Linux and other
 *    OSes, as it is a faulting page). In order to discern #2 and #4 we check the lowest bit. If it's off it's #2,
 *    otherwise #4. This makes use of the fact that malloc() will return "maximum aligned" memory, which definitely
 *    means the pointer is even. This means we can use the uneven pointers to reference static strings, as long as we
 *    make sure that all static strings used like this are aligned to 2 (or higher), and that we mask the bit on
 *    access. The JSON_VARIANT_STRING_CONST() macro encodes strings as JsonVariant* pointers, with the bit set. */

static bool json_variant_is_magic(const JsonVariant *v) {
        if (!v)
                return false;

        return v < _JSON_VARIANT_MAGIC_MAX;
}

static bool json_variant_is_const_string(const JsonVariant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        /* A proper JsonVariant is aligned to whatever malloc() aligns things too, which is definitely not uneven. We
         * hence use all uneven pointers as indicators for const strings. */

        return (((uintptr_t) v) & 1) != 0;
}

static bool json_variant_is_regular(const JsonVariant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        return (((uintptr_t) v) & 1) == 0;
}

static JsonVariant *json_variant_dereference(JsonVariant *v) {

        /* Recursively dereference variants that are references to other variants */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (!v->is_reference)
                return v;

        return json_variant_dereference(v->reference);
}

static uint16_t json_variant_depth(JsonVariant *v) {

        v = json_variant_dereference(v);
        if (!v)
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        return v->depth;
}

static JsonVariant *json_variant_normalize(JsonVariant *v) {

        /* Converts json variants to their normalized form, i.e. fully dereferenced and wherever possible converted to
         * the "magic" version if there is one */

        if (!v)
                return NULL;

        v = json_variant_dereference(v);

        switch (json_variant_type(v)) {

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(v) ? JSON_VARIANT_MAGIC_TRUE : JSON_VARIANT_MAGIC_FALSE;

        case JSON_VARIANT_NULL:
                return JSON_VARIANT_MAGIC_NULL;

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_INTEGER : v;

        case JSON_VARIANT_UNSIGNED:
                return json_variant_unsigned(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_UNSIGNED : v;

        case JSON_VARIANT_REAL:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                return json_variant_real(v) == 0.0 ? JSON_VARIANT_MAGIC_ZERO_REAL : v;
#pragma GCC diagnostic pop

        case JSON_VARIANT_STRING:
                return isempty(json_variant_string(v)) ? JSON_VARIANT_MAGIC_EMPTY_STRING : v;

        case JSON_VARIANT_ARRAY:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_ARRAY : v;

        case JSON_VARIANT_OBJECT:
                return json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_OBJECT : v;

        default:
                return v;
        }
}

static JsonVariant *json_variant_conservative_normalize(JsonVariant *v) {

        /* Much like json_variant_normalize(), but won't simplify if the variant has a source/line location attached to
         * it, in order not to lose context */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (v->source || v->line > 0 || v->column > 0)
                return v;

        return json_variant_normalize(v);
}

static int json_variant_new(JsonVariant **ret, JsonVariantType type, size_t space) {
        JsonVariant *v;

        assert_return(ret, -EINVAL);

        v = malloc0(MAX(sizeof(JsonVariant),
                        offsetof(JsonVariant, value) + space));
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = type;

        *ret = v;
        return 0;
}

int json_variant_new_integer(JsonVariant **ret, intmax_t i) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);

        if (i == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_INTEGER;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_INTEGER, sizeof(i));
        if (r < 0)
                return r;

        v->value.integer = i;
        *ret = v;

        return 0;
}

int json_variant_new_unsigned(JsonVariant **ret, uintmax_t u) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (u == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_UNSIGNED;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_UNSIGNED, sizeof(u));
        if (r < 0)
                return r;

        v->value.unsig = u;
        *ret = v;

        return 0;
}

int json_variant_new_real(JsonVariant **ret, long double d) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
        if (d == 0.0) {
#pragma GCC diagnostic pop
                *ret = JSON_VARIANT_MAGIC_ZERO_REAL;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_REAL, sizeof(d));
        if (r < 0)
                return r;

        v->value.real = d;
        *ret = v;

        return 0;
}

int json_variant_new_boolean(JsonVariant **ret, bool b) {
        assert_return(ret, -EINVAL);

        if (b)
                *ret = JSON_VARIANT_MAGIC_TRUE;
        else
                *ret = JSON_VARIANT_MAGIC_FALSE;

        return 0;
}

int json_variant_new_null(JsonVariant **ret) {
        assert_return(ret, -EINVAL);

        *ret = JSON_VARIANT_MAGIC_NULL;
        return 0;
}

int json_variant_new_stringn(JsonVariant **ret, const char *s, size_t n) {
        JsonVariant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (!s) {
                assert_return(IN_SET(n, 0, (size_t) -1), -EINVAL);
                return json_variant_new_null(ret);
        }
        if (n == (size_t) -1) /* determine length automatically */
                n = strlen(s);
        else if (memchr(s, 0, n)) /* don't allow embedded NUL, as we can't express that in JSON */
                return -EINVAL;
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_STRING;
                return 0;
        }

        r = json_variant_new(&v, JSON_VARIANT_STRING, n + 1);
        if (r < 0)
                return r;

        memcpy(v->string, s, n);
        v->string[n] = 0;

        *ret = v;
        return 0;
}

static void json_variant_set(JsonVariant *a, JsonVariant *b) {
        assert(a);

        b = json_variant_dereference(b);
        if (!b) {
                a->type = JSON_VARIANT_NULL;
                return;
        }

        a->type = json_variant_type(b);
        switch (a->type) {

        case JSON_VARIANT_INTEGER:
                a->value.integer = json_variant_integer(b);
                break;

        case JSON_VARIANT_UNSIGNED:
                a->value.unsig = json_variant_unsigned(b);
                break;

        case JSON_VARIANT_REAL:
                a->value.real = json_variant_real(b);
                break;

        case JSON_VARIANT_BOOLEAN:
                a->value.boolean = json_variant_boolean(b);
                break;

        case JSON_VARIANT_STRING: {
                const char *s;

                assert_se(s = json_variant_string(b));

                /* Short strings we can store inline */
                if (strnlen(s, INLINE_STRING_MAX+1) <= INLINE_STRING_MAX) {
                        strcpy(a->string, s);
                        break;
                }

                /* For longer strings, use a reference… */
                _fallthrough_;
        }

        case JSON_VARIANT_ARRAY:
        case JSON_VARIANT_OBJECT:
                a->is_reference = true;
                a->reference = json_variant_ref(json_variant_conservative_normalize(b));
                break;

        case JSON_VARIANT_NULL:
                break;

        default:
                assert_not_reached("Unexpected variant type");
        }
}

static void json_variant_copy_source(JsonVariant *v, JsonVariant *from) {
        assert(v);
        assert(from);

        if (!json_variant_is_regular(from))
                return;

        v->line = from->line;
        v->column = from->column;
        v->source = json_source_ref(from->source);
}

int json_variant_new_array(JsonVariant **ret, JsonVariant **array, size_t n) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(array, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements,
                        *c = array[v->n_elements];
                uint16_t d;

                d = json_variant_depth(c);
                if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                        return -ELNRNG;
                if (d >= v->depth)
                        v->depth = d + 1;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                };

                json_variant_set(w, c);
                json_variant_copy_source(w, c);
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int json_variant_new_array_bytes(JsonVariant **ret, const void *p, size_t n) {
        JsonVariant *v;
        size_t i;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(p, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .n_elements = n,
                .depth = 1,
        };

        for (i = 0; i < n; i++) {
                JsonVariant *w = v + 1 + i;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = JSON_VARIANT_UNSIGNED,
                        .value.unsig = ((const uint8_t*) p)[i],
                };
        }

        *ret = v;
        return 0;
}

int json_variant_new_array_strv(JsonVariant **ret, char **l) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        size_t n;
        int r;

        assert(ret);

        n = strv_length(l);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_ARRAY,
                .depth = 1,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements;
                size_t k;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = JSON_VARIANT_STRING,
                };

                k = strlen(l[v->n_elements]);

                if (k > INLINE_STRING_MAX) {
                        /* If string is too long, store it as reference. */

                        r = json_variant_new_string(&w->reference, l[v->n_elements]);
                        if (r < 0)
                                return r;

                        w->is_reference = true;
                } else
                        memcpy(w->string, l[v->n_elements], k+1);
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int json_variant_new_object(JsonVariant **ret, JsonVariant **array, size_t n) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_OBJECT;
                return 0;
        }
        assert_return(array, -EINVAL);
        assert_return(n % 2 == 0, -EINVAL);

        v = new(JsonVariant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (JsonVariant) {
                .n_ref = 1,
                .type = JSON_VARIANT_OBJECT,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                JsonVariant *w = v + 1 + v->n_elements,
                        *c = array[v->n_elements];
                uint16_t d;

                if ((v->n_elements & 1) == 0 &&
                    !json_variant_is_string(c))
                        return -EINVAL; /* Every second one needs to be a string, as it is the key name */

                d = json_variant_depth(c);
                if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                        return -ELNRNG;
                if (d >= v->depth)
                        v->depth = d + 1;

                *w = (JsonVariant) {
                        .is_embedded = true,
                        .parent = v,
                };

                json_variant_set(w, c);
                json_variant_copy_source(w, c);
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static void json_variant_free_inner(JsonVariant *v) {
        assert(v);

        if (!json_variant_is_regular(v))
                return;

        json_source_unref(v->source);

        if (v->is_reference) {
                json_variant_unref(v->reference);
                return;
        }

        if (IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT)) {
                size_t i;

                for (i = 0; i < v->n_elements; i++)
                        json_variant_free_inner(v + 1 + i);
        }
}

JsonVariant *json_variant_ref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return v;

        if (v->is_embedded)
                json_variant_ref(v->parent); /* ref the compounding variant instead */
        else {
                assert(v->n_ref > 0);
                v->n_ref++;
        }

        return v;
}

JsonVariant *json_variant_unref(JsonVariant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return NULL;

        if (v->is_embedded)
                json_variant_unref(v->parent);
        else {
                assert(v->n_ref > 0);
                v->n_ref--;

                if (v->n_ref == 0) {
                        json_variant_free_inner(v);
                        free(v);
                }
        }

        return NULL;
}

void json_variant_unref_many(JsonVariant **array, size_t n) {
        size_t i;

        assert(array || n == 0);

        for (i = 0; i < n; i++)
                json_variant_unref(array[i]);
}

const char *json_variant_string(JsonVariant *v) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return "";
        if (json_variant_is_magic(v))
                goto mismatch;
        if (json_variant_is_const_string(v)) {
                uintptr_t p = (uintptr_t) v;

                assert((p & 1) != 0);
                return (const char*) (p ^ 1U);
        }

        if (v->is_reference)
                return json_variant_string(v->reference);
        if (v->type != JSON_VARIANT_STRING)
                goto mismatch;

        return v->string;

mismatch:
        log_debug("Non-string JSON variant requested as string, returning NULL.");
        return NULL;
}

bool json_variant_boolean(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_TRUE)
                return true;
        if (v == JSON_VARIANT_MAGIC_FALSE)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != JSON_VARIANT_BOOLEAN)
                goto mismatch;
        if (v->is_reference)
                return json_variant_boolean(v->reference);

        return v->value.boolean;

mismatch:
        log_debug("Non-boolean JSON variant requested as boolean, returning false.");
        return false;
}

intmax_t json_variant_integer(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                return v->value.integer;

        case JSON_VARIANT_UNSIGNED:
                if (v->value.unsig <= INTMAX_MAX)
                        return (intmax_t) v->value.unsig;

                log_debug("Unsigned integer %ju requested as signed integer and out of range, returning 0.", v->value.unsig);
                return 0;

        case JSON_VARIANT_REAL: {
                intmax_t converted;

                converted = (intmax_t) v->value.real;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                if ((long double) converted == v->value.real)
#pragma GCC diagnostic pop
                        return converted;

                log_debug("Real %Lg requested as integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0;
}

uintmax_t json_variant_unsigned(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_integer(v->reference);

        switch (v->type) {

        case JSON_VARIANT_INTEGER:
                if (v->value.integer >= 0)
                        return (uintmax_t) v->value.integer;

                log_debug("Signed integer %ju requested as unsigned integer and out of range, returning 0.", v->value.integer);
                return 0;

        case JSON_VARIANT_UNSIGNED:
                return v->value.unsig;

        case JSON_VARIANT_REAL: {
                uintmax_t converted;

                converted = (uintmax_t) v->value.real;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                if ((long double) converted == v->value.real)
#pragma GCC diagnostic pop
                        return converted;

                log_debug("Real %Lg requested as unsigned integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as unsigned, returning 0.");
        return 0;
}

long double json_variant_real(JsonVariant *v) {
        if (!v)
                return 0.0;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0.0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_real(v->reference);

        switch (v->type) {

        case JSON_VARIANT_REAL:
                return v->value.real;

        case JSON_VARIANT_INTEGER: {
                long double converted;

                converted = (long double) v->value.integer;

                if ((intmax_t) converted == v->value.integer)
                        return converted;

                log_debug("Signed integer %ji requested as real, and cannot be converted losslessly, returning 0.", v->value.integer);
                return 0.0;
        }

        case JSON_VARIANT_UNSIGNED: {
                long double converted;

                converted = (long double) v->value.unsig;

                if ((uintmax_t) converted == v->value.unsig)
                        return converted;

                log_debug("Unsigned integer %ju requested as real, and cannot be converted losslessly, returning 0.", v->value.unsig);
                return 0.0;
        }

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0.0;
}

bool json_variant_is_negative(JsonVariant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return json_variant_is_negative(v->reference);

        /* This function is useful as checking whether numbers are negative is pretty complex since we have three types
         * of numbers. And some JSON code (OCI for example) uses negative numbers to mark "not defined" numeric
         * values. */

        switch (v->type) {

        case JSON_VARIANT_REAL:
                return v->value.real < 0;

        case JSON_VARIANT_INTEGER:
                return v->value.integer < 0;

        case JSON_VARIANT_UNSIGNED:
                return false;

        default:
                break;
        }

mismatch:
        log_debug("Non-integer JSON variant tested for negativity, returning false.");
        return false;
}

JsonVariantType json_variant_type(JsonVariant *v) {

        if (!v)
                return _JSON_VARIANT_TYPE_INVALID;

        if (json_variant_is_const_string(v))
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_TRUE || v == JSON_VARIANT_MAGIC_FALSE)
                return JSON_VARIANT_BOOLEAN;

        if (v == JSON_VARIANT_MAGIC_NULL)
                return JSON_VARIANT_NULL;

        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER)
                return JSON_VARIANT_INTEGER;

        if (v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED)
                return JSON_VARIANT_UNSIGNED;

        if (v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return JSON_VARIANT_REAL;

        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY)
                return JSON_VARIANT_ARRAY;

        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return JSON_VARIANT_OBJECT;

        return v->type;
}

bool json_variant_has_type(JsonVariant *v, JsonVariantType type) {
        JsonVariantType rt;

        v = json_variant_dereference(v);
        if (!v)
                return false;

        rt = json_variant_type(v);
        if (rt == type)
                return true;

        /* If it's a const string, then it only can be a string, and if it is not, it's not */
        if (json_variant_is_const_string(v))
                return false;

        /* All three magic zeroes qualify as integer, unsigned and as real */
        if ((v == JSON_VARIANT_MAGIC_ZERO_INTEGER || v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED || v == JSON_VARIANT_MAGIC_ZERO_REAL) &&
            IN_SET(type, JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL, JSON_VARIANT_NUMBER))
                return true;

        /* All other magic variant types are only equal to themselves */
        if (json_variant_is_magic(v))
                return false;

        /* Handle the "number" pseudo type */
        if (type == JSON_VARIANT_NUMBER)
                return IN_SET(rt, JSON_VARIANT_INTEGER, JSON_VARIANT_UNSIGNED, JSON_VARIANT_REAL);

        /* Integer conversions are OK in many cases */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_UNSIGNED)
                return v->value.integer >= 0;
        if (rt == JSON_VARIANT_UNSIGNED && type == JSON_VARIANT_INTEGER)
                return v->value.unsig <= INTMAX_MAX;

        /* Any integer that can be converted lossley to a real and back may also be considered a real */
        if (rt == JSON_VARIANT_INTEGER && type == JSON_VARIANT_REAL)
                return (intmax_t) (long double) v->value.integer == v->value.integer;
        if (rt == JSON_VARIANT_UNSIGNED && type == JSON_VARIANT_REAL)
                return (uintmax_t) (long double) v->value.unsig == v->value.unsig;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
        /* Any real that can be converted losslessly to an integer and back may also be considered an integer */
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_INTEGER)
                return (long double) (intmax_t) v->value.real == v->value.real;
        if (rt == JSON_VARIANT_REAL && type == JSON_VARIANT_UNSIGNED)
                return (long double) (uintmax_t) v->value.real == v->value.real;
#pragma GCC diagnostic pop

        return false;
}

size_t json_variant_elements(JsonVariant *v) {
        if (!v)
                return 0;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return json_variant_elements(v->reference);

        return v->n_elements;

mismatch:
        log_debug("Number of elements in non-array/non-object JSON variant requested, returning 0.");
        return 0;
}

JsonVariant *json_variant_by_index(JsonVariant *v, size_t idx) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return NULL;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, JSON_VARIANT_ARRAY, JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return json_variant_by_index(v->reference, idx);
        if (idx >= v->n_elements)
                return NULL;

        return json_variant_conservative_normalize(v + 1 + idx);

mismatch:
        log_debug("Element in non-array/non-object JSON variant requested by index, returning NULL.");
        return NULL;
}

JsonVariant *json_variant_by_key_full(JsonVariant *v, const char *key, JsonVariant **ret_key) {
        size_t i;

        if (!v)
                goto not_found;
        if (!key)
                goto not_found;
        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                goto not_found;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != JSON_VARIANT_OBJECT)
                goto mismatch;
        if (v->is_reference)
                return json_variant_by_key(v->reference, key);

        for (i = 0; i < v->n_elements; i += 2) {
                JsonVariant *p;

                p = json_variant_dereference(v + 1 + i);

                if (!json_variant_has_type(p, JSON_VARIANT_STRING))
                        continue;

                if (streq(json_variant_string(p), key)) {

                        if (ret_key)
                                *ret_key = json_variant_conservative_normalize(v + 1 + i);

                        return json_variant_conservative_normalize(v + 1 + i + 1);
                }
        }

not_found:
        if (ret_key)
                *ret_key = NULL;

        return NULL;

mismatch:
        log_debug("Element in non-object JSON variant requested by key, returning NULL.");
        if (ret_key)
                *ret_key = NULL;

        return NULL;
}

JsonVariant *json_variant_by_key(JsonVariant *v, const char *key) {
        return json_variant_by_key_full(v, key, NULL);
}

bool json_variant_equal(JsonVariant *a, JsonVariant *b) {
        JsonVariantType t;

        a = json_variant_normalize(a);
        b = json_variant_normalize(b);

        if (a == b)
                return true;

        t = json_variant_type(a);
        if (!json_variant_has_type(b, t))
                return false;

        switch (t) {

        case JSON_VARIANT_STRING:
                return streq(json_variant_string(a), json_variant_string(b));

        case JSON_VARIANT_INTEGER:
                return json_variant_integer(a) == json_variant_integer(b);

        case JSON_VARIANT_UNSIGNED:
                return json_variant_unsigned(a) == json_variant_unsigned(b);

        case JSON_VARIANT_REAL:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
                return json_variant_real(a) == json_variant_real(b);
#pragma GCC diagnostic pop

        case JSON_VARIANT_BOOLEAN:
                return json_variant_boolean(a) == json_variant_boolean(b);

        case JSON_VARIANT_NULL:
                return true;

        case JSON_VARIANT_ARRAY: {
                size_t i, n;

                n = json_variant_elements(a);
                if (n != json_variant_elements(b))
                        return false;

                for (i = 0; i < n; i++) {
                        if (!json_variant_equal(json_variant_by_index(a, i), json_variant_by_index(b, i)))
                                return false;
                }

                return true;
        }

        case JSON_VARIANT_OBJECT: {
                size_t i, n;

                n = json_variant_elements(a);
                if (n != json_variant_elements(b))
                        return false;

                /* Iterate through all keys in 'a' */
                for (i = 0; i < n; i += 2) {
                        bool found = false;
                        size_t j;

                        /* Match them against all keys in 'b' */
                        for (j = 0; j < n; j += 2) {
                                JsonVariant *key_b;

                                key_b = json_variant_by_index(b, j);

                                /* During the first iteration unmark everything */
                                if (i == 0)
                                        key_b->is_marked = false;
                                else if (key_b->is_marked) /* In later iterations if we already marked something, don't bother with it again */
                                        continue;

                                if (found)
                                        continue;

                                if (json_variant_equal(json_variant_by_index(a, i), key_b) &&
                                    json_variant_equal(json_variant_by_index(a, i+1), json_variant_by_index(b, j+1))) {
                                        /* Key and values match! */
                                        key_b->is_marked = found = true;

                                        /* In the first iteration we continue the inner loop since we want to mark
                                         * everything, otherwise exit the loop quickly after we found what we were
                                         * looking for. */
                                        if (i != 0)
                                                break;
                                }
                        }

                        if (!found)
                                return false;
                }

                return true;
        }

        default:
                assert_not_reached("Unknown variant type.");
        }
}

int json_variant_get_source(JsonVariant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column) {
        assert_return(v, -EINVAL);

        if (ret_source)
                *ret_source = json_variant_is_regular(v) && v->source ? v->source->name : NULL;

        if (ret_line)
                *ret_line = json_variant_is_regular(v) ? v->line : 0;

        if (ret_column)
                *ret_column = json_variant_is_regular(v) ? v->column : 0;

        return 0;
}

static int print_source(FILE *f, JsonVariant *v, JsonFormatFlags flags, bool whitespace) {
        size_t w, k;

        if (!FLAGS_SET(flags, JSON_FORMAT_SOURCE|JSON_FORMAT_PRETTY))
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        if (!v->source && v->line == 0 && v->column == 0)
                return 0;

        /* The max width we need to format the line numbers for this source file */
        w = (v->source && v->source->max_line > 0) ?
                DECIMAL_STR_WIDTH(v->source->max_line) :
                DECIMAL_STR_MAX(unsigned)-1;
        k = (v->source && v->source->max_column > 0) ?
                DECIMAL_STR_WIDTH(v->source->max_column) :
                DECIMAL_STR_MAX(unsigned) -1;

        if (whitespace) {
                size_t i, n;

                n = 1 + (v->source ? strlen(v->source->name) : 0) +
                        ((v->source && (v->line > 0 || v->column > 0)) ? 1 : 0) +
                        (v->line > 0 ? w : 0) +
                        (((v->source || v->line > 0) && v->column > 0) ? 1 : 0) +
                        (v->column > 0 ? k : 0) +
                        2;

                for (i = 0; i < n; i++)
                        fputc(' ', f);
        } else {
                fputc('[', f);

                if (v->source)
                        fputs(v->source->name, f);
                if (v->source && (v->line > 0 || v->column > 0))
                        fputc(':', f);
                if (v->line > 0)
                        fprintf(f, "%*u", (int) w, v->line);
                if ((v->source || v->line > 0) || v->column > 0)
                        fputc(':', f);
                if (v->column > 0)
                        fprintf(f, "%*u", (int) k, v->column);

                fputc(']', f);
                fputc(' ', f);
        }

        return 0;
}

static int json_format(FILE *f, JsonVariant *v, JsonFormatFlags flags, const char *prefix) {
        int r;

        assert(f);
        assert(v);

        switch (json_variant_type(v)) {

        case JSON_VARIANT_REAL: {
                locale_t loc;

                loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
                if (loc == (locale_t) 0)
                        return -errno;

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT_BLUE, f);

                fprintf(f, "%.*Le", DECIMAL_DIG, json_variant_real(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                freelocale(loc);
                break;
        }

        case JSON_VARIANT_INTEGER:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT_BLUE, f);

                fprintf(f, "%" PRIdMAX, json_variant_integer(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_UNSIGNED:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT_BLUE, f);

                fprintf(f, "%" PRIuMAX, json_variant_unsigned(v));

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_BOOLEAN:

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                if (json_variant_boolean(v))
                        fputs("true", f);
                else
                        fputs("false", f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                break;

        case JSON_VARIANT_NULL:
                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                fputs("null", f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case JSON_VARIANT_STRING: {
                const char *q;

                fputc('"', f);

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_GREEN, f);

                for (q = json_variant_string(v); *q; q++) {

                        switch (*q) {

                        case '"':
                                fputs("\\\"", f);
                                break;

                        case '\\':
                                fputs("\\\\", f);
                                break;

                        case '\b':
                                fputs("\\b", f);
                                break;

                        case '\f':
                                fputs("\\f", f);
                                break;

                        case '\n':
                                fputs("\\n", f);
                                break;

                        case '\r':
                                fputs("\\r", f);
                                break;

                        case '\t':
                                fputs("\\t", f);
                                break;

                        default:
                                if ((signed char) *q >= 0 && *q < ' ')
                                        fprintf(f, "\\u%04x", *q);
                                else
                                        fputc(*q, f);
                                break;
                        }
                }

                if (flags & JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                fputc('"', f);
                break;
        }

        case JSON_VARIANT_ARRAY: {
                size_t i, n;

                n = json_variant_elements(v);

                if (n == 0)
                        fputs("[]", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("[\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('[', f);
                        }

                        for (i = 0; i < n; i++) {
                                JsonVariant *e;

                                assert_se(e = json_variant_by_index(v, i));

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc(']', f);
                }
                break;
        }

        case JSON_VARIANT_OBJECT: {
                size_t i, n;

                n = json_variant_elements(v);

                if (n == 0)
                        fputs("{}", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("{\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('{', f);
                        }

                        for (i = 0; i < n; i += 2) {
                                JsonVariant *e;

                                e = json_variant_by_index(v, i);

                                if (i > 0) {
                                        if (flags & JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;

                                fputs(flags & JSON_FORMAT_PRETTY ? " : " : ":", f);

                                r = json_format(f, json_variant_by_index(v, i+1), flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc('}', f);
                }
                break;
        }

        default:
                assert_not_reached("Unexpected variant type.");
        }

        return 0;
}

int json_variant_format(JsonVariant *v, JsonFormatFlags flags, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t sz = 0;
        int r;

        /* Returns the length of the generated string (without the terminating NUL),
         * or negative on error. */

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        {
                _cleanup_fclose_ FILE *f = NULL;

                f = open_memstream_unlocked(&s, &sz);
                if (!f)
                        return -ENOMEM;

                json_variant_dump(v, flags, f, NULL);

                /* Add terminating 0, so that the output buffer is a valid string. */
                fputc('\0', f);

                r = fflush_and_check(f);
        }
        if (r < 0)
                return r;

        assert(s);
        *ret = TAKE_PTR(s);
        assert(sz > 0);
        return (int) sz - 1;
}

void json_variant_dump(JsonVariant *v, JsonFormatFlags flags, FILE *f, const char *prefix) {
        if (!v)
                return;

        if (!f)
                f = stdout;

        print_source(f, v, flags, false);

        if (((flags & (JSON_FORMAT_COLOR_AUTO|JSON_FORMAT_COLOR)) == JSON_FORMAT_COLOR_AUTO) && colors_enabled())
                flags |= JSON_FORMAT_COLOR;

        if (flags & JSON_FORMAT_SSE)
                fputs("data: ", f);
        if (flags & JSON_FORMAT_SEQ)
                fputc('\x1e', f); /* ASCII Record Separator */

        json_format(f, v, flags, prefix);

        if (flags & (JSON_FORMAT_PRETTY|JSON_FORMAT_SEQ|JSON_FORMAT_SSE|JSON_FORMAT_NEWLINE))
                fputc('\n', f);
        if (flags & JSON_FORMAT_SSE)
                fputc('\n', f); /* In case of SSE add a second newline */
}

static int json_variant_copy(JsonVariant **nv, JsonVariant *v) {
        JsonVariantType t;
        JsonVariant *c;
        JsonValue value;
        const void *source;
        size_t k;

        assert(nv);
        assert(v);

        /* Let's copy the simple types literally, and the larger types by references */
        t = json_variant_type(v);
        switch (t) {
        case JSON_VARIANT_INTEGER:
                k = sizeof(intmax_t);
                value.integer = json_variant_integer(v);
                source = &value;
                break;

        case JSON_VARIANT_UNSIGNED:
                k = sizeof(uintmax_t);
                value.unsig = json_variant_unsigned(v);
                source = &value;
                break;

        case JSON_VARIANT_REAL:
                k = sizeof(long double);
                value.real = json_variant_real(v);
                source = &value;
                break;

        case JSON_VARIANT_BOOLEAN:
                k = sizeof(bool);
                value.boolean = json_variant_boolean(v);
                source = &value;
                break;

        case JSON_VARIANT_NULL:
                k = 0;
                source = NULL;
                break;

        case JSON_VARIANT_STRING:
                source = json_variant_string(v);
                k = strnlen(source, INLINE_STRING_MAX + 1);
                if (k <= INLINE_STRING_MAX) {
                        k ++;
                        break;
                }

                _fallthrough_;

        default:
                /* Everything else copy by reference */

                c = malloc0(MAX(sizeof(JsonVariant),
                                offsetof(JsonVariant, reference) + sizeof(JsonVariant*)));
                if (!c)
                        return -ENOMEM;

                c->n_ref = 1;
                c->type = t;
                c->is_reference = true;
                c->reference = json_variant_ref(json_variant_normalize(v));

                *nv = c;
                return 0;
        }

        c = malloc0(MAX(sizeof(JsonVariant),
                        offsetof(JsonVariant, value) + k));
        if (!c)
                return -ENOMEM;

        c->n_ref = 1;
        c->type = t;

        memcpy_safe(&c->value, source, k);

        *nv = c;
        return 0;
}

static bool json_single_ref(JsonVariant *v) {

        /* Checks whether the caller is the single owner of the object, i.e. can get away with changing it */

        if (!json_variant_is_regular(v))
                return false;

        if (v->is_embedded)
                return json_single_ref(v->parent);

        assert(v->n_ref > 0);
        return v->n_ref == 1;
}

static int json_variant_set_source(JsonVariant **v, JsonSource *source, unsigned line, unsigned column) {
        JsonVariant *w;
        int r;

        assert(v);

        /* Patch in source and line/column number. Tries to do this in-place if the caller is the sole referencer of
         * the object. If not, allocates a new object, possibly a surrogate for the original one */

        if (!*v)
                return 0;

        if (source && line > source->max_line)
                source->max_line = line;
        if (source && column > source->max_column)
                source->max_column = column;

        if (!json_variant_is_regular(*v)) {

                if (!source && line == 0 && column == 0)
                        return 0;

        } else {
                if (json_source_equal((*v)->source, source) &&
                    (*v)->line == line &&
                    (*v)->column == column)
                        return 0;

                if (json_single_ref(*v)) { /* Sole reference? */
                        json_source_unref((*v)->source);
                        (*v)->source = json_source_ref(source);
                        (*v)->line = line;
                        (*v)->column = column;
                        return 1;
                }
        }

        r = json_variant_copy(&w, *v);
        if (r < 0)
                return r;

        assert(json_variant_is_regular(w));
        assert(!w->is_embedded);
        assert(w->n_ref == 1);
        assert(!w->source);

        w->source = json_source_ref(source);
        w->line = line;
        w->column = column;

        json_variant_unref(*v);
        *v = w;

        return 1;
}

static void inc_lines_columns(unsigned *line, unsigned *column, const char *s, size_t n) {
        assert(line);
        assert(column);
        assert(s || n == 0);

        while (n > 0) {
                if (*s == '\n') {
                        (*line)++;
                        *column = 1;
                } else if ((signed char) *s >= 0 && *s < 127) /* Process ASCII chars quickly */
                        (*column)++;
                else {
                        int w;

                        w = utf8_encoded_valid_unichar(s, n);
                        if (w < 0) /* count invalid unichars as normal characters */
                                w = 1;
                        else if ((size_t) w > n) /* never read more than the specified number of characters */
                                w = (int) n;

                        (*column)++;

                        s += w;
                        n -= w;
                        continue;
                }

                s++;
                n--;
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

                        *ret = TAKE_PTR(s);
                        return JSON_TOKEN_STRING;
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
                                char16_t x;
                                int r;

                                r = unhex_ucs2(c + 1, &x);
                                if (r < 0)
                                        return r;

                                c += 5;

                                if (!GREEDY_REALLOC(s, allocated, n + 5))
                                        return -ENOMEM;

                                if (!utf16_is_surrogate(x))
                                        n += utf8_encode_unichar(s + n, (char32_t) x);
                                else if (utf16_is_trailing_surrogate(x))
                                        return -EINVAL;
                                else {
                                        char16_t y;

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

                len = utf8_encoded_valid_unichar(c, (size_t) -1);
                if (len < 0)
                        return len;

                if (!GREEDY_REALLOC(s, allocated, n + len + 1))
                        return -ENOMEM;

                memcpy(s + n, c, len);
                n += len;
                c += len;
        }
}

static int json_parse_number(const char **p, JsonValue *ret) {
        bool negative = false, exponent_negative = false, is_real = false;
        long double x = 0.0, y = 0.0, exponent = 0.0, shift = 1.0;
        intmax_t i = 0;
        uintmax_t u = 0;
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
                        if (!is_real) {
                                if (negative) {

                                        if (i < INTMAX_MIN / 10) /* overflow */
                                                is_real = true;
                                        else {
                                                intmax_t t = 10 * i;

                                                if (t < INTMAX_MIN + (*c - '0')) /* overflow */
                                                        is_real = true;
                                                else
                                                        i = t - (*c - '0');
                                        }
                                } else {
                                        if (u > UINTMAX_MAX / 10) /* overflow */
                                                is_real = true;
                                        else {
                                                uintmax_t t = 10 * u;

                                                if (t > UINTMAX_MAX - (*c - '0')) /* overflow */
                                                        is_real = true;
                                                else
                                                        u = t + (*c - '0');
                                        }
                                }
                        }

                        x = 10.0 * x + (*c - '0');

                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (*c == '.') {
                is_real = true;
                c++;

                if (!strchr("0123456789", *c) || *c == 0)
                        return -EINVAL;

                do {
                        y = 10.0 * y + (*c - '0');
                        shift = 10.0 * shift;
                        c++;
                } while (strchr("0123456789", *c) && *c != 0);
        }

        if (IN_SET(*c, 'e', 'E')) {
                is_real = true;
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

        if (is_real) {
                ret->real = ((negative ? -1.0 : 1.0) * (x + (y / shift))) * exp10l((exponent_negative ? -1.0 : 1.0) * exponent);
                return JSON_TOKEN_REAL;
        } else if (negative) {
                ret->integer = i;
                return JSON_TOKEN_INTEGER;
        } else  {
                ret->unsig = u;
                return JSON_TOKEN_UNSIGNED;
        }
}

int json_tokenize(
                const char **p,
                char **ret_string,
                JsonValue *ret_value,
                unsigned *ret_line,   /* 'ret_line' returns the line at the beginning of this token */
                unsigned *ret_column,
                void **state,
                unsigned *line,       /* 'line' is used as a line state, it always reflect the line we are at after the token was read */
                unsigned *column) {

        unsigned start_line, start_column;
        const char *start, *c;
        size_t n;
        int t, r;

        enum {
                STATE_NULL,
                STATE_VALUE,
                STATE_VALUE_POST,
        };

        assert(p);
        assert(*p);
        assert(ret_string);
        assert(ret_value);
        assert(ret_line);
        assert(ret_column);
        assert(line);
        assert(column);
        assert(state);

        t = PTR_TO_INT(*state);
        if (t == STATE_NULL) {
                *line = 1;
                *column = 1;
                t = STATE_VALUE;
        }

        /* Skip over the whitespace */
        n = strspn(*p, WHITESPACE);
        inc_lines_columns(line, column, *p, n);
        c = *p + n;

        /* Remember where we started processing this token */
        start = c;
        start_line = *line;
        start_column = *column;

        if (*c == 0) {
                *ret_string = NULL;
                *ret_value = JSON_VALUE_NULL;
                r = JSON_TOKEN_END;
                goto finish;
        }

        switch (t) {

        case STATE_VALUE:

                if (*c == '{') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_OBJECT_OPEN;
                        goto null_return;

                } else if (*c == '}') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_OBJECT_CLOSE;
                        goto null_return;

                } else if (*c == '[') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_ARRAY_OPEN;
                        goto null_return;

                } else if (*c == ']') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_ARRAY_CLOSE;
                        goto null_return;

                } else if (*c == '"') {

                        r = json_parse_string(&c, ret_string);
                        if (r < 0)
                                return r;

                        *ret_value = JSON_VALUE_NULL;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        goto finish;

                } else if (strchr("-0123456789", *c)) {

                        r = json_parse_number(&c, ret_value);
                        if (r < 0)
                                return r;

                        *ret_string = NULL;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        goto finish;

                } else if (startswith(c, "true")) {
                        *ret_string = NULL;
                        ret_value->boolean = true;
                        c += 4;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_BOOLEAN;
                        goto finish;

                } else if (startswith(c, "false")) {
                        *ret_string = NULL;
                        ret_value->boolean = false;
                        c += 5;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_BOOLEAN;
                        goto finish;

                } else if (startswith(c, "null")) {
                        *ret_string = NULL;
                        *ret_value = JSON_VALUE_NULL;
                        c += 4;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_NULL;
                        goto finish;

                }

                return -EINVAL;

        case STATE_VALUE_POST:

                if (*c == ':') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_COLON;
                        goto null_return;

                } else if (*c == ',') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE);
                        r = JSON_TOKEN_COMMA;
                        goto null_return;

                } else if (*c == '}') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_OBJECT_CLOSE;
                        goto null_return;

                } else if (*c == ']') {
                        c++;
                        *state = INT_TO_PTR(STATE_VALUE_POST);
                        r = JSON_TOKEN_ARRAY_CLOSE;
                        goto null_return;
                }

                return -EINVAL;

        default:
                assert_not_reached("Unexpected tokenizer state");
        }

null_return:
        *ret_string = NULL;
        *ret_value = JSON_VALUE_NULL;

finish:
        inc_lines_columns(line, column, start, c - start);
        *p = c;

        *ret_line = start_line;
        *ret_column = start_column;

        return r;
}

typedef enum JsonExpect {
        /* The following values are used by json_parse() */
        EXPECT_TOPLEVEL,
        EXPECT_END,
        EXPECT_OBJECT_FIRST_KEY,
        EXPECT_OBJECT_NEXT_KEY,
        EXPECT_OBJECT_COLON,
        EXPECT_OBJECT_VALUE,
        EXPECT_OBJECT_COMMA,
        EXPECT_ARRAY_FIRST_ELEMENT,
        EXPECT_ARRAY_NEXT_ELEMENT,
        EXPECT_ARRAY_COMMA,

        /* And these are used by json_build() */
        EXPECT_ARRAY_ELEMENT,
        EXPECT_OBJECT_KEY,
} JsonExpect;

typedef struct JsonStack {
        JsonExpect expect;
        JsonVariant **elements;
        size_t n_elements, n_elements_allocated;
        unsigned line_before;
        unsigned column_before;
        size_t n_suppress; /* When building: if > 0, suppress this many subsequent elements. If == (size_t) -1, suppress all subsequent elements */
} JsonStack;

static void json_stack_release(JsonStack *s) {
        assert(s);

        json_variant_unref_many(s->elements, s->n_elements);
        s->elements = mfree(s->elements);
}

static int json_parse_internal(
                const char **input,
                JsonSource *source,
                JsonVariant **ret,
                unsigned *line,
                unsigned *column,
                bool continue_end) {

        size_t n_stack = 1, n_stack_allocated = 0, i;
        unsigned line_buffer = 0, column_buffer = 0;
        void *tokenizer_state = NULL;
        JsonStack *stack = NULL;
        const char *p;
        int r;

        assert_return(input, -EINVAL);
        assert_return(ret, -EINVAL);

        p = *input;

        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        if (!line)
                line = &line_buffer;
        if (!column)
                column = &column_buffer;

        for (;;) {
                _cleanup_(json_variant_unrefp) JsonVariant *add = NULL;
                _cleanup_free_ char *string = NULL;
                unsigned line_token, column_token;
                JsonStack *current;
                JsonValue value;
                int token;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                if (continue_end && current->expect == EXPECT_END)
                        goto done;

                token = json_tokenize(&p, &string, &value, &line_token, &column_token, &tokenizer_state, line, column);
                if (token < 0) {
                        r = token;
                        goto finish;
                }

                switch (token) {

                case JSON_TOKEN_END:
                        if (current->expect != EXPECT_END) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(current->n_elements == 1);
                        assert(n_stack == 1);
                        goto done;

                case JSON_TOKEN_COLON:

                        if (current->expect != EXPECT_OBJECT_COLON) {
                                r = -EINVAL;
                                goto finish;
                        }

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;

                case JSON_TOKEN_COMMA:

                        if (current->expect == EXPECT_OBJECT_COMMA)
                                current->expect = EXPECT_OBJECT_NEXT_KEY;
                        else if (current->expect == EXPECT_ARRAY_COMMA)
                                current->expect = EXPECT_ARRAY_NEXT_ELEMENT;
                        else {
                                r = -EINVAL;
                                goto finish;
                        }

                        break;

                case JSON_TOKEN_OBJECT_OPEN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        /* Prepare the expect for when we return from the child */
                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_FIRST_KEY,
                                .line_before = line_token,
                                .column_before = column_token,
                        };

                        current = stack + n_stack - 1;
                        break;

                case JSON_TOKEN_OBJECT_CLOSE:
                        if (!IN_SET(current->expect, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_COMMA)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_object(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        line_token = current->line_before;
                        column_token = current->column_before;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case JSON_TOKEN_ARRAY_OPEN:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        /* Prepare the expect for when we return from the child */
                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_FIRST_ELEMENT,
                                .line_before = line_token,
                                .column_before = column_token,
                        };

                        break;

                case JSON_TOKEN_ARRAY_CLOSE:
                        if (!IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_COMMA)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        r = json_variant_new_array(&add, current->elements, current->n_elements);
                        if (r < 0)
                                goto finish;

                        line_token = current->line_before;
                        column_token = current->column_before;

                        json_stack_release(current);
                        n_stack--, current--;
                        break;

                case JSON_TOKEN_STRING:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_NEXT_KEY, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_string(&add, string);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (IN_SET(current->expect, EXPECT_OBJECT_FIRST_KEY, EXPECT_OBJECT_NEXT_KEY))
                                current->expect = EXPECT_OBJECT_COLON;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_REAL:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_real(&add, value.real);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_INTEGER:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_integer(&add, value.integer);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_UNSIGNED:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_unsigned(&add, value.unsig);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_BOOLEAN:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_boolean(&add, value.boolean);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                case JSON_TOKEN_NULL:
                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        r = json_variant_new_null(&add);
                        if (r < 0)
                                goto finish;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_COMMA;
                        else {
                                assert(IN_SET(current->expect, EXPECT_ARRAY_FIRST_ELEMENT, EXPECT_ARRAY_NEXT_ELEMENT));
                                current->expect = EXPECT_ARRAY_COMMA;
                        }

                        break;

                default:
                        assert_not_reached("Unexpected token");
                }

                if (add) {
                        (void) json_variant_set_source(&add, source, line_token, column_token);

                        if (!GREEDY_REALLOC(current->elements, current->n_elements_allocated, current->n_elements + 1)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        *input = p;
        r = 0;

finish:
        for (i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

int json_parse(const char *input, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column) {
        return json_parse_internal(&input, NULL, ret, ret_line, ret_column, false);
}

int json_parse_continue(const char **p, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column) {
        return json_parse_internal(p, NULL, ret, ret_line, ret_column, true);
}

int json_parse_file(FILE *f, const char *path, JsonVariant **ret, unsigned *ret_line, unsigned *ret_column) {
        _cleanup_(json_source_unrefp) JsonSource *source = NULL;
        _cleanup_free_ char *text = NULL;
        const char *p;
        int r;

        if (f)
                r = read_full_stream(f, &text, NULL);
        else if (path)
                r = read_full_file(path, &text, NULL);
        else
                return -EINVAL;
        if (r < 0)
                return r;

        if (path) {
                source = json_source_new(path);
                if (!source)
                        return -ENOMEM;
        }

        p = text;
        return json_parse_internal(&p, source, ret, ret_line, ret_column, false);
}

int json_buildv(JsonVariant **ret, va_list ap) {
        JsonStack *stack = NULL;
        size_t n_stack = 1, n_stack_allocated = 0, i;
        int r;

        assert_return(ret, -EINVAL);

        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        for (;;) {
                _cleanup_(json_variant_unrefp) JsonVariant *add = NULL;
                size_t n_subtract = 0; /* how much to subtract from current->n_suppress, i.e. how many elements would
                                        * have been added to the current variant */
                JsonStack *current;
                int command;

                assert(n_stack > 0);
                current = stack + n_stack - 1;

                if (current->expect == EXPECT_END)
                        goto done;

                command = va_arg(ap, int);

                switch (command) {

                case _JSON_BUILD_STRING: {
                        const char *p;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_string(&add, p);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_INTEGER: {
                        intmax_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, intmax_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_integer(&add, j);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_UNSIGNED: {
                        uintmax_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, uintmax_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_unsigned(&add, j);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_REAL: {
                        long double d;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        d = va_arg(ap, long double);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_real(&add, d);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_BOOLEAN: {
                        bool b;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_boolean(&add, b);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_NULL:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (current->n_suppress == 0) {
                                r = json_variant_new_null(&add);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_VARIANT:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        /* Note that we don't care for current->n_suppress here, after all the variant is already
                         * allocated anyway... */
                        add = va_arg(ap, JsonVariant*);
                        if (!add)
                                add = JSON_VARIANT_MAGIC_NULL;
                        else
                                json_variant_ref(add);

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _JSON_BUILD_LITERAL: {
                        const char *l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, const char *);

                        if (l) {
                                /* Note that we don't care for current->n_suppress here, we should generate parsing
                                 * errors even in suppressed object properties */

                                r = json_parse(l, &add, NULL, NULL);
                                if (r < 0)
                                        goto finish;
                        } else
                                add = JSON_VARIANT_MAGIC_NULL;

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_ARRAY_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_ARRAY_ELEMENT,
                                .n_suppress = current->n_suppress != 0 ? (size_t) -1 : 0, /* if we shall suppress the
                                                                                           * new array, then we should
                                                                                           * also suppress all array
                                                                                           * members */
                        };

                        break;

                case _JSON_BUILD_ARRAY_END:
                        if (current->expect != EXPECT_ARRAY_ELEMENT) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_STRV: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_array_strv(&add, l);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;
                }

                case _JSON_BUILD_OBJECT_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack_allocated, n_stack+1)) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        current = stack + n_stack - 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        stack[n_stack++] = (JsonStack) {
                                .expect = EXPECT_OBJECT_KEY,
                                .n_suppress = current->n_suppress != 0 ? (size_t) -1 : 0, /* if we shall suppress the
                                                                                           * new object, then we should
                                                                                           * also suppress all object
                                                                                           * members */
                        };

                        break;

                case _JSON_BUILD_OBJECT_END:

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_object(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _JSON_BUILD_PAIR: {
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_PAIR_CONDITION: {
                        const char *n;
                        bool b;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);
                        n = va_arg(ap, const char *);

                        if (b && current->n_suppress == 0) {
                                r = json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1; /* we generated one item */

                        if (!b && current->n_suppress != (size_t) -1)
                                current->n_suppress += 2; /* Suppress this one and the next item */

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }}

                /* If a variant was generated, add it to our current variant, but only if we are not supposed to suppress additions */
                if (add && current->n_suppress == 0) {
                        if (!GREEDY_REALLOC(current->elements, current->n_elements_allocated, current->n_elements + 1)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                }

                /* If we are supposed to suppress items, let's subtract how many items where generated from that
                 * counter. Except if the counter is (size_t) -1, i.e. we shall suppress an infinite number of elements
                 * on this stack level */
                if (current->n_suppress != (size_t) -1) {
                        if (current->n_suppress <= n_subtract) /* Saturated */
                                current->n_suppress = 0;
                        else
                                current->n_suppress -= n_subtract;
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = json_variant_ref(stack[0].elements[0]);
        r = 0;

finish:
        for (i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

int json_build(JsonVariant **ret, ...) {
        va_list ap;
        int r;

        va_start(ap, ret);
        r = json_buildv(ret, ap);
        va_end(ap);

        return r;
}

int json_log_internal(
                JsonVariant *variant,
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) {

        PROTECT_ERRNO;

        unsigned source_line, source_column;
        char buffer[LINE_MAX];
        const char *source;
        va_list ap;
        int r;

        errno = ERRNO_VALUE(error);

        va_start(ap, format);
        (void) vsnprintf(buffer, sizeof buffer, format, ap);
        va_end(ap);

        if (variant) {
                r = json_variant_get_source(variant, &source, &source_line, &source_column);
                if (r < 0)
                        return r;
        } else {
                source = NULL;
                source_line = 0;
                source_column = 0;
        }

        if (source && source_line > 0 && source_column > 0)
                return log_struct_internal(
                                LOG_REALM_PLUS_LEVEL(LOG_REALM_SYSTEMD, level),
                                error,
                                file, line, func,
                                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                                "CONFIG_FILE=%s", source,
                                "CONFIG_LINE=%u", source_line,
                                "CONFIG_COLUMN=%u", source_column,
                                LOG_MESSAGE("%s:%u:%u: %s", source, source_line, source_column, buffer),
                                NULL);
        else
                return log_struct_internal(
                                LOG_REALM_PLUS_LEVEL(LOG_REALM_SYSTEMD, level),
                                error,
                                file, line, func,
                                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                                LOG_MESSAGE("%s", buffer),
                                NULL);
}

int json_dispatch(JsonVariant *v, const JsonDispatch table[], JsonDispatchCallback bad, JsonDispatchFlags flags, void *userdata) {
        const JsonDispatch *p;
        size_t i, n, m;
        int r, done = 0;
        bool *found;

        if (!json_variant_is_object(v)) {
                json_log(v, flags, 0, "JSON variant is not an object.");

                if (flags & JSON_PERMISSIVE)
                        return 0;

                return -EINVAL;
        }

        for (p = table, m = 0; p->name; p++)
                m++;

        found = newa0(bool, m);

        n = json_variant_elements(v);
        for (i = 0; i < n; i += 2) {
                JsonVariant *key, *value;

                assert_se(key = json_variant_by_index(v, i));
                assert_se(value = json_variant_by_index(v, i+1));

                for (p = table; p->name; p++)
                        if (p->name == (const char*) -1 ||
                            streq_ptr(json_variant_string(key), p->name))
                                break;

                if (p->name) { /* Found a matching entry! :-) */
                        JsonDispatchFlags merged_flags;

                        merged_flags = flags | p->flags;

                        if (p->type != _JSON_VARIANT_TYPE_INVALID &&
                            !json_variant_has_type(value, p->type)) {

                                json_log(value, merged_flags, 0,
                                         "Object field '%s' has wrong type %s, expected %s.", json_variant_string(key),
                                         json_variant_type_to_string(json_variant_type(value)), json_variant_type_to_string(p->type));

                                if (merged_flags & JSON_PERMISSIVE)
                                        continue;

                                return -EINVAL;
                        }

                        if (found[p-table]) {
                                json_log(value, merged_flags, 0, "Duplicate object field '%s'.", json_variant_string(key));

                                if (merged_flags & JSON_PERMISSIVE)
                                        continue;

                                return -ENOTUNIQ;
                        }

                        found[p-table] = true;

                        if (p->callback) {
                                r = p->callback(json_variant_string(key), value, merged_flags, (uint8_t*) userdata + p->offset);
                                if (r < 0) {
                                        if (merged_flags & JSON_PERMISSIVE)
                                                continue;

                                        return r;
                                }
                        }

                        done ++;

                } else { /* Didn't find a matching entry! :-( */

                        if (bad) {
                                r = bad(json_variant_string(key), value, flags, userdata);
                                if (r < 0) {
                                        if (flags & JSON_PERMISSIVE)
                                                continue;

                                        return r;
                                } else
                                        done ++;

                        } else  {
                                json_log(value, flags, 0, "Unexpected object field '%s'.", json_variant_string(key));

                                if (flags & JSON_PERMISSIVE)
                                        continue;

                                return -EADDRNOTAVAIL;
                        }
                }
        }

        for (p = table; p->name; p++) {
                JsonDispatchFlags merged_flags = p->flags | flags;

                if ((merged_flags & JSON_MANDATORY) && !found[p-table]) {
                        json_log(v, merged_flags, 0, "Missing object field '%s'.", p->name);

                        if ((merged_flags & JSON_PERMISSIVE))
                                continue;

                        return -ENXIO;
                }
        }

        return done;
}

int json_dispatch_boolean(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        bool *b = userdata;

        assert(variant);
        assert(b);

        if (!json_variant_is_boolean(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a boolean.", strna(name));

        *b = json_variant_boolean(variant);
        return 0;
}

int json_dispatch_tristate(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int *b = userdata;

        assert(variant);
        assert(b);

        if (!json_variant_is_boolean(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a boolean.", strna(name));

        *b = json_variant_boolean(variant);
        return 0;
}

int json_dispatch_integer(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        intmax_t *i = userdata;

        assert(variant);
        assert(i);

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        *i = json_variant_integer(variant);
        return 0;
}

int json_dispatch_unsigned(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        uintmax_t *u = userdata;

        assert(variant);
        assert(u);

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an unsigned integer.", strna(name));

        *u = json_variant_unsigned(variant);
        return 0;
}

int json_dispatch_uint32(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        uint32_t *u = userdata;

        assert(variant);
        assert(u);

        if (!json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an unsigned integer.", strna(name));

        if (json_variant_unsigned(variant) > UINT32_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *u = (uint32_t) json_variant_unsigned(variant);
        return 0;
}

int json_dispatch_int32(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        int32_t *i = userdata;

        assert(variant);
        assert(i);

        if (!json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        if (json_variant_integer(variant) < INT32_MIN || json_variant_integer(variant) > INT32_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *i = (int32_t) json_variant_integer(variant);
        return 0;
}

int json_dispatch_string(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        char **s = userdata;
        int r;

        assert(variant);
        assert(s);

        if (json_variant_is_null(variant)) {
                *s = mfree(*s);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = free_and_strdup(s, json_variant_string(variant));
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

int json_dispatch_strv(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        char ***s = userdata;
        JsonVariant *e;
        int r;

        assert(variant);
        assert(s);

        if (json_variant_is_null(variant)) {
                *s = strv_free(*s);
                return 0;
        }

        if (!json_variant_is_array(variant))
                return json_log(variant, SYNTHETIC_ERRNO(EINVAL), flags, "JSON field '%s' is not an array.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                if (!json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a string.");

                r = strv_extend(&l, json_variant_string(e));
                if (r < 0)
                        return json_log(e, flags, r, "Failed to append array element: %m");
        }

        strv_free_and_replace(*s, l);
        return 0;
}

int json_dispatch_variant(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        JsonVariant **p = userdata;

        assert(variant);
        assert(p);

        json_variant_unref(*p);
        *p = json_variant_ref(variant);

        return 0;
}

static const char* const json_variant_type_table[_JSON_VARIANT_TYPE_MAX] = {
        [JSON_VARIANT_STRING] = "string",
        [JSON_VARIANT_INTEGER] = "integer",
        [JSON_VARIANT_UNSIGNED] = "unsigned",
        [JSON_VARIANT_REAL] = "real",
        [JSON_VARIANT_NUMBER] = "number",
        [JSON_VARIANT_BOOLEAN] = "boolean",
        [JSON_VARIANT_ARRAY] = "array",
        [JSON_VARIANT_OBJECT] = "object",
        [JSON_VARIANT_NULL] = "null",
};

DEFINE_STRING_TABLE_LOOKUP(json_variant_type, JsonVariantType);

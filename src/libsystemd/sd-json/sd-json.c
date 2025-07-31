/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <stdlib.h>

#include "sd-json.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "fileio.h"
#include "float.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "json-internal.h"
#include "json-util.h"
#include "log.h"
#include "math-util.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "ordered-set.h"
#include "parse-util.h"
#include "pidref.h"
#include "ratelimit.h"
#include "signal-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"
#include "utf8.h"

/* Refuse putting together variants with a larger depth than 2K by default (as a protection against overflowing stacks
 * if code processes JSON objects recursively. Note that we store the depth in an uint16_t, hence make sure this
 * remains under 2^16.
 *
 * The value first was 16k, but it was discovered to be too high on llvm/x86-64. See also:
 * https://github.com/systemd/systemd/issues/10738
 *
 * The value then was 4k, but it was discovered to be too high on s390x/aarch64. See also:
 * https://github.com/systemd/systemd/issues/14396 */

#define DEPTH_MAX (2U*1024U)
assert_cc(DEPTH_MAX <= UINT16_MAX);

typedef struct JsonSource {
        /* When we parse from a file or similar, encodes the filename, to indicate the source of a json variant */
        unsigned n_ref;
        unsigned max_line;
        unsigned max_column;
        char name[];
} JsonSource;

/* On x86-64 this whole structure should have a size of 6 * 64 bit = 48 bytes */
struct sd_json_variant {
        union {
                /* We either maintain a reference counter for this variant itself, or we are embedded into an
                 * array/object, in which case only that surrounding object is ref-counted. (If 'embedded' is false,
                 * see below.) */
                unsigned n_ref;

                /* If this sd_json_variant is part of an array/object, then this field points to the surrounding
                 * JSON_VARIANT_ARRAY/JSON_VARIANT_OBJECT object. (If 'embedded' is true, see below.) */
                sd_json_variant *parent;
        };

        /* If this was parsed from some file or buffer, this stores where from, as well as the source line/column */
        JsonSource *source;
        unsigned line, column;

        /* The current 'depth' of the sd_json_variant, i.e. how many levels of member variants this has */
        uint16_t depth;

        signed int type:8; /* actually sd_json_variant_type_t, but reduced to 8bit size (we used "signed int"
                            * rather than just "int", since apparently compilers are free to pick signedness
                            * otherwise. We don't really care about the signedess, we care more about whether
                            * the enum can be converted to this, but we never use the negative values of
                            * sd_json_variant_type_t here.) */

        /* A marker whether this variant is embedded into in array/object or not. If true, the 'parent' pointer above
         * is valid. If false, the 'n_ref' field above is valid instead. */
        bool is_embedded:1;

        /* In some conditions (for example, if this object is part of an array of strings or objects), we don't store
         * any data inline, but instead simply reference an external object and act as surrogate of it. In that case
         * this bool is set, and the external object is referenced through the .reference field below. */
        bool is_reference:1;

        /* While comparing two arrays, we use this for marking what we already have seen */
        bool is_marked:1;

        /* Erase from memory when freeing */
        bool sensitive:1;

        /* True if we know that any referenced json object is marked sensitive */
        bool recursive_sensitive:1;

        /* If this is an object the fields are strictly ordered by name */
        bool sorted:1;

        /* If in addition to this object all objects referenced by it are also ordered strictly by name */
        bool normalized:1;

        union {
                /* For simple types we store the value in-line. */
                JsonValue value;

                /* For objects and arrays we store the number of elements immediately following */
                size_t n_elements;

                /* If is_reference as indicated above is set, this is where the reference object is actually stored. */
                sd_json_variant *reference;

                /* Strings are placed immediately after the structure. Note that when this is a sd_json_variant
                 * embedded into an array we might encode strings up to INLINE_STRING_LENGTH characters
                 * directly inside the element, while longer strings are stored as references. When this
                 * object is not embedded into an array, but stand-alone, we allocate the right size for the
                 * whole structure, i.e. the array might be much larger than INLINE_STRING_LENGTH. */
                DECLARE_FLEX_ARRAY(char, string);
        };
};

/* Inside string arrays we have a series of sd_json_variant structures one after the other. In this case, strings longer
 * than INLINE_STRING_MAX are stored as references, and all shorter ones inline. (This means — on x86-64 — strings up
 * to 7 chars are stored within the array elements, and all others in separate allocations) */
#define INLINE_STRING_MAX (sizeof(sd_json_variant) - offsetof(sd_json_variant, string) - 1U)

/* Let's make sure this structure isn't increased in size accidentally. This check is only for our most relevant arch
 * (x86-64). */
#if defined(__x86_64__) && __SIZEOF_POINTER__ == 8
assert_cc(sizeof(sd_json_variant) == 40U);
assert_cc(INLINE_STRING_MAX == 7U);
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

/* There are four kind of sd_json_variant* pointers:
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
 *    access. The JSON_VARIANT_STRING_CONST() macro encodes strings as sd_json_variant* pointers, with the bit set. */

static bool json_variant_is_magic(const sd_json_variant *v) {
        if (!v)
                return false;

        return v < _JSON_VARIANT_MAGIC_MAX;
}

static bool json_variant_is_const_string(const sd_json_variant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        /* A proper sd_json_variant is aligned to whatever malloc() aligns things too, which is definitely not uneven. We
         * hence use all uneven pointers as indicators for const strings. */

        return (((uintptr_t) v) & 1) != 0;
}

static bool json_variant_is_regular(const sd_json_variant *v) {

        if (v < _JSON_VARIANT_MAGIC_MAX)
                return false;

        return (((uintptr_t) v) & 1) == 0;
}

static sd_json_variant* json_variant_dereference(sd_json_variant *v) {

        /* Recursively dereference variants that are references to other variants */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (!v->is_reference)
                return v;

        return json_variant_dereference(v->reference);
}

static uint16_t json_variant_depth(sd_json_variant *v) {

        v = json_variant_dereference(v);
        if (!v)
                return 0;

        if (!json_variant_is_regular(v))
                return 0;

        return v->depth;
}

static sd_json_variant* json_variant_formalize(sd_json_variant *v) {

        /* Converts json variant pointers to their normalized form, i.e. fully dereferenced and wherever
         * possible converted to the "magic" version if there is one */

        if (!v)
                return NULL;

        v = json_variant_dereference(v);

        switch (sd_json_variant_type(v)) {

        case SD_JSON_VARIANT_BOOLEAN:
                return sd_json_variant_boolean(v) ? JSON_VARIANT_MAGIC_TRUE : JSON_VARIANT_MAGIC_FALSE;

        case SD_JSON_VARIANT_NULL:
                return JSON_VARIANT_MAGIC_NULL;

        case SD_JSON_VARIANT_INTEGER:
                return sd_json_variant_integer(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_INTEGER : v;

        case SD_JSON_VARIANT_UNSIGNED:
                return sd_json_variant_unsigned(v) == 0 ? JSON_VARIANT_MAGIC_ZERO_UNSIGNED : v;

        case SD_JSON_VARIANT_REAL:
                return iszero_safe(sd_json_variant_real(v)) ? JSON_VARIANT_MAGIC_ZERO_REAL : v;

        case SD_JSON_VARIANT_STRING:
                return isempty(sd_json_variant_string(v)) ? JSON_VARIANT_MAGIC_EMPTY_STRING : v;

        case SD_JSON_VARIANT_ARRAY:
                return sd_json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_ARRAY : v;

        case SD_JSON_VARIANT_OBJECT:
                return sd_json_variant_elements(v) == 0 ? JSON_VARIANT_MAGIC_EMPTY_OBJECT : v;

        default:
                return v;
        }
}

static sd_json_variant* json_variant_conservative_formalize(sd_json_variant *v) {

        /* Much like json_variant_formalize(), but won't simplify if the variant has a source/line location
         * attached to it, in order not to lose context */

        if (!v)
                return NULL;

        if (!json_variant_is_regular(v))
                return v;

        if (v->source || v->line > 0 || v->column > 0)
                return v;

        return json_variant_formalize(v);
}

static int json_variant_new(sd_json_variant **ret, sd_json_variant_type_t type, size_t space) {
        sd_json_variant *v;

        assert_return(ret, -EINVAL);

        v = malloc0(MAX(sizeof(sd_json_variant),
                        offsetof(sd_json_variant, value) + space));
        if (!v)
                return -ENOMEM;

        v->n_ref = 1;
        v->type = type;

        *ret = v;
        return 0;
}

_public_ int sd_json_variant_new_integer(sd_json_variant **ret, int64_t i) {
        sd_json_variant *v;
        int r;

        assert_return(ret, -EINVAL);

        if (i == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_INTEGER;
                return 0;
        }

        r = json_variant_new(&v, SD_JSON_VARIANT_INTEGER, sizeof(i));
        if (r < 0)
                return r;

        v->value.integer = i;
        *ret = v;

        return 0;
}

_public_ int sd_json_variant_new_unsigned(sd_json_variant **ret, uint64_t u) {
        sd_json_variant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (u == 0) {
                *ret = JSON_VARIANT_MAGIC_ZERO_UNSIGNED;
                return 0;
        }

        r = json_variant_new(&v, SD_JSON_VARIANT_UNSIGNED, sizeof(u));
        if (r < 0)
                return r;

        v->value.unsig = u;
        *ret = v;

        return 0;
}

_public_ int sd_json_variant_new_real(sd_json_variant **ret, double d) {
        sd_json_variant *v;
        int r;

        assert_return(ret, -EINVAL);

        r = fpclassify(d);
        switch (r) {
        case FP_NAN:
        case FP_INFINITE:
                /* JSON doesn't know NaN, +Infinity or -Infinity. Let's silently convert to 'null'. */
                *ret = JSON_VARIANT_MAGIC_NULL;
                return 0;

        case FP_ZERO:
                *ret = JSON_VARIANT_MAGIC_ZERO_REAL;
                return 0;
        }

        r = json_variant_new(&v, SD_JSON_VARIANT_REAL, sizeof(d));
        if (r < 0)
                return r;

        v->value.real = d;
        *ret = v;

        return 0;
}

_public_ int sd_json_variant_new_boolean(sd_json_variant **ret, int b) {
        assert_return(ret, -EINVAL);

        if (b)
                *ret = JSON_VARIANT_MAGIC_TRUE;
        else
                *ret = JSON_VARIANT_MAGIC_FALSE;

        return 0;
}

_public_ int sd_json_variant_new_null(sd_json_variant **ret) {
        assert_return(ret, -EINVAL);

        *ret = JSON_VARIANT_MAGIC_NULL;
        return 0;
}

_public_ int sd_json_variant_new_stringn(sd_json_variant **ret, const char *s, size_t n) {
        sd_json_variant *v;
        int r;

        assert_return(ret, -EINVAL);
        if (!s) {
                assert_return(IN_SET(n, 0, SIZE_MAX), -EINVAL);
                return sd_json_variant_new_null(ret);
        }
        if (n == SIZE_MAX) /* determine length automatically */
                n = strlen(s);
        else if (memchr(s, 0, n)) /* don't allow embedded NUL, as we can't express that in JSON */
                return -EINVAL;
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_STRING;
                return 0;
        }

        if (!utf8_is_valid_n(s, n)) /* JSON strings must be valid UTF-8 */
                return -EUCLEAN;

        r = json_variant_new(&v, SD_JSON_VARIANT_STRING, n + 1);
        if (r < 0)
                return r;

        memcpy(v->string, s, n);
        v->string[n] = 0;

        *ret = v;
        return 0;
}

_public_ int sd_json_variant_new_string(sd_json_variant **ret, const char *s) {
        return sd_json_variant_new_stringn(ret, s, SIZE_MAX);
}

_public_ int sd_json_variant_new_base64(sd_json_variant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;
        ssize_t k;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        k = base64mem(p, n, &s);
        if (k < 0)
                return k;

        return sd_json_variant_new_stringn(ret, s, k);
}

_public_ int sd_json_variant_new_base32hex(sd_json_variant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = base32hexmem(p, n, false);
        if (!s)
                return -ENOMEM;

        return sd_json_variant_new_string(ret, s);
}

_public_ int sd_json_variant_new_hex(sd_json_variant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = hexmem(p, n);
        if (!s)
                return -ENOMEM;

        return sd_json_variant_new_stringn(ret, s, n*2);
}

_public_ int sd_json_variant_new_octescape(sd_json_variant **ret, const void *p, size_t n) {
        _cleanup_free_ char *s = NULL;

        assert_return(ret, -EINVAL);
        assert_return(n == 0 || p, -EINVAL);

        s = octescape(p, n);
        if (!s)
                return -ENOMEM;

        return sd_json_variant_new_string(ret, s);
}

_public_ int sd_json_variant_new_id128(sd_json_variant **ret, sd_id128_t id) {
        return sd_json_variant_new_string(ret, SD_ID128_TO_STRING(id));
}

_public_ int sd_json_variant_new_uuid(sd_json_variant **ret, sd_id128_t id) {
        return sd_json_variant_new_string(ret, SD_ID128_TO_UUID_STRING(id));
}

static void json_variant_set(sd_json_variant *a, sd_json_variant *b) {
        assert(a);

        b = json_variant_dereference(b);
        if (!b) {
                a->type = SD_JSON_VARIANT_NULL;
                return;
        }

        a->type = sd_json_variant_type(b);
        switch (a->type) {

        case SD_JSON_VARIANT_INTEGER:
                a->value.integer = sd_json_variant_integer(b);
                break;

        case SD_JSON_VARIANT_UNSIGNED:
                a->value.unsig = sd_json_variant_unsigned(b);
                break;

        case SD_JSON_VARIANT_REAL:
                a->value.real = sd_json_variant_real(b);
                break;

        case SD_JSON_VARIANT_BOOLEAN:
                a->value.boolean = sd_json_variant_boolean(b);
                break;

        case SD_JSON_VARIANT_STRING: {
                const char *s;

                assert_se(s = sd_json_variant_string(b));

                /* Short strings we can store inline */
                if (strnlen(s, INLINE_STRING_MAX+1) <= INLINE_STRING_MAX) {
                        strcpy(a->string, s);
                        break;
                }

                /* For longer strings, use a reference… */
                _fallthrough_;
        }

        case SD_JSON_VARIANT_ARRAY:
        case SD_JSON_VARIANT_OBJECT:
                a->is_reference = true;
                a->reference = sd_json_variant_ref(json_variant_conservative_formalize(b));
                break;

        case SD_JSON_VARIANT_NULL:
                break;

        default:
                assert_not_reached();
        }
}

static void json_variant_copy_source(sd_json_variant *v, sd_json_variant *from) {
        assert(v);

        if (!json_variant_is_regular(from))
                return;

        v->line = from->line;
        v->column = from->column;
        v->source = json_source_ref(from->source);
}

static int json_variant_array_put_element(sd_json_variant *array, sd_json_variant *element) {
        assert(array);
        sd_json_variant *w = array + 1 + array->n_elements;

        uint16_t d = json_variant_depth(element);
        if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                return -ELNRNG;
        if (d >= array->depth)
                array->depth = d + 1;
        array->n_elements++;

        *w = (sd_json_variant) {
                .is_embedded = true,
                .parent = array,
        };

        json_variant_set(w, element);
        json_variant_copy_source(w, element);

        if (!sd_json_variant_is_normalized(element))
                array->normalized = false;

        return 0;
}

_public_ int sd_json_variant_new_array(sd_json_variant **ret, sd_json_variant **array, size_t n) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(array, -EINVAL);

        v = new(sd_json_variant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (sd_json_variant) {
                .n_ref = 1,
                .type = SD_JSON_VARIANT_ARRAY,
                .normalized = true,
        };

        while (v->n_elements < n) {
                r = json_variant_array_put_element(v, array[v->n_elements]);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

_public_ int sd_json_variant_new_array_bytes(sd_json_variant **ret, const void *p, size_t n) {
        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }
        assert_return(p, -EINVAL);

        sd_json_variant *v = new(sd_json_variant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (sd_json_variant) {
                .n_ref = 1,
                .type = SD_JSON_VARIANT_ARRAY,
                .n_elements = n,
                .depth = 1,
        };

        for (size_t i = 0; i < n; i++) {
                sd_json_variant *w = v + 1 + i;

                *w = (sd_json_variant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = SD_JSON_VARIANT_UNSIGNED,
                        .value.unsig = ((const uint8_t*) p)[i],
                };
        }

        v->normalized = true;

        *ret = v;
        return 0;
}

_public_ int sd_json_variant_new_array_strv(sd_json_variant **ret, char **l) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        size_t n;
        int r;

        assert_return(ret, -EINVAL);

        n = strv_length(l);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                return 0;
        }

        v = new(sd_json_variant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (sd_json_variant) {
                .n_ref = 1,
                .type = SD_JSON_VARIANT_ARRAY,
                .depth = 1,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                sd_json_variant *w = v + 1 + v->n_elements;
                size_t k;

                *w = (sd_json_variant) {
                        .is_embedded = true,
                        .parent = v,
                        .type = SD_JSON_VARIANT_STRING,
                };

                k = strlen(l[v->n_elements]);

                if (k > INLINE_STRING_MAX) {
                        /* If string is too long, store it as reference. */

                        r = sd_json_variant_new_string(&w->reference, l[v->n_elements]);
                        if (r < 0)
                                return r;

                        w->is_reference = true;
                } else {
                        if (!utf8_is_valid_n(l[v->n_elements], k)) /* JSON strings must be valid UTF-8 */
                                return -EUCLEAN;

                        memcpy(w->string, l[v->n_elements], k+1);
                }
        }

        v->normalized = true;

        *ret = TAKE_PTR(v);
        return 0;
}

_public_ int sd_json_variant_new_object(sd_json_variant **ret, sd_json_variant **array, size_t n) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *prev = NULL;
        bool sorted = true, normalized = true;

        assert_return(ret, -EINVAL);
        if (n == 0) {
                *ret = JSON_VARIANT_MAGIC_EMPTY_OBJECT;
                return 0;
        }
        assert_return(array, -EINVAL);
        assert_return(n % 2 == 0, -EINVAL);

        v = new(sd_json_variant, n + 1);
        if (!v)
                return -ENOMEM;

        *v = (sd_json_variant) {
                .n_ref = 1,
                .type = SD_JSON_VARIANT_OBJECT,
        };

        for (v->n_elements = 0; v->n_elements < n; v->n_elements++) {
                sd_json_variant *w = v + 1 + v->n_elements,
                            *c = array[v->n_elements];
                uint16_t d;

                if ((v->n_elements & 1) == 0) {
                        const char *k;

                        if (!sd_json_variant_is_string(c))
                                return -EINVAL; /* Every second one needs to be a string, as it is the key name */

                        assert_se(k = sd_json_variant_string(c));

                        if (prev && strcmp(k, prev) <= 0)
                                sorted = normalized = false;

                        prev = k;
                } else if (!sd_json_variant_is_normalized(c))
                        normalized = false;

                d = json_variant_depth(c);
                if (d >= DEPTH_MAX) /* Refuse too deep nesting */
                        return -ELNRNG;
                if (d >= v->depth)
                        v->depth = d + 1;

                *w = (sd_json_variant) {
                        .is_embedded = true,
                        .parent = v,
                };

                json_variant_set(w, c);
                json_variant_copy_source(w, c);
        }

        v->normalized = normalized;
        v->sorted = sorted;

        *ret = TAKE_PTR(v);
        return 0;
}

static size_t json_variant_size(sd_json_variant* v) {
        if (!json_variant_is_regular(v))
                return 0;

        if (v->is_reference)
                return offsetof(sd_json_variant, reference) + sizeof(sd_json_variant*);

        switch (v->type) {

        case SD_JSON_VARIANT_STRING:
                return offsetof(sd_json_variant, string) + strlen(v->string) + 1;

        case SD_JSON_VARIANT_REAL:
                return offsetof(sd_json_variant, value) + sizeof(double);

        case SD_JSON_VARIANT_UNSIGNED:
                return offsetof(sd_json_variant, value) + sizeof(uint64_t);

        case SD_JSON_VARIANT_INTEGER:
                return offsetof(sd_json_variant, value) + sizeof(int64_t);

        case SD_JSON_VARIANT_BOOLEAN:
                return offsetof(sd_json_variant, value) + sizeof(bool);

        case SD_JSON_VARIANT_ARRAY:
        case SD_JSON_VARIANT_OBJECT:
                return offsetof(sd_json_variant, n_elements) + sizeof(size_t);

        case SD_JSON_VARIANT_NULL:
                return offsetof(sd_json_variant, value);

        default:
                assert_not_reached();
        }
}

static void json_variant_free_inner(sd_json_variant *v, bool force_sensitive) {
        bool sensitive;

        assert(v);

        if (!json_variant_is_regular(v))
                return;

        json_source_unref(v->source);

        sensitive = v->sensitive || force_sensitive;

        if (v->is_reference) {
                if (sensitive)
                        sd_json_variant_sensitive(v->reference);

                sd_json_variant_unref(v->reference);
                return;
        }

        if (IN_SET(v->type, SD_JSON_VARIANT_ARRAY, SD_JSON_VARIANT_OBJECT))
                for (size_t i = 0; i < v->n_elements; i++)
                        json_variant_free_inner(v + 1 + i, sensitive);

        if (sensitive)
                explicit_bzero_safe(v, json_variant_size(v));
}

static unsigned json_variant_n_ref(const sd_json_variant *v) {
        /* Return the number of references to v.
         * 0  => NULL or not a regular object or embedded.
         * >0 => number of references
         */

        if (!v || !json_variant_is_regular(v) || v->is_embedded)
                return 0;

        assert(v->n_ref > 0);
        return v->n_ref;
}

_public_ sd_json_variant *sd_json_variant_ref(sd_json_variant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return v;

        if (v->is_embedded)
                sd_json_variant_ref(v->parent); /* ref the compounding variant instead */
        else {
                assert(v->n_ref > 0);
                v->n_ref++;
        }

        return v;
}

_public_ sd_json_variant *sd_json_variant_unref(sd_json_variant *v) {
        if (!v)
                return NULL;
        if (!json_variant_is_regular(v))
                return NULL;

        if (v->is_embedded)
                sd_json_variant_unref(v->parent);
        else {
                assert(v->n_ref > 0);
                v->n_ref--;

                if (v->n_ref == 0) {
                        json_variant_free_inner(v, false);
                        free(v);
                }
        }

        return NULL;
}

_public_ void sd_json_variant_unref_many(sd_json_variant **array, size_t n) {
        FOREACH_ARRAY(v, array, n)
                sd_json_variant_unref(*v);

        free(array);
}

_public_ const char* sd_json_variant_string(sd_json_variant *v) {
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
                return sd_json_variant_string(v->reference);
        if (v->type != SD_JSON_VARIANT_STRING)
                goto mismatch;

        return v->string;

mismatch:
        log_debug("Non-string JSON variant requested as string, returning NULL.");
        return NULL;
}

_public_ int sd_json_variant_boolean(sd_json_variant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_TRUE)
                return true;
        if (v == JSON_VARIANT_MAGIC_FALSE)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != SD_JSON_VARIANT_BOOLEAN)
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_boolean(v->reference);

        return v->value.boolean;

mismatch:
        log_debug("Non-boolean JSON variant requested as boolean, returning false.");
        return false;
}

_public_ int64_t sd_json_variant_integer(sd_json_variant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_integer(v->reference);

        switch (v->type) {

        case SD_JSON_VARIANT_INTEGER:
                return v->value.integer;

        case SD_JSON_VARIANT_UNSIGNED:
                if (v->value.unsig <= INT64_MAX)
                        return (int64_t) v->value.unsig;

                log_debug("Unsigned integer %" PRIu64 " requested as signed integer and out of range, returning 0.", v->value.unsig);
                return 0;

        case SD_JSON_VARIANT_REAL: {
                int64_t converted;

                converted = (int64_t) v->value.real;

                if (fp_equal((double) converted, v->value.real))
                        return converted;

                log_debug("Real %g requested as integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                ;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0;
}

_public_ uint64_t sd_json_variant_unsigned(sd_json_variant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_integer(v->reference);

        switch (v->type) {

        case SD_JSON_VARIANT_INTEGER:
                if (v->value.integer >= 0)
                        return (uint64_t) v->value.integer;

                log_debug("Signed integer %" PRIi64 " requested as unsigned integer and out of range, returning 0.", v->value.integer);
                return 0;

        case SD_JSON_VARIANT_UNSIGNED:
                return v->value.unsig;

        case SD_JSON_VARIANT_REAL: {
                uint64_t converted;

                converted = (uint64_t) v->value.real;

                if (fp_equal((double) converted, v->value.real))
                        return converted;

                log_debug("Real %g requested as unsigned integer, and cannot be converted losslessly, returning 0.", v->value.real);
                return 0;
        }

        default:
                ;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as unsigned, returning 0.");
        return 0;
}

_public_ double sd_json_variant_real(sd_json_variant *v) {
        if (!v)
                return 0.0;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return 0.0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_real(v->reference);

        switch (v->type) {

        case SD_JSON_VARIANT_REAL:
                return v->value.real;

        case SD_JSON_VARIANT_INTEGER: {
                double converted = (double) v->value.integer;

                if ((int64_t) converted == v->value.integer)
                        return converted;

                log_debug("Signed integer %" PRIi64 " requested as real, and cannot be converted losslessly, returning 0.", v->value.integer);
                return 0.0;
        }

        case SD_JSON_VARIANT_UNSIGNED: {
                double converted = (double) v->value.unsig;

                if ((uint64_t) converted == v->value.unsig)
                        return converted;

                log_debug("Unsigned integer %" PRIu64 " requested as real, and cannot be converted losslessly, returning 0.", v->value.unsig);
                return 0.0;
        }

        default:
                ;
        }

mismatch:
        log_debug("Non-integer JSON variant requested as integer, returning 0.");
        return 0.0;
}

_public_ int sd_json_variant_is_negative(sd_json_variant *v) {
        if (!v)
                goto mismatch;
        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER ||
            v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED ||
            v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return false;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_is_negative(v->reference);

        /* This function is useful as checking whether numbers are negative is pretty complex since we have three types
         * of numbers. And some JSON code (OCI for example) uses negative numbers to mark "not defined" numeric
         * values. */

        switch (v->type) {

        case SD_JSON_VARIANT_REAL:
                return v->value.real < 0;

        case SD_JSON_VARIANT_INTEGER:
                return v->value.integer < 0;

        case SD_JSON_VARIANT_UNSIGNED:
                return false;

        default:
                ;
        }

mismatch:
        log_debug("Non-integer JSON variant tested for negativity, returning false.");
        return false;
}

_public_ int sd_json_variant_is_blank_object(sd_json_variant *v) {
        /* Returns true if the specified object is null or empty */
        return !v ||
                sd_json_variant_is_null(v) ||
                (sd_json_variant_is_object(v) && sd_json_variant_elements(v) == 0);
}

_public_ int sd_json_variant_is_blank_array(sd_json_variant *v) {
        return !v ||
                sd_json_variant_is_null(v) ||
                (sd_json_variant_is_array(v) && sd_json_variant_elements(v) == 0);
}

_public_ sd_json_variant_type_t sd_json_variant_type(sd_json_variant *v) {

        if (!v)
                return _SD_JSON_VARIANT_TYPE_INVALID;

        if (json_variant_is_const_string(v))
                return SD_JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_TRUE || v == JSON_VARIANT_MAGIC_FALSE)
                return SD_JSON_VARIANT_BOOLEAN;

        if (v == JSON_VARIANT_MAGIC_NULL)
                return SD_JSON_VARIANT_NULL;

        if (v == JSON_VARIANT_MAGIC_ZERO_INTEGER)
                return SD_JSON_VARIANT_INTEGER;

        if (v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED)
                return SD_JSON_VARIANT_UNSIGNED;

        if (v == JSON_VARIANT_MAGIC_ZERO_REAL)
                return SD_JSON_VARIANT_REAL;

        if (v == JSON_VARIANT_MAGIC_EMPTY_STRING)
                return SD_JSON_VARIANT_STRING;

        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY)
                return SD_JSON_VARIANT_ARRAY;

        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return SD_JSON_VARIANT_OBJECT;

        return v->type;
}

_function_no_sanitize_float_cast_overflow_
_public_ int sd_json_variant_has_type(sd_json_variant *v, sd_json_variant_type_t type) {
        sd_json_variant_type_t rt;

        /* Note: we turn off ubsan float cast overflow detection for this function, since it would complain
         * about our float casts but we do them explicitly to detect conversion errors. */

        v = json_variant_dereference(v);
        if (!v)
                return false;

        rt = sd_json_variant_type(v);
        if (rt == type)
                return true;

        /* If it's a const string, then it only can be a string, and if it is not, it's not */
        if (json_variant_is_const_string(v))
                return false;

        /* All three magic zeroes qualify as integer, unsigned and as real */
        if ((v == JSON_VARIANT_MAGIC_ZERO_INTEGER || v == JSON_VARIANT_MAGIC_ZERO_UNSIGNED || v == JSON_VARIANT_MAGIC_ZERO_REAL) &&
            IN_SET(type, SD_JSON_VARIANT_INTEGER, SD_JSON_VARIANT_UNSIGNED, SD_JSON_VARIANT_REAL, SD_JSON_VARIANT_NUMBER))
                return true;

        /* All other magic variant types are only equal to themselves */
        if (json_variant_is_magic(v))
                return false;

        /* Handle the "number" pseudo type */
        if (type == SD_JSON_VARIANT_NUMBER)
                return IN_SET(rt, SD_JSON_VARIANT_INTEGER, SD_JSON_VARIANT_UNSIGNED, SD_JSON_VARIANT_REAL);

        /* Integer conversions are OK in many cases */
        if (rt == SD_JSON_VARIANT_INTEGER && type == SD_JSON_VARIANT_UNSIGNED)
                return v->value.integer >= 0;
        if (rt == SD_JSON_VARIANT_UNSIGNED && type == SD_JSON_VARIANT_INTEGER)
                return v->value.unsig <= INT64_MAX;

        /* Any integer that can be converted lossley to a real and back may also be considered a real */
        if (rt == SD_JSON_VARIANT_INTEGER && type == SD_JSON_VARIANT_REAL)
                return (int64_t) (double) v->value.integer == v->value.integer;
        if (rt == SD_JSON_VARIANT_UNSIGNED && type == SD_JSON_VARIANT_REAL)
                return (uint64_t) (double) v->value.unsig == v->value.unsig;

        /* Any real that can be converted losslessly to an integer and back may also be considered an integer */
        if (rt == SD_JSON_VARIANT_REAL && type == SD_JSON_VARIANT_INTEGER)
                return fp_equal((double) (int64_t) v->value.real, v->value.real);
        if (rt == SD_JSON_VARIANT_REAL && type == SD_JSON_VARIANT_UNSIGNED)
                return fp_equal((double) (uint64_t) v->value.real, v->value.real);

        return false;
}

_public_ int sd_json_variant_is_string(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_STRING);
}

_public_ int sd_json_variant_is_integer(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_INTEGER);
}

_public_ int sd_json_variant_is_unsigned(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_UNSIGNED);
}

_public_ int sd_json_variant_is_real(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_REAL);
}

_public_ int sd_json_variant_is_number(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_NUMBER);
}

_public_ int sd_json_variant_is_boolean(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_BOOLEAN);
}

_public_ int sd_json_variant_is_array(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_ARRAY);
}

_public_ int sd_json_variant_is_object(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_OBJECT);
}

_public_ int sd_json_variant_is_null(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_NULL);
}

_public_ size_t sd_json_variant_elements(sd_json_variant *v) {
        if (!v)
                return 0;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return 0;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, SD_JSON_VARIANT_ARRAY, SD_JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_elements(v->reference);

        return v->n_elements;

mismatch:
        log_debug("Number of elements in non-array/non-object JSON variant requested, returning 0.");
        return 0;
}

_public_ sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t idx) {
        if (!v)
                return NULL;
        if (v == JSON_VARIANT_MAGIC_EMPTY_ARRAY ||
            v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                return NULL;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (!IN_SET(v->type, SD_JSON_VARIANT_ARRAY, SD_JSON_VARIANT_OBJECT))
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_by_index(v->reference, idx);
        if (idx >= v->n_elements)
                return NULL;

        return json_variant_conservative_formalize(v + 1 + idx);

mismatch:
        log_debug("Element in non-array/non-object JSON variant requested by index, returning NULL.");
        return NULL;
}

_public_ sd_json_variant *sd_json_variant_by_key_full(sd_json_variant *v, const char *key, sd_json_variant **ret_key) {
        if (!v)
                goto not_found;
        if (!key)
                goto not_found;
        if (v == JSON_VARIANT_MAGIC_EMPTY_OBJECT)
                goto not_found;
        if (!json_variant_is_regular(v))
                goto mismatch;
        if (v->type != SD_JSON_VARIANT_OBJECT)
                goto mismatch;
        if (v->is_reference)
                return sd_json_variant_by_key(v->reference, key);

        if (v->sorted) {
                size_t a = 0, b = v->n_elements/2;

                /* If the variant is sorted we can use bisection to find the entry we need in O(log(n)) time */

                while (b > a) {
                        sd_json_variant *p;
                        const char *f;
                        size_t i;
                        int c;

                        i = (a + b) / 2;
                        p = json_variant_dereference(v + 1 + i*2);

                        assert_se(f = sd_json_variant_string(p));

                        c = strcmp(key, f);
                        if (c == 0) {
                                if (ret_key)
                                        *ret_key = json_variant_conservative_formalize(v + 1 + i*2);

                                return json_variant_conservative_formalize(v + 1 + i*2 + 1);
                        } else if (c < 0)
                                b = i;
                        else
                                a = i + 1;
                }

                goto not_found;
        }

        /* The variant is not sorted, hence search for the field linearly */
        for (size_t i = 0; i < v->n_elements; i += 2) {
                sd_json_variant *p;

                p = json_variant_dereference(v + 1 + i);

                if (!sd_json_variant_has_type(p, SD_JSON_VARIANT_STRING))
                        continue;

                if (streq(sd_json_variant_string(p), key)) {

                        if (ret_key)
                                *ret_key = json_variant_conservative_formalize(v + 1 + i);

                        return json_variant_conservative_formalize(v + 1 + i + 1);
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

_public_ sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key) {
        return sd_json_variant_by_key_full(v, key, NULL);
}

_public_ int sd_json_variant_equal(sd_json_variant *a, sd_json_variant *b) {
        sd_json_variant_type_t t;

        a = json_variant_formalize(a);
        b = json_variant_formalize(b);

        if (a == b)
                return true;

        t = sd_json_variant_type(a);
        if (!sd_json_variant_has_type(b, t))
                return false;

        switch (t) {

        case SD_JSON_VARIANT_STRING:
                return streq(sd_json_variant_string(a), sd_json_variant_string(b));

        case SD_JSON_VARIANT_INTEGER:
                return sd_json_variant_integer(a) == sd_json_variant_integer(b);

        case SD_JSON_VARIANT_UNSIGNED:
                return sd_json_variant_unsigned(a) == sd_json_variant_unsigned(b);

        case SD_JSON_VARIANT_REAL:
                return fp_equal(sd_json_variant_real(a), sd_json_variant_real(b));

        case SD_JSON_VARIANT_BOOLEAN:
                return sd_json_variant_boolean(a) == sd_json_variant_boolean(b);

        case SD_JSON_VARIANT_NULL:
                return true;

        case SD_JSON_VARIANT_ARRAY: {
                size_t n = sd_json_variant_elements(a);
                if (n != sd_json_variant_elements(b))
                        return false;

                for (size_t i = 0; i < n; i++)
                        if (!sd_json_variant_equal(sd_json_variant_by_index(a, i), sd_json_variant_by_index(b, i)))
                                return false;

                return true;
        }

        case SD_JSON_VARIANT_OBJECT: {
                size_t n = sd_json_variant_elements(a);
                if (n != sd_json_variant_elements(b))
                        return false;

                /* Iterate through all keys in 'a' */
                for (size_t i = 0; i < n; i += 2) {
                        bool found = false;

                        /* Match them against all keys in 'b' */
                        for (size_t j = 0; j < n; j += 2) {
                                sd_json_variant *key_b;

                                key_b = sd_json_variant_by_index(b, j);

                                /* During the first iteration unmark everything */
                                if (i == 0)
                                        key_b->is_marked = false;
                                else if (key_b->is_marked) /* In later iterations if we already marked something, don't bother with it again */
                                        continue;

                                if (found)
                                        continue;

                                if (sd_json_variant_equal(sd_json_variant_by_index(a, i), key_b) &&
                                    sd_json_variant_equal(sd_json_variant_by_index(a, i+1), sd_json_variant_by_index(b, j+1))) {
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
                assert_not_reached();
        }
}

_public_ void sd_json_variant_sensitive(sd_json_variant *v) {
        if (!v)
                return;

        /* Marks a variant as "sensitive", so that it is erased from memory when it is destroyed. This is a
         * one-way operation: as soon as it is marked this way it remains marked this way until it's
         * destroyed. A magic variant is never sensitive though, even when asked, since it's too
         * basic. Similar, const string variant are never sensitive either, after all they are included in
         * the source code as they are, which is not suitable for inclusion of secrets.
         *
         * Note that this flag has a recursive effect: when we destroy an object or array we'll propagate the
         * flag to all contained variants. And if those are then destroyed this is propagated further down,
         * and so on. */

        v = json_variant_formalize(v);
        if (!json_variant_is_regular(v))
                return;

        v->sensitive = true;
}

_public_ int sd_json_variant_is_sensitive(sd_json_variant *v) {
        v = json_variant_formalize(v);
        if (!json_variant_is_regular(v))
                return false;

        return v->sensitive;
}

_public_ int sd_json_variant_is_sensitive_recursive(sd_json_variant *v) {
        if (!v)
                return false;
        if (sd_json_variant_is_sensitive(v))
                return true;
        if (!json_variant_is_regular(v))
                return false;
        if (v->recursive_sensitive) /* Already checked this before */
                return true;
        if (!IN_SET(v->type, SD_JSON_VARIANT_ARRAY, SD_JSON_VARIANT_OBJECT))
                return false;
        if (v->is_reference) {
                if (!sd_json_variant_is_sensitive_recursive(v->reference))
                        return false;

                return (v->recursive_sensitive = true);
        }

        for (size_t i = 0; i < sd_json_variant_elements(v); i++)
                if (sd_json_variant_is_sensitive_recursive(sd_json_variant_by_index(v, i)))
                        return (v->recursive_sensitive = true);

        /* Note: we only cache the result here in case true, since we allow all elements down the tree to
         * have their sensitive flag toggled later on (but never off) */
        return false;
}

static void json_variant_propagate_sensitive(sd_json_variant *from, sd_json_variant *to) {
        if (sd_json_variant_is_sensitive(from))
                sd_json_variant_sensitive(to);
}

_public_ int sd_json_variant_get_source(sd_json_variant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column) {
        assert_return(v, -EINVAL);

        if (ret_source)
                *ret_source = json_variant_is_regular(v) && v->source ? v->source->name : NULL;

        if (ret_line)
                *ret_line = json_variant_is_regular(v) ? v->line : 0;

        if (ret_column)
                *ret_column = json_variant_is_regular(v) ? v->column : 0;

        return 0;
}

static int print_source(FILE *f, sd_json_variant *v, sd_json_format_flags_t flags, bool whitespace) {
        size_t w, k;

        if (!FLAGS_SET(flags, SD_JSON_FORMAT_SOURCE|SD_JSON_FORMAT_PRETTY))
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
                size_t n = 1 + (v->source ? strlen(v->source->name) : 0) +
                               ((v->source && (v->line > 0 || v->column > 0)) ? 1 : 0) +
                               (v->line > 0 ? w : 0) +
                               (((v->source || v->line > 0) && v->column > 0) ? 1 : 0) +
                               (v->column > 0 ? k : 0) +
                               2;

                for (size_t i = 0; i < n; i++)
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

static void json_format_string(FILE *f, const char *q, sd_json_format_flags_t flags) {
        assert(q);

        fputc('"', f);

        if (flags & SD_JSON_FORMAT_COLOR)
                fputs(ansi_green(), f);

        for (; *q; q++)
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
                                fprintf(f, "\\u%04x", (unsigned) *q);
                        else
                                fputc(*q, f);
                }

        if (flags & SD_JSON_FORMAT_COLOR)
                fputs(ANSI_NORMAL, f);

        fputc('"', f);
}

static int json_format(FILE *f, sd_json_variant *v, sd_json_format_flags_t flags, const char *prefix) {
        int r;

        assert(f);
        assert(v);

        if (FLAGS_SET(flags, SD_JSON_FORMAT_CENSOR_SENSITIVE) && sd_json_variant_is_sensitive(v)) {
                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ansi_red(), f);
                fputs("\"<sensitive data>\"", f);
                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                return 0;
        }

        switch (sd_json_variant_type(v)) {

        case SD_JSON_VARIANT_REAL: {
                locale_t loc, old_loc;

                loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
                if (loc == (locale_t) 0)
                        return -errno;

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ansi_highlight_blue(), f);

                old_loc = uselocale(loc);
                fprintf(f, "%.*e", DECIMAL_DIG, sd_json_variant_real(v));
                uselocale(old_loc);

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                freelocale(loc);
                break;
        }

        case SD_JSON_VARIANT_INTEGER:
                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ansi_highlight_blue(), f);

                fprintf(f, "%" PRIdMAX, sd_json_variant_integer(v));

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case SD_JSON_VARIANT_UNSIGNED:
                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ansi_highlight_blue(), f);

                fprintf(f, "%" PRIuMAX, sd_json_variant_unsigned(v));

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case SD_JSON_VARIANT_BOOLEAN:

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                if (sd_json_variant_boolean(v))
                        fputs("true", f);
                else
                        fputs("false", f);

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);

                break;

        case SD_JSON_VARIANT_NULL:
                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_HIGHLIGHT, f);

                fputs("null", f);

                if (flags & SD_JSON_FORMAT_COLOR)
                        fputs(ANSI_NORMAL, f);
                break;

        case SD_JSON_VARIANT_STRING:
                json_format_string(f, sd_json_variant_string(v), flags);
                break;

        case SD_JSON_VARIANT_ARRAY: {
                size_t n = sd_json_variant_elements(v);
                if (n == 0)
                        fputs("[]", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & SD_JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("[\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('[', f);
                        }

                        for (size_t i = 0; i < n; i++) {
                                sd_json_variant *e;

                                assert_se(e = sd_json_variant_by_index(v, i));

                                if (i > 0) {
                                        if (flags & SD_JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & SD_JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & SD_JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc(']', f);
                }
                break;
        }

        case SD_JSON_VARIANT_OBJECT: {
                size_t n = sd_json_variant_elements(v);
                if (n == 0)
                        fputs("{}", f);
                else {
                        _cleanup_free_ char *joined = NULL;
                        const char *prefix2;

                        if (flags & SD_JSON_FORMAT_PRETTY) {
                                joined = strjoin(strempty(prefix), "\t");
                                if (!joined)
                                        return -ENOMEM;

                                prefix2 = joined;
                                fputs("{\n", f);
                        } else {
                                prefix2 = strempty(prefix);
                                fputc('{', f);
                        }

                        for (size_t i = 0; i < n; i += 2) {
                                sd_json_variant *e;

                                e = sd_json_variant_by_index(v, i);

                                if (i > 0) {
                                        if (flags & SD_JSON_FORMAT_PRETTY)
                                                fputs(",\n", f);
                                        else
                                                fputc(',', f);
                                }

                                if (flags & SD_JSON_FORMAT_PRETTY) {
                                        print_source(f, e, flags, false);
                                        fputs(prefix2, f);
                                }

                                r = json_format(f, e, flags, prefix2);
                                if (r < 0)
                                        return r;

                                fputs(flags & SD_JSON_FORMAT_PRETTY ? " : " : ":", f);

                                r = json_format(f, sd_json_variant_by_index(v, i+1), flags, prefix2);
                                if (r < 0)
                                        return r;
                        }

                        if (flags & SD_JSON_FORMAT_PRETTY) {
                                fputc('\n', f);
                                print_source(f, v, flags, true);
                                fputs(strempty(prefix), f);
                        }

                        fputc('}', f);
                }
                break;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

_public_ int sd_json_variant_format(sd_json_variant *v, sd_json_format_flags_t flags, char **ret) {
        _cleanup_(memstream_done) MemStream m = {};
        size_t sz;
        FILE *f;
        int r;

        /* Returns the length of the generated string (without the terminating NUL),
         * or negative on error. */

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!sd_json_format_enabled(flags))
                return -ENOEXEC;

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        r = sd_json_variant_dump(v, flags, f, NULL);
        if (r < 0)
                return r;

        r = memstream_finalize(&m, ret, &sz);
        if (r < 0)
                return r;

        return sz;
}

_public_ int sd_json_variant_dump(sd_json_variant *v, sd_json_format_flags_t flags, FILE *f, const char *prefix) {
        if (!v) {
                if (flags & SD_JSON_FORMAT_EMPTY_ARRAY)
                        v = JSON_VARIANT_MAGIC_EMPTY_ARRAY;
                else
                        return 0;
        }

        if (!f)
                f = stdout;

        print_source(f, v, flags, false);

        if (((flags & (SD_JSON_FORMAT_COLOR_AUTO|SD_JSON_FORMAT_COLOR)) == SD_JSON_FORMAT_COLOR_AUTO) && colors_enabled())
                flags |= SD_JSON_FORMAT_COLOR;

        if (((flags & (SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_PRETTY)) == SD_JSON_FORMAT_PRETTY_AUTO))
                flags |= on_tty() ? SD_JSON_FORMAT_PRETTY : SD_JSON_FORMAT_NEWLINE;

        if (flags & SD_JSON_FORMAT_SSE)
                fputs("data: ", f);
        if (flags & SD_JSON_FORMAT_SEQ)
                fputc('\x1e', f); /* ASCII Record Separator */

        json_format(f, v, flags, prefix);

        if (flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_SEQ|SD_JSON_FORMAT_SSE|SD_JSON_FORMAT_NEWLINE))
                fputc('\n', f);
        if (flags & SD_JSON_FORMAT_SSE)
                fputc('\n', f); /* In case of SSE add a second newline */

        if (flags & SD_JSON_FORMAT_FLUSH)
                return fflush_and_check(f);
        return 0;
}

_public_ int sd_json_variant_filter(sd_json_variant **v, char **to_remove) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_free_ sd_json_variant **array = NULL;
        size_t n = 0, k = 0;
        int r;

        assert_return(v, -EINVAL);

        if (sd_json_variant_is_blank_object(*v))
                return 0;
        if (!sd_json_variant_is_object(*v))
                return -EINVAL;

        if (strv_isempty(to_remove))
                return 0;

        for (size_t i = 0; i < sd_json_variant_elements(*v); i += 2) {
                sd_json_variant *p;

                p = sd_json_variant_by_index(*v, i);
                if (!sd_json_variant_has_type(p, SD_JSON_VARIANT_STRING))
                        return -EINVAL;

                if (strv_contains(to_remove, sd_json_variant_string(p))) {
                        if (!array) {
                                array = new(sd_json_variant*, sd_json_variant_elements(*v) - 2);
                                if (!array)
                                        return -ENOMEM;

                                for (k = 0; k < i; k++)
                                        array[k] = sd_json_variant_by_index(*v, k);
                        }

                        n++;
                } else if (array) {
                        array[k++] = p;
                        array[k++] = sd_json_variant_by_index(*v, i + 1);
                }
        }

        if (n == 0)
                return 0;

        r = sd_json_variant_new_object(&w, array, k);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, w);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(w));

        return (int) n;
}

_public_ int sd_json_variant_set_field(sd_json_variant **v, const char *field, sd_json_variant *value) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *field_variant = NULL, *w = NULL;
        _cleanup_free_ sd_json_variant **array = NULL;
        size_t k = 0;
        int r;

        assert_return(v, -EINVAL);
        assert_return(field, -EINVAL);

        if (sd_json_variant_is_blank_object(*v)) {
                array = new(sd_json_variant*, 2);
                if (!array)
                        return -ENOMEM;

        } else {
                if (!sd_json_variant_is_object(*v))
                        return -EINVAL;

                for (size_t i = 0; i < sd_json_variant_elements(*v); i += 2) {
                        sd_json_variant *p;

                        p = sd_json_variant_by_index(*v, i);
                        if (!sd_json_variant_is_string(p))
                                return -EINVAL;

                        if (streq(sd_json_variant_string(p), field)) {

                                if (!array) {
                                        array = new(sd_json_variant*, sd_json_variant_elements(*v));
                                        if (!array)
                                                return -ENOMEM;

                                        for (k = 0; k < i; k++)
                                                array[k] = sd_json_variant_by_index(*v, k);
                                }

                        } else if (array) {
                                array[k++] = p;
                                array[k++] = sd_json_variant_by_index(*v, i + 1);
                        }
                }

                if (!array) {
                        array = new(sd_json_variant*, sd_json_variant_elements(*v) + 2);
                        if (!array)
                                return -ENOMEM;

                        for (k = 0; k < sd_json_variant_elements(*v); k++)
                                array[k] = sd_json_variant_by_index(*v, k);
                }
        }

        r = sd_json_variant_new_string(&field_variant, field);
        if (r < 0)
                return r;

        array[k++] = field_variant;
        array[k++] = value;

        r = sd_json_variant_new_object(&w, array, k);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, w);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(w));

        return 1;
}

_public_ int sd_json_variant_set_fieldb(sd_json_variant **v, const char *field, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        va_list ap;
        int r;

        va_start(ap, field);
        r = sd_json_buildv(&w, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, field, w);
}

_public_ int sd_json_variant_set_field_string(sd_json_variant **v, const char *field, const char *value) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        r = sd_json_variant_new_string(&m, value);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, field, m);
}

_public_ int sd_json_variant_set_field_id128(sd_json_variant **v, const char *field, sd_id128_t value) {
        return sd_json_variant_set_field_string(v, field, SD_ID128_TO_STRING(value));
}

_public_ int sd_json_variant_set_field_uuid(sd_json_variant **v, const char *field, sd_id128_t value) {
        return sd_json_variant_set_field_string(v, field, SD_ID128_TO_UUID_STRING(value));
}

_public_ int sd_json_variant_set_field_integer(sd_json_variant **v, const char *field, int64_t i) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        r = sd_json_variant_new_integer(&m, i);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, field, m);
}

_public_ int sd_json_variant_set_field_unsigned(sd_json_variant **v, const char *field, uint64_t u) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        r = sd_json_variant_new_unsigned(&m, u);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, field, m);
}

_public_ int sd_json_variant_set_field_boolean(sd_json_variant **v, const char *field, int b) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        r = sd_json_variant_new_boolean(&m, b);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, field, m);
}

_public_ int sd_json_variant_set_field_strv(sd_json_variant **v, const char *field, char **l) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        r = sd_json_variant_new_array_strv(&m, l);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, field, m);
}

_public_ int sd_json_variant_merge_object(sd_json_variant **v, sd_json_variant *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_free_ sd_json_variant **array = NULL;
        size_t v_elements, m_elements, k;
        bool v_blank, m_blank;
        int r;

        m = json_variant_dereference(m);

        v_blank = sd_json_variant_is_blank_object(*v);
        m_blank = sd_json_variant_is_blank_object(m);

        if (!v_blank && !sd_json_variant_is_object(*v))
                return -EINVAL;
        if (!m_blank && !sd_json_variant_is_object(m))
                return -EINVAL;

        if (m_blank)
                return 0; /* nothing to do */

        if (v_blank) {
                JSON_VARIANT_REPLACE(*v, sd_json_variant_ref(m));
                return 1;
        }

        v_elements = sd_json_variant_elements(*v);
        m_elements = sd_json_variant_elements(m);
        if (v_elements > SIZE_MAX - m_elements) /* overflow check */
                return -ENOMEM;

        array = new(sd_json_variant*, v_elements + m_elements);
        if (!array)
                return -ENOMEM;

        k = 0;
        for (size_t i = 0; i < v_elements; i += 2) {
                sd_json_variant *u;

                u = sd_json_variant_by_index(*v, i);
                if (!sd_json_variant_is_string(u))
                        return -EINVAL;

                if (sd_json_variant_by_key(m, sd_json_variant_string(u)))
                        continue; /* skip if exists in second variant */

                array[k++] = u;
                array[k++] = sd_json_variant_by_index(*v, i + 1);
        }

        for (size_t i = 0; i < m_elements; i++)
                array[k++] = sd_json_variant_by_index(m, i);

        r = sd_json_variant_new_object(&w, array, k);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, w);
        json_variant_propagate_sensitive(m, w);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(w));

        return 1;
}

_public_ int sd_json_variant_merge_objectb(sd_json_variant **v, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        va_list ap;
        int r;

        va_start(ap, v);
        r = sd_json_buildv(&w, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return sd_json_variant_merge_object(v, w);
}

_public_ int sd_json_variant_append_array(sd_json_variant **v, sd_json_variant *element) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *nv = NULL;
        bool blank;
        int r;

        assert_return(v, -EINVAL);
        assert_return(element, -EINVAL);

        if (!*v || sd_json_variant_is_null(*v))
                blank = true;
        else if (sd_json_variant_is_array(*v))
                blank = sd_json_variant_elements(*v) == 0;
        else
                return -EINVAL;

        if (blank) {
                r = sd_json_variant_new_array(&nv, (sd_json_variant*[]) { element }, 1);
                if (r < 0)
                        return r;
        } else if (json_variant_n_ref(*v) == 1) {
                /* Let's bump the reference count on element. We can't do the realloc if we're appending *v
                 * to itself, or one of the objects embedded in *v to *v. If the reference count grows, we
                 * need to fall back to the other method below. */

                _unused_ _cleanup_(sd_json_variant_unrefp) sd_json_variant *dummy = sd_json_variant_ref(element);
                if (json_variant_n_ref(*v) == 1) {
                        /* We hold the only reference. Let's mutate the object. */
                        size_t size = sd_json_variant_elements(*v);
                        void *old = *v;

                        if (!GREEDY_REALLOC(*v, size + 1 + 1))
                                return -ENOMEM;

                        if (old != *v)
                                /* Readjust the parent pointers to the new address */
                                for (size_t i = 1; i < size; i++)
                                        (*v)[1 + i].parent = *v;

                        return json_variant_array_put_element(*v, element);
                }
        }

        if (!blank) {
                size_t size = sd_json_variant_elements(*v);

                _cleanup_free_ sd_json_variant **array = new(sd_json_variant*, size + 1);
                if (!array)
                        return -ENOMEM;

                for (size_t i = 0; i < size; i++)
                        array[i] = sd_json_variant_by_index(*v, i);

                array[size] = element;

                r = sd_json_variant_new_array(&nv, array, size + 1);
                if (r < 0)
                        return r;
        }

        json_variant_propagate_sensitive(*v, nv);
        JSON_VARIANT_REPLACE(*v, TAKE_PTR(nv));

        return 0;
}

_public_ int sd_json_variant_append_arrayb(sd_json_variant **v, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        va_list ap;
        int r;

        va_start(ap, v);
        r = sd_json_buildv(&w, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return sd_json_variant_append_array(v, w);
}

_public_ sd_json_variant *sd_json_variant_find(sd_json_variant *haystack, sd_json_variant *needle) {
        sd_json_variant *i;

        /* Find a json object in an array. Returns NULL if not found, or if the array is not actually an array. */

        JSON_VARIANT_ARRAY_FOREACH(i, haystack)
                if (sd_json_variant_equal(i, needle))
                        return i;

        return NULL;
}

_public_ int sd_json_variant_append_array_nodup(sd_json_variant **v, sd_json_variant *element) {
        assert_return(v, -EINVAL);

        if (sd_json_variant_find(*v, element))
                return 0;

        return sd_json_variant_append_array(v, element);
}

_public_ int sd_json_variant_strv(sd_json_variant *v, char ***ret) {
        char **l = NULL;
        bool sensitive;
        int r;

        assert_return(ret, -EINVAL);

        if (!v || sd_json_variant_is_null(v)) {
                l = new0(char*, 1);
                if (!l)
                        return -ENOMEM;

                *ret = l;
                return 0;
        }

        if (!sd_json_variant_is_array(v))
                return -EINVAL;

        sensitive = sd_json_variant_is_sensitive(v);

        size_t n = sd_json_variant_elements(v);
        l = new(char*, n+1);
        if (!l)
                return -ENOMEM;

        for (size_t i = 0; i < n; i++) {
                sd_json_variant *e;

                assert_se(e = sd_json_variant_by_index(v, i));
                sensitive = sensitive || sd_json_variant_is_sensitive(e);

                if (!sd_json_variant_is_string(e)) {
                        l[i] = NULL;
                        r = -EINVAL;
                        goto fail;
                }

                l[i] = strdup(sd_json_variant_string(e));
                if (!l[i]) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        l[n] = NULL;
        *ret = TAKE_PTR(l);

        return 0;

fail:
        if (sensitive)
                strv_free_erase(l);
        else
                strv_free(l);

        return r;
}

static int json_variant_copy(sd_json_variant **nv, sd_json_variant *v) {
        sd_json_variant_type_t t;
        sd_json_variant *c;
        JsonValue value;
        const void *source;
        size_t k;

        assert(nv);
        assert(v);

        /* Let's copy the simple types literally, and the larger types by references */
        t = sd_json_variant_type(v);
        switch (t) {
        case SD_JSON_VARIANT_INTEGER:
                k = sizeof(int64_t);
                value.integer = sd_json_variant_integer(v);
                source = &value;
                break;

        case SD_JSON_VARIANT_UNSIGNED:
                k = sizeof(uint64_t);
                value.unsig = sd_json_variant_unsigned(v);
                source = &value;
                break;

        case SD_JSON_VARIANT_REAL:
                k = sizeof(double);
                value.real = sd_json_variant_real(v);
                source = &value;
                break;

        case SD_JSON_VARIANT_BOOLEAN:
                k = sizeof(bool);
                value.boolean = sd_json_variant_boolean(v);
                source = &value;
                break;

        case SD_JSON_VARIANT_NULL:
                k = 0;
                source = NULL;
                break;

        case SD_JSON_VARIANT_STRING:
                source = sd_json_variant_string(v);
                k = strnlen(source, INLINE_STRING_MAX + 1);
                if (k <= INLINE_STRING_MAX) {
                        k++;
                        break;
                }

                _fallthrough_;

        default:
                /* Everything else copy by reference */

                c = malloc0(MAX(sizeof(sd_json_variant),
                                offsetof(sd_json_variant, reference) + sizeof(sd_json_variant*)));
                if (!c)
                        return -ENOMEM;

                c->n_ref = 1;
                c->type = t;
                c->is_reference = true;
                c->reference = sd_json_variant_ref(json_variant_formalize(v));

                *nv = c;
                return 0;
        }

        c = malloc0(MAX(sizeof(sd_json_variant),
                        offsetof(sd_json_variant, value) + k));
        if (!c)
                return -ENOMEM;

        c->n_ref = 1;
        c->type = t;

        memcpy_safe(&c->value, source, k);

        json_variant_propagate_sensitive(v, c);

        *nv = c;
        return 0;
}

static bool json_single_ref(sd_json_variant *v) {

        /* Checks whether the caller is the single owner of the object, i.e. can get away with changing it */

        if (!json_variant_is_regular(v))
                return false;

        if (v->is_embedded)
                return json_single_ref(v->parent);

        assert(v->n_ref > 0);
        return v->n_ref == 1;
}

static int json_variant_set_source(sd_json_variant **v, JsonSource *source, unsigned line, unsigned column) {
        sd_json_variant *w;
        int r;

        assert(v);

        /* Patch in source and line/column number. Tries to do this in-place if the caller is the sole
         * referencer of the object. If not, allocates a new object, possibly a surrogate for the original
         * one */

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

        JSON_VARIANT_REPLACE(*v, w);

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
        size_t n = 0;
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

                                if (!GREEDY_REALLOC(s, n + 5))
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

                        if (!GREEDY_REALLOC(s, n + 2))
                                return -ENOMEM;

                        s[n++] = ch;
                        c++;
                        continue;
                }

                len = utf8_encoded_valid_unichar(c, SIZE_MAX);
                if (len < 0)
                        return len;

                if (!GREEDY_REALLOC(s, n + len + 1))
                        return -ENOMEM;

                memcpy(s + n, c, len);
                n += len;
                c += len;
        }
}

static int json_parse_number(const char **p, JsonValue *ret) {
        bool negative = false, exponent_negative = false, is_real = false;
        double x = 0.0, y = 0.0, exponent = 0.0, shift = 1.0;
        int64_t i = 0;
        uint64_t u = 0;
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

                                        if (i < INT64_MIN / 10) /* overflow */
                                                is_real = true;
                                        else {
                                                int64_t t = 10 * i;

                                                if (t < INT64_MIN + (*c - '0')) /* overflow */
                                                        is_real = true;
                                                else
                                                        i = t - (*c - '0');
                                        }
                                } else {
                                        if (u > UINT64_MAX / 10) /* overflow */
                                                is_real = true;
                                        else {
                                                uint64_t t = 10 * u;

                                                if (t > UINT64_MAX - (*c - '0')) /* overflow */
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
                ret->real = ((negative ? -1.0 : 1.0) * (x + (y / shift))) * exp10((exponent_negative ? -1.0 : 1.0) * exponent);
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
                unsigned *ret_line,   /* 'reterr_line' returns the line at the beginning of this token */
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
                assert_not_reached();
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
        /* The following values are used by sd_json_parse() */
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

        /* And these are used by sd_json_build() */
        EXPECT_ARRAY_ELEMENT,
        EXPECT_OBJECT_KEY,
} JsonExpect;

typedef struct JsonStack {
        JsonExpect expect;
        sd_json_variant **elements;
        size_t n_elements;
        unsigned line_before;
        unsigned column_before;
        size_t n_suppress; /* When building: if > 0, suppress this many subsequent elements. If == SIZE_MAX, suppress all subsequent elements */
} JsonStack;

static void json_stack_release(JsonStack *s) {
        assert(s);

        CLEANUP_ARRAY(s->elements, s->n_elements, sd_json_variant_unref_many);
}

static int json_parse_internal(
                const char **input,
                JsonSource *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *line,
                unsigned *column,
                bool continue_end) {

        size_t n_stack = 1;
        unsigned line_buffer = 0, column_buffer = 0;
        void *tokenizer_state = NULL;
        JsonStack *stack = NULL;
        const char *p;
        int r;

        assert_return(input, -EINVAL);
        assert_return(ret, -EINVAL);

        p = *input;

        if (!GREEDY_REALLOC(stack, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        if (!line)
                line = &line_buffer;
        if (!column)
                column = &column_buffer;

        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *add = NULL;
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

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
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

                        r = sd_json_variant_new_object(&add, current->elements, current->n_elements);
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

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
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

                        r = sd_json_variant_new_array(&add, current->elements, current->n_elements);
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

                        r = sd_json_variant_new_string(&add, string);
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

                        r = sd_json_variant_new_real(&add, value.real);
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

                        r = sd_json_variant_new_integer(&add, value.integer);
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

                        r = sd_json_variant_new_unsigned(&add, value.unsig);
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

                        r = sd_json_variant_new_boolean(&add, value.boolean);
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

                        r = sd_json_variant_new_null(&add);
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
                        assert_not_reached();
                }

                if (add) {
                        /* If we are asked to make this parsed object sensitive, then let's apply this
                         * immediately after allocating each variant, so that when we abort half-way
                         * everything we already allocated that is then freed is correctly marked. */
                        if (FLAGS_SET(flags, SD_JSON_PARSE_SENSITIVE))
                                sd_json_variant_sensitive(add);

                        (void) json_variant_set_source(&add, source, line_token, column_token);

                        if (!GREEDY_REALLOC(current->elements, current->n_elements + 1)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = sd_json_variant_ref(stack[0].elements[0]);
        *input = p;
        r = 0;

finish:
        for (size_t i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

_public_ int sd_json_parse_with_source(
                const char *input,
                const char *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {

        _cleanup_(json_source_unrefp) JsonSource *s = NULL;

        if (isempty(input))
                return -ENODATA;

        if (source) {
                s = json_source_new(source);
                if (!s)
                        return -ENOMEM;
        }

        return json_parse_internal(&input, s, flags, ret, reterr_line, reterr_column, false);
}

_public_ int sd_json_parse_with_source_continue(
                const char **p,
                const char *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {

        _cleanup_(json_source_unrefp) JsonSource *s = NULL;

        if (source) {
                s = json_source_new(source);
                if (!s)
                        return -ENOMEM;
        }

        return json_parse_internal(p, s, flags, ret, reterr_line, reterr_column, true);
}

_public_ int sd_json_parse(
                const char *string,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {

        return sd_json_parse_with_source(string, NULL, flags, ret, reterr_line, reterr_column);
}

_public_ int sd_json_parse_continue(
                const char **p,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {

        return sd_json_parse_with_source_continue(p, NULL, flags, ret, reterr_line, reterr_column);
}

_public_ int sd_json_parse_file_at(
                FILE *f,
                int dir_fd,
                const char *path,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {

        _cleanup_free_ char *text = NULL;
        int r;

        if (f)
                r = read_full_stream(f, &text, NULL);
        else if (path)
                r = read_full_file_full(dir_fd, path, UINT64_MAX, SIZE_MAX, 0, NULL, &text, NULL);
        else
                return -EINVAL;
        if (r < 0)
                return r;

        return sd_json_parse_with_source(text, path, flags, ret, reterr_line, reterr_column);
}

_public_ int sd_json_parse_file(
                FILE *f,
                const char *path,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {

        return sd_json_parse_file_at(f, AT_FDCWD, path, flags, ret, reterr_line, reterr_column);
}

_public_ int sd_json_buildv(sd_json_variant **ret, va_list ap) {
        JsonStack *stack = NULL;
        size_t n_stack = 1;
        const char *name = NULL;
        int r;

        assert_return(ret, -EINVAL);

        if (!GREEDY_REALLOC(stack, n_stack))
                return -ENOMEM;

        stack[0] = (JsonStack) {
                .expect = EXPECT_TOPLEVEL,
        };

        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *add = NULL, *add_more = NULL;
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

                case _SD_JSON_BUILD_STRING:
                case _JSON_BUILD_STRING_UNDERSCORIFY: {
                        const char *p;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                _cleanup_free_ char *c = NULL;

                                if (command == _JSON_BUILD_STRING_UNDERSCORIFY) {
                                        c = strreplace(p, "-", "_");
                                        if (!c) {
                                                r = -ENOMEM;
                                                goto finish;
                                        }

                                        p = c;
                                }

                                r = sd_json_variant_new_string(&add, p);
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

                case _SD_JSON_BUILD_INTEGER: {
                        int64_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, int64_t);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_integer(&add, j);
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

                case _SD_JSON_BUILD_UNSIGNED: {
                        uint64_t j;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        j = va_arg(ap, uint64_t);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_unsigned(&add, j);
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

                case _SD_JSON_BUILD_REAL: {
                        double d;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        d = va_arg(ap, double);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_real(&add, d);
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

                case _SD_JSON_BUILD_BOOLEAN: {
                        bool b;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_boolean(&add, b);
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

                case _SD_JSON_BUILD_NULL:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_null(&add);
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

                case _SD_JSON_BUILD_VARIANT:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        /* Note that we don't care for current->n_suppress here, after all the variant is already
                         * allocated anyway... */
                        add = va_arg(ap, sd_json_variant*);
                        if (!add)
                                add = JSON_VARIANT_MAGIC_NULL;
                        else
                                sd_json_variant_ref(add);

                        n_subtract = 1;

                        if (current->expect == EXPECT_TOPLEVEL)
                                current->expect = EXPECT_END;
                        else if (current->expect == EXPECT_OBJECT_VALUE)
                                current->expect = EXPECT_OBJECT_KEY;
                        else
                                assert(current->expect == EXPECT_ARRAY_ELEMENT);

                        break;

                case _SD_JSON_BUILD_VARIANT_ARRAY: {
                        sd_json_variant **array;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        array = va_arg(ap, sd_json_variant**);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_array(&add, array, n);
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

                case _SD_JSON_BUILD_LITERAL: {
                        const char *l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, const char *);

                        if (l) {
                                /* Note that we don't care for current->n_suppress here, we should generate parsing
                                 * errors even in suppressed object properties */

                                r = sd_json_parse(l, 0, &add, NULL, NULL);
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

                case _SD_JSON_BUILD_ARRAY_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
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
                                .n_suppress = current->n_suppress != 0 ? SIZE_MAX : 0, /* if we shall suppress the
                                                                                           * new array, then we should
                                                                                           * also suppress all array
                                                                                           * members */
                        };

                        break;

                case _SD_JSON_BUILD_ARRAY_END:
                        if (current->expect != EXPECT_ARRAY_ELEMENT) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_array(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _SD_JSON_BUILD_STRV: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_array_strv(&add, l);
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

                case _JSON_BUILD_STRV_ENV_PAIR: {
                        char **l;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        l = va_arg(ap, char **);

                        if (current->n_suppress == 0) {
                                _cleanup_strv_free_ char **el = NULL;

                                r = strv_env_get_merged(l, &el);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_strv(&add, el);
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

                case _SD_JSON_BUILD_BASE64:
                case _SD_JSON_BUILD_BASE32HEX:
                case _SD_JSON_BUILD_HEX:
                case _SD_JSON_BUILD_OCTESCAPE: {
                        const void *p;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        p = va_arg(ap, const void *);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = command == _SD_JSON_BUILD_BASE64    ? sd_json_variant_new_base64(&add, p, n) :
                                    command == _SD_JSON_BUILD_BASE32HEX ? sd_json_variant_new_base32hex(&add, p, n) :
                                    command == _SD_JSON_BUILD_HEX       ? sd_json_variant_new_hex(&add, p, n) :
                                                                          sd_json_variant_new_octescape(&add, p, n);
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

                case _JSON_BUILD_IOVEC_BASE64:
                case _JSON_BUILD_IOVEC_HEX: {
                        const struct iovec *iov;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        iov = va_arg(ap, const struct iovec*);

                        if (current->n_suppress == 0) {
                                if (iov)
                                        r = command == _JSON_BUILD_IOVEC_BASE64 ? sd_json_variant_new_base64(&add, iov->iov_base, iov->iov_len) :
                                                                                  sd_json_variant_new_hex(&add, iov->iov_base, iov->iov_len);
                                else
                                        r = sd_json_variant_new_string(&add, "");
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

                case _SD_JSON_BUILD_ID128:
                case _SD_JSON_BUILD_UUID: {
                        const sd_id128_t *id;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert_se(id = va_arg(ap, sd_id128_t*));

                        if (current->n_suppress == 0) {
                                r = command == _SD_JSON_BUILD_ID128 ?
                                        sd_json_variant_new_id128(&add, *id) :
                                        sd_json_variant_new_uuid(&add, *id);
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

                case _SD_JSON_BUILD_BYTE_ARRAY: {
                        const void *array;
                        size_t n;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        array = va_arg(ap, const void*);
                        n = va_arg(ap, size_t);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_array_bytes(&add, array, n);
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

                case _JSON_BUILD_HW_ADDR: {
                        const struct hw_addr_data *hw_addr;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert_se(hw_addr = va_arg(ap, struct hw_addr_data*));

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_array_bytes(&add, hw_addr->bytes, hw_addr->length);
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

                case _JSON_BUILD_STRING_SET: {
                        Set *set;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        set = va_arg(ap, Set*);

                        if (current->n_suppress == 0) {
                                _cleanup_free_ char **sorted = NULL;

                                r = set_dump_sorted(set, (void ***) &sorted, NULL);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_strv(&add, sorted);
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

                case _JSON_BUILD_STRING_ORDERED_SET: {
                        OrderedSet *set;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        set = va_arg(ap, OrderedSet*);

                        if (current->n_suppress == 0) {
                                _cleanup_free_ char **sv = NULL;

                                sv = ordered_set_get_strv(set);
                                if (!sv) {
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                r = sd_json_variant_new_array_strv(&add, sv);
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

                case _JSON_BUILD_DUAL_TIMESTAMP: {
                        dual_timestamp *ts;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        ts = va_arg(ap, dual_timestamp*);

                        if (current->n_suppress == 0) {
                                if (dual_timestamp_is_set(ts)) {
                                        r = sd_json_buildo(
                                                        &add,
                                                        SD_JSON_BUILD_PAIR("realtime", SD_JSON_BUILD_UNSIGNED(ts->realtime)),
                                                        SD_JSON_BUILD_PAIR("monotonic", SD_JSON_BUILD_UNSIGNED(ts->monotonic)));
                                        if (r < 0)
                                                goto finish;
                                } else
                                        add = JSON_VARIANT_MAGIC_NULL;
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

                case _JSON_BUILD_RATELIMIT: {
                        const RateLimit *rl;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        rl = va_arg(ap, const RateLimit*);

                        if (current->n_suppress == 0) {
                                if (ratelimit_configured(rl)) {
                                        r = sd_json_buildo(
                                                        &add,
                                                        SD_JSON_BUILD_PAIR("intervalUSec", SD_JSON_BUILD_UNSIGNED(rl->interval)),
                                                        SD_JSON_BUILD_PAIR("burst", SD_JSON_BUILD_UNSIGNED(rl->burst)));
                                        if (r < 0)
                                                goto finish;
                                } else
                                        add = JSON_VARIANT_MAGIC_NULL;
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

                case _JSON_BUILD_PIDREF: {
                        PidRef *pidref;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        pidref = va_arg(ap, PidRef*);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_pidref(&add, pidref);
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

                case _JSON_BUILD_DEVNUM: {
                        dev_t devnum;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        devnum = va_arg(ap, dev_t);

                        if (current->n_suppress == 0) {
                                r = json_variant_new_devnum(&add, devnum);
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

                case _JSON_BUILD_TRISTATE: {
                        int tristate;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        tristate = va_arg(ap, int);

                        if (current->n_suppress == 0) {
                                if (tristate >= 0) {
                                        r = sd_json_variant_new_boolean(&add, tristate);
                                        if (r < 0)
                                                goto finish;
                                } else
                                        add = JSON_VARIANT_MAGIC_NULL;
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

                case _SD_JSON_BUILD_CALLBACK: {
                        sd_json_build_callback_t cb;
                        void *userdata;

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        cb = va_arg(ap, sd_json_build_callback_t);
                        userdata = va_arg(ap, void *);

                        if (current->n_suppress == 0) {
                                if (cb) {
                                        r = cb(&add, name, userdata);
                                        if (r < 0)
                                                goto finish;
                                }

                                if (!add)
                                        add = JSON_VARIANT_MAGIC_NULL;

                                name = NULL;
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

                case _SD_JSON_BUILD_OBJECT_BEGIN:

                        if (!IN_SET(current->expect, EXPECT_TOPLEVEL, EXPECT_OBJECT_VALUE, EXPECT_ARRAY_ELEMENT)) {
                                r = -EINVAL;
                                goto finish;
                        }

                        if (!GREEDY_REALLOC(stack, n_stack+1)) {
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
                                .n_suppress = current->n_suppress != 0 ? SIZE_MAX : 0, /* If we shall suppress the
                                                                                        * new object, then we should
                                                                                        * also suppress all object
                                                                                        * members. */
                        };

                        break;

                case _SD_JSON_BUILD_OBJECT_END:

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        assert(n_stack > 1);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_object(&add, current->elements, current->n_elements);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        json_stack_release(current);
                        n_stack--, current--;

                        break;

                case _SD_JSON_BUILD_PAIR: {

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        name = va_arg(ap, const char *);

                        if (current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, name);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1;

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _SD_JSON_BUILD_PAIR_CONDITION: {
                        bool b;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        b = va_arg(ap, int);
                        name = va_arg(ap, const char *);

                        if (b && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, name);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 1; /* we generated one item */

                        if (!b && current->n_suppress != SIZE_MAX)
                                current->n_suppress += 2; /* Suppress this one and the next item */

                        current->expect = EXPECT_OBJECT_VALUE;
                        break;
                }

                case _JSON_BUILD_PAIR_INTEGER_NON_ZERO:
                case _JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE: {
                        const char *n;
                        int64_t i;
                        bool include;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        i = va_arg(ap, int64_t);

                        if (command == _JSON_BUILD_PAIR_INTEGER_NON_ZERO)
                                include = i != 0;
                        else if (command == _JSON_BUILD_PAIR_INTEGER_NON_NEGATIVE)
                                include = i >= 0;
                        else
                                assert_not_reached();

                        if (include && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_integer(&add_more, i);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO:
                case _JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL: {
                        const char *n;
                        uint64_t u, eq;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        u = va_arg(ap, uint64_t);
                        eq = command == _JSON_BUILD_PAIR_UNSIGNED_NON_ZERO ? 0 : va_arg(ap, uint64_t);

                        if (u != eq && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_unsigned(&add_more, u);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_FINITE_USEC: {
                        const char *n;
                        usec_t u;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        u = va_arg(ap, usec_t);

                        if (u != USEC_INFINITY && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_unsigned(&add_more, u);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_STRING_NON_EMPTY: {
                        const char *n, *s;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        s = va_arg(ap, const char *);

                        if (!isempty(s) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_string(&add_more, s);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_STRV_NON_EMPTY:
                case _JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY: {
                        const char *n;
                        char **l;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        l = va_arg(ap, char **);

                        if (!strv_isempty(l) && current->n_suppress == 0) {
                                _cleanup_strv_free_ char **el = NULL;

                                if (command == _JSON_BUILD_PAIR_STRV_ENV_PAIR_NON_EMPTY) {
                                        r = strv_env_get_merged(l, &el);
                                        if (r < 0)
                                                goto finish;
                                }

                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_strv(&add_more, el ?: l);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_VARIANT_NON_NULL: {
                        sd_json_variant *v;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        v = va_arg(ap, sd_json_variant *);

                        if (v && !sd_json_variant_is_null(v) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                add_more = sd_json_variant_ref(v);
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_BYTE_ARRAY_NON_EMPTY: {
                        const void *array;
                        size_t sz;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        array = va_arg(ap, const void*);
                        sz = va_arg(ap, size_t);

                        if (sz > 0 && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_bytes(&add_more, array, sz);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_IN4_ADDR_NON_NULL: {
                        const struct in_addr *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct in_addr *);

                        if (a && in4_addr_is_set(a) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_bytes(&add_more, a, sizeof(struct in_addr));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_IN6_ADDR_NON_NULL: {
                        const struct in6_addr *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct in6_addr *);

                        if (a && in6_addr_is_set(a) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_bytes(&add_more, a, sizeof(struct in6_addr));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_IN_ADDR_NON_NULL: {
                        const union in_addr_union *a;
                        const char *n;
                        int f;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const union in_addr_union *);
                        f = va_arg(ap, int);

                        if (a && in_addr_is_set(f, a) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_bytes(&add_more, a->bytes, FAMILY_ADDRESS_SIZE(f));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL: {
                        const struct ether_addr *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct ether_addr *);

                        if (a && !ether_addr_is_null(a) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_bytes(&add_more, a->ether_addr_octet, sizeof(struct ether_addr));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_HW_ADDR_NON_NULL: {
                        const struct hw_addr_data *a;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char *);
                        a = va_arg(ap, const struct hw_addr_data *);

                        if (a && !hw_addr_is_null(a) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_array_bytes(&add_more, a->bytes, a->length);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_DUAL_TIMESTAMP_NON_NULL: {
                        const dual_timestamp *ts;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        ts = va_arg(ap, const dual_timestamp*);

                        if (ts && dual_timestamp_is_set(ts) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_buildo(&add_more,
                                                SD_JSON_BUILD_PAIR("realtime", SD_JSON_BUILD_UNSIGNED(ts->realtime)),
                                                SD_JSON_BUILD_PAIR("monotonic", SD_JSON_BUILD_UNSIGNED(ts->monotonic)));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_RATELIMIT_ENABLED: {
                        const RateLimit *rl;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        rl = va_arg(ap, const RateLimit*);

                        if (rl && ratelimit_configured(rl) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_buildo(&add_more,
                                                SD_JSON_BUILD_PAIR("intervalUSec", SD_JSON_BUILD_UNSIGNED(rl->interval)),
                                                SD_JSON_BUILD_PAIR("burst", SD_JSON_BUILD_UNSIGNED(rl->burst)));
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_PIDREF_NON_NULL: {
                        PidRef *p;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        p = va_arg(ap, PidRef*);

                        if (pidref_is_set(p) && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = json_variant_new_pidref(&add_more, p);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two items */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_CALLBACK_NON_NULL: {
                        sd_json_build_callback_t cb;
                        void *userdata;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        cb = va_arg(ap, sd_json_build_callback_t);
                        userdata = va_arg(ap, void*);

                        if (current->n_suppress == 0) {
                                if (cb) {
                                        r = cb(&add_more, n, userdata);
                                        if (r < 0)
                                                goto finish;
                                }

                                if (add_more) {
                                        r = sd_json_variant_new_string(&add, n);
                                        if (r < 0)
                                                goto finish;
                                }
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_BASE64_NON_EMPTY:
                case _JSON_BUILD_PAIR_BASE32HEX_NON_EMPTY:
                case _JSON_BUILD_PAIR_HEX_NON_EMPTY:
                case _JSON_BUILD_PAIR_OCTESCAPE_NON_EMPTY: {
                        const void *p;
                        size_t sz;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        p = va_arg(ap, const void *);
                        sz = va_arg(ap, size_t);

                        if (sz > 0 && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = command == _JSON_BUILD_PAIR_BASE64_NON_EMPTY    ? sd_json_variant_new_base64(&add_more, p, sz) :
                                    command == _JSON_BUILD_PAIR_BASE32HEX_NON_EMPTY ? sd_json_variant_new_base32hex(&add_more, p, sz) :
                                    command == _JSON_BUILD_PAIR_HEX_NON_EMPTY       ? sd_json_variant_new_hex(&add_more, p, sz) :
                                                                                      sd_json_variant_new_octescape(&add_more, p, sz);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }

                case _JSON_BUILD_PAIR_TRISTATE_NON_NULL: {
                        int tristate;
                        const char *n;

                        if (current->expect != EXPECT_OBJECT_KEY) {
                                r = -EINVAL;
                                goto finish;
                        }

                        n = va_arg(ap, const char*);
                        tristate = va_arg(ap, int);

                        if (tristate >= 0 && current->n_suppress == 0) {
                                r = sd_json_variant_new_string(&add, n);
                                if (r < 0)
                                        goto finish;

                                r = sd_json_variant_new_boolean(&add_more, tristate);
                                if (r < 0)
                                        goto finish;
                        }

                        n_subtract = 2; /* we generated two item */

                        current->expect = EXPECT_OBJECT_KEY;
                        break;
                }
                }

                /* If variants were generated, add them to our current variant, but only if we are not supposed to suppress additions */
                if (add && current->n_suppress == 0) {
                        if (!GREEDY_REALLOC(current->elements, current->n_elements + 1 + !!add_more)) {
                                r = -ENOMEM;
                                goto finish;
                        }

                        current->elements[current->n_elements++] = TAKE_PTR(add);
                        if (add_more)
                                current->elements[current->n_elements++] = TAKE_PTR(add_more);
                }

                /* If we are supposed to suppress items, let's subtract how many items where generated from
                 * that counter. Except if the counter is SIZE_MAX, i.e. we shall suppress an infinite number
                 * of elements on this stack level */
                if (current->n_suppress != SIZE_MAX) {
                        if (current->n_suppress <= n_subtract) /* Saturated */
                                current->n_suppress = 0;
                        else
                                current->n_suppress -= n_subtract;
                }
        }

done:
        assert(n_stack == 1);
        assert(stack[0].n_elements == 1);

        *ret = sd_json_variant_ref(stack[0].elements[0]);
        r = 0;

finish:
        for (size_t i = 0; i < n_stack; i++)
                json_stack_release(stack + i);

        free(stack);

        return r;
}

_public_ int sd_json_build(sd_json_variant **ret, ...) {
        va_list ap;
        int r;

        va_start(ap, ret);
        r = sd_json_buildv(ret, ap);
        va_end(ap);

        return r;
}

int json_log_internal(
                sd_json_variant *variant,
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
                r = sd_json_variant_get_source(variant, &source, &source_line, &source_column);
                if (r < 0)
                        return r;
        } else {
                source = NULL;
                source_line = 0;
                source_column = 0;
        }

        if (source && source_line > 0 && source_column > 0)
                return log_struct_internal(
                                level,
                                error,
                                file, line, func,
                                LOG_MESSAGE_ID(SD_MESSAGE_INVALID_CONFIGURATION_STR),
                                LOG_ITEM("CONFIG_FILE=%s", source),
                                LOG_ITEM("CONFIG_LINE=%u", source_line),
                                LOG_ITEM("CONFIG_COLUMN=%u", source_column),
                                LOG_MESSAGE("%s:%u:%u: %s", source, source_line, source_column, buffer),
                                NULL);
        else if (source_line > 0 && source_column > 0)
                return log_struct_internal(
                                level,
                                error,
                                file, line, func,
                                LOG_MESSAGE_ID(SD_MESSAGE_INVALID_CONFIGURATION_STR),
                                LOG_ITEM("CONFIG_LINE=%u", source_line),
                                LOG_ITEM("CONFIG_COLUMN=%u", source_column),
                                LOG_MESSAGE("(string):%u:%u: %s", source_line, source_column, buffer),
                                NULL);
        else
                return log_struct_internal(
                                level,
                                error,
                                file, line, func,
                                LOG_MESSAGE_ID(SD_MESSAGE_INVALID_CONFIGURATION_STR),
                                LOG_MESSAGE("%s", buffer),
                                NULL);
}

static void* dispatch_userdata(const sd_json_dispatch_field *p, void *userdata) {

        /* When the userdata pointer is passed in as NULL, then we'll just use the offset as a literal
         * address, and convert it to a pointer.  Note that might as well just add the offset to the NULL
         * pointer, but UndefinedBehaviourSanitizer doesn't like pointer arithmetics based on NULL pointers,
         * hence we code this explicitly here. */

        if (userdata)
                return (uint8_t*) userdata + p->offset;

        return SIZE_TO_PTR(p->offset);
}

_public_ int sd_json_dispatch_full(
                sd_json_variant *v,
                const sd_json_dispatch_field table[],
                sd_json_dispatch_callback_t bad,
                sd_json_dispatch_flags_t flags,
                void *userdata,
                const char **reterr_bad_field) {
        size_t m;
        int r, done = 0;
        bool *found;

        if (!sd_json_variant_is_object(v)) {
                json_log(v, flags, 0, "JSON variant is not an object.");

                if (flags & SD_JSON_PERMISSIVE)
                        return 0;

                if (reterr_bad_field)
                        *reterr_bad_field = NULL;

                return -EINVAL;
        }

        m = 0;
        for (const sd_json_dispatch_field *p = table; p && p->name; p++)
                m++;

        found = newa0(bool, m);

        size_t n = sd_json_variant_elements(v);
        for (size_t i = 0; i < n; i += 2) {
                sd_json_variant *key, *value;
                const sd_json_dispatch_field *p;

                assert_se(key = sd_json_variant_by_index(v, i));
                assert_se(value = sd_json_variant_by_index(v, i+1));

                for (p = table; p && p->name; p++)
                        if (p->name == POINTER_MAX ||
                            streq_ptr(sd_json_variant_string(key), p->name))
                                break;

                if (p && p->name) { /* Found a matching entry! 🙂 */
                        sd_json_dispatch_flags_t merged_flags;

                        merged_flags = flags | p->flags;

                        /* If an explicit type is specified, verify it matches */
                        if (p->type != _SD_JSON_VARIANT_TYPE_INVALID &&
                            !sd_json_variant_has_type(value, p->type) &&
                            !(FLAGS_SET(merged_flags, SD_JSON_NULLABLE) && sd_json_variant_is_null(value))) {

                                json_log(value, merged_flags, 0,
                                         "Object field '%s' has wrong type %s, expected %s.", sd_json_variant_string(key),
                                         sd_json_variant_type_to_string(sd_json_variant_type(value)), sd_json_variant_type_to_string(p->type));

                                if (merged_flags & SD_JSON_PERMISSIVE)
                                        continue;

                                if (reterr_bad_field)
                                        *reterr_bad_field = p->name;

                                return -EINVAL;
                        }

                        /* If the SD_JSON_REFUSE_NULL flag is specified, insist the field is not "null". Note
                         * that this provides overlapping functionality with the type check above. */
                        if (FLAGS_SET(merged_flags, SD_JSON_REFUSE_NULL) && sd_json_variant_is_null(value)) {

                                json_log(value, merged_flags, 0,
                                         "Object field '%s' may not be null.", sd_json_variant_string(key));

                                if (merged_flags & SD_JSON_PERMISSIVE)
                                        continue;

                                if (reterr_bad_field)
                                        *reterr_bad_field = p->name;

                                return -EINVAL;
                        }

                        if (found[p-table]) {
                                json_log(value, merged_flags, 0, "Duplicate object field '%s'.", sd_json_variant_string(key));

                                if (merged_flags & SD_JSON_PERMISSIVE)
                                        continue;

                                if (reterr_bad_field)
                                        *reterr_bad_field = p->name;

                                return -ENOTUNIQ;
                        }

                        found[p-table] = true;

                        if (p->callback) {
                                r = p->callback(sd_json_variant_string(key), value, merged_flags, dispatch_userdata(p, userdata));
                                if (r < 0) {
                                        if (merged_flags & SD_JSON_PERMISSIVE)
                                                continue;

                                        if (reterr_bad_field)
                                                *reterr_bad_field = sd_json_variant_string(key);

                                        return r;
                                }
                        }

                        done++;

                } else { /* Didn't find a matching entry! ☹️ */

                        if (bad) {
                                r = bad(sd_json_variant_string(key), value, flags, userdata);
                                if (r < 0) {
                                        if (flags & SD_JSON_PERMISSIVE)
                                                continue;

                                        if (reterr_bad_field)
                                                *reterr_bad_field = sd_json_variant_string(key);

                                        return r;
                                } else
                                        done++;

                        } else  {
                                if (flags & SD_JSON_ALLOW_EXTENSIONS) {
                                        json_log(value, flags|SD_JSON_DEBUG, 0, "Unrecognized object field '%s', assuming extension.", sd_json_variant_string(key));
                                        continue;
                                }

                                json_log(value, flags, 0, "Unexpected object field '%s'.", sd_json_variant_string(key));
                                if (flags & SD_JSON_PERMISSIVE)
                                        continue;

                                if (reterr_bad_field)
                                        *reterr_bad_field = sd_json_variant_string(key);

                                return -EADDRNOTAVAIL;
                        }
                }
        }

        for (const sd_json_dispatch_field *p = table; p && p->name; p++) {
                sd_json_dispatch_flags_t merged_flags = p->flags | flags;

                if ((merged_flags & SD_JSON_MANDATORY) && !found[p-table]) {
                        json_log(v, merged_flags, 0, "Missing object field '%s'.", p->name);

                        if ((merged_flags & SD_JSON_PERMISSIVE))
                                continue;

                        if (reterr_bad_field)
                                *reterr_bad_field = p->name;

                        return -ENXIO;
                }
        }

        return done;
}

_public_ int sd_json_dispatch(
                sd_json_variant *v,
                const sd_json_dispatch_field table[],
                sd_json_dispatch_flags_t flags,
                void *userdata) {

        return sd_json_dispatch_full(v, table, NULL, flags, userdata, NULL);
}

_public_ int sd_json_dispatch_stdbool(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        bool *b = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (!sd_json_variant_is_boolean(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a boolean.", strna(name));

        *b = sd_json_variant_boolean(variant);
        return 0;
}

_public_ int sd_json_dispatch_intbool(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int *b = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (!sd_json_variant_is_boolean(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a boolean.", strna(name));

        *b = sd_json_variant_boolean(variant);
        return 0;
}

_public_ int sd_json_dispatch_tristate(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int *b = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (sd_json_variant_is_null(variant)) {
                *b = -1;
                return 0;
        }

        if (!sd_json_variant_is_boolean(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a boolean.", strna(name));

        *b = sd_json_variant_boolean(variant);
        return 0;
}

_public_ int sd_json_dispatch_int64(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int64_t *i = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        /* Also accept numbers formatted as string, to increase compatibility with less capable JSON
         * implementations that cannot do 64bit integers. */
        if (sd_json_variant_is_string(variant) && safe_atoi64(sd_json_variant_string(variant), i) >= 0)
                return 0;

        if (!sd_json_variant_is_integer(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer, nor one formatted as decimal string.", strna(name));

        *i = sd_json_variant_integer(variant);
        return 0;
}

_public_ int sd_json_dispatch_uint64(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        uint64_t *u = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        /* Since 64bit values (in particular unsigned ones) in JSON are problematic, let's also accept them
         * formatted as strings. If this is not desired make sure to set the .type field in
         * sd_json_dispatch_field to SD_JSON_UNSIGNED rather than _SD_JSON_VARIANT_TYPE_INVALID, so that
         * json_dispatch() already filters out the non-matching type. */

        if (sd_json_variant_is_string(variant) && safe_atou64(sd_json_variant_string(variant), u) >= 0)
                return 0;

        if (!sd_json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an unsigned integer, nor one formatted as decimal string.", strna(name));

        *u = sd_json_variant_unsigned(variant);
        return 0;
}

_public_ int sd_json_dispatch_uint32(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        uint32_t *u = userdata;
        uint64_t u64;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_uint64(name, variant, flags, &u64);
        if (r < 0)
                return r;

        if (u64 > UINT32_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *u = (uint32_t) u64;
        return 0;
}

/* We define sd_json_dispatch_uint() as alias for json_dispatch_uint32(), let's make sure this is safe */
assert_cc(sizeof(uint32_t) == sizeof(unsigned));

_public_ int sd_json_dispatch_int32(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int32_t *i = userdata;
        int64_t i64;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_int64(name, variant, flags, &i64);
        if (r < 0)
                return r;

        if (i64 < INT32_MIN || i64 > INT32_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *i = (int32_t) i64;
        return 0;
}

/* We define sd_json_dispatch_int() as alias for json_dispatch_int32(), let's make sure this is safe */
assert_cc(sizeof(int32_t) == sizeof(int));

_public_ int sd_json_dispatch_int16(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int16_t *i = userdata;
        int64_t i64;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_int64(name, variant, flags, &i64);
        if (r < 0)
                return r;

        if (i64 < INT16_MIN || i64 > INT16_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *i = (int16_t) i64;
        return 0;
}

_public_ int sd_json_dispatch_uint16(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        uint16_t *u = userdata;
        uint64_t u64;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_uint64(name, variant, flags, &u64);
        if (r < 0)
                return r;

        if (u64 > UINT16_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *u = (uint16_t) u64;
        return 0;
}

_public_ int sd_json_dispatch_int8(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int8_t *i = userdata;
        int64_t i64;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_int64(name, variant, flags, &i64);
        if (r < 0)
                return r;

        if (i64 < INT8_MIN || i64 > INT8_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *i = (int8_t) i64;
        return 0;
}

_public_ int sd_json_dispatch_uint8(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        uint8_t *u = userdata;
        uint64_t u64;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_uint64(name, variant, flags, &u64);
        if (r < 0)
                return r;

        if (u64 > UINT8_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(ERANGE), "JSON field '%s' out of bounds.", strna(name));

        *u = (uint8_t) u64;
        return 0;
}

_public_ int sd_json_dispatch_double(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        double *d = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        /* Note, this will take care of parsing NaN, -Infinity, Infinity for us */
        if (sd_json_variant_is_string(variant) && safe_atod(sd_json_variant_string(variant), d) >= 0)
                return 0;

        if (!sd_json_variant_is_real(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a floating point value, nor one formatted as string.", strna(name));

        *d = sd_json_variant_real(variant);
        return 0;
}

_public_ int sd_json_dispatch_string(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **s = userdata;
        const char *n;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        r = sd_json_dispatch_const_string(name, variant, flags, &n);
        if (r < 0)
                return r;

        r = free_and_strdup(s, n);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to allocate string: %m");

        return 0;
}

_public_ int sd_json_dispatch_const_string(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        const char **s = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (sd_json_variant_is_null(variant)) {
                *s = NULL;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        if ((flags & SD_JSON_STRICT) && !string_is_safe(sd_json_variant_string(variant)))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' contains unsafe characters, refusing.", strna(name));

        *s = sd_json_variant_string(variant);
        return 0;
}

_public_ int sd_json_dispatch_strv(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        char ***s = userdata;
        sd_json_variant *e;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (sd_json_variant_is_null(variant)) {
                *s = strv_free(*s);
                return 0;
        }

        /* Let's be flexible here: accept a single string in place of a single-item array */
        if (sd_json_variant_is_string(variant)) {
                if ((flags & SD_JSON_STRICT) && !string_is_safe(sd_json_variant_string(variant)))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' contains unsafe characters, refusing.", strna(name));

                l = strv_new(sd_json_variant_string(variant));
                if (!l)
                        return log_oom();

                strv_free_and_replace(*s, l);
                return 0;
        }

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, SYNTHETIC_ERRNO(EINVAL), flags, "JSON field '%s' is not an array.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                if (!sd_json_variant_is_string(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a string.");

                if ((flags & SD_JSON_STRICT) && !string_is_safe(sd_json_variant_string(e)))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' contains unsafe characters, refusing.", strna(name));

                r = strv_extend(&l, sd_json_variant_string(e));
                if (r < 0)
                        return json_log(e, flags, r, "Failed to append array element: %m");
        }

        strv_free_and_replace(*s, l);
        return 0;
}

_public_ int sd_json_dispatch_variant(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_json_variant **p = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        /* Takes a reference */
        JSON_VARIANT_REPLACE(*p, sd_json_variant_ref(variant));
        return 0;
}

_public_ int sd_json_dispatch_variant_noref(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_json_variant **p = userdata;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        /* Doesn't take a reference */
        *p = variant;
        return 0;
}

_public_ int sd_json_dispatch_uid_gid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        uid_t *uid = userdata;
        uint64_t k;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));
        assert_cc(sizeof(gid_t) == sizeof(uint32_t));

        DISABLE_WARNING_TYPE_LIMITS;
        assert_cc((UID_INVALID < (uid_t) 0) == (GID_INVALID < (gid_t) 0));
        REENABLE_WARNING;

        if (sd_json_variant_is_null(variant)) {
                *uid = UID_INVALID;
                return 0;
        }

        if (!sd_json_variant_is_unsigned(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an integer.", strna(name));

        k = sd_json_variant_unsigned(variant);
        if (k > UINT32_MAX || !uid_is_valid(k))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid UID/GID.", strna(name));

        *uid = k;
        return 0;
}

_public_ int sd_json_dispatch_id128(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_id128_t *uuid = userdata;
        int r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (sd_json_variant_is_null(variant)) {
                *uuid = SD_ID128_NULL;
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = sd_id128_from_string(sd_json_variant_string(variant), uuid);
        if (r < 0)
                return json_log(variant, flags, r, "JSON field '%s' is not a valid UID.", strna(name));

        return 0;
}

_public_ int sd_json_dispatch_signal(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int *signo = userdata, r;

        assert_return(variant, -EINVAL);
        assert_return(userdata, -EINVAL);

        if (sd_json_variant_is_null(variant)) {
                *signo = SIGNO_INVALID;
                return 0;
        }

        int k;
        r = sd_json_dispatch_int(name, variant, flags, &k);
        if (r < 0)
                return r;

        if (!SIGNAL_VALID(k))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid signal.", strna(name));

        *signo = k;
        return 0;
}

_public_ int sd_json_dispatch_unsupported(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not allowed in this object.", strna(name));
}

static int json_cmp_strings(const void *x, const void *y) {
        sd_json_variant *const *a = x, *const *b = y;

        if (!sd_json_variant_is_string(*a) || !sd_json_variant_is_string(*b))
                return CMP(*a, *b);

        return strcmp(sd_json_variant_string(*a), sd_json_variant_string(*b));
}

_public_ int sd_json_variant_sort(sd_json_variant **v) {
        _cleanup_free_ sd_json_variant **a = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *n = NULL;
        size_t m;
        int r;

        assert_return(v, -EINVAL);

        if (sd_json_variant_is_sorted(*v))
                return 0;

        if (!sd_json_variant_is_object(*v))
                return -EMEDIUMTYPE;

        /* Sorts they key/value pairs in an object variant */

        m = sd_json_variant_elements(*v);
        a = new(sd_json_variant*, m);
        if (!a)
                return -ENOMEM;

        for (size_t i = 0; i < m; i++)
                a[i] = sd_json_variant_by_index(*v, i);

        qsort(a, m/2, sizeof(sd_json_variant*)*2, json_cmp_strings);

        r = sd_json_variant_new_object(&n, a, m);
        if (r < 0)
                return r;

        json_variant_propagate_sensitive(*v, n);

        if (!n->sorted) /* Check if this worked. This will fail if there are multiple identical keys used. */
                return -ENOTUNIQ;

        JSON_VARIANT_REPLACE(*v, TAKE_PTR(n));

        return 1;
}

_public_ int sd_json_variant_normalize(sd_json_variant **v) {
        _cleanup_free_ sd_json_variant **a = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *n = NULL;
        size_t i, m;
        int r;

        assert_return(v, -EINVAL);

        if (sd_json_variant_is_normalized(*v))
                return 0;

        if (!sd_json_variant_is_object(*v) && !sd_json_variant_is_array(*v))
                return -EMEDIUMTYPE;

        /* Sorts the key/value pairs in an object variant anywhere down the tree in the specified variant */

        m = sd_json_variant_elements(*v);
        a = new(sd_json_variant*, m);
        if (!a)
                return -ENOMEM;

        for (i = 0; i < m; ) {
                a[i] = sd_json_variant_ref(sd_json_variant_by_index(*v, i));
                i++;

                r = sd_json_variant_normalize(&a[i-1]);
                if (r < 0)
                        goto finish;
        }

        qsort(a, m/2, sizeof(sd_json_variant*)*2, json_cmp_strings);

        if (sd_json_variant_is_object(*v))
                r = sd_json_variant_new_object(&n, a, m);
        else {
                assert(sd_json_variant_is_array(*v));
                r = sd_json_variant_new_array(&n, a, m);
        }
        if (r < 0)
                goto finish;

        json_variant_propagate_sensitive(*v, n);

        if (!n->normalized) { /* Let's see if normalization worked. It will fail if there are multiple
                               * identical keys used in the same object anywhere, or if there are floating
                               * point numbers used (see below) */
                r = -ENOTUNIQ;
                goto finish;
        }

        JSON_VARIANT_REPLACE(*v, TAKE_PTR(n));

        r = 1;

finish:
        for (size_t j = 0; j < i; j++)
                sd_json_variant_unref(a[j]);

        return r;
}

_public_ int sd_json_variant_is_normalized(sd_json_variant *v) {
        /* For now, let's consider anything containing numbers not expressible as integers as non-normalized.
         * That's because we cannot sensibly compare them due to accuracy issues, nor even store them if they
         * are too large. */
        if (sd_json_variant_is_real(v) && !sd_json_variant_is_integer(v) && !sd_json_variant_is_unsigned(v))
                return false;

        /* The concept only applies to variants that include other variants, i.e. objects and arrays. All
         * others are normalized anyway. */
        if (!sd_json_variant_is_object(v) && !sd_json_variant_is_array(v))
                return true;

        /* Empty objects/arrays don't include any other variant, hence are always normalized too */
        if (sd_json_variant_elements(v) == 0)
                return true;

        return v->normalized; /* For everything else there's an explicit boolean we maintain */
}

_public_ int sd_json_variant_is_sorted(sd_json_variant *v) {

        /* Returns true if all key/value pairs of an object are properly sorted. Note that this only applies
         * to objects, not arrays. */

        if (!sd_json_variant_is_object(v))
                return true;
        if (sd_json_variant_elements(v) <= 1)
                return true;

        return v->sorted;
}

_public_ int sd_json_variant_unbase64(sd_json_variant *v, void **ret, size_t *ret_size) {
        if (!sd_json_variant_is_string(v))
                return -EINVAL;

        return unbase64mem_full(sd_json_variant_string(v), SIZE_MAX, /* secure= */ sd_json_variant_is_sensitive(v), ret, ret_size);
}

_public_ int sd_json_variant_unhex(sd_json_variant *v, void **ret, size_t *ret_size) {
        if (!sd_json_variant_is_string(v))
                return -EINVAL;

        return unhexmem_full(sd_json_variant_string(v), SIZE_MAX, /* secure= */ sd_json_variant_is_sensitive(v), ret, ret_size);
}

static const char* const sd_json_variant_type_table[_SD_JSON_VARIANT_TYPE_MAX] = {
        [SD_JSON_VARIANT_STRING]   = "string",
        [SD_JSON_VARIANT_INTEGER]  = "integer",
        [SD_JSON_VARIANT_UNSIGNED] = "unsigned",
        [SD_JSON_VARIANT_REAL]     = "real",
        [SD_JSON_VARIANT_NUMBER]   = "number",
        [SD_JSON_VARIANT_BOOLEAN]  = "boolean",
        [SD_JSON_VARIANT_ARRAY]    = "array",
        [SD_JSON_VARIANT_OBJECT]   = "object",
        [SD_JSON_VARIANT_NULL]     = "null",
};

_DEFINE_STRING_TABLE_LOOKUP(sd_json_variant_type, sd_json_variant_type_t, _public_);

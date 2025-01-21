/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "alloc-util.h"
#include "macro.h"
#include "siphash24.h"

typedef void (*hash_func_t)(const void *p, struct siphash *state);
typedef int (*compare_func_t)(const void *a, const void *b);

struct hash_ops {
        hash_func_t hash;
        compare_func_t compare;
        free_func_t free_key;
        free_func_t free_value;
};

#define _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func, free_key_func, free_value_func, scope) \
        _unused_ static void (* UNIQ_T(static_hash_wrapper, uq))(const type *, struct siphash *) = hash_func; \
        _unused_ static int (* UNIQ_T(static_compare_wrapper, uq))(const type *, const type *) = compare_func; \
        scope const struct hash_ops name = {                            \
                .hash = (hash_func_t) hash_func,                        \
                .compare = (compare_func_t) compare_func,               \
                .free_key = free_key_func,                              \
                .free_value = free_value_func,                          \
        }

#define _DEFINE_FREE_FUNC(uq, type, wrapper_name, func)                 \
        /* Type-safe free function */                                   \
        static void UNIQ_T(wrapper_name, uq)(void *a) {                 \
                type *_a = a;                                           \
                func(_a);                                               \
        }

#define _DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(uq, name, type, hash_func, compare_func, free_func, scope) \
        _DEFINE_FREE_FUNC(uq, type, static_free_wrapper, free_func);    \
        _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func,       \
                         UNIQ_T(static_free_wrapper, uq), NULL, scope)

#define _DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(uq, name, type, hash_func, compare_func, type_value, free_func, scope) \
        _DEFINE_FREE_FUNC(uq, type_value, static_free_wrapper, free_func); \
        _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func,       \
                         NULL, UNIQ_T(static_free_wrapper, uq), scope)

#define _DEFINE_HASH_OPS_FULL(uq, name, type, hash_func, compare_func, free_key_func, type_value, free_value_func, scope) \
        _DEFINE_FREE_FUNC(uq, type, static_free_key_wrapper, free_key_func); \
        _DEFINE_FREE_FUNC(uq, type_value, static_free_value_wrapper, free_value_func); \
        _DEFINE_HASH_OPS(uq, name, type, hash_func, compare_func,       \
                         UNIQ_T(static_free_key_wrapper, uq),           \
                         UNIQ_T(static_free_value_wrapper, uq), scope)

#define DEFINE_HASH_OPS(name, type, hash_func, compare_func)            \
        _DEFINE_HASH_OPS(UNIQ, name, type, hash_func, compare_func, NULL, NULL,)

#define DEFINE_PRIVATE_HASH_OPS(name, type, hash_func, compare_func)    \
        _DEFINE_HASH_OPS(UNIQ, name, type, hash_func, compare_func, NULL, NULL, static)

#define DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(name, type, hash_func, compare_func, free_func) \
        _DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, free_func,)

#define DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(name, type, hash_func, compare_func, free_func) \
        _DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, free_func, static)

#define DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(name, type, hash_func, compare_func, value_type, free_func) \
        _DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, value_type, free_func,)

#define DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(name, type, hash_func, compare_func, value_type, free_func) \
        _DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(UNIQ, name, type, hash_func, compare_func, value_type, free_func, static)

#define DEFINE_HASH_OPS_FULL(name, type, hash_func, compare_func, free_key_func, value_type, free_value_func) \
        _DEFINE_HASH_OPS_FULL(UNIQ, name, type, hash_func, compare_func, free_key_func, value_type, free_value_func,)

#define DEFINE_PRIVATE_HASH_OPS_FULL(name, type, hash_func, compare_func, free_key_func, value_type, free_value_func) \
        _DEFINE_HASH_OPS_FULL(UNIQ, name, type, hash_func, compare_func, free_key_func, value_type, free_value_func, static)

void string_hash_func(const char *p, struct siphash *state);
#define string_compare_func strcmp
extern const struct hash_ops string_hash_ops;
extern const struct hash_ops string_hash_ops_free;
extern const struct hash_ops string_hash_ops_value_free;
extern const struct hash_ops string_hash_ops_free_free;
extern const struct hash_ops string_hash_ops_free_strv_free;

void path_hash_func(const char *p, struct siphash *state);
extern const struct hash_ops path_hash_ops;
extern const struct hash_ops path_hash_ops_free;
extern const struct hash_ops path_hash_ops_free_free;

/* This will compare the passed pointers directly, and will not dereference them. This is hence not useful for strings
 * or suchlike. */
void trivial_hash_func(const void *p, struct siphash *state);
int trivial_compare_func(const void *a, const void *b) _const_;
extern const struct hash_ops trivial_hash_ops;
extern const struct hash_ops trivial_hash_ops_free;
extern const struct hash_ops trivial_hash_ops_value_free;
extern const struct hash_ops trivial_hash_ops_free_free;

/* 32-bit values we can always just embed in the pointer itself, but in order to support 32-bit archs we need store 64-bit
 * values indirectly, since they don't fit in a pointer. */
void uint64_hash_func(const uint64_t *p, struct siphash *state);
int uint64_compare_func(const uint64_t *a, const uint64_t *b) _pure_;
extern const struct hash_ops uint64_hash_ops;
extern const struct hash_ops uint64_hash_ops_value_free;

/* On some archs dev_t is 32-bit, and on others 64-bit. And sometimes it's 64-bit on 32-bit archs, and sometimes 32-bit on
 * 64-bit archs. Yuck! */
#if SIZEOF_DEV_T != 8
void devt_hash_func(const dev_t *p, struct siphash *state);
#else
#define devt_hash_func uint64_hash_func
#endif

int devt_compare_func(const dev_t *a, const dev_t *b) _pure_;
extern const struct hash_ops devt_hash_ops;

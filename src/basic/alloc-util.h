/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <alloca.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "macro.h"

#if HAS_FEATURE_MEMORY_SANITIZER
#  include <sanitizer/msan_interface.h>
#endif

typedef void (*free_func_t)(void *p);

/* If for some reason more than 4M are allocated on the stack, let's abort immediately. It's better than
 * proceeding and smashing the stack limits. Note that by default RLIMIT_STACK is 8M on Linux. */
#define ALLOCA_MAX (4U*1024U*1024U)

#define ROUND_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

#define new(t, n) ((t*) malloc_multiply(sizeof(t), (n)))

#define new0(t, n) ((t*) calloc((n) ?: 1, sizeof(t)))

#define newa(t, n)                                                      \
        ({                                                              \
                size_t _n_ = n;                                         \
                assert(!size_multiply_overflow(sizeof(t), _n_));        \
                assert(sizeof(t)*_n_ <= ALLOCA_MAX);                    \
                (t*) alloca(sizeof(t)*_n_);                             \
        })

#define newmalloca(t, n)                                                \
        ({                                                              \
                size_t _n_ = n;                                         \
                assert(!size_multiply_overflow(sizeof(t), _n_));        \
                assert(sizeof(t) * _n_ <= ALLOCA_MAX);                  \
                (t *) malloca(sizeof(t) * _n_, __alignof__(t));         \
        })

#define newa0(t, n)                                                     \
        ({                                                              \
                size_t _n_ = n;                                         \
                assert(!size_multiply_overflow(sizeof(t), _n_));        \
                assert(sizeof(t)*_n_ <= ALLOCA_MAX);                    \
                (t*) alloca0(sizeof(t)*_n_);                            \
        })

#define newmalloca0(t, n)                                               \
        ({                                                              \
                size_t _n_ = n;                                         \
                assert(!size_multiply_overflow(sizeof(t), _n_));        \
                assert(sizeof(t) * _n_ <= ALLOCA_MAX);                  \
                (t *) malloca0(sizeof(t) * _n_, __alignof__(t));        \
        })

#define newdup(t, p, n) ((t*) memdup_multiply(p, sizeof(t), (n)))

#define newdup_suffix0(t, p, n) ((t*) memdup_suffix0_multiply(p, sizeof(t), (n)))

#define malloc0(n) (calloc(1, (n)))

static inline void *mfree(void *memory) {
        free(memory);
        return NULL;
}

#define free_and_replace(a, b)                  \
        ({                                      \
                free(a);                        \
                (a) = (b);                      \
                (b) = NULL;                     \
                0;                              \
        })

void* memdup(const void *p, size_t l) _alloc_(2);
void* memdup_suffix0(const void *p, size_t l) _alloc_(2);

#define memdupa(p, l)                           \
        ({                                      \
                void *_q_;                      \
                size_t _l_ = l;                 \
                assert(_l_ <= ALLOCA_MAX);      \
                _q_ = alloca(_l_);              \
                memcpy(_q_, p, _l_);            \
        })

#define memdupa_suffix0(p, l)                   \
        ({                                      \
                void *_q_;                      \
                size_t _l_ = l;                 \
                assert(_l_ <= ALLOCA_MAX);      \
                _q_ = alloca(_l_ + 1);          \
                ((uint8_t*) _q_)[_l_] = 0;      \
                memcpy(_q_, p, _l_);            \
        })

static inline void freep(void *p) {
        free(*(void**) p);
}

#define MALLOCA_THRESHOLD 256

#define DECLARE_MALLOCABLE_TYPE_FULL(t, n)                              \
        static inline void malloca_release_##n(void *p) {               \
                void *pc = *(void **)p;                                 \
                size_t a = __alignof__(t) * 2;                          \
                if (((uintptr_t)pc & (a - 1)) == 0)                     \
                        free(pc);                                       \
        }

#define DECLARE_MALLOCABLE_TYPE(t) DECLARE_MALLOCABLE_TYPE_FULL(t, t)

#define _mallocable_full_(t, n) _cleanup_(malloca_release_##n) t
#define _mallocable_(t) _mallocable_full_(t, t)

DECLARE_MALLOCABLE_TYPE(char)
DECLARE_MALLOCABLE_TYPE(uint8_t)
DECLARE_MALLOCABLE_TYPE(int)
DECLARE_MALLOCABLE_TYPE_FULL(long double, long_double)
DECLARE_MALLOCABLE_TYPE_FULL(unsigned long long, unsigned_long_long)

/* malloca/malloca_release are based on address alignment.
 * Allocations that go on the stack are aligned to "align" but not to 2*"align".
 * Allocations that go on the heap are aligned to 2*"align".
 */
#define malloca(sz, align)                                              \
        ({                                                              \
                void *_mr_;                                             \
                size_t _mda_ = (align) * 2;                             \
                size_t _mlen_ = (sz);                                   \
                if (_mlen_ < MALLOCA_THRESHOLD)                         \
                        _mr_ = alloca_half_align(_mlen_, _mda_);        \
                else                                                    \
                        _mr_ = aligned_alloc(_mda_, ROUND_UP(_mlen_, _mda_)); \
                _mr_;                                                   \
        })

#define malloca0(sz, align)                                     \
        ({                                                      \
                char *_cnew_;                                   \
                size_t _clen_ = (sz);                           \
                _cnew_ = malloca(_clen_, (align));              \
                if (_cnew_)                                     \
                        (void *) memset(_cnew_, 0, _clen_);     \
                _cnew_;                                         \
        })

#define _cleanup_free_ _cleanup_(freep)

static inline bool size_multiply_overflow(size_t size, size_t need) {
        return _unlikely_(need != 0 && size > (SIZE_MAX / need));
}

_malloc_  _alloc_(1, 2) static inline void *malloc_multiply(size_t size, size_t need) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return malloc(size * need ?: 1);
}

#if !HAVE_REALLOCARRAY
_alloc_(2, 3) static inline void *reallocarray(void *p, size_t need, size_t size) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return realloc(p, size * need ?: 1);
}
#endif

_alloc_(2, 3) static inline void *memdup_multiply(const void *p, size_t size, size_t need) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return memdup(p, size * need);
}

_alloc_(2, 3) static inline void *memdup_suffix0_multiply(const void *p, size_t size, size_t need) {
        if (size_multiply_overflow(size, need))
                return NULL;

        return memdup_suffix0(p, size * need);
}

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size);
void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size);

#define GREEDY_REALLOC(array, allocated, need)                          \
        greedy_realloc((void**) &(array), &(allocated), (need), sizeof((array)[0]))

#define GREEDY_REALLOC0(array, allocated, need)                         \
        greedy_realloc0((void**) &(array), &(allocated), (need), sizeof((array)[0]))

#define alloca0(n)                                      \
        ({                                              \
                char *_new_;                            \
                size_t _len_ = n;                       \
                assert(_len_ <= ALLOCA_MAX);            \
                _new_ = alloca(_len_);                  \
                (void *) memset(_new_, 0, _len_);       \
        })

/* It's not clear what alignment glibc/gcc alloca() guarantee, hence provide a guaranteed safe version */
#define alloca_align(size, align)                                       \
        ({                                                              \
                void *_ptr_;                                            \
                size_t _mask_ = (align) - 1;                            \
                size_t _size_ = size;                                   \
                assert(_size_ <= ALLOCA_MAX);                           \
                _ptr_ = alloca(_size_ + _mask_);                        \
                (void*)ROUND_UP((uintptr_t)_ptr_, align);               \
        })

/* Allocate size bytes on the stack, aligned to "align/2" but not to "align" */
#define alloca_half_align(size, align)                                  \
        ({                                                              \
                uintptr_t _ptr_;                                        \
                size_t _align_ = (align);                               \
                size_t _size_ = (size);                                 \
                size_t _mask_ = _align_ - 1;                            \
                size_t _half_ = _align_ / 2;                            \
                assert(_size_ <= ALLOCA_MAX);                           \
                /* find the nearest value that is aligned to _half_ but \
                 * not to "align" */                                    \
                _ptr_ = (uintptr_t)alloca(_size_ + _mask_) - _half_;    \
                (void *)(ROUND_UP(_ptr_, _align_) + _half_);            \
        })

#define alloca0_align(size, align)                                      \
        ({                                                              \
                void *_new_;                                            \
                size_t _xsize_ = (size);                                \
                _new_ = alloca_align(_xsize_, (align));                 \
                (void*)memset(_new_, 0, _xsize_);                       \
        })

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_PTR(ptr)                           \
        ({                                      \
                typeof(ptr) _ptr_ = (ptr);      \
                (ptr) = NULL;                   \
                _ptr_;                          \
        })

#if HAS_FEATURE_MEMORY_SANITIZER
#  define msan_unpoison(r, s) __msan_unpoison(r, s)
#else
#  define msan_unpoison(r, s)
#endif

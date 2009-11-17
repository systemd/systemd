/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foomacrohfoo
#define foomacrohfoo

#include <assert.h>
#include <sys/types.h>

#define __printf_attr(a,b) __attribute__ ((format (printf, a, b)))
#define __sentinel __attribute__ ((sentinel))
#define __noreturn __attribute__((noreturn))
#define __unused __attribute__ ((unused))
#define __destructor __attribute__ ((destructor))
#define __pure __attribute__ ((pure))
#define __const __attribute__ ((const))
#define __deprecated __attribute__ ((deprecated))
#define __packed __attribute__ ((packed))
#define __malloc __attribute__ ((malloc))

/* Rounds up */
static inline size_t ALIGN(size_t l) {
        return ((l + sizeof(void*) - 1) & ~(sizeof(void*) - 1));
}

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

#define MAX(a,b)                                \
        __extension__ ({                        \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a > _b ? _a : _b;      \
                })

#define MIN(a,b)                                \
        __extension__ ({                        \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a < _b ? _a : _b;      \
                })

#define CLAMP(x, low, high)                                             \
        __extension__ ({                                                \
                        typeof(x) _x = (x);                             \
                        typeof(low) _low = (low);                       \
                        typeof(high) _high = (high);                    \
                        ((_x > _high) ? _high : ((_x < _low) ? _low : _x)); \
                })



#define assert_not_reached(t) assert(!(t))

#define assert_se(x) assert(x)

#define assert_cc(expr)                            \
        do {                                       \
                switch (0) {                       \
                        case 0:                    \
                        case !!(expr):             \
                                ;                  \
                }                                  \
        } while (false)

#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_UINT32(p) ((uint32_t) ((uintptr_t) (p)))
#define UINT32_TO_PTR(u) ((void*) ((uintptr_t) (u)))

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(u) ((void*) ((intptr_t) (u)))

#define TO_INT32(p) ((int32_t) ((intptr_t) (p)))
#define INT32_TO_PTR(u) ((void*) ((intptr_t) (u)))

#endif

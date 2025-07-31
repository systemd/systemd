/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <time.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timex.h>

#define __STDC_WANT_IEC_60559_TYPES_EXT__
#include <float.h>

#include "forward.h"

/* Print information about various types. Useful when diagnosing
 * gcc diagnostics on an unfamiliar architecture. */

DISABLE_WARNING_TYPE_LIMITS;

#define info_no_sign(t)                                                 \
        printf("%s → %zu bits, %zu byte alignment\n", STRINGIFY(t),    \
               sizeof(t)*CHAR_BIT,                                      \
               alignof(t))

#define info(t)                                                         \
        printf("%s → %zu bits%s, %zu byte alignment\n", STRINGIFY(t),  \
               sizeof(t)*CHAR_BIT,                                      \
               strstr(STRINGIFY(t), "signed") ? "" :                    \
               (t)-1 < (t)0 ? ", signed" : ", unsigned",                \
               alignof(t))

#define check_no_sign(t, size)                  \
        do {                                    \
                info_no_sign(t);                \
                assert_se(sizeof(t) == size);   \
        } while (false)

#define check(t, size)                          \
        do {                                    \
                info(t);                        \
                assert_se(sizeof(t) == size);   \
        } while (false)

enum Enum {
        enum_value,
};

enum BigEnum {
        big_enum_value = UINT64_C(1),
};

enum BigEnum2 {
        big_enum2_pos = UINT64_C(1),
        big_enum2_neg = UINT64_C(-1),
};

int main(void) {
        int (*function_pointer)(void);

        check_no_sign(dev_t, SIZEOF_DEV_T);
        check_no_sign(ino_t, SIZEOF_INO_T);
        check_no_sign(rlim_t, SIZEOF_RLIM_T);
        check(time_t, SIZEOF_TIME_T);
        check(typeof_field(struct timex, freq), SIZEOF_TIMEX_MEMBER);

        info_no_sign(typeof(function_pointer));
        info_no_sign(void*);
        info(char*);

        info(char);
        info(signed char);
        info(unsigned char);
        info(short unsigned);
        info(unsigned);
        info(unsigned long);
        info(unsigned long long);
#ifdef __GLIBC__
        info(__syscall_ulong_t);
        info(__syscall_slong_t);
#endif
        info(intmax_t);
        info(uintmax_t);

        info(float);
        info(double);
        info(long double);

#ifdef FLT128_MAX
        info(_Float128);
        info(_Float64);
        info(_Float64x);
        info(_Float32);
        info(_Float32x);
#endif

        info(size_t);
        info(ssize_t);
        info(usec_t);
#ifdef __GLIBC__
        info(__time_t);
#endif
        info(pid_t);
        info(uid_t);
        info(gid_t);
        info(socklen_t);

#ifdef __GLIBC__
        info(__cpu_mask);
#endif

        info(enum Enum);
        info(enum BigEnum);
        info(enum BigEnum2);
        assert_cc(sizeof(enum BigEnum2) == 8);
        printf("big_enum2_pos → %zu\n", sizeof(big_enum2_pos));
        printf("big_enum2_neg → %zu\n", sizeof(big_enum2_neg));

        printf("timeval: %zu\n", sizeof(struct timeval));
        printf("timespec: %zu\n", sizeof(struct timespec));

        void *x = malloc(100);

        printf("local variable: %p\n", &function_pointer);
        printf("glibc function: %p\n", memcpy);
        printf("heap allocation: %p\n", x);
        free(x);

        return 0;
}

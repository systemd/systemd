/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek
***/

#include <stdio.h>
#include <string.h>

#include "time-util.h"

/* Print information about various types. Useful when diagnosing
 * gcc diagnostics on an unfamiliar architecture. */

#pragma GCC diagnostic ignored "-Wtype-limits"

#define info(t)                                                 \
        printf("%s → %zu bits%s\n", STRINGIFY(t),               \
               sizeof(t)*CHAR_BIT,                              \
               strstr(STRINGIFY(t), "signed") ? "" :            \
               ((t)-1 < (t)0 ? ", signed" : ", unsigned"));

enum Enum {
        enum_value,
};

enum BigEnum {
        big_enum_value = UINT64_C(-1),
};

int main(void) {
        info(char);
        info(signed char);
        info(unsigned char);
        info(short unsigned);
        info(unsigned);
        info(long unsigned);
        info(long long unsigned);
        info(__syscall_ulong_t);
        info(__syscall_slong_t);

        info(float);
        info(double);
        info(long double);

        info(size_t);
        info(ssize_t);
        info(time_t);
        info(usec_t);
        info(__time_t);
        info(pid_t);
        info(uid_t);
        info(gid_t);

        info(enum Enum);
        info(enum BigEnum);

        return 0;
}

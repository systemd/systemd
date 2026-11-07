/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/syscall.h>

int main(void) {
#if defined(SYS_settimeofday) || defined(SYS_settimeofday_time32)
        return EXIT_SUCCESS;
#else
        return EXIT_FAILURE;
#endif
}

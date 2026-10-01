/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(SYS_gettimeofday)
#define SYSCALL SYS_gettimeofday
#elif defined(SYS_gettimeofday_time32)
#define SYSCALL SYS_gettimeofday_time32
#else
#define SYSCALL -1 /* Force -ENOSYS. */
#endif

int main(void) {
        struct timezone tz;

        if (syscall(SYSCALL, NULL, &tz) < 0)
                return EXIT_FAILURE;

        printf("%d\n", tz.tz_minuteswest);

        return EXIT_SUCCESS;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

int main(void) {
        struct timezone tz;

        if (syscall(SYS_gettimeofday, NULL, &tz) < 0)
                return EXIT_FAILURE;

        printf("%d\n", tz.tz_minuteswest);

        return EXIT_SUCCESS;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

int main(void)
{
        struct timezone tz;

        if (syscall(SYS_gettimeofday, NULL, &tz) < 0)
                return 1;

        printf("%d\n", tz.tz_minuteswest);

        return 0;
}

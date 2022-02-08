/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "ticks.h"

#ifdef __x86_64__
UINT64 ticks_read(void) {
        UINT64 a, d;
        __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
        return (d << 32) | a;
}
#elif defined(__i386__)
UINT64 ticks_read(void) {
        UINT64 val;
        __asm__ volatile ("rdtsc" : "=A" (val));
        return val;
}
#elif defined(__aarch64__)
UINT64 ticks_read(void) {
        UINT64 val;
        __asm__ volatile ("mrs %0, cntpct_el0" : "=r" (val));
        return val;
}
#else
UINT64 ticks_read(void) {
        UINT64 val = 1;
        return val;
}
#endif

#if defined(__aarch64__)
UINT64 ticks_freq(void) {
        UINT64 freq;
        __asm__ volatile ("mrs %0, cntfrq_el0": "=r" (freq));
        return freq;
}
#else
/* count TSC ticks during a millisecond delay */
UINT64 ticks_freq(void) {
        UINT64 ticks_start, ticks_end;

        ticks_start = ticks_read();
        BS->Stall(1000);
        ticks_end = ticks_read();

        return (ticks_end - ticks_start) * 1000UL;
}
#endif

UINT64 time_usec(void) {
        UINT64 ticks;
        static UINT64 freq;

        ticks = ticks_read();
        if (ticks == 0)
                return 0;

        if (freq == 0) {
                freq = ticks_freq();
                if (freq == 0)
                        return 0;
        }

        return 1000UL * 1000UL * ticks / freq;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>
#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif

#include "ticks.h"

#if defined(__i386__) || defined(__x86_64__)
static BOOLEAN in_hypervisor(void) {
        uint32_t eax, ebx, ecx, edx;

        /* The TSC might or might not be virtualized in VMs (and thus might not be accurate or start at zero
         * at boot), depending on hypervisor and CPU functionality. If it's not virtualized it's not useful
         * for keeping time, hence don't attempt to use it.
         *
         * This is a dumbed down version of src/basic/virt.c's detect_vm() that safely works in the UEFI
         * environment. */

        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0)
                return FALSE;

        return !!(ecx & 0x80000000U);
}
#endif

#ifdef __x86_64__
static UINT64 ticks_read(void) {
        UINT64 a, d;

        if (in_hypervisor())
                return 0;

        __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
        return (d << 32) | a;
}
#elif defined(__i386__)
static UINT64 ticks_read(void) {
        UINT64 val;

        if (in_hypervisor())
                return 0;

        __asm__ volatile ("rdtsc" : "=A" (val));
        return val;
}
#elif defined(__aarch64__)
static UINT64 ticks_read(void) {
        UINT64 val;
        __asm__ volatile ("mrs %0, cntpct_el0" : "=r" (val));
        return val;
}
#else
static UINT64 ticks_read(void) {
        return 0;
}
#endif

#if defined(__aarch64__)
static UINT64 ticks_freq(void) {
        UINT64 freq;
        __asm__ volatile ("mrs %0, cntfrq_el0": "=r" (freq));
        return freq;
}
#else
/* count TSC ticks during a millisecond delay */
static UINT64 ticks_freq(void) {
        UINT64 ticks_start, ticks_end;
        static UINT64 cache = 0;

        if (cache != 0)
                return cache;

        ticks_start = ticks_read();
        BS->Stall(1000);
        ticks_end = ticks_read();

        if (ticks_end < ticks_start) /* Check for an overflow (which is not that unlikely, given on some
                                      * archs the value is 32bit) */
                return 0;

        cache = (ticks_end - ticks_start) * 1000UL;
        return cache;
}
#endif

UINT64 time_usec(void) {
        UINT64 ticks, freq;

        ticks = ticks_read();
        if (ticks == 0)
                return 0;

        freq = ticks_freq();
        if (freq == 0)
                return 0;

        return 1000UL * 1000UL * ticks / freq;
}

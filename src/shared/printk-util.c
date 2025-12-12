/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "log.h"
#include "parse-util.h"
#include "printk-util.h"
#include "sysctl-util.h"

int sysctl_printk_read(void) {
        int r;

        _cleanup_free_ char *sysctl_printk_vals = NULL;
        r = sysctl_read("kernel/printk", &sysctl_printk_vals);
        if (r < 0)
                return log_debug_errno(r, "Cannot read sysctl kernel.printk: %m");

        _cleanup_free_ char *sysctl_printk_curr = NULL;
        const char *p = sysctl_printk_vals;
        r = extract_first_word(&p, &sysctl_printk_curr, NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to split out kernel printk priority: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Short read while reading kernel.printk sysctl");

        int current_lvl;
        r = safe_atoi(sysctl_printk_curr, &current_lvl);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse kernel.printk sysctl: %s", sysctl_printk_vals);

        return current_lvl;
}

int sysctl_printk_write(int l) {
        int r;

        r = sysctl_writef("kernel/printk", "%i", l);
        if (r < 0)
                return log_debug_errno(r, "Failed to set kernel.printk to %i: %m", l);

        return 0;
}

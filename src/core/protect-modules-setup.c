/***
  This file is part of systemd.

  Copyright 2017 Djalal Harouni

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <linux/prctl.h>

#include "protect-modules-setup.h"
#include "string-util.h"
#include "string-table.h"
#include "strv.h"
#include "util.h"

int setup_module_auto_restrict(ProtectKernelModules protect_modules)
{
        int r;
        unsigned int protectvalue = 0;

        switch (protect_modules) {
        case PROTECT_KERNEL_MODULES_FULL:
                protectvalue = 1;
                break;
        case PROTECT_KERNEL_MODULES_STRICT:
                protectvalue = 2;
                break;
        default:
                break;
        }

        /* No Module Auto-load Restrict Protection */
        if (protectvalue == 0)
                return 0;

        r = prctl(PR_MOD_AUTO_RESTRICT_OPTS, PR_SET_MOD_AUTO_RESTRICT, protectvalue, 0, 0);
        if (r < 0) {
                if (errno == EINVAL)
                        log_debug("ModAutoRestrict is not enabled in the kernel.");
                else
                        return log_debug_errno(errno, "Failed to enable ModAutoRestrict: %m");
        }

        return 0;
}

static const char *const protect_kernel_modules_table[_PROTECT_KERNEL_MODULES_MAX] = {
        [PROTECT_KERNEL_MODULES_NO] = "no",
        [PROTECT_KERNEL_MODULES_YES] = "yes",
        [PROTECT_KERNEL_MODULES_FULL] = "full",
        [PROTECT_KERNEL_MODULES_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP(protect_kernel_modules, ProtectKernelModules);

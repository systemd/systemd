#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2017 Djalal Harouni

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published
  by  the Free Software Foundation; either version 2.1 of the License,
  or  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "macro.h"

typedef enum ProtectKernelModules {
        PROTECT_KERNEL_MODULES_NO,      /* Classic permissions, no protection installed */
        PROTECT_KERNEL_MODULES_YES,     /* Use seccomp to block module syscalls and explicit module loading */
        PROTECT_KERNEL_MODULES_FULL,    /* Use PROTECT_KERNEL_MODULES_YES protections + use ModAutoRestrict LSM
                                           protection if available to block unprivileged module auto-loading */
        PROTECT_KERNEL_MODULES_STRICT,  /* Use PROTECT_KERNEL_MODULES_YES protections + removes CAP_SYS_MODULE
                                           capability + use ModAutoRestrict LSM protection if available to block
                                           all implicit module auto-loading operations */
        _PROTECT_KERNEL_MODULES_MAX,
        _PROTECT_KERNEL_MODULES_INVALID = -1
} ProtectKernelModules;

const char* protect_kernel_modules_to_string(ProtectKernelModules p) _const_;
ProtectKernelModules protect_kernel_modules_from_string(const char *s) _pure_;

int setup_module_auto_restrict(ProtectKernelModules protect_modules);

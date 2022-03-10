/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

_noreturn_ void freeze_or_exit_or_reboot(void);
void install_crash_handler(void);

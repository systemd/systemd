/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int install_name_printf(
                RuntimeScope scope,
                const InstallInfo *info,
                const char *format,
                char **ret);

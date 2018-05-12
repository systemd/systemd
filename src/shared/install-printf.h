/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek
***/

#include "install.h"

int install_full_printf(UnitFileInstallInfo *i, const char *format, char **ret);

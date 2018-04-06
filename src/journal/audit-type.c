/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2015 Zbigniew Jędrzejewski-Szmek
***/

#include <stdio.h>
#include <linux/audit.h>
#if HAVE_AUDIT
#  include <libaudit.h>
#endif

#include "missing.h"
#include "audit-type.h"
#include "audit_type-to-name.h"
#include "macro.h"

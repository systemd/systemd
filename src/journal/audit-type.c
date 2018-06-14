/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <linux/audit.h>
#if HAVE_AUDIT
#  include <libaudit.h>
#endif

#include "missing.h"
#include "audit-type.h"
#include "audit_type-to-name.h"
#include "macro.h"

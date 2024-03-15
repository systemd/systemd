/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/audit.h>

#if HAVE_AUDIT
#  include <libaudit.h>
#endif

#ifndef AUDIT_SERVICE_START
#  define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#else
assert_cc(AUDIT_SERVICE_START == 1130);
#endif

#ifndef AUDIT_SERVICE_STOP
#  define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#else
assert_cc(AUDIT_SERVICE_STOP == 1131);
#endif

#ifndef MAX_AUDIT_MESSAGE_LENGTH
#  define MAX_AUDIT_MESSAGE_LENGTH 8970
#else
assert_cc(MAX_AUDIT_MESSAGE_LENGTH == 8970);
#endif

#ifndef AUDIT_NLGRP_MAX
#  define AUDIT_NLGRP_READLOG 1
#else
assert_cc(AUDIT_NLGRP_MAX == 1);
#endif

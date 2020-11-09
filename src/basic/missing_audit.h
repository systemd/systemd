/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/audit.h>

#if HAVE_AUDIT
#include <libaudit.h>
#endif

#ifndef AUDIT_SERVICE_START
#define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#endif

#ifndef AUDIT_SERVICE_STOP
#define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#endif

#ifndef MAX_AUDIT_MESSAGE_LENGTH
#define MAX_AUDIT_MESSAGE_LENGTH 8970
#endif

#ifndef AUDIT_NLGRP_MAX
#define AUDIT_NLGRP_READLOG 1
#endif

/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/capability.h>

/* 3a101b8de0d39403b2c7e5c23fd0b005668acf48 (3.16) */
#ifndef CAP_AUDIT_READ
#define CAP_AUDIT_READ 37

#undef  CAP_LAST_CAP
#define CAP_LAST_CAP   CAP_AUDIT_READ
#endif

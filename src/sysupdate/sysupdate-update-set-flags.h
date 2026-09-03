/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum UpdateSetFlags {
        UPDATE_NEWEST     = 1 << 0,
        UPDATE_AVAILABLE  = 1 << 1,
        UPDATE_INSTALLED  = 1 << 2,
        UPDATE_OBSOLETE   = 1 << 3,
        UPDATE_PROTECTED  = 1 << 4,
        UPDATE_INCOMPLETE = 1 << 5,
        UPDATE_PARTIAL    = 1 << 6,
        UPDATE_PENDING    = 1 << 7,
        UPDATE_TOO_NEW    = 1 << 8, /* Newer than MaxVersion= permits */
        UPDATE_CANDIDATE  = 1 << 9, /* The version selected for updating to */
} UpdateSetFlags;

const char* update_set_flags_to_color(UpdateSetFlags flags);
const char* update_set_flags_to_glyph(UpdateSetFlags flags);

#define UPDATE_SET_FLAGS_STRING_MAX sizeof("candidate+partial+obsolete+too-new+incomplete")
char* update_set_flags_to_string_buf(UpdateSetFlags flags, char buf[static UPDATE_SET_FLAGS_STRING_MAX]);
#define FORMAT_UPDATE_SET_FLAGS(flags) update_set_flags_to_string_buf((flags), (char[UPDATE_SET_FLAGS_STRING_MAX]) {})

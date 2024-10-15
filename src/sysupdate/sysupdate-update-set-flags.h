/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum UpdateSetFlags {
        UPDATE_NEWEST     = 1 << 0,
        UPDATE_AVAILABLE  = 1 << 1,
        UPDATE_INSTALLED  = 1 << 2,
        UPDATE_OBSOLETE   = 1 << 3,
        UPDATE_PROTECTED  = 1 << 4,
        UPDATE_INCOMPLETE = 1 << 5,
} UpdateSetFlags;

const char* update_set_flags_to_color(UpdateSetFlags flags);
const char* update_set_flags_to_glyph(UpdateSetFlags flags);
const char* update_set_flags_to_string(UpdateSetFlags flags);

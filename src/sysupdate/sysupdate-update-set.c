/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "glyph-util.h"
#include "string-util.h"
#include "sysupdate-update-set.h"
#include "terminal-util.h"

UpdateSet *update_set_free(UpdateSet *us) {
        if (!us)
                return NULL;

        free(us->version);
        free(us->instances); /* The objects referenced by this array are freed via resource_free(), not us */

        return mfree(us);
}

int update_set_cmp(UpdateSet *const*a, UpdateSet *const*b) {
        assert(a);
        assert(b);
        assert(*a);
        assert(*b);
        assert((*a)->version);
        assert((*b)->version);

        /* Newest version at the beginning */
        return -strverscmp_improved((*a)->version, (*b)->version);
}

const char *update_set_flags_to_color(UpdateSetFlags flags) {

        if (flags == 0 || (flags & UPDATE_OBSOLETE))
                return (flags & UPDATE_NEWEST) ? ansi_highlight_grey() : ansi_grey();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_NEWEST))
                return ansi_highlight();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_PROTECTED))
                return ansi_highlight_magenta();

        if ((flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_OBSOLETE)) == (UPDATE_AVAILABLE|UPDATE_NEWEST))
                return ansi_highlight_green();

        return NULL;
}

const char *update_set_flags_to_glyph(UpdateSetFlags flags) {

        if (flags == 0 || (flags & UPDATE_OBSOLETE))
                return special_glyph(SPECIAL_GLYPH_MULTIPLICATION_SIGN);

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_NEWEST))
                return special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE);

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_PROTECTED))
                return special_glyph(SPECIAL_GLYPH_WHITE_CIRCLE);

        if ((flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_OBSOLETE)) == (UPDATE_AVAILABLE|UPDATE_NEWEST))
                return special_glyph(SPECIAL_GLYPH_CIRCLE_ARROW);

        return " ";
}

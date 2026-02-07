/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
#include "glyph-util.h"
#include "sysupdate-update-set-flags.h"

const char* update_set_flags_to_color(UpdateSetFlags flags) {

        if (flags == 0 || (flags & UPDATE_OBSOLETE))
                return (flags & UPDATE_NEWEST) ? ansi_highlight_grey() : ansi_grey();

        if (flags & (UPDATE_PARTIAL|UPDATE_PENDING))
                return ansi_highlight_cyan();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_INCOMPLETE))
                return ansi_highlight_yellow();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_NEWEST))
                return ansi_highlight();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_PROTECTED))
                return ansi_highlight_magenta();

        if ((flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_OBSOLETE)) == (UPDATE_AVAILABLE|UPDATE_NEWEST))
                return ansi_highlight_green();

        return NULL;
}

const char* update_set_flags_to_glyph(UpdateSetFlags flags) {

        if (flags == 0 || (flags & UPDATE_OBSOLETE))
                return glyph(GLYPH_MULTIPLICATION_SIGN);

        if (flags & (UPDATE_PARTIAL|UPDATE_PENDING))
                return glyph(GLYPH_DOWNLOAD);

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_NEWEST))
                return glyph(GLYPH_BLACK_CIRCLE);

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_PROTECTED))
                return glyph(GLYPH_WHITE_CIRCLE);

        if ((flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_OBSOLETE)) == (UPDATE_AVAILABLE|UPDATE_NEWEST))
                return glyph(GLYPH_CIRCLE_ARROW);

        return " ";
}

const char* update_set_flags_to_string(UpdateSetFlags flags) {

        switch ((unsigned) flags) {

        case 0:
                return "n/a";

        case UPDATE_INSTALLED|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current";

        case UPDATE_INSTALLED|UPDATE_PENDING|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_PENDING|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PENDING|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PENDING|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+pending";

        case UPDATE_INSTALLED|UPDATE_PARTIAL|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_PARTIAL|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PARTIAL|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PARTIAL|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+partial";

        case UPDATE_AVAILABLE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "candidate";

        case UPDATE_INSTALLED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE:
                return "installed";

        case UPDATE_INSTALLED|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PROTECTED:
                return "protected";

        case UPDATE_AVAILABLE:
        case UPDATE_AVAILABLE|UPDATE_PROTECTED:
                return "available";

        case UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_INCOMPLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_INCOMPLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+incomplete";

        case UPDATE_INSTALLED|UPDATE_INCOMPLETE:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_INCOMPLETE:
                return "installed+incomplete";

        case UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_INCOMPLETE|UPDATE_PROTECTED:
                return "protected+incomplete";

        case UPDATE_AVAILABLE|UPDATE_INCOMPLETE:
        case UPDATE_AVAILABLE|UPDATE_INCOMPLETE|UPDATE_PROTECTED:
        case UPDATE_AVAILABLE|UPDATE_INCOMPLETE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_INCOMPLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                /* We must never offer an update as available for download if it's incomplete */
                assert_not_reached();

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE:
                return "installed+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_PROTECTED:
                return "protected+obsolete";

        case UPDATE_AVAILABLE|UPDATE_OBSOLETE:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_PROTECTED:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "available+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+obsolete+incomplete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_INCOMPLETE:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE:
                return "installed+obsolete+incomplete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_PROTECTED:
                return "protected+obsolete+incomplete";

        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_PROTECTED:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                assert_not_reached();

        default:
                assert_not_reached();
        }
}

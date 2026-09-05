/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <string.h>

#include "ansi-color.h"
#include "glyph-util.h"
#include "sysupdate-update-set-flags.h"

const char* update_set_flags_to_color(UpdateSetFlags flags) {

        if (flags == 0 || (flags & (UPDATE_OBSOLETE|UPDATE_TOO_NEW)))
                return (flags & UPDATE_NEWEST) ? ansi_highlight_grey() : ansi_grey();

        if (flags & (UPDATE_PARTIAL|UPDATE_PENDING))
                return ansi_highlight_cyan();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_INCOMPLETE))
                return ansi_highlight_yellow();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_NEWEST))
                return ansi_highlight();

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_PROTECTED))
                return ansi_highlight_magenta();

        if ((flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_CANDIDATE)) == (UPDATE_AVAILABLE|UPDATE_CANDIDATE))
                return ansi_highlight_green();

        return NULL;
}

const char* update_set_flags_to_glyph(UpdateSetFlags flags) {

        if (flags == 0 || (flags & (UPDATE_OBSOLETE|UPDATE_TOO_NEW)))
                return glyph(GLYPH_MULTIPLICATION_SIGN);

        if (flags & (UPDATE_PARTIAL|UPDATE_PENDING))
                return glyph(GLYPH_DOWNLOAD);

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_NEWEST))
                return glyph(GLYPH_BLACK_CIRCLE);

        if (FLAGS_SET(flags, UPDATE_INSTALLED|UPDATE_PROTECTED))
                return glyph(GLYPH_WHITE_CIRCLE);

        if ((flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_CANDIDATE)) == (UPDATE_AVAILABLE|UPDATE_CANDIDATE))
                return glyph(GLYPH_CIRCLE_ARROW);

        return " ";
}

char* update_set_flags_to_string_buf(UpdateSetFlags flags, char buf[static UPDATE_SET_FLAGS_STRING_MAX]) {
        const char *base;

        assert(buf);

        /* Composes a human readable assessment of an update set from its flags, in the form
         * "<base>[+partial|+pending][+obsolete][+too-new][+incomplete]". */

        /* We must never offer an update as available for download if it's incomplete */
        assert(!FLAGS_SET(flags, UPDATE_AVAILABLE|UPDATE_INCOMPLETE) || FLAGS_SET(flags, UPDATE_INSTALLED));

        if (flags == 0)
                return strcpy(buf, "n/a");

        if (flags & UPDATE_INSTALLED)
                base = (flags & UPDATE_NEWEST) ? "current" :
                       (flags & UPDATE_PROTECTED) ? "protected" : "installed";
        else
                base = (flags & UPDATE_CANDIDATE) ? "candidate" : "available";

        /* Partial and pending instances may be mixed in the same update set, report the "least done" state */
        const char *progress = (flags & UPDATE_PARTIAL) ? "+partial" :
                               (flags & UPDATE_PENDING) ? "+pending" : "";

        assert_se(snprintf(buf, UPDATE_SET_FLAGS_STRING_MAX, "%s%s%s%s%s",
                           base,
                           progress,
                           (flags & UPDATE_OBSOLETE) ? "+obsolete" : "",
                           (flags & UPDATE_TOO_NEW) ? "+too-new" : "",
                           (flags & UPDATE_INCOMPLETE) ? "+incomplete" : "") < (int) UPDATE_SET_FLAGS_STRING_MAX);
        return buf;
}

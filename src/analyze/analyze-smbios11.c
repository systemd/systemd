/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-smbios11.h"
#include "escape.h"
#include "smbios11.h"
#include "virt.h"

int verb_smbios11(int argc, char *argv[], void *userdata) {
        unsigned n = 0;
        int r;

        for (unsigned i = 0;; i++) {
                _cleanup_free_ char *data = NULL;
                bool written = false;
                size_t size;

                r = read_smbios11_field(i, SIZE_MAX, &data, &size);
                if (r == -ENOENT) /* Reached the end */
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to read SMBIOS Type #11 string %u: %m", i);
                bool incomplete = r == 0;

                size_t left, skip;
                const char *p;
                for (p = data, left = size; left > 0; p += skip, left -= skip) {
                        const char *nul;

                        nul = memchr(p, 0, left);
                        if (nul)
                                skip = (nul - p) + 1;
                        else {
                                nul = p + left;
                                skip = left;
                        }

                        if (nul - p == 0) /* Skip empty strings */
                                continue;

                        _cleanup_free_ char *escaped = NULL;
                        escaped = cescape_length(p, nul - p);
                        if (!escaped)
                                return log_oom();

                        if (written)
                                fputc('\n', stdout);

                        fputs(escaped, stdout);
                        written = true;
                        n++;
                }

                if (written) {
                        if (incomplete)
                                fputs(special_glyph(SPECIAL_GLYPH_ELLIPSIS), stdout);

                        fputc('\n', stdout);
                }

                if (i == UINT_MAX) /* Prevent overflow */
                        break;
        }

        if (!arg_quiet) {
                if (n == 0)
                        log_info("No SMBIOS Type #11 strings passed.");
                else
                        log_info("\n%u SMBIOS Type #11 strings passed.", n);
        }

        return EXIT_SUCCESS;
}

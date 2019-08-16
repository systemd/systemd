/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "securebits-util.h"
#include "string-util.h"

int secure_bits_to_string_alloc(int i, char **s) {
        _cleanup_free_ char *str = NULL;
        size_t len;
        int r;

        assert(s);

        r = asprintf(&str, "%s%s%s%s%s%s",
                     (i & (1 << SECURE_KEEP_CAPS)) ? "keep-caps " : "",
                     (i & (1 << SECURE_KEEP_CAPS_LOCKED)) ? "keep-caps-locked " : "",
                     (i & (1 << SECURE_NO_SETUID_FIXUP)) ? "no-setuid-fixup " : "",
                     (i & (1 << SECURE_NO_SETUID_FIXUP_LOCKED)) ? "no-setuid-fixup-locked " : "",
                     (i & (1 << SECURE_NOROOT)) ? "noroot " : "",
                     (i & (1 << SECURE_NOROOT_LOCKED)) ? "noroot-locked " : "");
        if (r < 0)
                return -ENOMEM;

        len = strlen(str);
        if (len != 0)
                str[len - 1] = '\0';

        *s = TAKE_PTR(str);

        return 0;
}

int secure_bits_from_string(const char *s) {
        int secure_bits = 0;
        const char *p;
        int r;

        for (p = s;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return r;
                if (r <= 0)
                        break;

                if (streq(word, "keep-caps"))
                        secure_bits |= 1 << SECURE_KEEP_CAPS;
                else if (streq(word, "keep-caps-locked"))
                        secure_bits |= 1 << SECURE_KEEP_CAPS_LOCKED;
                else if (streq(word, "no-setuid-fixup"))
                        secure_bits |= 1 << SECURE_NO_SETUID_FIXUP;
                else if (streq(word, "no-setuid-fixup-locked"))
                        secure_bits |= 1 << SECURE_NO_SETUID_FIXUP_LOCKED;
                else if (streq(word, "noroot"))
                        secure_bits |= 1 << SECURE_NOROOT;
                else if (streq(word, "noroot-locked"))
                        secure_bits |= 1 << SECURE_NOROOT_LOCKED;
        }

        return secure_bits;
}

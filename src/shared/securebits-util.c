/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "securebits-util.h"
#include "string-util.h"
#include "strv.h"

/* match a single bit */
static inline const char* secure_bit_to_string(int i) {
        switch (i) {
                case SECURE_KEEP_CAPS:
                        return "keep-caps";
                case SECURE_KEEP_CAPS_LOCKED:
                        return "keep-caps-locked";
                case SECURE_NO_SETUID_FIXUP:
                        return "no-setuid-fixup";
                case SECURE_NO_SETUID_FIXUP_LOCKED:
                        return "no-setuid-fixup-locked";
                case SECURE_NOROOT:
                        return "noroot";
                case SECURE_NOROOT_LOCKED:
                        return "noroot-locked";
                default:
                        assert_not_reached();
        }
}

int secure_bits_to_string_alloc(int i, char **s) {
        _cleanup_free_ char *str = NULL;
        size_t len;
        int r;

        assert(s);

        r = asprintf(&str, "%s%s%s%s%s%s%s%s%s%s%s%s",
                     (i & (1 << SECURE_KEEP_CAPS)) ? secure_bit_to_string(SECURE_KEEP_CAPS) : "",
                     (i & (1 << SECURE_KEEP_CAPS)) ? " ": "",
                     (i & (1 << SECURE_KEEP_CAPS_LOCKED)) ? secure_bit_to_string(SECURE_KEEP_CAPS_LOCKED) : "",
                     (i & (1 << SECURE_KEEP_CAPS_LOCKED)) ? " ": "",
                     (i & (1 << SECURE_NO_SETUID_FIXUP)) ? secure_bit_to_string(SECURE_NO_SETUID_FIXUP) : "",
                     (i & (1 << SECURE_NO_SETUID_FIXUP)) ? " " : "",
                     (i & (1 << SECURE_NO_SETUID_FIXUP_LOCKED)) ? secure_bit_to_string(SECURE_NO_SETUID_FIXUP_LOCKED) : "",
                     (i & (1 << SECURE_NO_SETUID_FIXUP_LOCKED)) ? " " : "",
                     (i & (1 << SECURE_NOROOT)) ? secure_bit_to_string(SECURE_NOROOT) : "",
                     (i & (1 << SECURE_NOROOT)) ? " ": "",
                     (i & (1 << SECURE_NOROOT_LOCKED)) ? secure_bit_to_string(SECURE_NOROOT_LOCKED) : "",
                     (i & (1 << SECURE_NOROOT_LOCKED)) ? " " : "");
        if (r < 0)
                return -ENOMEM;

        len = strlen(str);
        if (len != 0)
                str[len - 1] = '\0';

        *s = TAKE_PTR(str);

        return 0;
}

int secure_bits_to_strv_alloc(int i, char ***ret_sv) {
        _cleanup_strv_free_ char **sv = NULL;
        static const int bits[] = {
                SECURE_KEEP_CAPS,
                SECURE_KEEP_CAPS_LOCKED,
                SECURE_NO_SETUID_FIXUP,
                SECURE_NO_SETUID_FIXUP_LOCKED,
                SECURE_NOROOT,
                SECURE_NOROOT_LOCKED,
        };
        int r;

        assert(ret_sv);

        FOREACH_ELEMENT(bit, bits) {
                if (i & (1 << *bit)) {
                        r = strv_extend(&sv, secure_bit_to_string(*bit));
                        if (r < 0)
                                return r;
                }
        }

        *ret_sv = TAKE_PTR(sv);
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

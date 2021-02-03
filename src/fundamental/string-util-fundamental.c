/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef SD_BOOT
#include "macro.h"
#endif
#include "string-util-fundamental.h"

sd_char *startswith(const sd_char *s, const sd_char *prefix) {
        sd_size_t l;

        assert(s);
        assert(prefix);

        l = strlen(prefix);
        if (!strneq(s, prefix, l))
                return NULL;

        return (sd_char*) s + l;
}

#ifndef SD_BOOT
sd_char *startswith_no_case(const sd_char *s, const sd_char *prefix) {
        sd_size_t l;

        assert(s);
        assert(prefix);

        l = strlen(prefix);
        if (!strncaseeq(s, prefix, l))
                return NULL;

        return (sd_char*) s + l;
}
#endif

sd_char* endswith(const sd_char *s, const sd_char *postfix) {
        sd_size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return (sd_char*) s + sl;

        if (sl < pl)
                return NULL;

        if (strcmp(s + sl - pl, postfix) != 0)
                return NULL;

        return (sd_char*) s + sl - pl;
}

sd_char* endswith_no_case(const sd_char *s, const sd_char *postfix) {
        sd_size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return (sd_char*) s + sl;

        if (sl < pl)
                return NULL;

        if (strcasecmp(s + sl - pl, postfix) != 0)
                return NULL;

        return (sd_char*) s + sl - pl;
}

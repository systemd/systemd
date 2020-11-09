/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "modhex.h"
#include "macro.h"
#include "memory-util.h"

const char modhex_alphabet[16] = {
        'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v'
};

int decode_modhex_char(char x) {

        for (size_t i = 0; i < ELEMENTSOF(modhex_alphabet); i++)
                /* Check both upper and lowercase */
                if (modhex_alphabet[i] == x || (modhex_alphabet[i] - 32) == x)
                        return i;

        return -EINVAL;
}

int normalize_recovery_key(const char *password, char **ret) {
        _cleanup_(erase_and_freep) char *mangled = NULL;
        size_t l;

        assert(password);
        assert(ret);

        l = strlen(password);
        if (!IN_SET(l,
                    MODHEX_RAW_LENGTH*2,          /* syntax without dashes */
                    MODHEX_FORMATTED_LENGTH-1))   /* syntax with dashes */
                return -EINVAL;

        mangled = new(char, MODHEX_FORMATTED_LENGTH);
        if (!mangled)
                return -ENOMEM;

        for (size_t i = 0, j = 0; i < MODHEX_RAW_LENGTH; i++) {
                size_t k;
                int a, b;

                if (l == MODHEX_RAW_LENGTH*2)
                        /* Syntax without dashes */
                        k = i * 2;
                else {
                        /* Syntax with dashes */
                        assert(l == MODHEX_FORMATTED_LENGTH-1);
                        k = i * 2 + i / 4;

                        if (i > 0 && i % 4 == 0 && password[k-1] != '-')
                                return -EINVAL;
                }

                a = decode_modhex_char(password[k]);
                if (a < 0)
                        return -EINVAL;
                b = decode_modhex_char(password[k+1]);
                if (b < 0)
                        return -EINVAL;

                mangled[j++] = modhex_alphabet[a];
                mangled[j++] = modhex_alphabet[b];

                if (i % 4 == 3)
                        mangled[j++] = '-';
        }

        mangled[MODHEX_FORMATTED_LENGTH-1] = 0;

        *ret = TAKE_PTR(mangled);
        return 0;
}

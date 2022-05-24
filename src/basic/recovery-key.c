/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "memory-util.h"
#include "random-util.h"
#include "recovery-key.h"

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
                    RECOVERY_KEY_MODHEX_RAW_LENGTH*2,          /* syntax without dashes */
                    RECOVERY_KEY_MODHEX_FORMATTED_LENGTH-1))   /* syntax with dashes */
                return -EINVAL;

        mangled = new(char, RECOVERY_KEY_MODHEX_FORMATTED_LENGTH);
        if (!mangled)
                return -ENOMEM;

        for (size_t i = 0, j = 0; i < RECOVERY_KEY_MODHEX_RAW_LENGTH; i++) {
                size_t k;
                int a, b;

                if (l == RECOVERY_KEY_MODHEX_RAW_LENGTH*2)
                        /* Syntax without dashes */
                        k = i * 2;
                else {
                        /* Syntax with dashes */
                        assert(l == RECOVERY_KEY_MODHEX_FORMATTED_LENGTH-1);
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

        mangled[RECOVERY_KEY_MODHEX_FORMATTED_LENGTH-1] = 0;

        *ret = TAKE_PTR(mangled);
        return 0;
}

int make_recovery_key(char **ret) {
        _cleanup_(erase_and_freep) char *formatted = NULL;
        _cleanup_(erase_and_freep) uint8_t *key = NULL;
        size_t j = 0;
        int r;

        assert(ret);

        key = new(uint8_t, RECOVERY_KEY_MODHEX_RAW_LENGTH);
        if (!key)
                return -ENOMEM;

        r = crypto_random_bytes(key, RECOVERY_KEY_MODHEX_RAW_LENGTH);
        if (r < 0)
                return r;

        /* Let's now format it as 64 modhex chars, and after each 8 chars insert a dash */
        formatted = new(char, RECOVERY_KEY_MODHEX_FORMATTED_LENGTH);
        if (!formatted)
                return -ENOMEM;

        for (size_t i = 0; i < RECOVERY_KEY_MODHEX_RAW_LENGTH; i++) {
                formatted[j++] = modhex_alphabet[key[i] >> 4];
                formatted[j++] = modhex_alphabet[key[i] & 0xF];

                if (i % 4 == 3)
                        formatted[j++] = '-';
        }

        assert(j == RECOVERY_KEY_MODHEX_FORMATTED_LENGTH);
        assert(formatted[RECOVERY_KEY_MODHEX_FORMATTED_LENGTH-1] == '-');
        formatted[RECOVERY_KEY_MODHEX_FORMATTED_LENGTH-1] = 0; /* replace final dash with a NUL */

        *ret = TAKE_PTR(formatted);
        return 0;
}

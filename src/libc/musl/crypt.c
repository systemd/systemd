/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <crypt.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

char* crypt_ra(const char *phrase, const char *setting, void **data, int *size) {
        struct crypt_data *buf = NULL;
        bool allocated = false;

        if (!phrase || !setting || !data || !size) {
                errno = EINVAL;
                return NULL;
        }

        if (*data) {
                if (*size != sizeof(struct crypt_data)) {
                        errno = EINVAL;
                        return NULL;
                }

                buf = *data;
        } else {
                if (*size != 0) {
                        errno = EINVAL;
                        return NULL;
                }

                buf = calloc(1, sizeof(struct crypt_data));
                if (!buf) {
                        errno = ENOMEM;
                        return NULL;
                }

                allocated = true;
        }

        /* crypt_r may return a pointer to an invalid hashed password on error. Our callers expect NULL on
         * error, so let's just return that. */

        char *t = crypt_r(phrase, setting, buf);
        if (!t || t[0] == '*') {
                if (allocated)
                        free(buf);
                return NULL;
        }

        if (allocated) {
                *data = buf;
                *size = sizeof(struct crypt_data);
        }
        return t;
}

char* crypt_gensalt_ra(const char *prefix, unsigned long count, const char *rbytes, int nrbytes) {
        static const char table[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789"
                "./";

        _Static_assert(sizeof(table) == 64U + 1U, "Unexpected table size in crypt_gensalt_ra().");

        /* This doesn't do anything but SHA512, and silently ignore all arguments, to make it legacy-free and
         * minimize the implementation. */

        /* Insist on the best randomness by getrandom(), this is about keeping passwords secret after all. */
        uint8_t raw[16];
        for (size_t i = 0; i < sizeof(raw);) {
                size_t n = sizeof(raw) - i;
                ssize_t l = getrandom(raw + i, n, 0);
                if (l < 0)
                        return NULL;
                if (l == 0) {
                        /* Weird, should never happen. */
                        errno = EIO;
                        return NULL;
                }

                if ((size_t) l == n)
                        break; /* Done reading, success. */

                i += l;
                /* Interrupted by a signal; keep going. */
        }

        /* "$6$" + salt + "$" + NUL */
        char *salt = malloc(3 + sizeof(raw) + 1 + 1);
        if (!salt) {
                errno = ENOMEM;
                return NULL;
        }

        /* We only bother with SHA512 hashed passwords, the rest is legacy, and we don't do legacy. */
        char *p = stpcpy(salt, "$6$");
        for (size_t i = 0; i < sizeof(raw); i++)
                *p++ = table[raw[i] & 63];
        *p++ = '$';
        *p = 0;

        return salt;
}

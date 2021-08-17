/* Public domain */
/* Taken from https://clc-wiki.net/wiki */
#include <stdint.h>

#include "stdclib.h"

/* These are C library functions required by libfdt */

void *memmove(void *dest, const void *src, size_t n) {
        unsigned char *pd = dest;
        const unsigned char *ps = src;
        if (ps < pd)
                for (pd += n, ps += n; n--;)
                        *--pd = *--ps;
        else
                while(n--)
                        *pd++ = *ps++;
        return dest;
}

int memcmp(const void* s1, const void* s2, size_t n) {
        const unsigned char *p1 = s1, *p2 = s2;
        while(n--)
                if (*p1 != *p2)
                        return *p1 - *p2;
                else
                        p1++,p2++;
        return 0;
}

void *memchr(const void *s, int c, size_t n) {
        unsigned char *p = (unsigned char*)s;
        while (n--)
                if (*p != (unsigned char)c)
                        p++;
                else
                        return p;
        return 0;
}

size_t strlen(const char *s) {
        size_t i;
        for (i = 0; s[i] != '\0'; i++);
        return i;
}

size_t strnlen(const char *s, size_t maxlen) {
        size_t i;
        for (i = 0; i < maxlen && s[i] != '\0'; i++);
        return i;
}

char *strchr(const char *s, int c) {
        while (*s != (char)c)
                if (!*s++)
                        return 0;
        return (char *)s;
}

char *strrchr(const char *s, int c) {
        const char *ret = 0;
        do {
                if (*s == (char)c)
                        ret = s;
        } while(*s++);
        return (char *)ret;
}

/* Define __stack_chk_* so all symbols required by libfdt exist */

uintptr_t __stack_chk_guard = 0xdeadbeefa55a857;

void __stack_chk_fail(void) {
}

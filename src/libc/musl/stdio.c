/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef renameat2
extern typeof(missing_renameat2) renameat2;
#pragma weak renameat2
int missing_renameat2(int __oldfd, const char *__old, int __newfd, const char *__new, unsigned __flags) {
        if (renameat2)
                return renameat2(__oldfd, __old, __newfd, __new, __flags);
        return syscall(__NR_renameat2, __oldfd, __old, __newfd, __new, __flags);
}

#define DEFINE_PUT(func)                                         \
        int func##_check_writable(int c, FILE *stream) {         \
                if (!__fwritable(stream)) {                      \
                        errno = EBADF;                           \
                        return EOF;                              \
                }                                                \
                                                                 \
                return func(c, stream);                          \
        }

#define DEFINE_FPUTS(func)                                       \
        int func##_check_writable(const char *s, FILE *stream) { \
                if (!__fwritable(stream)) {                      \
                        errno = EBADF;                           \
                        return EOF;                              \
                }                                                \
                                                                 \
                return func(s, stream);                          \
        }

#undef putc
#undef putc_unlocked
#undef fputc
#undef fputc_unlocked
#undef fputs
#undef fputs_unlocked

DEFINE_PUT(putc);
DEFINE_PUT(putc_unlocked);
DEFINE_PUT(fputc);
DEFINE_PUT(fputc_unlocked);
DEFINE_FPUTS(fputs);
DEFINE_FPUTS(fputs_unlocked);

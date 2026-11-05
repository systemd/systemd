/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* gcov support for the EFI boot loader.
 *
 * With -Defi-coverage=true the boot loader is compiled with -ftest-coverage
 * -fprofile-arcs and linked against the host libgcov. This file provides what
 * libgcov needs to flush the coverage counters to .gcda files in a
 * freestanding EFI environment:
 *
 *   - the POSIX file shims libgcov's __gcov_open() is built on
 *     (open()/fcntl()/fdopen()/close(), *not* fopen(); plus access()/mkdir()/
 *     getpid()/mmap()/getenv() for its failure and merge paths)
 *   - a minimal stdio layer over the EFI Simple File Access Protocol
 *   - efi_gcov_enter()/efi_gcov_exit(), called by DEFINE_EFI_MAIN_FUNCTION
 *     around the boot loader: enter() runs the .init_array constructors
 *     (libgcov's per-object registration lives there, and with no CRT startup
 *     nothing else would run them), exit() calls __gcov_dump() which writes
 *     the .gcda files to the volume the boot loader was loaded from
 *     (typically the ESP).
 *
 * The .gcda file names libgcov uses are baked in at compile time as absolute
 * host build paths. As the ESP is a flat FAT volume, the files are written to
 * the volume root under their basename.
 */

#include "efi.h"

/* For the efi_gcov_enter()/efi_gcov_exit() prototypes (both build variants
 * define them, see below). */
#include "util.h"

#if EFI_COVERAGE

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "efi-log.h"
#include "efi-string.h"
#include "proto/loaded-image.h"

typedef long off_t;
typedef unsigned int mode_t;

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define O_ACCMODE 3

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

extern void __gcov_dump(void);

/* Plain address symbols at the .init_array boundaries (see efi_gcov_enter()).
 * Declared as arrays so that the names decay to the boundary addresses. */
extern char __init_array_start[];
extern char __init_array_end[];

/* --- the volume root of the boot loader's own device --- */

static EFI_HANDLE gcov_image;
static EFI_FILE *gcov_root;

/* --- POSIX shims for libgcov --- */

int getpid(void);
int fcntl(int fd, int cmd, ...);
int open(const char *name, int flags, mode_t mode);
int close(int fd);
int access(const char *path, int mode);
int mkdir(const char *path, mode_t mode);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
const char *getenv(const char *name);
long pthread_mutex_lock(long mutex);
long pthread_mutex_unlock(long mutex);

int getpid(void) {
        return 0;
}

int fcntl(int fd, int cmd, ...) {
        (void) fd;
        (void) cmd;
        return 0;
}

int access(const char *path, int mode) {
        /* The ESP is a flat volume, the "directory" is always the volume root. */
        (void) path;
        (void) mode;
        return 0;
}

int mkdir(const char *path, mode_t mode) {
        (void) path;
        (void) mode;
        return 0;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
        (void) addr;
        (void) length;
        (void) prot;
        (void) flags;
        (void) fd;
        (void) offset;
        return (void *) -1; /* MAP_FAILED */
}

const char *getenv(const char *name) {
        /* No environment in EFI mode, GCOV_PREFIX is not supported. */
        (void) name;
        return NULL;
}

long pthread_mutex_lock(long mutex) {
        (void) mutex;
        return 0;
}

long pthread_mutex_unlock(long mutex) {
        (void) mutex;
        return 0;
}

/* libgcov is built against glibc and pulls in a few more host symbols: */

int *__errno_location(void);
_noreturn_ void exit(int code);
long __isoc23_strtol(const char *nptr, char **endptr, int base);
void *malloc(size_t size);
int sprintf(char *str, const char *format, ...);
char *strcat(char *dest, const char *src);
char *strchr(const char *s, int c);
size_t strlen(const char *s);

int *__errno_location(void) {
        static int errnum;
        return &errnum;
}

/* A failed coverage flush is a hard error for a measurement run: end the image. */
_noreturn_ void exit(int code) {
        if (gcov_image)
                (void) BS->Exit(gcov_image, code ? EFI_LOAD_ERROR : EFI_SUCCESS, 0, NULL);
        for (;;)
                ;
}

long __isoc23_strtol(const char *nptr, char **endptr, int base) {
        long value = 0;
        int negative = 0;

        while (*nptr == ' ' || *nptr == '\t')
                nptr++;
        if (*nptr == '-') {
                negative = 1;
                nptr++;
        } else if (*nptr == '+')
                nptr++;
        if (base == 0)
                base = (nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X')) ? 16 : 10;
        else if (base == 16 && nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X'))
                nptr += 2;

        for (; *nptr; nptr++) {
                int d;
                if (*nptr >= '0' && *nptr <= '9')
                        d = *nptr - '0';
                else if (*nptr >= 'a' && *nptr <= 'f')
                        d = *nptr - 'a' + 10;
                else if (*nptr >= 'A' && *nptr <= 'F')
                        d = *nptr - 'A' + 10;
                else
                        break;
                if (d >= base)
                        break;
                value = value * base + d;
        }
        if (endptr)
                *endptr = (char *) nptr;
        return negative ? -value : value;
}

/* The EFI build has its own (nofail) allocator, reuse it. */
void *malloc(size_t size) {
        return xmalloc(size);
}

static size_t gcov_format_number(char *dst, long value, unsigned base, bool uppercase) {
        static const char digits_lower[] = "0123456789abcdef";
        static const char digits_upper[] = "0123456789ABCDEF";
        const char *digits = uppercase ? digits_upper : digits_lower;
        char tmp[32];
        size_t n = 0, i;

        if (value == 0)
                tmp[n++] = '0';
        while (value > 0) {
                tmp[n++] = digits[value % base];
                value /= base;
        }
        for (i = n; i > 0; i--)
                dst[i - 1] = tmp[i - 1];
        return n;
}

/* Minimal sprintf for libgcov's diagnostic and version strings. */
int sprintf(char *str, const char *format, ...) {
        va_list ap;
        size_t n = 0;

        va_start(ap, format);
        for (; *format; format++) {
                if (*format != '%') {
                        str[n++] = *format;
                        continue;
                }
                format++;
                while (IN_SET(*format, 'l', 'h', 'z'))
                        format++;
                switch (*format) {
                case 's': {
                        const char *s = va_arg(ap, const char *);
                        if (!s)
                                s = "(null)";
                        for (; *s; s++)
                                str[n++] = *s;
                        break;
                }
                case 'd':
                case 'i': {
                        long v = va_arg(ap, long);
                        if (v < 0) {
                                str[n++] = '-';
                                v = -v;
                        }
                        n += gcov_format_number(str + n, v, 10, false);
                        break;
                }
                case 'u':
                        n += gcov_format_number(str + n, (long) va_arg(ap, unsigned long), 10, false);
                        break;
                case 'x':
                        n += gcov_format_number(str + n, (long) va_arg(ap, unsigned long), 16, false);
                        break;
                case 'X':
                        n += gcov_format_number(str + n, (long) va_arg(ap, unsigned long), 16, true);
                        break;
                case 'c':
                        str[n++] = (char) va_arg(ap, int);
                        break;
                case '%':
                        str[n++] = '%';
                        break;
                default:
                        str[n++] = '%';
                        if (*format)
                                str[n++] = *format;
                        break;
                }
        }
        va_end(ap);
        str[n] = 0;
        return (int) n;
}

char *strcat(char *dest, const char *src) {
        size_t n = strlen8(dest);
        while (*src)
                dest[n++] = *src++;
        dest[n] = 0;
        return dest;
}

char *strchr(const char *s, int c) {
        return strchr8(s, (char) c);
}

size_t strlen(const char *s) {
        return strlen8(s);
}

static EFI_STATUS gcov_get_root(EFI_FILE **ret_root) {
        EFI_LOADED_IMAGE_PROTOCOL *li;
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sf;
        EFI_STATUS r;

        assert(ret_root);

        if (gcov_root) {
                *ret_root = gcov_root;
                return EFI_SUCCESS;
        }

        /* The volume we were loaded from. */
        r = BS->HandleProtocol(gcov_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &li);
        if (!EFI_STATUS_IS_ERROR(r)) {
                r = open_volume(li->DeviceHandle, &gcov_root);
                if (!EFI_STATUS_IS_ERROR(r)) {
                        *ret_root = gcov_root;
                        return EFI_SUCCESS;
                }
                log_debug_status(r, "gcov: failed to open the boot loader's volume");
        }

        /* Fallback: the first attached FAT volume (the UEFI shell may not
         * pass us a usable image handle). */
        r = BS->LocateProtocol(MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), NULL, (void **) &sf);
        if (EFI_STATUS_IS_ERROR(r))
                return r;
        r = sf->OpenVolume(sf, &gcov_root);
        if (EFI_STATUS_IS_ERROR(r))
                return r;

        *ret_root = gcov_root;
        return EFI_SUCCESS;
}

/* --- fd table over the EFI file protocol (libgcov's __gcov_open() path) --- */

#define GCOV_FD_MAX 8
typedef struct {
        EFI_FILE *f;
        uint64_t pos;
} gcov_fd_t;
static gcov_fd_t gcov_fds[GCOV_FD_MAX];

static const char *basename8(const char *path) {
        const char *base = path;
        for (; *path; path++)
                if (*path == '/')
                        base = path + 1;
        return base;
}

static void ascii_to_utf16(const char *s, char16_t *dst, size_t max) {
        size_t n = strlen8(s);
        if (n + 1 > max)
                n = max - 1;
        for (size_t i = 0; i < n; i++)
                dst[i] = (char16_t) s[i];
        dst[n] = 0;
}

int open(const char *name, int flags, mode_t mode) {
        static char16_t path[256];
        EFI_FILE *root;
        int slot;

        (void) mode;

        if (EFI_STATUS_IS_ERROR(gcov_get_root(&root)))
                return -1;

        /* The baked name is the absolute host build path, only the leaf
         * exists on the volume. */
        ascii_to_utf16(basename8(name), path, sizeof(path) / 2);

        for (slot = 1; slot < GCOV_FD_MAX; slot++)
                if (!gcov_fds[slot].f)
                        break;
        if (slot == GCOV_FD_MAX)
                return -1;

        /* Writable opens also CREATE: a fresh ESP has no .gcda yet, and a
         * pre-existing one is merged (no O_TRUNC is ever passed). */
        if (EFI_STATUS_IS_ERROR(root->Open(root, &gcov_fds[slot].f, path,
                                 (flags & O_ACCMODE) != O_RDONLY
                                         ? (EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE)
                                         : EFI_FILE_MODE_READ,
                                 0))) {
                log_error("gcov: failed to open %s on the volume", name);
                return -1;
        }

        gcov_fds[slot].pos = 0;
        return slot;
}

int close(int fd) {
        if (fd < 1 || fd >= GCOV_FD_MAX || !gcov_fds[fd].f)
                return -1;
        (void) gcov_fds[fd].f->Close(gcov_fds[fd].f);
        gcov_fds[fd].f = NULL;
        return 0;
}

/* --- minimal stdio over the EFI file protocol (libgcov's secondary paths) --- */

typedef struct {
        EFI_FILE *f;
        uint64_t pos;
        int eof;
        int fd; /* 0 = opened via fopen(), >= 1 = index into gcov_fds[] (fdopen()) */
} FILE;

FILE *fopen(const char *name, const char *mode);
FILE *fdopen(int fd, const char *mode);
int fclose(FILE *f);
size_t fwrite(const void *p, size_t size, size_t n, FILE *f);
size_t fread(void *p, size_t size, size_t n, FILE *f);
int fseek(FILE *f, off_t offset, int whence);
int feof(FILE *f);
int fflush(FILE *f);
_gnu_printf_(2, 0) int vfprintf(FILE *f, const char *format, va_list ap);
_gnu_printf_(2, 3) int fprintf(FILE *f, const char *format, ...);

static FILE *const gcov_stderr = (FILE * const) -1;
FILE *stderr = gcov_stderr;

#define GCOV_FILE_POOL 8
static FILE gcov_files[GCOV_FILE_POOL];

/* A slot without an open handle is free. */
static FILE *gcov_file_alloc(void) {
        for (size_t i = 0; i < GCOV_FILE_POOL; i++)
                if (!gcov_files[i].f)
                        return &gcov_files[i];
        return NULL;
}

static int gcov_open_mode(const char *mode) {
        return strchr8(mode, 'w')
                ? (EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE)
                : EFI_FILE_MODE_READ;
}

FILE *fopen(const char *name, const char *mode) {
        static char16_t path[256];
        EFI_FILE *root;
        FILE *f;
        uint64_t om;

        if (!(f = gcov_file_alloc()))
                return NULL;
        om = gcov_open_mode(mode);

        if (EFI_STATUS_IS_ERROR(gcov_get_root(&root)))
                return NULL;

        ascii_to_utf16(basename8(name), path, sizeof(path) / 2);
        if (EFI_STATUS_IS_ERROR(root->Open(root, &f->f, path, om, 0)))
                return NULL;

        f->pos = 0;
        f->eof = 0;
        f->fd = 0;
        return f;
}

FILE *fdopen(int fd, const char *mode) {
        FILE *f;

        (void) mode;

        if (fd < 1 || fd >= GCOV_FD_MAX || !gcov_fds[fd].f)
                return NULL;
        if (!(f = gcov_file_alloc()))
                return NULL;
        f->f = gcov_fds[fd].f;
        f->pos = gcov_fds[fd].pos;
        f->eof = 0;
        f->fd = fd;
        return f;
}

int fclose(FILE *f) {
        int fd;

        if (!f || (void *) f == (void *) gcov_stderr)
                return 0;
        fd = f->fd;
        (void) f->f->Close(f->f);
        f->f = NULL; /* release the FILE slot for reuse */
        if (fd >= 1 && fd < GCOV_FD_MAX)
                gcov_fds[fd].f = NULL; /* fd slot and FILE share one handle */
        return 0;
}

size_t fwrite(const void *p, size_t size, size_t n, FILE *f) {
        size_t total;

        if (!f || (void *) f == (void *) gcov_stderr)
                return n;
        total = size * n;
        if (EFI_STATUS_IS_ERROR(f->f->Write(f->f, &total, (void *) p)))
                return 0;
        f->pos += total;
        return total / size;
}

size_t fread(void *p, size_t size, size_t n, FILE *f) {
        size_t total;

        if (!f || (void *) f == (void *) gcov_stderr)
                return 0;
        total = size * n;
        (void) f->f->Read(f->f, &total, p);
        if (total < size * n)
                f->eof = 1;
        f->pos += total;
        return total / size;
}

int fseek(FILE *f, off_t offset, int whence) {
        uint64_t pos;

        if (!f || (void *) f == (void *) gcov_stderr)
                return 0;
        pos = (whence == SEEK_CUR) ? f->pos + (uint64_t) offset : (uint64_t) offset;
        if (f->f->SetPosition(f->f, pos) != EFI_SUCCESS)
                return -1;
        f->pos = pos;
        return 0;
}

int feof(FILE *f) {
        return !f ? 1 : f->eof;
}

int fflush(FILE *f) {
        if (!f || (void *) f == (void *) gcov_stderr)
                return 0;
        return f->f->Flush(f->f) == EFI_SUCCESS ? 0 : -1;
}

int vfprintf(FILE *f, const char *format, va_list ap) {
        /* libgcov only uses this for error reporting. Route it to the boot
         * console so failures are visible in the serial log. */
        if (f == gcov_stderr || !f) {
                vprintf_status(EFI_SUCCESS, format, ap);
                return 0;
        }
        (void) format;
        (void) ap;
        return 0;
}

int fprintf(FILE *f, const char *format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = vfprintf(f, format, ap);
        va_end(ap);
        return r;
}

/* --- entry point hooks (see the file comment) --- */

void efi_gcov_enter(EFI_HANDLE image) {
        /* libgcov registers its counter sets in .init_array constructors, one
         * per instrumented object. The linker materializes the
         * __init_array_start/__init_array_end PROVIDE symbols because we
         * reference them here. They are plain address symbols (section
         * boundaries), so we iterate over the addresses between them; the
         * section itself is an array of function pointers. */
        for (char *p = __init_array_start; p < __init_array_end; p += sizeof(void *))
                ((void (*)(void)) *(const void **) p)();

        gcov_image = image;
}

void efi_gcov_exit(void) {
        log_debug("gcov: dumping coverage counters to the volume root");
        __gcov_dump();
}

#else /* !EFI_COVERAGE */

void efi_gcov_enter(EFI_HANDLE image) {
        (void) image;
}

void efi_gcov_exit(void) {
}

#endif /* !EFI_COVERAGE */

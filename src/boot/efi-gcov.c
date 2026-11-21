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
 * host build paths that do not exist on the volume, so the files are written
 * to the loader directory of the volume the boot loader was loaded from
 * (volume root as fallback). They are stored under the '#' encoded object
 * path — the same convention GCC's -fprofile-dir uses for its data files —
 * so the host-side coverage collection (the mkosi coverage setup and the
 * integration test wrapper) can pair them with the .gcno notes.
 */

#include "efi.h"

/* For the efi_gcov_enter()/efi_gcov_exit() prototypes (both build variants
 * define them, see below). */
#include "util.h"

#ifdef EFI_COVERAGE

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
extern void __gcov_reset(void);

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
        /* libgcov probes the baked host path; report it as present so
         * open() below gets the chance to remap it to the volume. */
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

/* libgcov is built against glibc and pulls in a few more host symbols.
 * This list matches the host toolchain's libgcov.a (Red Hat GCC 15, verified
 * with nm on the members the link pulls in: _gcov.o, _gcov_dump.o,
 * _gcov_reset.o, _gcov_lock_unlock.o). Hosts that build their libgcov.a
 * with glibc fortification (e.g. Ubuntu) reference the __*_chk() variants
 * of sprintf(), fprintf(), vfprintf() and memcpy() instead, which are
 * provided below. The host libgcov is also compiled with the red zone,
 * which EFI code must not use: our own code is built with -mno-red-zone,
 * and the pulled-in libgcov members currently contain no red-zone accesses
 * (checked by disassembly); a host build that changes that needs a libgcov
 * compiled for the EFI target. */

int *__errno_location(void);
_noreturn_ void exit(int code);
long __isoc23_strtol(const char *nptr, char **endptr, int base);
void *malloc(size_t size);
int sprintf(char *str, const char *format, ...);
int __sprintf_chk(char *str, int flag, size_t slen, const char *format, ...);
void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen);
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
        freeze();
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

static size_t gcov_format_number(char *dst, uint64_t value, unsigned base, bool uppercase) {
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
        /* tmp[] holds the digits least significant first; copy them
         * reversed. */
        for (i = n; i > 0; i--)
                dst[i - 1] = tmp[n - i];
        return n;
}

/* Minimal sprintf for libgcov's diagnostic and version strings. It covers
 * the subset libgcov uses: %s (optionally with a precision, e.g. %.4s in
 * the version string), %d %i %u %x %X, %c and %%. The length modifier
 * selects the argument type — reading a variadic argument with the wrong
 * width is undefined behavior — so: no modifier and h/hh read int (shorts
 * are promoted), l/z/t/j read long, ll reads long long. That is exact on
 * x86-64, the only architecture with a matching host libgcov for the EFI
 * target (see the ia32 note in src/boot/meson.build). */
static int gcov_vsprintf(char *str, const char *format, va_list ap) {
        size_t n = 0;

        assert(str);
        assert(format);

        for (; *format; format++) {
                if (*format != '%') {
                        str[n++] = *format;
                        continue;
                }
                format++;

                /* Optional precision (libgcov's version ID uses %.4s). */
                size_t precision = (size_t) -1;
                if (*format == '.') {
                        format++;
                        while (*format >= '0' && *format <= '9') {
                                precision = precision == (size_t) -1
                                        ? (size_t) (*format - '0')
                                        : precision * 10 + (size_t) (*format - '0');
                                format++;
                        }
                }

                /* Length modifier: 0: int, 1: long, 2: long long. */
                int longness = 0;
                if (*format == 'h') {
                        format++;
                        if (*format == 'h')
                                format++;
                } else if (*format == 'l') {
                        format++;
                        longness = (*format == 'l') ? 2 : 1;
                        if (longness == 2)
                                format++;
                } else if (IN_SET(*format, 'z', 't', 'j')) {
                        format++;
                        longness = 1;
                }
                switch (*format) {
                case 's': {
                        const char *s = va_arg(ap, const char *);
                        size_t i;

                        if (!s)
                                s = "(null)";
                        /* Check the precision before s[i]: libgcov's %.4s
                         * argument is a non-terminated char[4]. */
                        for (i = 0; (precision == (size_t) -1 || i < precision) && s[i]; i++)
                                str[n++] = s[i];
                        break;
                }
                case 'd':
                case 'i': {
                        int64_t v;

                        if (longness == 2)
                                v = va_arg(ap, long long);
                        else if (longness == 1)
                                v = va_arg(ap, long);
                        else
                                v = va_arg(ap, int);
                        if (v < 0) {
                                str[n++] = '-';
                                /* INT64_MIN-safe sign flip */
                                v = (int64_t) -(uint64_t) v;
                        }
                        n += gcov_format_number(str + n, (uint64_t) v, 10, false);
                        break;
                }
                case 'u':
                case 'x':
                case 'X': {
                        uint64_t v;

                        if (longness == 2)
                                v = va_arg(ap, unsigned long long);
                        else if (longness == 1)
                                v = va_arg(ap, unsigned long);
                        else
                                v = va_arg(ap, unsigned int);
                        n += gcov_format_number(str + n, v,
                                                *format == 'u' ? 10 : 16, *format == 'X');
                        break;
                }
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
        str[n] = 0;
        return (int) n;
}

int sprintf(char *str, const char *format, ...) {
        va_list ap;
        int n;

        va_start(ap, format);
        n = gcov_vsprintf(str, format, ap);
        va_end(ap);
        return n;
}

int __sprintf_chk(char *str, int flag, size_t slen, const char *format, ...) {
        /* Fortified variant, see the host symbol list above. The flag and
         * size arguments only feed glibc's bounds checks; the caller
         * (libgcov) passes consistent sizes, so they are not checked. */
        va_list ap;
        int n;

        (void) flag;
        (void) slen;
        va_start(ap, format);
        n = gcov_vsprintf(str, format, ap);
        va_end(ap);
        return n;
}

char *strcat(char *dest, const char *src) {
        assert(dest);
        assert(src);

        strcpy8(dest + strlen8(dest), src);
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

/* The counter data file libgcov opens is named after the object path baked
 * in at compile time. When the loader is built with -fprofile-dir, libgcov
 * prefixes the profile directory and passes the name with every '/' already
 * replaced by '#' (the GCC profile directory convention); otherwise it
 * passes the plain path. The volume only has the flat loader directory, so
 * the file is stored under the '#' encoded object path in either case: use
 * the leaf as-is if it is already encoded, otherwise encode the full path. */
static char *gcov_data_name8(const char *name) {
        assert(name);

        const char *base = name;
        char *out;

        for (; *name; name++)
                if (*name == '/')
                        base = name + 1;

        if (strchr8(base, '#'))
                return xstrdup8(base);

        out = xstrdup8(name);
        for (char *p = out; *p; p++)
                if (*p == '/')
                        *p = '#';
        return out;
}

/* The counter files go to the loader directory (where sd-boot keeps its own
 * state files), created on first use. If that is not possible, fall back to
 * the volume root so the counters are not lost. */
static EFI_FILE *gcov_file_dir(void) {
        static EFI_FILE *dir;
        EFI_FILE *root;
        EFI_STATUS r;

        if (dir)
                return dir;

        if (EFI_STATUS_IS_ERROR(gcov_get_root(&root)))
                return NULL;

        /* Open the directory read-only if it already exists — some firmware
         * implementations refuse write access on an already-present
         * directory — and only request write access when creating it. */
        r = root->Open(root, &dir, (char16_t *) u"loader", EFI_FILE_MODE_READ, 0);
        if (r == EFI_NOT_FOUND)
                r = root->Open(root, &dir, (char16_t *) u"loader",
                                EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                                EFI_FILE_DIRECTORY);
        if (EFI_STATUS_IS_ERROR(r)) {
                log_debug_status(r, "gcov: using the volume root instead of the loader directory");
                dir = root;
        }
        return dir;
}

int open(const char *name, int flags, mode_t mode) {
        _cleanup_free_ char *data_name = NULL;
        _cleanup_free_ char16_t *path = NULL;
        EFI_FILE *dir;
        int slot;

        (void) mode;

        if (!(dir = gcov_file_dir()))
                return -1;

        data_name = gcov_data_name8(name);
        path = xstr8_to_16(data_name);

        for (slot = 1; slot < GCOV_FD_MAX; slot++)
                if (!gcov_fds[slot].f)
                        break;
        if (slot == GCOV_FD_MAX)
                return -1;

        /* Writable opens also CREATE: a fresh ESP has no .gcda yet, and a
         * pre-existing one is merged (no O_TRUNC is ever passed). */
        if (EFI_STATUS_IS_ERROR(dir->Open(dir, &gcov_fds[slot].f, path,
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
_gnu_printf_(3, 0) int __vfprintf_chk(FILE *f, int flag, const char *format, va_list ap);
_gnu_printf_(3, 4) int __fprintf_chk(FILE *f, int flag, const char *format, ...);

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
        _cleanup_free_ char *data_name = NULL;
        _cleanup_free_ char16_t *path = NULL;
        EFI_FILE *dir;
        FILE *f;
        uint64_t om;

        if (!(f = gcov_file_alloc()))
                return NULL;
        om = gcov_open_mode(mode);

        if (!(dir = gcov_file_dir()))
                return NULL;

        data_name = gcov_data_name8(name);
        path = xstr8_to_16(data_name);
        if (EFI_STATUS_IS_ERROR(dir->Open(dir, &f->f, path, om, 0)))
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
        /* On a failed read the firmware may leave the size untouched, so
         * the status is decisive, not the returned count — an untouched
         * count would report a full read of an uninitialized buffer. */
        if (EFI_STATUS_IS_ERROR(f->f->Read(f->f, &total, p)))
                total = 0;
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

/* Fortified variants of the functions above, referenced by host libgcov
 * builds compiled with glibc fortification (see the host symbol list). */
int __vfprintf_chk(FILE *f, int flag, const char *format, va_list ap) {
        (void) flag;
        return vfprintf(f, format, ap);
}

int __fprintf_chk(FILE *f, int flag, const char *format, ...) {
        va_list ap;
        int r;

        (void) flag;
        va_start(ap, format);
        r = vfprintf(f, format, ap);
        va_end(ap);
        return r;
}

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
        (void) destlen;
        return memcpy(dest, src, len);
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
        /* __gcov_dump() merges the current counters into the .gcda file
         * and then marks the counter sets as dumped, so without an
         * intervening reset a second dump in the same boot is a no-op.
         * The __gcov_reset() after the dump closes the counter window:
         * counting continues from zero, and the next dump of this boot
         * (another reset hook or the efi_main() exit) merges those
         * counters into the same file. That matters when a started
         * image returns to the boot manager (an EFI app or a compat
         * kernel entry that exits): without the reset, every counter
         * accumulated after the handoff attempt would be dropped. Each
         * counter is thus written exactly once, by the first dump
         * after it was counted. */
        log_debug("gcov: dumping coverage counters to the loader directory");
        __gcov_dump();
        __gcov_reset();
}

#else /* !EFI_COVERAGE */

void efi_gcov_enter(EFI_HANDLE image) {
        (void) image;
}

void efi_gcov_exit(void) {
}

#endif /* EFI_COVERAGE */

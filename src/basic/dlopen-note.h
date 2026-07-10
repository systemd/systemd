/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dlopen.h"

#include "forward.h"
#include "strv.h"

/* Prevent dlopen helper functions (e.g., dlopen_libfoo()) from being inlined or cloned by the compiler/LTO.
 * This ensures that their specific symbols remain intact in the final executable, allowing the developer
 * test utility to verify that the functions corresponding to the dlopen ELF notes are actually invoked.
 * This is restricted to BUILD_MODE_DEVELOPER to avoid degrading production performance. */
#if BUILD_MODE_DEVELOPER
#  define _dlopen_loader_ _noclone_ _noinline_
#else
#  define _dlopen_loader_
#endif

/* Avoid invalid priority. */
#define _DLOPEN_CHECK_PRIORITY_required    1
#define _DLOPEN_CHECK_PRIORITY_recommended 1
#define _DLOPEN_CHECK_PRIORITY_suggested   1

/* Unlike SD_ELF_NOTE_DLOPEN_ANCHORED(), this takes feature and priority without quotation. */
#define ELF_NOTE_DLOPEN_ANCHORED(feature, description, priority, ...)   \
        assert_cc(_DLOPEN_CHECK_PRIORITY_##priority);                   \
        SD_ELF_NOTE_DLOPEN_ANCHORED(                                    \
                        feature##_##priority,                           \
                        STRINGIFY(feature),                             \
                        description,                                    \
                        STRINGIFY(priority),                            \
                        __VA_ARGS__)

#if HAVE_BZIP2
#  define LIBBZ2_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        bzip2,                                          \
                        "Support bzip2 compression and decompression",  \
                        priority,                                       \
                        "libbz2.so.1")
#else
#  define LIBBZ2_NOTE(priority)
#endif

#if HAVE_LZ4
#  define LIBLZ4_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        lz4,                                            \
                        "Support lz4 compression in journal and coredump files", \
                        priority,                                       \
                        "liblz4.so.1")
#else
#  define LIBLZ4_NOTE(priority)
#endif

#if HAVE_XZ
#  define LIBLZMA_NOTE(priority)                                        \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        lzma,                                           \
                        "Support lzma compression in journal and coredump files", \
                        priority,                                       \
                        "liblzma.so.5")
#else
#  define LIBLZMA_NOTE(priority)
#endif

#if HAVE_ZLIB
#  define LIBZ_NOTE(priority)                                           \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        zlib,                                           \
                        "Support gzip compression and decompression",   \
                        priority,                                       \
                        "libz.so.1")
#else
#  define LIBZ_NOTE(priority)
#endif

#if HAVE_ZSTD
#  define LIBZSTD_NOTE(priority)                                        \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        zstd,                                           \
                        "Support zstd compression in journal and coredump files", \
                        priority,                                       \
                        "libzstd.so.1")
#else
#  define LIBZSTD_NOTE(priority)
#endif

#define COMPRESS_NOTE(priority)                         \
        LIBBZ2_NOTE(priority);                          \
        LIBLZ4_NOTE(priority);                          \
        LIBLZMA_NOTE(priority);                         \
        LIBZ_NOTE(priority);                            \
        LIBZSTD_NOTE(priority)

#define COMPRESS_DEFAULT_NOTE                           \
        COMPRESS_JOURNAL_NOTE;                          \
        LIBBZ2_NOTE(suggested);                         \
        LIBZ_NOTE(suggested)

#define COMPRESS_JOURNAL_NOTE                           \
        LIBLZ4_NOTE(COMPRESSION_PRIORITY_LZ4);          \
        LIBLZMA_NOTE(COMPRESSION_PRIORITY_XZ);          \
        LIBZSTD_NOTE(COMPRESSION_PRIORITY_ZSTD)

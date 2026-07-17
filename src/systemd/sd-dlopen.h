/* SPDX-License-Identifier: MIT-0 */
#ifndef foosddlopenhfoo
#define foosddlopenhfoo

/***
  Copyright © 2026 The systemd Project

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
***/

#include <stdint.h>

/* Note: do not include other internal headers from here, to keep it MIT-0 and self-contained*/

#ifdef __cplusplus
extern "C" {
#endif

/* ELF note macros implementing the FDO .note.dlopen standard.
 *
 * These macros embed metadata in an ELF binary's .note.dlopen section,
 * declaring optional shared library dependencies that are loaded via
 * dlopen() at runtime. Package managers and build systems can read
 * these notes to discover runtime dependencies not visible in ELF
 * DT_NEEDED entries.
 *
 * Usage:
 *
 *   SD_ELF_NOTE_DLOPEN("myfeature", "Feature description",
 *                       SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
 *                       "libfoo.so.1");
 *
 * See SD_ELF_NOTE_DLOPEN(3) for details.
 */

#define SD_ELF_NOTE_DLOPEN_VENDOR "FDO"
#define SD_ELF_NOTE_DLOPEN_TYPE UINT32_C(0x407c0c0a)
#define SD_ELF_NOTE_DLOPEN_PRIORITY_REQUIRED    "required"
#define SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED "recommended"
#define SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED   "suggested"

/* The "R" (SHF_GNU_RETAIN) flag is only understood by binutils >= 2.36, so it can be disabled by defining
 * _SD_ELF_NOTE_DLOPEN_SECTION_FLAGS as 'aG' manually, but note that if --gc-sections is used when linking,
 * the note will be dropped. */
#ifndef _SD_ELF_NOTE_DLOPEN_SECTION_FLAGS
#  define _SD_ELF_NOTE_DLOPEN_SECTION_FLAGS "aGR"
#endif

/* This guard tag ensures the assembler folds identical notes when compiling. Unfortunately hppa redefines
 * '.equ' so it cannot be used. '.equiv' works on all arches, but it breaks with binutils 2.35 which is used
 * on CentOS 9, so we need an ifdef here until the binutils baseline is updated, as above. */
#if defined(__hppa__) || defined(__hppa64__)
#  define _SD_ELF_NOTE_DLOPEN_GUARD ".set"
#else
#  define _SD_ELF_NOTE_DLOPEN_GUARD ".equ"
#endif

/* The json argument is a C string containing already backslash-escaped double quotes (i.e. the bytes
 * [{\"feature\"...), so that once it is pasted into the assembler's .asciz directive the assembler decodes
 * them back to plain quotes. The note is emitted into a COMDAT group keyed on the payload itself, which
 * makes byte-identical notes fold to a single copy: the assembler folds duplicates within a translation
 * unit (via the .ifndef guard) and the linker folds them across translation units (via the COMDAT group).
 * This way a binary that triggers the same optional dependency from multiple call sites ends up with just
 * one note for it. The n_type value below must match SD_ELF_NOTE_DLOPEN_TYPE (it is spelled out as a
 * literal here as it cannot be expanded inside the assembler string). */
#define _SD_ELF_NOTE_DLOPEN(json)                                                                                               \
        __asm__ (                                                                                                               \
                ".ifndef \"sd_dlopen:" json "\"\n"                                                                              \
                _SD_ELF_NOTE_DLOPEN_GUARD " \"sd_dlopen:" json "\", 1\n" /* guard tag, to fold identical notes */               \
                ".pushsection .note.dlopen, \"" _SD_ELF_NOTE_DLOPEN_SECTION_FLAGS "\", %note, \"sd_dlopen:" json "\", comdat\n" \
                ".balign 4\n"         /* notes require 4-byte alignment for the header and fields */                            \
                ".long 884f - 883f\n" /* n_namesz: byte length of the vendor name (label 883->884) */                           \
                ".long 882f - 881f\n" /* n_descsz: byte length of the JSON payload (label 881->882) */                          \
                ".long 0x407c0c0a\n"  /* n_type: must match SD_ELF_NOTE_DLOPEN_TYPE */                                          \
                "883:\n"              /* start of vendor name */                                                                \
                ".asciz \"" SD_ELF_NOTE_DLOPEN_VENDOR "\"\n"                                                                    \
                "884:\n"              /* end of vendor name */                                                                  \
                ".balign 4\n"                                                                                                   \
                "881:\n"              /* start of JSON payload */                                                               \
                ".asciz \"" json "\"\n"                                                                                         \
                "882:\n"              /* end of JSON payload */                                                                 \
                ".balign 4\n"                                                                                                   \
                ".popsection\n"                                                                                                 \
                ".endif\n")

/*
 * SD_ELF_NOTE_DLOPEN_ANCHORED() emits a .note.dlopen ELF note that is "anchored" to a dummy symbol via the
 * SHF_LINK_ORDER ('o') section flag, in addition to SHF_GROUP ('G') for folding identical notes together.
 *
 * Unlike the plain SD_ELF_NOTE_DLOPEN() macro, this variant ties the note's lifetime to a dummy symbol named
 * with the specified tag: if the linker's --gc-sections removes the function that calls the macro (e.g.
 * because the function is never referenced), the associated .note.dlopen entry is garbage-collected along
 * with it.
 *
 * USAGE NOTE:
 * - The 'tag' argument must be a unique symbol name to characterize the dlopen note (e.g. generated from
 *   feature and its priority).
 *
 *   Example:
 *       void dlopen_libfoo(int log_level) {
 *               SD_ELF_NOTE_DLOPEN_ANCHORED(foo_suggested, "foo", "description of foo", "suggested", "libfoo.so.0");
 *               ...
 *       }
 *
 * TOOLCHAIN REQUIREMENTS:
 * - GNU as (binutils) >= 2.35: this is when support for specifying the SHF_LINK_ORDER ('o') associated
 *   symbol as a direct argument to .section/.pushsection was added.
 * - LLVM (clang -integrated-as) >= 18: matching support for the 'o' flag argument combined with 'G'
 *   (SHF_GROUP) landed around LLVM 18.
 * - Do NOT add 'R' (SHF_GNU_RETAIN) to these flags: combined with SHF_LINK_ORDER, it would prevent the
 *   linker from ever garbage-collecting the note, defeating the whole purpose of anchoring it to a symbol in
 *   the first place.
 */
#define _SD_ELF_NOTE_DLOPEN_ANCHORED(tag, json)                                                                                 \
        _Pragma("GCC diagnostic push")                                                                                          \
        _Pragma("GCC diagnostic ignored \"-Wnested-externs\"")                                                                  \
        _Pragma("GCC diagnostic ignored \"-Wredundant-decls\"")                                                                 \
        __attribute__((visibility("hidden")))                                                                                   \
        extern volatile const char __sd_dlopen_anchor_##tag __asm__("__sd_dlopen_anchor_" #tag);                                \
        _Pragma("GCC diagnostic pop")                                                                                           \
        __asm__ (                                                                                                               \
                ".ifndef \"sd_dlopen:emitted:" #tag "\"\n"                                                                      \
                _SD_ELF_NOTE_DLOPEN_GUARD " \"sd_dlopen:emitted:" #tag "\", 1\n"                                                \
                ".pushsection .data.sd_dlopen_dummy." #tag ", \"awG\", %progbits, sd_dlopen_group_" #tag ", comdat\n"           \
                ".weak __sd_dlopen_anchor_" #tag "\n"                                                                           \
                ".hidden __sd_dlopen_anchor_" #tag "\n"                                                                         \
                ".type __sd_dlopen_anchor_" #tag ", %object\n"                                                                  \
                ".balign 8\n"                                                                                                   \
                "__sd_dlopen_anchor_" #tag ":\n"                                                                                \
                ".byte 0\n"                                                                                                     \
                ".popsection\n"                                                                                                 \
                ".pushsection .note.dlopen, \"aGo\", %note, __sd_dlopen_anchor_" #tag ", sd_dlopen_group_" #tag ", comdat\n"    \
                ".balign 4\n"                                                                                                   \
                ".long 884f - 883f\n"                                                                                           \
                ".long 882f - 881f\n"                                                                                           \
                ".long 0x407c0c0a\n"                                                                                            \
                "883:\n"                                                                                                        \
                ".asciz \"" SD_ELF_NOTE_DLOPEN_VENDOR "\"\n"                                                                    \
                "884:\n"                                                                                                        \
                ".balign 4\n"                                                                                                   \
                "881:\n"                                                                                                        \
                ".asciz \"" json "\"\n"                                                                                         \
                "882:\n"                                                                                                        \
                ".balign 4\n"                                                                                                   \
                ".popsection\n"                                                                                                 \
                ".endif\n"                                                                                                      \
        );                                                                                                                      \
        __asm__ volatile ("" : : "r" (&__sd_dlopen_anchor_##tag))

#define _SD_SONAME_ARRAY1(a) "[\\\"" a "\\\"]"
#define _SD_SONAME_ARRAY2(a, b) "[\\\"" a "\\\",\\\"" b "\\\"]"
#define _SD_SONAME_ARRAY3(a, b, c) "[\\\"" a "\\\",\\\"" b "\\\",\\\"" c "\\\"]"
#define _SD_SONAME_ARRAY4(a, b, c, d) "[\\\"" a "\\\",\\\"" b "\\\",\\\"" c "\\\",\\\"" d "\\\"]"
#define _SD_SONAME_ARRAY5(a, b, c, d, e) "[\\\"" a "\\\",\\\"" b "\\\",\\\"" c "\\\",\\\"" d "\\\",\\\"" e "\\\"]"
#define _SD_SONAME_ARRAY_GET(_1,_2,_3,_4,_5,NAME,...) NAME
#define _SD_SONAME_ARRAY(...) _SD_SONAME_ARRAY_GET(__VA_ARGS__, _SD_SONAME_ARRAY5, _SD_SONAME_ARRAY4, _SD_SONAME_ARRAY3, _SD_SONAME_ARRAY2, _SD_SONAME_ARRAY1)(__VA_ARGS__)

#define _SD_DLOPEN_JSON(feature, description, priority, ...)    \
        "[{"                                                    \
        "\\\"feature\\\":\\\"" feature "\\\","                  \
        "\\\"description\\\":\\\"" description "\\\","          \
        "\\\"priority\\\":\\\"" priority "\\\","                \
        "\\\"soname\\\":" _SD_SONAME_ARRAY(__VA_ARGS__)         \
        "}]"

#define SD_ELF_NOTE_DLOPEN(feature, description, priority, ...) \
        _SD_ELF_NOTE_DLOPEN(_SD_DLOPEN_JSON(feature, description, priority, __VA_ARGS__))

/* The anchored note requires LLVM >= 18 (see above). Fall back to the non-anchored note on older clang. */
#if defined(__clang__) && !defined(__apple_build_version__) && __clang_major__ < 18
#  define SD_ELF_NOTE_DLOPEN_ANCHORED(tag, feature, description, priority, ...) \
        SD_ELF_NOTE_DLOPEN(feature, description, priority, __VA_ARGS__)
#else
#  define SD_ELF_NOTE_DLOPEN_ANCHORED(tag, feature, description, priority, ...) \
        _SD_ELF_NOTE_DLOPEN_ANCHORED(tag, _SD_DLOPEN_JSON(feature, description, priority, __VA_ARGS__))
#endif

#ifdef __cplusplus
}
#endif

#endif

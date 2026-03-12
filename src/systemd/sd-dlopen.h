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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _SD_PASTE
#  define _SD_PASTE_INNER(a, b) a##b
#  define _SD_PASTE(a, b) _SD_PASTE_INNER(a, b)
#endif

#ifndef _SD_UNIQ
#  ifdef __COUNTER__
#    define _SD_UNIQ _SD_PASTE(_sd_uniq_, __COUNTER__)
#  else
#    define _SD_UNIQ _SD_PASTE(_sd_uniq_, __LINE__)
#  endif
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

#define _SD_ELF_NOTE_DLOPEN(json, variable_name)                               \
        __attribute__((used, section(".note.dlopen"))) _Alignas(sizeof(uint32_t)) static const struct { \
                struct {                                                        \
                        uint32_t n_namesz, n_descsz, n_type;                    \
                } nhdr;                                                         \
                char name[sizeof(SD_ELF_NOTE_DLOPEN_VENDOR)];                   \
                _Alignas(sizeof(uint32_t)) char dlopen_json[sizeof(json)];      \
        } variable_name = {                                                     \
                .nhdr = {                                                       \
                        .n_namesz = sizeof(SD_ELF_NOTE_DLOPEN_VENDOR),          \
                        .n_descsz = sizeof(json),                               \
                        .n_type   = SD_ELF_NOTE_DLOPEN_TYPE,                    \
                },                                                              \
                .name = SD_ELF_NOTE_DLOPEN_VENDOR,                              \
                .dlopen_json = json,                                            \
        }

#define _SD_SONAME_ARRAY1(a) "[\"" a "\"]"
#define _SD_SONAME_ARRAY2(a, b) "[\"" a "\",\"" b "\"]"
#define _SD_SONAME_ARRAY3(a, b, c) "[\"" a "\",\"" b "\",\"" c "\"]"
#define _SD_SONAME_ARRAY4(a, b, c, d) "[\"" a "\",\"" b "\",\"" c "\",\"" d "\"]"
#define _SD_SONAME_ARRAY5(a, b, c, d, e) "[\"" a "\",\"" b "\",\"" c "\",\"" d "\",\"" e "\"]"
#define _SD_SONAME_ARRAY_GET(_1,_2,_3,_4,_5,NAME,...) NAME
#define _SD_SONAME_ARRAY(...) _SD_SONAME_ARRAY_GET(__VA_ARGS__, _SD_SONAME_ARRAY5, _SD_SONAME_ARRAY4, _SD_SONAME_ARRAY3, _SD_SONAME_ARRAY2, _SD_SONAME_ARRAY1)(__VA_ARGS__)

#define SD_ELF_NOTE_DLOPEN(feature, description, priority, ...) \
        _SD_ELF_NOTE_DLOPEN("[{\"feature\":\"" feature "\",\"description\":\"" description "\",\"priority\":\"" priority "\",\"soname\":" _SD_SONAME_ARRAY(__VA_ARGS__) "}]", _SD_PASTE(_sd_elf_note_dlopen_, _SD_UNIQ))

#ifdef __cplusplus
}
#endif

#endif

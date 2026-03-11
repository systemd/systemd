/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddlopenhfoo
#define foosddlopenhfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <stdint.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

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

_SD_END_DECLARATIONS;

#endif

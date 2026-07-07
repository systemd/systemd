/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Test fixture for "systemd-analyze inspect-elf". This translation unit is built into a shared library
 * (test-inspect-elf-helper.so) rather than an executable on purpose: shared objects do not pull in the C
 * runtime startup objects (crt1.o/Scrt1.o), some of which ship their own .note.package note on certain
 * distributions (e.g. Ubuntu's glibc). Building a .so therefore leaves the binary with exactly the two
 * FDO_PACKAGING_METADATA notes embedded below and nothing else, which keeps the test output deterministic
 * across build hosts.
 *
 * The note layout (owner "FDO", type NT_FDO_PACKAGING_METADATA == 0xcafe1a7e, description = JSON) follows
 * https://uapi-group.org/specifications/specs/package_metadata_for_executable_files/ and is written by hand
 * as a plain struct so that no special assembler or linker support is required. Two stanzas are embedded to
 * model a binary that carries metadata for both the application and a vendored dependency, exercising
 * inspect-elf's parsing of multiple .note.package notes in a single object. */

#if defined(__ELF__)

/* Emit one .note.package note carrying the given JSON payload. Each note is a separately-aligned variable so
 * that consecutive notes stay 4-byte aligned as the ELF note format requires. The "used"/"retain" attributes
 * keep the note even when the linker runs with --gc-sections (retain needs binutils >= 2.36). */
#define PACKAGE_METADATA_NOTE(varname, json)                                    \
        __attribute__((used, retain, section(".note.package"), aligned(4)))     \
        static const struct {                                                   \
                unsigned int namesz;                                            \
                unsigned int descsz;                                            \
                unsigned int type;                                              \
                char name[4];                                                   \
                char desc[sizeof(json)];                                        \
        } varname = {                                                           \
                sizeof("FDO"),                                                  \
                sizeof(json),                                                   \
                0xcafe1a7e,                                                     \
                "FDO",                                                          \
                json,                                                           \
        }

PACKAGE_METADATA_NOTE(package_note_systemd,
        "{\"type\":\"test-type\",\"os\":\"test-os\",\"name\":\"test-systemd\"}");

PACKAGE_METADATA_NOTE(package_note_glibc,
        "{\"type\":\"test-type\",\"os\":\"test-os\",\"name\":\"test-glibc\"}");

#endif

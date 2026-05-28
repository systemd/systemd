/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for userspace UKI / PE inspection.
 *
 * pe_load_headers / pe_load_sections / pe_read_section_data_by_name / uki_hash
 * are exercised by bootctl, systemd-measure, pcrlock, kernel-install and
 * reboot-util against UKIs that an unprivileged actor may have produced.
 *
 * Expected input: bytes that look like a PE/COFF file (DOS "MZ" header,
 * `e_lfanew` pointing to a "PE\0\0" signature, followed by IMAGE_FILE_HEADER,
 * IMAGE_OPTIONAL_HEADER and a section table). The harness wraps the bytes in
 * a memfd, walks the headers, then attempts to read the known UKI sections
 * and finally hashes them via uki_hash() when OpenSSL is available.
 */

#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "memfd-util.h"
#include "pe-binary.h"
#include "tests.h"
#include "uki.h"

/* Cap section reads so a crafted VirtualSize cannot drive a multi-GiB malloc
 * and OOM-kill the fuzzer. Well under the 16 MiB input limit; real code uses
 * PE_SECTION_READ_MAX (16 KiB) or smaller. */
#define FUZZ_SECTION_READ_MAX (1U*1024U*1024U)

static void fuzz_read_section(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                const char *name) {

        _cleanup_free_ void *buf = NULL;
        size_t buf_size = 0;

        (void) pe_read_section_data_by_name(fd, pe_header, sections, name, FUZZ_SECTION_READ_MAX, &buf, &buf_size);
        DO_NOT_OPTIMIZE(buf);
        DO_NOT_OPTIMIZE(buf_size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;

        if (outside_size_range(size, 0, 16 * 1024 * 1024))
                return 0;

        fuzz_setup_logging();

        _cleanup_close_ int fd = ASSERT_OK(memfd_new("fuzz-pe-binary"));
        if (size > 0)
                ASSERT_OK_EQ_ERRNO(write(fd, data, size), (ssize_t) size);
        ASSERT_OK_ERRNO(lseek(fd, 0, SEEK_SET));

        if (pe_load_headers(fd, &dos_header, &pe_header) < 0)
                return 0;

        if (pe_load_sections(fd, dos_header, pe_header, &sections) < 0)
                return 0;

        /* Exercise the section-read path for every UKI section. unified_sections[]
         * (uki.h) is the canonical list; .sdmagic is written by sd-boot/sd-stub but
         * is not part of that table, so read it as an extra step. */
        FOREACH_ARRAY(s, unified_sections, _UNIFIED_SECTION_MAX)
                fuzz_read_section(fd, pe_header, sections, *s);
        fuzz_read_section(fd, pe_header, sections, ".sdmagic");

        (void) pe_is_uki(pe_header, sections);
        (void) pe_is_addon(pe_header, sections);
        (void) pe_is_native(pe_header);

#if HAVE_OPENSSL
        if (dlopen_libcrypto(LOG_DEBUG) >= 0) {
                void *hashes[_UNIFIED_SECTION_MAX] = {};
                size_t hash_size = 0;

                /* uki_hash() can return partway through with some hashes already
                 * allocated; free unconditionally. */
                (void) uki_hash(fd, sym_EVP_sha256(), hashes, &hash_size);
                free_many(hashes, _UNIFIED_SECTION_MAX);
        }
#endif

        return 0;
}

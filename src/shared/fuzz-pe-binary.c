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
#include "uki.h"

static const char *uki_section_names[] = {
        ".linux",
        ".osrel",
        ".cmdline",
        ".initrd",
        ".ucode",
        ".splash",
        ".dtb",
        ".uname",
        ".sbat",
        ".pcrsig",
        ".pcrpkey",
        ".profile",
        ".sdmagic",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        int r;

        if (outside_size_range(size, 0, 16 * 1024 * 1024))
                return 0;

        fuzz_setup_logging();

        fd = memfd_new_full("fuzz-pe-binary", 0);
        if (fd < 0)
                return 0;
        if (size > 0 && write(fd, data, size) != (ssize_t) size)
                return 0;
        if (lseek(fd, 0, SEEK_SET) < 0)
                return 0;

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return 0;

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r < 0)
                return 0;

        FOREACH_ELEMENT(name, uki_section_names) {
                _cleanup_free_ void *buf = NULL;
                size_t buf_size = 0;
                (void) pe_read_section_data_by_name(fd, pe_header, sections,
                                                    *name,
                                                    /* max_size = */ 4U * 1024U * 1024U,
                                                    &buf, &buf_size);
                DO_NOT_OPTIMIZE(buf);
                DO_NOT_OPTIMIZE(buf_size);
        }

        (void) pe_is_uki(pe_header, sections);
        (void) pe_is_addon(pe_header, sections);
        (void) pe_is_native(pe_header);

#if HAVE_OPENSSL
        if (dlopen_libcrypto(LOG_DEBUG) >= 0) {
                void *hashes[_UNIFIED_SECTION_MAX] = {};
                size_t hash_size = 0;

                if (uki_hash(fd, sym_EVP_sha256(), hashes, &hash_size) >= 0) {
                        for (size_t i = 0; i < _UNIFIED_SECTION_MAX; i++)
                                free(hashes[i]);
                }
        }
#endif

        return 0;
}

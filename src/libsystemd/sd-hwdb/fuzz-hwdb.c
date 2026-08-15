/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Fuzz target for the sd-hwdb binary trie parser.
 *
 * sd-hwdb consumes an mmap'd hwdb.bin produced by `systemd-hwdb update`. The
 * file is walked via offset-chasing into struct trie_node_f / trie_child_entry_f
 * / trie_value_entry_f records. A malformed file can drive the walker outside
 * the mapped region; the validators in trie_node_from_off / trie_string don't
 * guard every dereference site.
 *
 * Expected input: bytes that look like an `hwdb.bin` file (header magic
 * "KSLPHHRH" + trie). The harness writes the fuzzer bytes to a temp file,
 * mmaps it via sd_hwdb_new_from_path, then exercises sd_hwdb_get (which
 * drives trie_search_f / trie_fnmatch_f) and sd_hwdb_seek + sd_hwdb_enumerate
 * (capped to bound infinite loops via crafted offset cycles).
 */

#include <unistd.h>

#include "sd-hwdb.h"

#include "fd-util.h"
#include "fileio.h"
#include "fuzz.h"
#include "tests.h"
#include "tmpfile-util.h"

#define MAX_ENUMERATE 1024

static const char * const modaliases[] = {
        "pci:v00008086d00000A04",
        "usb:v1234p5678",
        "acpi:PNP0C0D:",
        "dmi:bvnLENOVO:bvrR0KET20W:bd02/01/2020:svnLENOVO:pnThinkPadX1:",
        "*",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-hwdb.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;

        if (outside_size_range(size, 0, 4 * 1024 * 1024))
                return 0;

        fuzz_setup_logging();

        ASSERT_OK(fmkostemp_safe(filename, "r+", &f));
        if (size != 0)
                ASSERT_OK_EQ_ERRNO((ssize_t) fwrite(data, size, 1, f), (ssize_t) 1);
        ASSERT_OK(fflush_and_check(f));

        if (sd_hwdb_new_from_path(filename, &hwdb) < 0)
                return 0;

        FOREACH_ELEMENT(modalias, modaliases) {
                const char *key, *value;
                size_t n = 0;

                (void) sd_hwdb_get(hwdb, *modalias, "ID_VENDOR", &value);

                if (sd_hwdb_seek(hwdb, *modalias) < 0)
                        continue;
                while (sd_hwdb_enumerate(hwdb, &key, &value) > 0) {
                        DO_NOT_OPTIMIZE(key);
                        DO_NOT_OPTIMIZE(value);
                        if (++n >= MAX_ENUMERATE)
                                break;
                }
        }

        return 0;
}

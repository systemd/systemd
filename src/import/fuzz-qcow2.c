/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "memfd-util.h"
#include "qcow2-util.h"

/* systemd-importd runs this over images it just downloaded (see pull-raw.c), so the header, the L1/L2
 * tables and every offset in them are attacker controlled. */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_close_ int qcow2_fd = -EBADF, raw_fd = -EBADF;

        if (size < sizeof(uint32_t))
                return 0;

        fuzz_setup_logging();

        qcow2_fd = memfd_new_and_seal("fuzz-qcow2-in", data, size);
        if (qcow2_fd < 0)
                return 0;

        raw_fd = memfd_new("fuzz-qcow2-out");
        if (raw_fd < 0)
                return 0;

        if (qcow2_detect(qcow2_fd) <= 0)
                return 0;

        (void) qcow2_convert(qcow2_fd, raw_fd);
        return 0;
}

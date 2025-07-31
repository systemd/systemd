/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "fuzz.h"
#include "rm-rf.h"
#include "tmpfile-util.h"
#include "xdg-autostart-service.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-xdg-desktop.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(xdg_autostart_service_freep) XdgAutostartService *service = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        fuzz_setup_logging();

        assert_se(mkdtemp_malloc("/tmp/fuzz-xdg-desktop-XXXXXX", &tmpdir) >= 0);

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(write(fd, data, size) == (ssize_t) size);

        assert_se(service = xdg_autostart_service_parse_desktop(name));
        assert_se(service->name = strdup("fuzz-xdg-desktop.service"));
        (void) xdg_autostart_service_generate_unit(service, tmpdir);

        return 0;
}

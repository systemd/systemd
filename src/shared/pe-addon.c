/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "fd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "memfd-util.h"
#include "pe-addon.h"
#include "pe-binary.h"
#include "pe-writer.h"
#include "string-util.h"
#include "strv.h"

/* The same SBAT policy ukify adds to addons it builds */
#define PE_ADDON_SBAT                                                                                           \
        "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"                        \
        "uki-addon,1,UKI Addon,addon,1,https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html\n"

static int add_data_section(PeWriter *w, const char *name, const void *data, size_t size) {
        int r;

        assert(w);
        assert(name);
        assert(data || size == 0);

        /* The writer takes its section contents from file descriptors, hence put the data in a memfd */
        _cleanup_close_ int fd = memfd_new_and_seal(name, data, size);
        if (fd < 0)
                return log_error_errno(fd, "Failed to allocate memory file for PE section '%s': %m", name);

        PeWriterSection *s;
        r = pe_writer_add_section(w, name, IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ, &s);
        if (r < 0)
                return log_error_errno(r, "Failed to add PE section '%s': %m", name);

        r = pe_writer_section_append_fd(s, fd, /* offset= */ 0, size);
        if (r < 0)
                return log_error_errno(r, "Failed to append data to PE section '%s': %m", name);

        return 0;
}

int pe_addon_make(
                const char *stub_path,
                const char *cmdline,
                const struct iovec *initrd,
                int output_fd) {

        int r;

        assert(stub_path);
        assert(output_fd >= 0);

        _cleanup_close_ int stub_fd = open(stub_path, O_RDONLY|O_CLOEXEC);
        if (stub_fd < 0)
                return log_error_errno(errno, "Failed to open addon stub '%s': %m", stub_path);

        _cleanup_(pe_writer_freep) PeWriter *w = NULL;
        r = pe_writer_new(stub_fd, &w);
        if (r < 0)
                return log_error_errno(r, "Failed to parse addon stub '%s': %m", stub_path);

        /* We add our own .sbat section below, and don't merge with an existing one. Refuse a stub that has
         * one (or that is an addon already), rather than producing a file with two. */
        FOREACH_STRING(section, ".sbat", ".cmdline", ".initrd") {
                r = pe_writer_find_section(w, section, /* start= */ 0, /* ret_index= */ NULL);
                if (r >= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Addon stub '%s' already carries a '%s' section, refusing.", stub_path, section);
                if (r != -ENXIO)
                        return log_error_errno(r, "Failed to look for section '%s' in addon stub '%s': %m", section, stub_path);
        }

        /* Keep the section order ukify uses, so that the result looks the same to all consumers */
        if (!isempty(cmdline)) {
                r = add_data_section(w, ".cmdline", cmdline, strlen(cmdline));
                if (r < 0)
                        return r;
        }

        if (iovec_is_set(initrd)) {
                r = add_data_section(w, ".initrd", initrd->iov_base, initrd->iov_len);
                if (r < 0)
                        return r;
        }

        r = add_data_section(w, ".sbat", PE_ADDON_SBAT, strlen(PE_ADDON_SBAT));
        if (r < 0)
                return r;

        r = pe_writer_write(w, output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to write addon: %m");

        return 0;
}

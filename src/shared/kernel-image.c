/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fileio.h"
#include "env-file.h"
#include "kernel-image.h"
#include "os-util.h"
#include "parse-util.h"
#include "pe-binary.h"
#include "string-table.h"

#define PE_SECTION_READ_MAX (16U*1024U)

static const char * const kernel_image_type_table[_KERNEL_IMAGE_TYPE_MAX] = {
        [KERNEL_IMAGE_TYPE_UNKNOWN] = "unknown",
        [KERNEL_IMAGE_TYPE_UKI]     = "uki",
        [KERNEL_IMAGE_TYPE_ADDON]   = "addon",
        [KERNEL_IMAGE_TYPE_PE]      = "pe",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(kernel_image_type, KernelImageType);

static int uki_read_pretty_name(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                char **ret) {

        _cleanup_free_ char *pname = NULL, *name = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ void *osrel = NULL;
        size_t osrel_size;
        int r;

        assert(fd >= 0);
        assert(pe_header);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);
        assert(ret);

        r = pe_read_section_data_by_name(
                        fd,
                        pe_header,
                        sections,
                        ".osrel",
                        /* max_size=*/ PE_SECTION_READ_MAX,
                        &osrel,
                        &osrel_size);
        if (r == -ENXIO) { /* Section not found */
                *ret = NULL;
                return 0;
        }

        f = fmemopen(osrel, osrel_size, "r");
        if (!f)
                return log_error_errno(errno, "Failed to open embedded os-release file: %m");

        r = parse_env_file(
                        f, NULL,
                        "PRETTY_NAME", &pname,
                        "NAME",        &name);
        if (r < 0)
                return log_error_errno(r, "Failed to parse embedded os-release file: %m");

        /* follow the same logic as os_release_pretty_name() */
        if (!isempty(pname))
                *ret = TAKE_PTR(pname);
        else if (!isempty(name))
                *ret = TAKE_PTR(name);
        else {
                char *n = strdup("Linux");
                if (!n)
                        return log_oom();

                *ret = n;
        }

        return 0;
}

static int inspect_uki(
                int fd,
                const PeHeader *pe_header,
                const IMAGE_SECTION_HEADER *sections,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_free_ char *cmdline = NULL, *uname = NULL, *pname = NULL;
        int r;

        assert(fd >= 0);
        assert(sections || le16toh(pe_header->pe.NumberOfSections) == 0);

        if (ret_cmdline) {
                r = pe_read_section_data_by_name(fd, pe_header, sections, ".cmdline", PE_SECTION_READ_MAX, (void**) &cmdline, NULL);
                if (r < 0 && r != -ENXIO) /* If the section doesn't exist, that's fine */
                        return r;
        }

        if (ret_uname) {
                r = pe_read_section_data_by_name(fd, pe_header, sections, ".uname", PE_SECTION_READ_MAX, (void**) &uname, NULL);
                if (r < 0 && r != -ENXIO) /* If the section doesn't exist, that's fine */
                        return r;
        }

        if (ret_pretty_name) {
                r = uki_read_pretty_name(fd, pe_header, sections, &pname);
                if (r < 0)
                        return r;
        }

        if (ret_cmdline)
                *ret_cmdline = TAKE_PTR(cmdline);
        if (ret_uname)
                *ret_uname = TAKE_PTR(uname);
        if (ret_pretty_name)
                *ret_pretty_name = TAKE_PTR(pname);

        return 0;
}

int inspect_kernel(
                int dir_fd,
                const char *filename,
                KernelImageType *ret_type,
                char **ret_cmdline,
                char **ret_uname,
                char **ret_pretty_name) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        KernelImageType t = KERNEL_IMAGE_TYPE_UNKNOWN;
        _cleanup_free_ PeHeader *pe_header = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(filename);

        fd = openat(dir_fd, filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open kernel image file '%s': %m", filename);

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r == -EBADMSG) /* not a valid PE file */
                goto not_uki;
        if (r < 0)
                return log_error_errno(r, "Failed to parse kernel image file '%s': %m", filename);

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r == -EBADMSG) /* not a valid PE file */
                goto not_uki;
        if (r < 0)
                return log_error_errno(r, "Failed to load PE sections from kernel image file '%s': %m", filename);

        if (pe_is_uki(pe_header, sections)) {
                r = inspect_uki(fd, pe_header, sections, ret_cmdline, ret_uname, ret_pretty_name);
                if (r < 0)
                        return r;

                t = KERNEL_IMAGE_TYPE_UKI;
                goto done;
        } else if (pe_is_addon(pe_header, sections)) {
                r = inspect_uki(fd, pe_header, sections, ret_cmdline, ret_uname, /* ret_pretty_name= */ NULL);
                if (r < 0)
                        return r;

                if (ret_pretty_name)
                        *ret_pretty_name = NULL;

                t = KERNEL_IMAGE_TYPE_ADDON;
                goto done;
        } else
                t = KERNEL_IMAGE_TYPE_PE;

not_uki:
        if (ret_cmdline)
                *ret_cmdline = NULL;
        if (ret_uname)
                *ret_uname = NULL;
        if (ret_pretty_name)
                *ret_pretty_name = NULL;

done:
        if (ret_type)
                *ret_type = t;

        return 0;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-journal.h"

#include "chase.h"
#include "compress.h"
#include "copy.h"
#include "coredumpctl.h"
#include "coredumpctl-core.h"
#include "coredumpctl-info.h"
#include "coredumpctl-journal.h"
#include "coredumpctl-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"

static int coredump_open_tmpfile(char **ret_path, int *ret_fd) {
        int r;

        assert(ret_path);
        assert(ret_fd);

        const char *vt;
        r = var_tmp_dir(&vt);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire temporary directory path: %m");

        _cleanup_free_ char *path = path_join(vt, "coredump-XXXXXX");
        if (!path)
                return log_oom();

        _cleanup_close_ int fd = mkostemp_safe(path);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create temporary file: %m");

        log_debug("Created temporary file %s", path);

        *ret_path = TAKE_PTR(path);
        *ret_fd = TAKE_FD(fd);
        return 0;
}

static int acquire_core_from_journal(sd_journal *j, int fd, char **ret_tmpfile) {
        int r;

        assert(j);
        assert((fd >= 0) == !ret_tmpfile);

        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_close_ int fdt = -EBADF;
        if (fd < 0) {
                r = coredump_open_tmpfile(&temp, &fdt);
                if (r < 0)
                        return r;

                fd = fdt;
        }

        /* We want full data, nothing truncated. */
        (void) sd_journal_set_data_threshold(j, 0);

        r = sd_journal_get_data_to_fd(j, "COREDUMP", SD_JOURNAL_DATA_SKIP_FIELD, fd, /* ret_size= */ NULL);
        if (r == -ENOENT)
                return log_error_errno(r, "Coredump entry has no core attached (neither internally in the journal nor externally on disk).");
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve COREDUMP field: %m");

        if (ret_tmpfile)
                *ret_tmpfile = TAKE_PTR(temp);

        return 0;
}

int acquire_core(sd_journal *j, int fd, char **ret_tmpfile, char **ret_path) {
        int r;

        assert(j);
        assert((fd >= 0) == !ret_tmpfile);
        assert((fd >= 0) == !ret_path);

        /* Look for a coredump on disk first. */
        const char *data;
        size_t len;
        r = sd_journal_get_data(j, "COREDUMP_FILENAME", (const void**) &data, &len);
        if (r == -ENOENT) {
                /* If not found, try to obtain a coredump from a COREDUMP field. */
                r = acquire_core_from_journal(j, fd, ret_tmpfile);
                if (r < 0)
                        return r;

                if (ret_path)
                        *ret_path = NULL;

                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve COREDUMP_FILENAME field: %m");

        _cleanup_free_ char *filename = NULL;
        r = retrieve(data, len, "COREDUMP_FILENAME", &filename);
        if (r < 0)
                return r;
        assert(r > 0);

        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int fdf_opath = -EBADF;
        r = chase(filename, arg_root, CHASE_PREFIX_ROOT | CHASE_MUST_BE_REGULAR, &path, &fdf_opath);
        if (r < 0)
                return log_error_errno(r, "Failed to chase '%s%s': %m", strempty(arg_root), filename);

        Compression c = compression_from_filename(path);
        if (c == COMPRESSION_NONE) {
                if (fd >= 0) {
                        r = copy_bytes(fdf_opath, fd, /* max_bytes= */ UINT64_MAX, /* copy_flags= */ 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to dump '%s': %m", path);
                }

                if (ret_tmpfile)
                        *ret_tmpfile = NULL;
                if (ret_path)
                        *ret_path = TAKE_PTR(path);

                return 0;
        }

#if HAVE_COMPRESSION
        _cleanup_close_ int fdf = fd_reopen(fdf_opath, O_RDONLY | O_CLOEXEC);
        if (fdf < 0)
                return log_error_errno(fdf, "Failed to open '%s': %m", path);

        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_close_ int fdt = -EBADF;
        if (fd < 0) {
                r = coredump_open_tmpfile(&temp, &fdt);
                if (r < 0)
                        return r;

                fd = fdt;
        }

        r = decompress_stream(c, fdf, fd, /* max_bytes= */ UINT64_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to decompress '%s': %m", path);

        if (ret_tmpfile)
                *ret_tmpfile = TAKE_PTR(temp);
        if (ret_path)
                *ret_path = NULL;

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Cannot decompress file. Compiled without compression support.");
#endif
}

int verb_dump_core(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (arg_field)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --field/-F only makes sense with list");

        r = acquire_journal(&j, strv_skip(argv, 1));
        if (r < 0)
                return r;

        r = focus(j);
        if (r < 0)
                return r;

        if (arg_output) {
                f = fopen(arg_output, "we");
                if (!f)
                        return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", arg_output);
        } else if (on_tty())
                /* We will write core to stdout. Let's refuse if stdout is connected to a tty. */
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                       "Refusing to dump core to tty (use shell redirection or specify --output).");

        (void) print_entry(f ? stdout : stderr, j, /* need_space= */ false, /* table= */ NULL);

        r = acquire_core(j, fileno(f ?: stdout), /* ret_tmpfile= */ NULL, /* ret_path= */ NULL);
        if (r < 0)
                return r;

        r = sd_journal_previous(j);
        if (r > 0 && !arg_quiet)
                log_notice("More than one entry matches, ignoring rest.");

        return 0;
}

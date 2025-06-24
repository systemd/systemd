/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "discover-image.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "image.h"
#include "io-util.h"
#include "log.h"
#include "machined.h"
#include "operation.h"
#include "process-util.h"
#include "string-table.h"
#include "tmpfile-util.h"

int clean_pool_read_first_entry(FILE *file, int child_error, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        bool success;
        int r;

        assert(file);

        if (fseek(file, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek to the beginning of tmp file: %m");

        /* The resulting temporary file starts with a boolean value that indicates success or not. */
        errno = 0;
        size_t n = fread(&success, 1, sizeof(success), file);
        if (n != sizeof(success)) {
                log_debug_errno(errno_or_else(EIO), "Received unexpected amount of %zu bytes: %m", n);
                return child_error < 0 ? child_error : errno_or_else(EIO);
        }

        if (child_error < 0) {
                /* The clean-up operation failed. In this case the resulting temporary file should contain a boolean
                 * set to false followed by the name of the failed image. Let's try to read this and use it for the
                 * error message. If we can't read it, don't mind, and return the naked error. */

                if (success) { /* The resulting temporary file could not be updated, ignore it. */
                        log_debug("Child process exited with an error. We expected a name of the image which caused the failure in the tmp file, but it failed as well.");
                        return child_error;
                }

                r = read_nul_string(file, LONG_LINE_MAX, &name);
                if (r <= 0) { /* Same here... */
                        log_debug_errno(r, "Failed to read nul-terminated string from tmp file: %m");
                        return child_error;
                }

                log_debug_errno(child_error, "Failed to remove image '%s': %m", name);
                return sd_bus_error_set_errnof(error, child_error, "Failed to remove image '%s': %m", name);
        }

        if (!success)
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Inconsistent state of the temporary file.");

        return 0;
}

int clean_pool_read_next_entry(FILE *file, char **ret_name, uint64_t *ret_usage) {
        /* Return value:
         * r < 0: error
         * r == 0 last record returned
         * r > 0 more records expected */

        _cleanup_free_ char *name = NULL;
        uint64_t usage;
        int r;

        assert(file);

        r = read_nul_string(file, LONG_LINE_MAX, &name);
        if (r < 0)
                return log_debug_errno(r, "Failed to read nul-terminated string: %m");
        if (r == 0) /* reached the end */
                return 0;

        errno = 0;
        size_t n = fread(&usage, 1, sizeof(usage), file);
        if (n != sizeof(usage))
                return log_debug_errno(errno_or_else(EIO), "Received unexpected amount of %zu bytes: %m", n);

        if (ret_name)
                *ret_name = TAKE_PTR(name);
        if (ret_usage)
                *ret_usage = usage;

        return 1;
}

int image_clean_pool_operation(Manager *manager, ImageCleanPoolMode mode, Operation **ret_operation) {
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        _cleanup_close_ int result_fd = -EBADF;
        _cleanup_(sigkill_waitp) pid_t child = 0;
        int r;

        assert(manager);
        assert(ret_operation);

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        /* Create a temporary file we can dump information about deleted images into. We use a temporary file for this
         * instead of a pipe or so, since this might grow quit large in theory and we don't want to process this
         * continuously */
        result_fd = open_tmpfile_unlinkable(NULL, O_RDWR|O_CLOEXEC);
        if (result_fd < 0)
                return log_debug_errno(result_fd, "Failed to open tmpfile: %m");

        /* This might be a slow operation, run it asynchronously in a background process */
        r = safe_fork("(sd-clean)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork(): %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                _cleanup_hashmap_free_ Hashmap *images = NULL;
                r = image_discover(manager->runtime_scope, IMAGE_MACHINE, /* root = */ NULL, &images);
                if (r < 0) {
                        log_debug_errno(r, "Failed to discover images: %m");
                        report_errno_and_exit(errno_pipe_fd[1], r);
                }

                bool success = true;
                ssize_t n = loop_write(result_fd, &success, sizeof(success));
                if (n < 0) {
                        log_debug_errno(n, "Failed to write to tmp file: %m");
                        report_errno_and_exit(errno_pipe_fd[1], n);
                }

                Image *image;
                HASHMAP_FOREACH(image, images) {
                        /* We can't remove vendor images (i.e. those in /usr) */
                        if (image_is_vendor(image))
                                continue;
                        if (image_is_host(image))
                                continue;
                        if (mode == IMAGE_CLEAN_POOL_REMOVE_HIDDEN && !image_is_hidden(image))
                                continue;

                        r = image_remove(image);
                        if (r == -EBUSY) {
                                log_debug("Keeping image '%s' because it's currently used.", image->name);
                                continue;
                        }
                        if (r < 0) {
                                log_debug_errno(r, "Failed to remove image '%s': %m", image->name);
                                success = false;

                                /* If the operation failed, let's override everything we wrote, and instead write there at which image we failed. */
                                if (ftruncate(result_fd, 0) < 0 ||
                                    lseek(result_fd, 0, SEEK_SET) < 0 ||
                                    write(result_fd, &success, sizeof(success)) < 0 ||
                                    write(result_fd, image->name, strlen(image->name)+1) < 0)
                                        log_debug_errno(errno, "Failed to truncate, rewind, or write to tmp file, ignoring: %m");

                                /* Report original error code (not results of rewind/truncate/etc */
                                report_errno_and_exit(errno_pipe_fd[1], r);
                        }

                        n = loop_write(result_fd, image->name, strlen(image->name) + 1);
                        if (n < 0) {
                                log_debug_errno(n, "Failed to write image name to tmp file: %m");
                                report_errno_and_exit(errno_pipe_fd[1], n);
                        }

                        n = loop_write(result_fd, &image->usage_exclusive, sizeof(image->usage_exclusive));
                        if (n < 0) {
                                log_debug_errno(n, "Failed to write image's usage to tmp file: %m");
                                report_errno_and_exit(errno_pipe_fd[1], n);
                        }
                }

                result_fd = safe_close(result_fd);
                _exit(EXIT_SUCCESS);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        /* The clean-up might take a while, hence install a watch on the child and return */
        r = operation_new(manager, /* machine= */ NULL, child, errno_pipe_fd[0], ret_operation);
        if (r < 0)
                 return r;

        (*ret_operation)->extra_fd = TAKE_FD(result_fd);
        TAKE_FD(errno_pipe_fd[0]);
        TAKE_PID(child);
        return 0;
}

static const char* const image_clean_pool_mode_table[_IMAGE_CLEAN_POOL_MAX] = {
        [IMAGE_CLEAN_POOL_REMOVE_ALL]    = "all",
        [IMAGE_CLEAN_POOL_REMOVE_HIDDEN] = "hidden"
};

DEFINE_STRING_TABLE_LOOKUP(image_clean_pool_mode, ImageCleanPoolMode);

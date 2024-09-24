/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "async.h"
#include "fd-util.h"
#include "file-descriptor.h"

int file_descriptor_validate(const FileDescriptor *fd) {
        assert(fd);

        // Disallow empty string for ExtraFileDescriptor
        // Unlike OpenFile, StandardInput and friends, there isn't a good sane
        // default for an arbitrary FD
        if (fd->fd < 0 || !fdname_is_valid(fd->fdname) || strlen(fd->fdname) == 0)
                return -EINVAL;

        return 0;
}

int file_descriptor_to_string(const FileDescriptor *fd, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(fd);
        assert(ret);

        r = asprintf(&s, "%d:%s", fd->fd, fd->fdname);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);

        return 0;
}

FileDescriptor* file_descriptor_free(FileDescriptor *fd) {
        if (!fd)
                return NULL;

        free(fd->fdname);

        return mfree(fd);
}

FileDescriptor* file_descriptor_free_and_close(FileDescriptor *fd) {
        if (!fd)
                return NULL;

        fd->fd = asynchronous_close(fd->fd);
        return file_descriptor_free(fd);
}

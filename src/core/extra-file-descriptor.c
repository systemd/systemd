/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "async.h"
#include "fd-util.h"
#include "extra-file-descriptor.h"

int extra_file_descriptor_validate(const ExtraFileDescriptor *fd) {
        assert(fd);

        /* Disallow empty string for ExtraFileDescriptor
         * Unlike OpenFile, StandardInput and friends, there isn't a good sane
         * default for an arbitrary FD
         */
        if (fd->fd < 0 || !fdname_is_valid(fd->fdname) || strlen(fd->fdname) == 0)
                return -EINVAL;

        return 0;
}

int extra_file_descriptor_to_string(const ExtraFileDescriptor *fd, char **ret) {
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

ExtraFileDescriptor* extra_file_descriptor_free(ExtraFileDescriptor *fd) {
        if (!fd)
                return NULL;

        fd->fd = asynchronous_close(fd->fd);
        free(fd->fdname);
        return mfree(fd);
}

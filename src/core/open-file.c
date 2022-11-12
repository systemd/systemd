/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "open-file.h"
#include "string-util.h"
#include "strv.h"

int parse_open_file(const char *v, OpenFile *ret) {
    _cleanup_strv_free_ char **parts = NULL;
    int r;

    if (!v)
        return -EINVAL;

    r = strv_split_full(&parts, v, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
    if (r < 0)
            return r;
    if (strv_length(parts) != 3)
            return -EINVAL;

    ret->path = TAKE_PTR(parts[0]);
    ret->fdname = TAKE_PTR(parts[1]);
    ret->flags = streq(parts[2], "rw") ? O_RDWR : O_RDONLY;

    return 0;
}

const char *open_file_to_string(const OpenFile *open_file) {
    if (!open_file)
        return "";
    return strjoin(open_file->path, ":", open_file->fdname, ":", open_file->flags == O_RDWR ? "rw" : "ro");
}
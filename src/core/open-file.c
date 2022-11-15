/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "open-file.h"
#include "string-util.h"
#include "strv.h"

const char *open_file_to_string(const OpenFile *open_file) {
    if (!open_file)
        return "";
    return strjoin(open_file->path, ":", open_file->fdname, ":", open_file->flags == O_RDWR ? "rw" : "ro");
}

void free_open_file_fields(const OpenFile *open_file) {
    free(open_file->path);
    free(open_file->fdname);
}
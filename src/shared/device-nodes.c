/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "device-nodes.h"
#include "path-util.h"
#include "string-util.h"
#include "utf8.h"

int allow_listed_char_for_devnode(char c, const char *additional) {
        return
                ascii_isdigit(c) ||
                ascii_isalpha(c) ||
                strchr("#+-.:=@_", c) ||
                (additional && strchr(additional, c));
}

int encode_devnode_name(const char *str, char *str_enc, size_t len) {
        size_t i, j;

        if (!str || !str_enc)
                return -EINVAL;

        for (i = 0, j = 0; str[i] != '\0'; i++) {
                int seqlen;

                seqlen = utf8_encoded_valid_unichar(str + i, SIZE_MAX);
                if (seqlen > 1) {

                        if (len-j < (size_t) seqlen)
                                return -EINVAL;

                        memcpy(&str_enc[j], &str[i], seqlen);
                        j += seqlen;
                        i += (seqlen-1);

                } else if (str[i] == '\\' || !allow_listed_char_for_devnode(str[i], NULL)) {

                        if (len-j < 4)
                                return -EINVAL;

                        sprintf(&str_enc[j], "\\x%02x", (unsigned char) str[i]);
                        j += 4;

                } else {
                        if (len-j < 1)
                                return -EINVAL;

                        str_enc[j] = str[i];
                        j++;
                }
        }

        if (len-j < 1)
                return -EINVAL;

        str_enc[j] = '\0';
        return 0;
}

int devnode_same(const char *a, const char *b) {
        struct stat sa, sb;

        assert(a);
        assert(b);

        if (!valid_device_node_path(a) || !valid_device_node_path(b))
                return -EINVAL;

        if (stat(a, &sa) < 0)
                return -errno;
        if (stat(b, &sb) < 0)
                return -errno;

        if (!S_ISBLK(sa.st_mode) && !S_ISCHR(sa.st_mode))
                return -ENODEV;
        if (!S_ISBLK(sb.st_mode) && !S_ISCHR(sb.st_mode))
                return -ENODEV;

        if (((sa.st_mode ^ sb.st_mode) & S_IFMT) != 0) /* both inode same device node type? */
                return false;

        return sa.st_rdev == sb.st_rdev;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "manifest-util.h"
#include "recurse-dir.h"
#include "sha256.h"
#include "string-table.h"
#include "string-util.h"

void manifest_context_done(ManifestContext *c) {
        assert(c);

        /* Nothing to release for now. */
}

static const char* const manifest_format_table[_MANIFEST_FORMAT_MAX] = {
        [MANIFEST_FORMAT_LIST]  = "list",
};

DEFINE_STRING_TABLE_LOOKUP(manifest_format, ManifestFormat);

static const struct {
        ManifestField field;
        const char *name;
} manifest_field_table[] = {
        /* This is a bitfield, hence not a simple array indexed by the enum */
        { MANIFEST_FIELD_MODE,     "mode"     },
        { MANIFEST_FIELD_UID,      "uid"      },
        { MANIFEST_FIELD_GID,      "gid"      },
        { MANIFEST_FIELD_SIZE,     "size"     },
        { MANIFEST_FIELD_HASH,     "hash"     },
        { MANIFEST_FIELD_SYMLINK,  "symlink"  },
        { MANIFEST_FIELD_DEVICE,   "device"   },
        { MANIFEST_FIELD_HARDLINK, "hardlink" },
        { MANIFEST_FIELD_MTIME,    "mtime"    },
};

const char* manifest_field_to_string(ManifestField f) {
        FOREACH_ELEMENT(i, manifest_field_table)
                if (i->field == f)
                        return i->name;

        return NULL;
}

ManifestField manifest_field_from_string(const char *s) {
        if (!s)
                return _MANIFEST_FIELD_INVALID;

        FOREACH_ELEMENT(i, manifest_field_table)
                if (streq(i->name, s))
                        return i->field;

        return _MANIFEST_FIELD_INVALID;
}

int manifest_fields_from_string(const char *s, ManifestField *ret) {
        ManifestField fields;
        bool first = true;
        int r;

        assert(s);
        assert(ret);

        fields = *ret;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&s, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                const char *n = word;
                bool add = true, relative = false;
                if (n[0] == '+') {
                        n++;
                        relative = true;
                } else if (n[0] == '-') {
                        n++;
                        add = false;
                        relative = true;
                }

                /* The first non-relative item resets the mask, subsequent items add to it. */
                if (first && !relative)
                        fields = 0;
                first = false;

                ManifestField f;
                if (streq(n, "all"))
                        f = _MANIFEST_FIELD_ALL;
                else if (streq(n, "default"))
                        f = _MANIFEST_FIELD_DEFAULT;
                else if (streq(n, "none"))
                        f = 0;
                else {
                        f = manifest_field_from_string(n);
                        if (f < 0)
                                return -EINVAL;
                }

                if (add)
                        fields |= f;
                else
                        fields &= ~f;
        }

        *ret = fields;
        return 0;
}

int manifest_fields_to_string(ManifestField f, char **ret) {
        _cleanup_free_ char *s = NULL;

        assert(ret);

        FOREACH_ELEMENT(i, manifest_field_table) {
                if (!FLAGS_SET(f, i->field))
                        continue;

                if (!strextend_with_separator(&s, ",", i->name))
                        return -ENOMEM;
        }

        if (!s) {
                s = strdup("none");
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

int manifest_context_hash_fd(ManifestContext *c, int inode_fd, uint8_t ret[static SHA256_DIGEST_SIZE]) {
        assert(c);
        assert(inode_fd >= 0);
        assert(ret);

        /* Calculating the hash might be slow, hence let's flush the output first, to give users an idea
         * where we are slow. */
        if (c->output)
                (void) fflush(c->output);

        /* Convert O_PATH fd into a regular one */
        _cleanup_close_ int fd =  fd_reopen(inode_fd, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        return sha256_fd(fd, /* max_size= */ UINT64_MAX, ret);
}

static int manifest_list_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        ManifestContext *c = ASSERT_PTR(userdata);

        assert(path);

        if (event == RECURSE_DIR_ENTER)
                fprintf(c->output, "%s%s/%s\n",
                        path,
                        c->color ? ansi_grey() : "",
                        c->color ? ansi_normal() : "");
        else if (event == RECURSE_DIR_ENTRY)
                fprintf(c->output, "%s\n", path);

        return RECURSE_DIR_CONTINUE;
}

int manifest_make(ManifestContext *c, int dir_fd) {
        int r;

        assert(c);
        assert(dir_fd >= 0);

        if (!c->output)
                c->output = stdout;

        int (*item_callback)(
                        RecurseDirEvent event,
                        const char *path,
                        int dir_fd,
                        int inode_fd,
                        const struct dirent *de,
                        const struct statx *sx,
                        void *userdata) = NULL;
        unsigned statx_mask = 0;
        const char *path = NULL;
        RecurseDirFlags flags = RECURSE_DIR_SORT;

        switch (c->format) {

        case MANIFEST_FORMAT_LIST:
                item_callback = manifest_list_item;
                break;

        default:
                assert_not_reached();
        }

        r = recurse_dir(dir_fd, path, statx_mask, /* n_depth_max= */ UINT_MAX, flags, item_callback, c);
        if (r < 0)
                return r;

        r = fflush_and_check(c->output);
        if (r < 0)
                return log_error_errno(r, "Failed to write manifest: %m");

        return 0;
}

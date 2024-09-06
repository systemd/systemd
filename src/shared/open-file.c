/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "open-file.h"
#include "path-util.h"
#include "string-table.h"
#include "string-util.h"

int open_file_parse(const char *v, OpenFile **ret) {
        _cleanup_free_ char *options = NULL;
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        assert(v);
        assert(ret);

        of = new0(OpenFile, 1);
        if (!of)
                return -ENOMEM;

        r = extract_many_words(&v, ":", EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_CUNESCAPE, &of->path, &of->fdname, &options);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        /* Enforce that at most 3 colon-separated words are present */
        if (!isempty(v))
                return -EINVAL;

        for (const char *p = options;;) {
                OpenFileFlag flag;
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                flag = open_file_flags_from_string(word);
                if (flag < 0)
                        return flag;

                if ((flag & of->flags) != 0)
                        return -EINVAL;

                of->flags |= flag;
        }

        if (isempty(of->fdname)) {
                of->fdname = mfree(of->fdname);
                r = path_extract_filename(of->path, &of->fdname);
                if (r < 0)
                        return r;
        }

        r = open_file_validate(of);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(of);

        return 0;
}

int open_file_validate(const OpenFile *of) {
        assert(of);

        if (!path_is_valid(of->path) || !path_is_absolute(of->path))
                return -EINVAL;

        if (!fdname_is_valid(of->fdname))
                return -EINVAL;

        if ((FLAGS_SET(of->flags, OPENFILE_READ_ONLY) + FLAGS_SET(of->flags, OPENFILE_APPEND) +
             FLAGS_SET(of->flags, OPENFILE_TRUNCATE)) > 1)
                return -EINVAL;

        if ((of->flags & ~_OPENFILE_MASK_PUBLIC) != 0)
                return -EINVAL;

        return 0;
}

int open_file_to_string(const OpenFile *of, char **ret) {
        _cleanup_free_ char *options = NULL, *fname = NULL, *s = NULL;
        bool has_fdname = false;
        int r;

        assert(of);
        assert(ret);

        s = xescape(of->path, ":");
        if (!s)
                return -ENOMEM;

        r = path_extract_filename(of->path, &fname);
        if (r < 0)
                return r;

        has_fdname = !streq(fname, of->fdname);
        if (has_fdname)
                if (!strextend(&s, ":", of->fdname))
                        return -ENOMEM;

        for (OpenFileFlag flag = OPENFILE_READ_ONLY; flag < _OPENFILE_MAX; flag <<= 1)
                if (FLAGS_SET(of->flags, flag) && !strextend_with_separator(&options, ",", open_file_flags_to_string(flag)))
                        return -ENOMEM;

        if (options)
                if (!(has_fdname ? strextend(&s, ":", options) : strextend(&s, "::", options)))
                        return -ENOMEM;

        *ret = TAKE_PTR(s);

        return 0;
}

OpenFile* open_file_free(OpenFile *of) {
        if (!of)
                return NULL;

        free(of->path);
        free(of->fdname);

        return mfree(of);
}

static const char * const open_file_flags_table[_OPENFILE_MAX] = {
        [OPENFILE_READ_ONLY] = "read-only",
        [OPENFILE_APPEND]    = "append",
        [OPENFILE_TRUNCATE]  = "truncate",
        [OPENFILE_GRACEFUL]  = "graceful",
};

DEFINE_STRING_TABLE_LOOKUP(open_file_flags, OpenFileFlag);

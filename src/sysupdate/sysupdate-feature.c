/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-parser.h"
#include "hash-funcs.h"
#include "path-util.h"
#include "string-util.h"
#include "sysupdate-config.h"
#include "sysupdate-feature.h"

static Feature *feature_free(Feature *f) {
        if (!f)
                return NULL;

        free(f->id);

        free(f->description);
        free(f->documentation);
        free(f->appstream);

        return mfree(f);
}

Feature *feature_new(void) {
        Feature *f;

        f = new(Feature, 1);
        if (!f)
                return NULL;

        *f = (Feature) {
                .n_ref = 1,
        };

        return f;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Feature, feature, feature_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(feature_hash_ops,
                                      char, string_hash_func, string_compare_func,
                                      Feature, feature_unref);

int feature_read_definition(Feature *f, const char *root, const char *path, const char *const *dirs) {
        assert(f);

        ConfigTableItem table[] = {
                { "Feature", "Description",   config_parse_string,         0, &f->description },
                { "Feature", "Documentation", config_parse_url_specifiers, 0, &f->documentation },
                { "Feature", "AppStream",     config_parse_url_specifiers, 0, &f->appstream },
                { "Feature", "Enabled",       config_parse_bool,           0, &f->enabled },
                {}
        };

        _cleanup_free_ char *filename = NULL;
        int r;

        assert(path);
        assert(dirs);

        r = path_extract_filename(path, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        r = config_parse_many_full(
                        STRV_MAKE_CONST(path),
                        dirs,
                        strjoina(filename, ".d"),
                        root,
                        /* root_fd= */ -EBADF,
                        "Feature\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        (void *) root,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_drop_in_files= */ NULL);
        if (r < 0)
                return r;

        *ASSERT_PTR(endswith(filename, ".feature")) = 0; /* Remove the file extension */
        f->id = TAKE_PTR(filename);

        return 0;
}

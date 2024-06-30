/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <stdio.h>

#include "conf-files.h"
#include "conf-parser.h"
#include "erofs.h"
#include "glyph-util.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "repart-util.h"
#include "string-util.h"
#include "strv.h"


/* Everything here besides parse_<fstype>_options is meant for internal consumption.
 * 
 * The general idea is to use the ConfigTableItem mechanism from basic/conf-parser.h to read all the data
 * from the relevant <fstype>-named section (e.g. '[BtrfsOptions]' when '<fstype>' is 'btrfs'). 
 * Those data are stored in temporary structs and the structs are finally processed into an array of string
 * (i.e. 'strv') that is returned as `char **ret_options` argument of `parse_<fstype>_options`
 */



/* =========================================
 *             Extended Options 
 * ========================================= */
 
typedef struct ErofsExtendedOptions {
        int fragments;
        int dedupe;
        int ztailpacking;
} ErofsExtendedOptions;


/* =========================================
 *                 Parsers
 * ========================================= */

static int config_parse_max_pcluster_size_bytes(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *sz = data, parsed;
        int r;

        assert(rvalue);
        assert(data);
                        
        
        r = parse_size(rvalue, 1024, &parsed);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r,
                                  "Failed to parse size value: %s", rvalue);
        
        *sz = round_up_size(parsed, 4096);  /* ensures alignment with FS blocks, no point cutting hair with 512B */
                        
        if (*sz != parsed)
                log_syntax(unit, LOG_NOTICE, filename, line, r, "Rounded %s= size %" PRIu64 " %s %" PRIu64 ", a multiple of 4096.",
                           lvalue, parsed, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), *sz);

        return 0;
}

static int config_parse_erofs_compression(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        
        _cleanup_free_ char *n = NULL;
        char **compress = ASSERT_PTR(data);
        
        assert(rvalue);
                        
        /* We accept empty value to mean "no compression" */
        if (isempty(rvalue)) {
                *compress = mfree(*compress);
                return 0;
        }
        
        /* Pretend it's a bool:
         *   true  => LZ4
         *   false => no compression, default.
         */
        int k;
        k = parse_boolean(rvalue);  /* k < 0: not a bool, handled later */
        if (k >= 0) {
                *compress = mfree(*compress);
                if (k)
                        *compress = strdup("lz4");
                return 0;
        }
        
        /* Now assume the user did input correctly formatted in that field 
         * sc. <algo>[,level=<X>][,dictionary=<Y>] with compiled-in algo and valid algo-specific level.
         */
        n = strdup(rvalue);
        if (!n)
                return log_oom();
                        
        return free_and_replace(*compress, n);
}


/* =========================================
 *               Main Struct
 * ========================================= */

typedef struct ErofsMakeFsOptions {
        uint32_t max_pcluster_bytes;                  /* ignored if 0 else multiples of 4096 | -C */
        bool copy_xattrs;                             /*                                     | -x */
        bool drop_timestamp;                          /*                                     | -T */
        char *compression_scheme;                     /*                                     | -z */
        ErofsExtendedOptions *extended_options;       /*                                     | -E */
        int32_t forced_uid;                           /* negative: ignore option             | --force-uid */
        int32_t forced_gid;                           /* negative: ignore option             | --force-gid */
} ErofsMakeFsOptions;

/* new */
static ErofsMakeFsOptions *erofs_makefs_options_new(void){
        ErofsMakeFsOptions *opt = NULL;
        ErofsExtendedOptions *eo = NULL;
        
        opt = new(ErofsMakeFsOptions, 1);
        if (!opt)
                return NULL;
        
        eo = new(ErofsExtendedOptions, 1);
        if (!eo) {
                opt = mfree(opt);
                return NULL;
        }
        
        *eo  = (ErofsExtendedOptions)   {false, false, false}; /* i.e. use mkfs.erofs defaults */
        *opt = (ErofsMakeFsOptions)     {
                .max_pcluster_bytes = 0,               /* i.e. use mkfs.erofs defaults */
                .copy_xattrs = true,                   /* i.e. use mkfs.erofs defaults */
                .drop_timestamp = false,               /* i.e. use mkfs.erofs defaults */
                .extended_options = eo,
                .forced_uid = -1,                      /* i.e. use mkfs.erofs defaults */
                .forced_gid = -1,                      /* i.e. use mkfs.erofs defaults */
        };
        
        return TAKE_PTR(opt);
}

/* free */
static void* erofs_makefs_options_free(ErofsMakeFsOptions *opt){
        if (!opt)
                return NULL;
        
        free(opt->extended_options);
        free(opt->compression_scheme);
        
        return mfree(opt);
}

static int erofs_makefs_options_free_and_log_oom(ErofsMakeFsOptions *opt){
    opt = erofs_makefs_options_free(opt);
    return log_oom();
}

/* =========================================
 *         *Options -> strv Converters
 * ========================================= */

static int append_max_pcluster_bytes(ErofsMakeFsOptions const *opt, char ***ret_options) {
        int r;
        
        if (opt->max_pcluster_bytes == 0)
                return 0; /* no-op */
                
        r = strv_extendf(ret_options, "-C");
        if (r < 0)
                return log_oom();
        
        r = strv_extendf(ret_options, "%"PRIu32, opt->max_pcluster_bytes);
        if (r < 0)
                return log_oom();
        return 0;
}

static int append_drop_timestamp(ErofsMakeFsOptions const *opt, char ***ret_options) {
        int r;
        
        if (!opt->drop_timestamp)
                return 0; /* no-op */
                
        r = strv_extendf(ret_options, "-T");
        if (r < 0)
                return log_oom();
           
        r = strv_extendf(ret_options, "0");
        if (r < 0)
                return log_oom();
        return 0;
}

static int append_copy_xattrs(ErofsMakeFsOptions const *opt, char ***ret_options) {
        int r;
        
        if (opt->copy_xattrs)
                return 0; /* no-op */
           
        r = strv_extendf(ret_options, "-x");
        if (r < 0)
                return log_oom();
                
        r = strv_extendf(ret_options, "-1");
        if (r < 0)
                return log_oom();
        return 0;
}

static int append_force_uid(ErofsMakeFsOptions const *opt, char ***ret_options) {
        int r;
        
        if (opt->forced_uid < 0)
                return 0; /* no-op */
        
        r = strv_extendf(ret_options, "--force-uid");
        if (r < 0)
                return log_oom();
                
        r = strv_extendf(ret_options, "%"PRIi32, opt->forced_uid);
        if (r < 0)
                return log_oom();
        return 0;
}

static int append_force_gid(ErofsMakeFsOptions const *opt, char ***ret_options) {
        int r;
        
        if (opt->forced_gid < 0)
                return 0; /* no-op */
        
        r = strv_extendf(ret_options, "--force-gid");
        if (r < 0)
                return log_oom();
                
        r = strv_extendf(ret_options, "%"PRIi32, opt->forced_gid);
        if (r < 0)
                return log_oom();
        return 0;
}

static int append_compression(ErofsMakeFsOptions const *opt, char ***ret_options) {
        int r;
        
        if (!opt->compression_scheme)
                return 0; /* no-op */
        
        r = strv_extendf(ret_options, "-z");
        if (r < 0)
                return log_oom();
        
        r = strv_extendf(ret_options, "%s", opt->compression_scheme);
        if (r < 0)
                return log_oom();
        return 0;
}

static int append_single_extended_option(char ***ret_elist, const char *option, const int tristate) {
        int r;
        switch (tristate){
                case -1: /* AUTO */
                        return 0;
                case 0: /* Force OFF */
                        /* Erofs does not support force-off declarations like e.f. ext4 does. */
                        //r = strv_extendf(ret_elist, "^%s", option);
                        //if (r<0)
                        //        return log_oom();
                        //return r;
                        return 0;
                case 1: /* Force ON */ 
                        r = strv_extendf(ret_elist, "%s", option);
                        if (r<0)
                                return log_oom();
                        return r;
                default:
                        return log_error_errno(-EINVAL, "Invalid value for erofs extended option '%s': %m", option);
        }
} 

static int append_extended_options(ErofsMakeFsOptions const *opt, char ***ret_options) {
        _cleanup_strv_free_ char **elist = strv_new(NULL);
        int r;
        
        r = append_single_extended_option(&elist, "fragments", opt->extended_options->fragments);
        if (r < 0)
                return r;
                
        r = append_single_extended_option(&elist, "dedup", opt->extended_options->dedupe);
        if (r < 0)
                return r;
                
        r = append_single_extended_option(&elist, "ztailpacking", opt->extended_options->ztailpacking);
        if (r < 0)
                return r;
        
        if (strv_isempty(elist))
                return 0; 
        
        r = strv_extendf(ret_options, "-E");
        if (r < 0)
                return log_oom();
        
        char * extended_options = strv_join(elist, ",");
        
        r = strv_extendf(ret_options, "%s", extended_options);
        if (r < 0)
                return log_oom();
        
        return 0;
}

/* =========================================
 *              Public interface
 * ========================================= */

int parse_erofs_options(const char* root, const char *path, const char *const *conf_file_dirs, char ***ret_options) {
        
        /* Data declaration */
        ErofsMakeFsOptions   *o = erofs_makefs_options_new();
        if (!o)
                return log_oom();
        ErofsExtendedOptions *e = o->extended_options;
        
        ConfigTableItem erofs_table[] = {
                { "ErofsOptions", "MaxPhysicalClusterSizeBytes", config_parse_max_pcluster_size_bytes,     0, &o->max_pcluster_bytes},
                { "ErofsOptions", "CopyExtendedAttributes",      config_parse_bool,                        0, &o->copy_xattrs       },
                { "ErofsOptions", "DropTimestamp",               config_parse_bool,                        0, &o->drop_timestamp    },
                { "ErofsOptions", "ForceUid",                    config_parse_int32,                       0, &o->forced_uid        },
                { "ErofsOptions", "ForceGid",                    config_parse_int32,                       0, &o->forced_gid        },
                { "ErofsOptions", "Compression",                 config_parse_erofs_compression,           0, &o->compression_scheme},
                { "ErofsOptions", "ForceUseFragments",           config_parse_tristate,                    0, &e->fragments         },
                { "ErofsOptions", "ForceDeduplicate",            config_parse_tristate,                    0, &e->dedupe            },
                { "ErofsOptions", "ForcePackTail",               config_parse_tristate,                    0, &e->ztailpacking      },
                {}
        };
        int r;
        _cleanup_free_ char *filename = NULL;
        const char* dropin_dirname;
        
        r = path_extract_filename(path, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        dropin_dirname = strjoina(filename, ".d");

        /* Data parsing */
        r = config_parse_many(
                        STRV_MAKE_CONST(path),
                        conf_file_dirs,
                        dropin_dirname,
                        root,
                        REPART_CONF_FILE_VALID_SECTIONS,
                        config_item_table_lookup, erofs_table,
                        CONFIG_PARSE_WARN,
                        o,
                        NULL,
                        NULL); /* Do we want to return/compare drop-ins? */ 
        if (r < 0)
                return r;
        
        /* Custom Struct to strv transformation */
        _cleanup_strv_free_ char **options = strv_new(NULL);
        
        r = append_max_pcluster_bytes(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = append_drop_timestamp(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = append_force_uid(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = append_force_gid(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = append_compression(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = append_extended_options(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = append_copy_xattrs(o, &options);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        r = strv_extend_strv(ret_options, TAKE_PTR(options), /* filter_duplicates = */ false);
        if (r < 0)
                return erofs_makefs_options_free_and_log_oom(o);
        
        erofs_makefs_options_free(o);
        return 0;
}

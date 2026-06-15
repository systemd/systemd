/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "fileio.h"
#include "log.h"
#include "metrics.h"
#include "path-util.h"
#include "report-files.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "varlink-idl-util.h"

/* Upper bounds, to protect against pathologically large directories or files. */
#define REPORT_FILES_MAX 1024U
#define REPORT_FILE_SIZE_MAX (4U * 1024U * 1024U)

/* The directories we look for files to report in. This is the usual CONF_PATHS() set (/etc/, /run/,
 * /usr/local/lib/, /usr/lib/), plus an extra directory below /var/lib/ for persistent local additions. Files
 * (typically symlinks to the actual files to report) dropped into any of these are reported as metrics, keyed
 * by their name. Entries in earlier directories override identically named ones in later directories. */
static const char* const report_files_dirs[] = {
        "/etc/systemd/report.files",
        "/run/systemd/report.files",
        "/var/lib/systemd/report.files",
        "/usr/local/lib/systemd/report.files",
        "/usr/lib/systemd/report.files",
        NULL,
};

static MetricFamily* metric_family_array_free(MetricFamily *families) {
        if (!families)
                return NULL;

        /* The array is NULL-name terminated. We own the name/description strings. */
        for (MetricFamily *mf = families; mf->name; mf++) {
                free((char*) mf->name);
                free((char*) mf->description);
        }

        return mfree(families);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(MetricFamily*, metric_family_array_free);

static int file_metric_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;

        assert(mf && mf->name);
        assert(link);

        /* Recover the file name from the metric family name: it is the part following the interface prefix.
         * We look it up across our directories again (rather than caching the path found while building the
         * metric list), and read the first instance we find, matching the precedence used at enumeration. */
        const char *field = startswith(mf->name, METRIC_IO_SYSTEMD_FILES_PREFIX);
        assert(field);

        _cleanup_free_ char *buf = NULL;
        size_t size = 0;
        STRV_FOREACH(d, report_files_dirs) {
                _cleanup_free_ char *path = path_join(*d, field);
                if (!path)
                        return log_oom();

                r = read_full_file_full(AT_FDCWD, path, /* offset= */ UINT64_MAX, REPORT_FILE_SIZE_MAX,
                                        READ_FULL_FILE_FAIL_WHEN_LARGER, /* bind_name= */ NULL, &buf, &size);
                if (r == -ENOENT) /* Not in this directory (or dangling symlink): try the next one. */
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read '%s', skipping: %m", path);
                        return 0;
                }

                break;
        }

        if (!buf) {
                log_debug("File for metric '%s' disappeared, skipping.", mf->name);
                return 0;
        }

        /* Metric values are JSON strings, so we can only report text files. Skip anything that isn't valid,
         * NUL-free UTF-8. */
        if (memchr(buf, 0, size) || !utf8_is_valid(buf)) {
                log_debug("File for metric '%s' is not valid UTF-8 text, skipping.", mf->name);
                return 0;
        }

        return metric_build_send_string(mf, link, /* object= */ NULL, buf, /* fields= */ NULL);
}

static int build_file_metrics(MetricFamily **ret) {
        _cleanup_(metric_family_array_freep) MetricFamily *families = NULL;
        _cleanup_strv_free_ char **files = NULL;
        size_t n = 0;
        int r;

        assert(ret);

        /* Enumerate the files to report across all our directories, deduplicated by name. The entry name is
         * used as the metric field name. */
        r = conf_files_list_strv(&files, /* suffix= */ NULL, /* root= */ NULL, CONF_FILES_REGULAR, report_files_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate report files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_free_ char *base = NULL;
                r = path_extract_filename(*f, &base);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", *f);

                /* The name becomes the metric field name, so it must be a valid one. */
                if (!varlink_idl_field_name_is_valid(base)) {
                        log_debug("Report file '%s' does not have a valid metric field name, skipping.", *f);
                        continue;
                }

                if (n >= REPORT_FILES_MAX) {
                        log_warning("More than %u report files found, not reporting the rest.", REPORT_FILES_MAX);
                        break;
                }

                _cleanup_free_ char *name = strjoin(METRIC_IO_SYSTEMD_FILES_PREFIX, base);
                _cleanup_free_ char *description = strjoin("Contents of the '", base, "' report file");
                if (!name || !description)
                        return log_oom();

                /* Room for the new entry plus the NULL-name terminator. */
                if (!GREEDY_REALLOC(families, n + 2))
                        return log_oom();

                families[n++] = (MetricFamily) {
                        .name = TAKE_PTR(name),
                        .description = TAKE_PTR(description),
                        .type = METRIC_FAMILY_TYPE_STRING,
                        .generate = file_metric_generate,
                };
                families[n] = (MetricFamily) {}; /* terminator */
        }

        /* The metrics helpers expect a valid, terminated array even when empty. */
        if (!families) {
                families = new0(MetricFamily, 1);
                if (!families)
                        return log_oom();
        }

        *ret = TAKE_PTR(families);
        return 0;
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        _cleanup_(metric_family_array_freep) MetricFamily *families = NULL;
        r = build_file_metrics(&families);
        if (r < 0)
                return r;

        return metrics_method_list(families, link, parameters, flags, /* userdata= */ NULL);
}

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        _cleanup_(metric_family_array_freep) MetricFamily *families = NULL;
        r = build_file_metrics(&families);
        if (r < 0)
                return r;

        return metrics_method_describe(families, link, parameters, flags, /* userdata= */ NULL);
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>

#include "alloc-util.h"
#include "copy.h"
#include "edit-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

void edit_file_free_all(EditFile **f) {
        if (!f || !*f)
                return;

        for (EditFile *i = *f; i->path; i++) {
                free(i->path);
                free(i->tmp);
        }

        free(*f);
}

int create_edit_temp_file(
                const char *new_path,
                const char *original_path,
                char ** const original_unit_paths,
                const char *marker_start,
                const char *marker_end,
                char **ret_tmp_fn,
                unsigned *ret_edit_line) {

        _cleanup_free_ char *t = NULL;
        unsigned ln = 1;
        int r;

        assert(new_path);
        assert(ret_tmp_fn);
        assert(ret_edit_line);

        r = tempfn_random(new_path, NULL, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to determine temporary filename for \"%s\": %m", new_path);

        r = mkdir_parents_label(new_path, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create directories for \"%s\": %m", new_path);

        if (original_path) {
                r = mac_selinux_create_file_prepare(new_path, S_IFREG);
                if (r < 0)
                        return r;

                r = copy_file(original_path, t, 0, 0644, 0, 0, COPY_REFLINK);
                if (r == -ENOENT) {
                        r = touch(t);
                        mac_selinux_create_file_clear();
                        if (r < 0)
                                return log_error_errno(r, "Failed to create temporary file \"%s\": %m", t);
                } else {
                        mac_selinux_create_file_clear();
                        if (r < 0)
                                return log_error_errno(r, "Failed to create temporary file for \"%s\": %m", new_path);
                }
        } else if (original_unit_paths) {
                _cleanup_free_ char *new_contents = NULL;
                _cleanup_fclose_ FILE *f = NULL;

                r = mac_selinux_create_file_prepare(new_path, S_IFREG);
                if (r < 0)
                        return r;

                f = fopen(t, "we");
                mac_selinux_create_file_clear();
                if (!f)
                        return log_error_errno(errno, "Failed to open \"%s\": %m", t);

                if (fchmod(fileno(f), 0644) < 0)
                        return log_error_errno(errno, "Failed to change mode of \"%s\": %m", t);

                r = read_full_file(new_path, &new_contents, NULL);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read \"%s\": %m", new_path);

                fprintf(f,
                        "### Editing %s\n"
                        "%s\n"
                        "\n"
                        "%s%s"
                        "\n"
                        "%s\n",
                        new_path,
                        strempty(marker_start),
                        strempty(new_contents),
                        new_contents && endswith(new_contents, "\n") ? "" : "\n",
                        strempty(marker_end));

                ln = 4; /* start editing at the contents */

                /* Add a comment with the contents of the original unit files */
                STRV_FOREACH(path, original_unit_paths) {
                        _cleanup_free_ char *contents = NULL;

                        /* Skip the file that's being edited */
                        if (path_equal(*path, new_path))
                                continue;

                        r = read_full_file(*path, &contents, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read \"%s\": %m", *path);

                        fprintf(f, "\n\n### %s", *path);
                        if (!isempty(contents)) {
                                _cleanup_free_ char *commented_contents = NULL;

                                commented_contents = strreplace(strstrip(contents), "\n", "\n# ");
                                if (!commented_contents)
                                        return log_oom();
                                fprintf(f, "\n# %s", commented_contents);
                        }
                }

                r = fflush_and_check(f);
                if (r < 0)
                        return log_error_errno(r, "Failed to create temporary file \"%s\": %m", t);
        }

        *ret_tmp_fn = TAKE_PTR(t);
        *ret_edit_line = ln;

        return 0;
}

int run_editor(const EditFile *files) {
        int r;

        assert(files);

        r = safe_fork("(editor)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_WAIT, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                size_t n_editor_args = 0, i = 1, argc;
                char **editor_args = NULL, **args;
                const char *editor;

                /* SYSTEMD_EDITOR takes precedence over EDITOR which takes precedence over VISUAL.  If
                 * neither SYSTEMD_EDITOR nor EDITOR nor VISUAL are present, we try to execute well known
                 * editors. */
                editor = getenv("SYSTEMD_EDITOR");
                if (!editor)
                        editor = getenv("EDITOR");
                if (!editor)
                        editor = getenv("VISUAL");

                if (isempty(editor))
                        argc = 1;
                else {
                        editor_args = strv_split(editor, WHITESPACE);
                        if (!editor_args) {
                                (void) log_oom();
                                _exit(EXIT_FAILURE);
                        }
                        n_editor_args = strv_length(editor_args);
                        argc = n_editor_args;
                }

                for (const EditFile *f = files; f->path; f++)
                        argc += 2;

                args = newa(char*, argc + 1);

                if (n_editor_args > 0) {
                        args[0] = editor_args[0];
                        for (; i < n_editor_args; i++)
                                args[i] = editor_args[i];
                }

                if (files[0].path && files[0].line > 1 && !files[1].path) {
                        /* If editing a single file only, use the +LINE syntax to put cursor on the right line */
                        if (asprintf(args + i, "+%u", files[0].line) < 0) {
                                (void) log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        i++;
                        args[i++] = files[0].tmp;
                } else
                        for (const EditFile *f = files; f->path; f++)
                                args[i++] = f->tmp;

                args[i] = NULL;

                if (n_editor_args > 0)
                        execvp(args[0], (char* const*) args);

                FOREACH_STRING(name, "editor", "nano", "vim", "vi") {
                        args[0] = (char*) name;
                        execvp(name, (char* const*) args);
                        /* We do not fail if the editor doesn't exist because we want to try each one of them
                         * before failing. */
                        if (errno != ENOENT) {
                                log_error_errno(errno, "Failed to execute %s: %m", name);
                                _exit(EXIT_FAILURE);
                        }
                }

                log_error("Cannot edit units, no editor available. Please set either $SYSTEMD_EDITOR, $EDITOR or $VISUAL.");
                _exit(EXIT_FAILURE);
        }

        return 0;
}

int trim_edit_markers(const char *path, const char *marker_start, const char *marker_end) {
        _cleanup_free_ char *old_contents = NULL, *new_contents = NULL;
        char *contents_start, *contents_end;
        const char *c = NULL;
        int r;

        /* Trim out the lines between the two markers */
        r = read_full_file(path, &old_contents, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read temporary file \"%s\": %m", path);

        contents_start = strstr(old_contents, marker_start);
        if (contents_start)
                contents_start += strlen(marker_start);
        else
                contents_start = old_contents;

        contents_end = strstr(contents_start, marker_end);
        if (contents_end)
                contents_end[0] = 0;

        c = strstrip(contents_start);
        if (isempty(c))
                return 0; /* All gone now */

        new_contents = strjoin(c, "\n"); /* Trim prefix and suffix, but ensure suffixed by single newline */
        if (!new_contents)
                return log_oom();

        if (streq(old_contents, new_contents)) /* Don't touch the file if the above didn't change a thing */
                return 1; /* Unchanged, but good */

        r = write_string_file(path, new_contents, WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_TRUNCATE | WRITE_STRING_FILE_AVOID_NEWLINE);
        if (r < 0)
                return log_error_errno(r, "Failed to modify temporary file \"%s\": %m", path);

        return 1; /* Changed, but good */
}

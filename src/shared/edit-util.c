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

size_t edit_files_count(const EditFile *ef) {
        size_t n = 0;

        EDIT_FILE_FOREACH(i, ef)
                n++;

        return n;
}

void edit_file_free_all(EditFile **ef) {
        assert(ef);

        EDIT_FILE_FOREACH(i, *ef) {
                free(i->path);
                free(i->original_path);
                free(i->temp);
                strv_free(i->comment_paths);
        }

        *ef = mfree(*ef);
}

int create_edit_temp_file(
                const char *target_path,
                const char *original_path,
                char * const *comment_paths,
                const char *marker_start,
                const char *marker_end,
                char **ret_temp_filename,
                unsigned *ret_edit_line) {

        _cleanup_free_ char *temp = NULL;
        unsigned line = 1;
        int r;

        assert(target_path);
        assert(!comment_paths || (comment_paths && (marker_start || marker_end)));
        assert(ret_temp_filename);

        r = tempfn_random(target_path, NULL, &temp);
        if (r < 0)
                return log_error_errno(r, "Failed to determine temporary filename for \"%s\": %m", target_path);

        r = mkdir_parents_label(target_path, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create parent directories for \"%s\": %m", target_path);

        if (original_path) {
                r = mac_selinux_create_file_prepare(target_path, S_IFREG);
                if (r < 0)
                        return r;

                r = copy_file(original_path, temp, 0, 0644, 0, 0, COPY_REFLINK);
                if (r == -ENOENT) {
                        r = touch(temp);
                        mac_selinux_create_file_clear();
                        if (r < 0)
                                return log_error_errno(r, "Failed to create temporary file \"%s\": %m", temp);
                } else {
                        mac_selinux_create_file_clear();
                        if (r < 0)
                                return log_error_errno(r, "Failed to create temporary file for \"%s\": %m", target_path);
                }
        }

        if (comment_paths) {
                _cleanup_free_ char *target_contents = NULL;
                _cleanup_fclose_ FILE *f = NULL;

                r = mac_selinux_create_file_prepare(target_path, S_IFREG);
                if (r < 0)
                        return r;

                f = fopen(temp, "we");
                mac_selinux_create_file_clear();
                if (!f)
                        return log_error_errno(errno, "Failed to open temporary file \"%s\": %m", temp);

                if (fchmod(fileno(f), 0644) < 0)
                        return log_error_errno(errno, "Failed to change mode of temporary file \"%s\": %m", temp);

                r = read_full_file(target_path, &target_contents, NULL);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read target file \"%s\": %m", target_path);

                fprintf(f,
                        "### Editing %s\n"
                        "%s\n"
                        "\n"
                        "%s%s"
                        "\n"
                        "%s\n",
                        target_path,
                        marker_start,
                        strempty(target_contents),
                        target_contents && endswith(target_contents, "\n") ? "" : "\n",
                        marker_end);

                line = 4; /* Start editing at the contents area */

                /* Add a comment with the contents of the original files */
                STRV_FOREACH(path, comment_paths) {
                        _cleanup_free_ char *contents = NULL;

                        /* Skip the file that's being edited, already processed in above */
                        if (path_equal(*path, target_path))
                                continue;

                        r = read_full_file(*path, &contents, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read original unit file \"%s\": %m", *path);

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
                        return log_error_errno(r, "Failed to create temporary file \"%s\": %m", temp);
        }

        *ret_temp_filename = TAKE_PTR(temp);

        if (ret_edit_line)
                *ret_edit_line = line;

        return 0;
}

int run_editor(const EditFile *edit_files) {
        int r;

        assert(edit_files);

        r = safe_fork("(editor)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_WAIT, NULL);
        if (r < 0)
                return r;
        if (r == 0) { /* child */
                _cleanup_strv_free_ char **args = NULL;
                const char *editor;
                bool prepended = false;

                /* SYSTEMD_EDITOR takes precedence over EDITOR which takes precedence over VISUAL.
                 * If none of SYSTEMD_EDITOR, EDITOR or VISUAL is present, try to execute well known
                 * editors. */
                editor = getenv("SYSTEMD_EDITOR");
                if (!editor)
                        editor = getenv("EDITOR");
                if (!editor)
                        editor = getenv("VISUAL");

                if (!isempty(editor)) {
                        _cleanup_strv_free_ char **editor_args = NULL;

                        editor_args = strv_split(editor, WHITESPACE);
                        if (!editor_args) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        r = strv_extend_strv(&args, editor_args, /* filter_duplicates = */ false);
                        if (r < 0) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }
                }

                if (edit_files_count(edit_files) == 1) {
                        _cleanup_free_ char *l = NULL;

                        /* If editing a single file only, use the +LINE syntax to put cursor on the right line */
                        if (asprintf(&l, "+%u", edit_files[0].line) < 0) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        r = strv_consume(&args, TAKE_PTR(l));
                        if (r < 0) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        r = strv_push(&args, edit_files[0].temp);
                        if (r < 0) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }
                } else
                        EDIT_FILE_FOREACH(i, edit_files) {
                                r = strv_push(&args, i->temp);
                                if (r < 0) {
                                        log_oom();
                                        _exit(EXIT_FAILURE);
                                }
                        }

                if (!isempty(editor))
                        execvp(args[0], (char* const*) args);

                FOREACH_STRING(name, "editor", "nano", "vim", "vi") {
                        _cleanup_free_ char *e = NULL;

                        e = strdup(name);
                        if (!e) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        if (!prepended)
                                r = strv_prepend(&args, e);
                        else
                                r = free_and_replace(args[0], e);
                        if (r < 0) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        execvp(name, (char* const*) args);

                        /* We do not fail if the editor doesn't exist because we want to try each one of them
                         * before failing. */
                        if (errno != ENOENT) {
                                log_error_errno(errno, "Failed to execute '%s': %m", name);
                                _exit(EXIT_FAILURE);
                        }
                }

                log_error("Cannot edit files, no editor available. Please set either $SYSTEMD_EDITOR, $EDITOR or $VISUAL.");
                _exit(EXIT_FAILURE);
        }

        return 0;
}

int trim_edit_markers(const char *path, const char *marker_start, const char *marker_end) {
        _cleanup_free_ char *old_contents = NULL, *new_contents = NULL;
        char *start, *end, *stripped;
        int r;

        /* Trim out the lines between the two markers */
        r = read_full_file(path, &old_contents, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read temporary file \"%s\": %m", path);

        start = strstr(old_contents, marker_start);
        if (start)
                start += strlen(marker_start);
        else
                start = old_contents;

        end = strstr(start, marker_end);
        if (end)
                *end = '\0';

        stripped = strstrip(start);
        if (isempty(stripped))
                return 0; /* All gone now */

        new_contents = strjoin(stripped, "\n"); /* Trim prefix and suffix, but ensure suffixed by single newline */
        if (!new_contents)
                return log_oom();

        if (streq(old_contents, new_contents)) /* Don't touch the file if the above didn't change a thing */
                return 1; /* Unchanged, but good */

        r = write_string_file(path, new_contents, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE|WRITE_STRING_FILE_AVOID_NEWLINE);
        if (r < 0)
                return log_error_errno(r, "Failed to modify temporary file \"%s\": %m", path);

        return 1; /* Changed, but good */
}

int edit_files_add(
                EditFile **ef,
                const char *path,
                const char *original_path,
                char * const *comment_paths) {

        EditFile edit_file = {};
        size_t n;

        assert(ef);
        assert(path);

        n = edit_files_count(*ef);

        if (!GREEDY_REALLOC0(*ef, n + 2))
                return log_oom();

        edit_file.path = strdup(path);
        if (!edit_file.path)
                return log_oom();

        if (original_path) {
                edit_file.original_path = strdup(original_path);
                if (!edit_file.original_path)
                        return log_oom();
        }

        if (comment_paths) {
                edit_file.comment_paths = strv_copy(comment_paths);
                if (!edit_file.comment_paths)
                        return log_oom();
        }

        (*ef)[n] = edit_file;
        return 0;
}

int edit_files_and_install(
                EditFile *ef,
                const char *marker_start,
                const char *marker_end) {

        int r;

        assert(ef);

        EDIT_FILE_FOREACH(i, ef)
                if (isempty(i->temp)) {
                        r = create_edit_temp_file(i->path,
                                                  i->original_path,
                                                  i->comment_paths,
                                                  marker_start,
                                                  marker_end,
                                                  &i->temp,
                                                  &i->line);
                        if (r < 0)
                                goto end;
                }

        r = run_editor(ef);
        if (r < 0)
                goto end;

        EDIT_FILE_FOREACH(i, ef) {
                /* Always call trim_edit_markers to tell if the temp file is empty */
                r = trim_edit_markers(i->temp, marker_start, marker_end);
                if (r < 0)
                        goto end;
                if (r == 0)
                        continue;

                r = RET_NERRNO(rename(i->temp, i->path));
                if (r < 0) {
                        log_error_errno(r, "Failed to rename \"%s\" to \"%s\": %m", i->temp, i->path);
                        goto end;
                }

                log_info("Successfully installed edited file '%s'.", i->path);
        }

        r = 0;

end:
        EDIT_FILE_FOREACH(i, ef)
                if (i->temp)
                        (void) unlink(i->temp);

        return r;
}

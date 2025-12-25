/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "edit-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util-label.h"

typedef struct EditFile {
        EditFileContext *context;
        char *path;
        char *original_path;
        char **comment_paths;
        char *temp;
        unsigned line;
} EditFile;

void edit_file_context_done(EditFileContext *context) {
        int r;

        assert(context);

        FOREACH_ARRAY(i, context->files, context->n_files) {
                unlink_and_free(i->temp);

                if (context->remove_parent) {
                        _cleanup_free_ char *parent = NULL;

                        r = path_extract_directory(i->path, &parent);
                        if (r < 0)
                                log_debug_errno(r, "Failed to extract directory from '%s', ignoring: %m", i->path);
                        else if (rmdir(parent) < 0 && !IN_SET(errno, ENOENT, ENOTEMPTY))
                                log_debug_errno(errno, "Failed to remove parent directory '%s', ignoring: %m", parent);
                }

                free(i->path);
                free(i->original_path);
                strv_free(i->comment_paths);
        }

        context->files = mfree(context->files);
        context->n_files = 0;
}

bool edit_files_contains(const EditFileContext *context, const char *path) {
        assert(context);
        assert(path);

        FOREACH_ARRAY(i, context->files, context->n_files)
                if (path_equal(i->path, path))
                        return true;

        return false;
}

int edit_files_add(
                EditFileContext *context,
                const char *path,
                const char *original_path,
                char * const *comment_paths) {

        _cleanup_free_ char *new_path = NULL, *new_original_path = NULL;
        _cleanup_strv_free_ char **new_comment_paths = NULL;

        assert(context);
        assert(path);

        if (edit_files_contains(context, path))
                return 0;

        if (!GREEDY_REALLOC(context->files, context->n_files + 1))
                return log_oom();

        new_path = strdup(path);
        if (!new_path)
                return log_oom();

        if (original_path) {
                new_original_path = strdup(original_path);
                if (!new_original_path)
                        return log_oom();
        }

        if (comment_paths) {
                new_comment_paths = strv_copy(comment_paths);
                if (!new_comment_paths)
                        return log_oom();
        }

        context->files[context->n_files] = (EditFile) {
                .context = context,
                .path = TAKE_PTR(new_path),
                .original_path = TAKE_PTR(new_original_path),
                .comment_paths = TAKE_PTR(new_comment_paths),
                .line = 1,
        };
        context->n_files++;

        return 1;
}

static int populate_edit_temp_file(EditFile *e, FILE *f, const char *filename) {
        assert(e);
        assert(e->context);
        assert(!e->context->read_from_stdin);
        assert(e->path);
        assert(f);
        assert(filename);

        bool has_original = e->original_path && access(e->original_path, F_OK) >= 0;
        bool has_target = access(e->path, F_OK) >= 0;
        const char *source;
        int r;

        if (has_original && (!has_target || e->context->overwrite_with_origin))
                /* We are asked to overwrite target with original_path or target doesn't exist. */
                source = e->original_path;
        else if (has_target)
                /* Target exists and shouldn't be overwritten. */
                source = e->path;
        else
                source = NULL;

        if (e->comment_paths) {
                _cleanup_free_ char *source_contents = NULL;

                if (source) {
                        r = read_full_file(source, &source_contents, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read source file '%s': %m", source);
                }

                fprintf(f,
                        "### Editing %s\n"
                        "%s\n"
                        "\n"
                        "%s%s"
                        "\n"
                        "%s\n",
                        e->path,
                        e->context->marker_start,
                        strempty(source_contents),
                        source_contents && endswith(source_contents, "\n") ? "" : "\n",
                        e->context->marker_end);

                e->line = 4; /* Start editing at the contents area */

                STRV_FOREACH(path, e->comment_paths) {
                        _cleanup_free_ char *comment = NULL;

                        /* Skip the file which is being edited and the source file (can be the same) */
                        if (PATH_IN_SET(*path, e->path, source))
                                continue;

                        r = read_full_file(*path, &comment, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read comment file '%s': %m", *path);

                        fprintf(f, "\n\n### %s", *path);

                        if (!isempty(comment)) {
                                _cleanup_free_ char *c = NULL;

                                c = strreplace(strstrip(comment), "\n", "\n# ");
                                if (!c)
                                        return log_oom();

                                fprintf(f, "\n# %s", c);
                        }
                }
        } else if (source) {
                r = copy_file_fd(source, fileno(f), COPY_REFLINK);
                if (r < 0) {
                        assert(r != -ENOENT);
                        return log_error_errno(r, "Failed to copy file '%s' to temporary file '%s': %m",
                                               source, filename);
                }
        }

        return 0;
}

static int create_edit_temp_file(EditFile *e, const char *contents, size_t contents_size) {
        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(e);
        assert(e->context);
        assert(e->path);
        assert(!e->comment_paths || (e->context->marker_start && e->context->marker_end));
        assert(contents || contents_size == 0);
        assert(e->context->read_from_stdin == !!contents);

        if (e->temp)
                return 0;

        r = mkdir_parents_label(e->path, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create parent directories for '%s': %m", e->path);

        r = fopen_temporary_label(e->path, e->path, &f, &temp);
        if (r < 0)
                return log_error_errno(r, "Failed to create temporary file for '%s': %m", e->path);

        if (fchmod(fileno(f), 0644) < 0)
                return log_error_errno(errno, "Failed to change mode of temporary file '%s': %m", temp);

        if (e->context->read_from_stdin) {
                if (fwrite(contents, 1, contents_size, f) != contents_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to write stdin data to temporary file '%s'.", temp);
        } else {
                r = populate_edit_temp_file(e, f, temp);
                if (r < 0)
                        return r;
        }

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write to temporary file '%s': %m", temp);

        e->temp = TAKE_PTR(temp);

        return 0;
}

static int run_editor_child(const EditFileContext *context) {
        _cleanup_strv_free_ char **args = NULL, **editor = NULL;
        int r;

        assert(context);
        assert(context->n_files >= 1);

        /* SYSTEMD_EDITOR takes precedence over EDITOR which takes precedence over VISUAL.
         * If neither SYSTEMD_EDITOR nor EDITOR nor VISUAL are present, we try to execute
         * well known editors. */
        FOREACH_STRING(e, "SYSTEMD_EDITOR", "EDITOR", "VISUAL") {
                const char *m = empty_to_null(getenv(e));
                if (m) {
                        editor = strv_split(m, WHITESPACE);
                        if (!editor)
                                return log_oom();

                        break;
                }
        }

        if (context->n_files == 1 && context->files[0].line > 1) {
                /* If editing a single file only, use the +LINE syntax to put cursor on the right line */
                r = strv_extendf(&args, "+%u", context->files[0].line);
                if (r < 0)
                        return log_oom();
        }

        FOREACH_ARRAY(i, context->files, context->n_files) {
                r = strv_extend(&args, i->temp);
                if (r < 0)
                        return log_oom();
        }

        size_t editor_n = strv_length(editor);
        if (editor_n > 0) {
                /* Strings are owned by 'editor' and 'args' */
                _cleanup_free_ char **cmdline = new(char*, editor_n + strv_length(args) + 1);
                if (!cmdline)
                        return log_oom();

                *mempcpy_typesafe(mempcpy_typesafe(cmdline, editor, editor_n), args, strv_length(args)) = NULL;

                execvp(cmdline[0], cmdline);
                log_warning_errno(errno, "Specified editor '%s' not available, trying fallbacks: %m", editor[0]);
        }

        bool prepended = false;
        FOREACH_STRING(name, "editor", "nano", "vim", "vi") {
                if (!prepended) {
                        r = strv_prepend(&args, name);
                        prepended = true;
                } else
                        r = free_and_strdup(&args[0], name);
                if (r < 0)
                        return log_oom();

                execvp(args[0], (char* const*) args);

                if (errno == ENOTDIR) {
                        log_debug_errno(errno,
                                        "Failed to execute '%s': a path component is not a directory, skipping...",
                                        name);
                        continue;
                }
                /* We do not fail if the editor doesn't exist because we want to try each one of them
                 * before failing. */
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to execute '%s': %m", name);
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                               "Cannot edit files, no editor available. Please set either $SYSTEMD_EDITOR, $EDITOR or $VISUAL.");
}

static int run_editor(const EditFileContext *context) {
        int r;

        assert(context);

        r = safe_fork("(editor)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT, NULL);
        if (r < 0)
                return r;
        if (r == 0) { /* Child */
                r = run_editor_child(context);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        return 0;
}

static int strip_edit_temp_file(EditFile *e) {
        _cleanup_free_ char *old_contents = NULL, *tmp = NULL, *new_contents = NULL;
        const char *stripped;
        bool with_marker;
        int r;

        assert(e);
        assert(e->context);
        assert(!e->context->marker_start == !e->context->marker_end);
        assert(e->temp);

        r = read_full_file(e->temp, &old_contents, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read temporary file '%s': %m", e->temp);

        tmp = strdup(old_contents);
        if (!tmp)
                return log_oom();

        with_marker = e->context->marker_start && !e->context->read_from_stdin;

        if (with_marker) {
                /* Trim out the lines between the two markers */
                char *contents_start, *contents_end;

                contents_start = strstrafter(tmp, e->context->marker_start) ?: tmp;

                contents_end = strstr(contents_start, e->context->marker_end);
                if (contents_end)
                        *contents_end = '\0';

                stripped = strstrip(contents_start);
        } else
                stripped = strstrip(tmp);

        if (isempty(stripped)) {
                /* People keep coming back to #24208 due to edits outside of markers. Let's detect this
                 * and point them in the right direction. */
                if (with_marker)
                        for (const char *p = old_contents;;) {
                                p = skip_leading_chars(p, WHITESPACE);
                                if (*p == '\0')
                                        break;
                                if (*p != '#') {
                                        log_warning("Found modifications outside of the staging area, which would be discarded.");
                                        break;
                                }

                                /* Skip the whole line if commented out */
                                p = strchr(p, '\n');
                                if (!p)
                                        break;
                                p++;
                        }

                return 0; /* File is empty (has no real changes) */
        }

        /* Trim prefix and suffix, but ensure suffixed by single newline */
        new_contents = strjoin(stripped, "\n");
        if (!new_contents)
                return log_oom();

        if (streq(old_contents, new_contents)) /* Don't touch the file if the above didn't change a thing */
                return 1; /* Contents have real changes */

        r = write_string_file(e->temp, new_contents,
                              WRITE_STRING_FILE_TRUNCATE | WRITE_STRING_FILE_AVOID_NEWLINE);
        if (r < 0)
                return log_error_errno(r, "Failed to strip temporary file '%s': %m", e->temp);

        return 1; /* Contents have real changes */
}

static int edit_file_install_one(EditFile *e) {
        int r;

        assert(e);
        assert(e->path);
        assert(e->temp);

        r = strip_edit_temp_file(e);
        if (r <= 0)
                return r;

        r = RET_NERRNO(rename(e->temp, e->path));
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to rename temporary file '%s' to target file '%s': %m",
                                       e->temp, e->path);
        e->temp = mfree(e->temp);

        return 1;
}

static int edit_file_install_one_stdin(EditFile *e, const char *contents, size_t contents_size, int *fd) {
        int r;

        assert(e);
        assert(e->path);
        assert(contents || contents_size == 0);
        assert(fd);

        if (contents_size == 0)
                return 0;

        if (*fd >= 0) {
                r = mkdir_parents_label(e->path, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create parent directories for '%s': %m", e->path);

                r = copy_file_atomic_at(*fd, NULL, AT_FDCWD, e->path, 0644, COPY_REFLINK|COPY_REPLACE|COPY_MAC_CREATE);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy stdin contents to '%s': %m", e->path);

                return 1;
        }

        r = create_edit_temp_file(e, contents, contents_size);
        if (r < 0)
                return r;

        _cleanup_close_ int tfd = open(e->temp, O_PATH|O_CLOEXEC);
        if (tfd < 0)
                return log_error_errno(errno, "Failed to pin temporary file '%s': %m", e->temp);

        r = edit_file_install_one(e);
        if (r <= 0)
                return r;

        *fd = TAKE_FD(tfd);

        return 1;
}

int do_edit_files_and_install(EditFileContext *context) {
        _cleanup_free_ char *stdin_data = NULL;
        size_t stdin_size = 0;
        int r;

        assert(context);

        if (context->n_files == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Got no files to edit.");

        if (context->read_from_stdin) {
                r = read_full_stream(stdin, &stdin_data, &stdin_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to read stdin: %m");
        } else {
                FOREACH_ARRAY(editfile, context->files, context->n_files) {
                        r = create_edit_temp_file(editfile, /* contents = */ NULL, /* contents_size = */ 0);
                        if (r < 0)
                                return r;
                }

                r = run_editor(context);
                if (r < 0)
                        return r;
        }

        _cleanup_close_ int stdin_data_fd = -EBADF;

        FOREACH_ARRAY(editfile, context->files, context->n_files) {
                if (context->read_from_stdin) {
                        r = edit_file_install_one_stdin(editfile, stdin_data, stdin_size, &stdin_data_fd);
                        if (r == 0) {
                                log_notice("Stripped stdin content is empty, not writing file.");
                                return 0;
                        }
                } else {
                        r = edit_file_install_one(editfile);
                        if (r == 0) {
                                log_notice("%s: after editing, new contents are empty, not writing file.",
                                           editfile->path);
                                continue;
                        }
                }
                if (r < 0)
                        return r;

                log_info("Successfully installed edited file '%s'.", editfile->path);
        }

        return 0;
}

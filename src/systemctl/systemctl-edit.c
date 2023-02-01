/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "edit-util.h"
#include "fs-util.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "selinux-util.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-edit.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "terminal-util.h"

#define EDIT_MARKER_START "### Anything between here and the comment below will become the contents of the drop-in file"
#define EDIT_MARKER_END "### Edits below this comment will be discarded"

int verb_cat(int argc, char *argv[], void *userdata) {
        _cleanup_(hashmap_freep) Hashmap *cached_name_map = NULL, *cached_id_map = NULL;
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_strv_free_ char **names = NULL;
        sd_bus *bus;
        bool first = true;
        int r, rc = 0;

        /* Include all units by default — i.e. continue as if the --all option was used */
        if (strv_isempty(arg_states))
                arg_all = true;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot remotely cat units.");

        r = lookup_paths_init_or_warn(&lp, arg_scope, 0, arg_root);
        if (r < 0)
                return r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        r = expand_unit_names(bus, strv_skip(argv, 1), NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand names: %m");

        r = maybe_extend_with_unit_dependencies(bus, &names);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        STRV_FOREACH(name, names) {
                _cleanup_free_ char *fragment_path = NULL;
                _cleanup_strv_free_ char **dropin_paths = NULL;

                r = unit_find_paths(bus, *name, &lp, false, &cached_name_map, &cached_id_map, &fragment_path, &dropin_paths);
                if (r == -ERFKILL) {
                        printf("%s# Unit %s is masked%s.\n",
                               ansi_highlight_magenta(),
                               *name,
                               ansi_normal());
                        continue;
                }
                if (r == -EKEYREJECTED) {
                        printf("%s# Unit %s could not be loaded.%s\n",
                               ansi_highlight_magenta(),
                               *name,
                               ansi_normal());
                        continue;
                }
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Skip units which have no on-disk counterpart, but propagate the error to the
                         * user */
                        rc = -ENOENT;
                        continue;
                }

                if (first)
                        first = false;
                else
                        puts("");

                if (need_daemon_reload(bus, *name) > 0) /* ignore errors (<0), this is informational output */
                        fprintf(stderr,
                                "%s# Warning: %s changed on disk, the version systemd has loaded is outdated.\n"
                                "%s# This output shows the current version of the unit's original fragment and drop-in files.\n"
                                "%s# If fragments or drop-ins were added or removed, they are not properly reflected in this output.\n"
                                "%s# Run 'systemctl%s daemon-reload' to reload units.%s\n",
                                ansi_highlight_red(),
                                *name,
                                ansi_highlight_red(),
                                ansi_highlight_red(),
                                ansi_highlight_red(),
                                arg_scope == LOOKUP_SCOPE_SYSTEM ? "" : " --user",
                                ansi_normal());

                r = cat_files(fragment_path, dropin_paths, 0);
                if (r < 0)
                        return r;
        }

        return rc;
}

static int get_file_to_edit(
                const LookupPaths *paths,
                const char *name,
                char **ret_path) {

        _cleanup_free_ char *path = NULL, *run = NULL;

        assert(name);
        assert(ret_path);

        path = path_join(paths->persistent_config, name);
        if (!path)
                return log_oom();

        if (arg_runtime) {
                run = path_join(paths->runtime_config, name);
                if (!run)
                        return log_oom();

                if (access(path, F_OK) >= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                               "Refusing to create \"%s\" because it would be overridden by \"%s\" anyway.",
                                               run, path);

                *ret_path = TAKE_PTR(run);
        } else
                *ret_path = TAKE_PTR(path);

        return 0;
}

static int unit_file_create_new(
                EditFile **edit_files,
                const LookupPaths *paths,
                const char *unit_name,
                const char *suffix,
                char * const *original_unit_paths) {

        _cleanup_free_ char *new_path = NULL;
        const char *ending;
        int r;

        assert(edit_files);
        assert(unit_name);

        ending = strjoina(unit_name, suffix);
        r = get_file_to_edit(paths, ending, &new_path);
        if (r < 0)
                return r;

        r = edit_files_add(edit_files, new_path, NULL, original_unit_paths);
        if (r < 0)
                return r;

        return 0;
}

static int unit_file_create_copy(
                EditFile **edit_files,
                const LookupPaths *paths,
                const char *unit_name,
                const char *fragment_path) {

        _cleanup_free_ char *new_path = NULL;
        int r;

        assert(edit_files);
        assert(fragment_path);
        assert(unit_name);

        r = get_file_to_edit(paths, unit_name, &new_path);
        if (r < 0)
                return r;

        if (!path_equal(fragment_path, new_path) && access(new_path, F_OK) >= 0) {
                char response;

                r = ask_char(&response, "yn", "\"%s\" already exists. Overwrite with \"%s\"? [(y)es, (n)o] ", new_path, fragment_path);
                if (r < 0)
                        return r;
                if (response != 'y')
                        return log_warning_errno(SYNTHETIC_ERRNO(EKEYREJECTED), "%s skipped.", unit_name);
        }

        r = edit_files_add(edit_files, new_path, fragment_path, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int find_paths_to_edit(
                sd_bus *bus,
                EditFile **edit_files,
                char **names) {

        _cleanup_(hashmap_freep) Hashmap *cached_name_map = NULL, *cached_id_map = NULL;
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_free_ char *drop_in_alloc = NULL, *suffix = NULL;
        const char *drop_in;
        int r;

        assert(edit_files);
        assert(names);

        if (isempty(arg_drop_in))
                drop_in = "override.conf";
        else if (!endswith(arg_drop_in, ".conf")) {
                drop_in_alloc = strjoin(arg_drop_in, ".conf");
                if (!drop_in_alloc)
                        return log_oom();

                drop_in = drop_in_alloc;
        } else
                drop_in = arg_drop_in;

        if (!filename_is_valid(drop_in))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid drop-in file name '%s'.", drop_in);

        suffix = strjoin(".d/", drop_in);
        if (!suffix)
                return log_oom();

        r = lookup_paths_init(&lp, arg_scope, 0, arg_root);
        if (r < 0)
                return r;

        STRV_FOREACH(name, names) {
                _cleanup_free_ char *path = NULL, *tmp_name = NULL;
                _cleanup_strv_free_ char **unit_paths = NULL;

                r = unit_find_paths(bus, *name, &lp, false, &cached_name_map, &cached_id_map, &path, &unit_paths);
                if (r == -EKEYREJECTED) {
                        /* If loading of the unit failed server side complete, then the server won't tell us
                         * the unit file path. In that case, find the file client side. */
                        log_debug_errno(r, "Unit '%s' was not loaded correctly, retrying client-side.", *name);
                        r = unit_find_paths(bus, *name, &lp, true, &cached_name_map, &cached_id_map, &path, &unit_paths);
                }
                if (r == -ERFKILL)
                        return log_error_errno(r, "Unit '%s' masked, cannot edit.", *name);
                if (r < 0)
                        return r;

                if (!path) {
                        if (!arg_force) {
                                log_info("Run 'systemctl edit%s --force --full %s' to create a new unit.",
                                         arg_scope == LOOKUP_SCOPE_GLOBAL ? " --global" :
                                         arg_scope == LOOKUP_SCOPE_USER ? " --user" : "",
                                         *name);
                                return -ENOENT;
                        }

                        /* Create a new unit from scratch */
                        r = unit_file_create_new(
                                        edit_files,
                                        &lp,
                                        *name,
                                        arg_full ? NULL : suffix,
                                        NULL);
                } else {
                        _cleanup_free_ char *unit_name = NULL;

                        r = path_extract_filename(path, &unit_name);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract unit name from path '%s': %m", path);

                        /* We follow unit aliases, but we need to propagate the instance */
                        if (unit_name_is_valid(*name, UNIT_NAME_INSTANCE) &&
                            unit_name_is_valid(unit_name, UNIT_NAME_TEMPLATE)) {
                                _cleanup_free_ char *instance = NULL;

                                r = unit_name_to_instance(*name, &instance);
                                if (r < 0)
                                        return r;

                                r = unit_name_replace_instance(unit_name, instance, &tmp_name);
                                if (r < 0)
                                        return r;

                                unit_name = tmp_name;
                        }

                        if (arg_full)
                                r = unit_file_create_copy(
                                                edit_files,
                                                &lp,
                                                unit_name,
                                                path);
                        else {
                                r = strv_prepend(&unit_paths, path);
                                if (r < 0)
                                        return log_oom();

                                r = unit_file_create_new(
                                                edit_files,
                                                &lp,
                                                unit_name,
                                                suffix,
                                                unit_paths);
                        }
                }
                if (r < 0)
                        return r;
        }

        return 0;
}

int verb_edit(int argc, char *argv[], void *userdata) {
        _cleanup_(edit_file_free_all) EditFile *edit_files = NULL;
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_strv_free_ char **names = NULL;
        sd_bus *bus;
        int r;

        if (!on_tty())
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot edit units if not on a tty.");

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot edit units remotely.");

        r = lookup_paths_init_or_warn(&lp, arg_scope, 0, arg_root);
        if (r < 0)
                return r;

        r = mac_selinux_init();
        if (r < 0)
                return r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        r = expand_unit_names(bus, strv_skip(argv, 1), NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand names: %m");
        if (strv_isempty(names))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No units matched the specified patterns.");

        STRV_FOREACH(tmp, names) {
                r = unit_is_masked(bus, &lp, *tmp);
                if (r < 0)
                        return r;
                if (r > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot edit %s: unit is masked.", *tmp);
        }

        r = find_paths_to_edit(bus, &edit_files, names);
        if (r < 0)
                return r;
        if (!edit_files)
                return -ENOENT;

        r = edit_files_and_install(edit_files, EDIT_MARKER_START, EDIT_MARKER_END);
        if (r < 0)
                goto end;

        if (!arg_no_reload && !install_client_side())
                r = daemon_reload(ACTION_RELOAD, /* graceful= */ false);
        if (r > 0)
                r = 0;

end:
        EDIT_FILE_FOREACH(i, edit_files) {
                /* Removing empty dropin dirs */
                if (!arg_full) {
                        _cleanup_free_ char *dir = NULL;

                        r = path_extract_directory(i->path, &dir);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract directory from '%s': %m", i->path);

                        /* No need to check if the dir is empty, rmdir does nothing if it is not the case. */
                        (void) rmdir(dir);
                }
        }

        return r;
}

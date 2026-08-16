/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-messages.h"

#include "all-units.h"
#include "alloc-util.h"
#include "analyze-verify-util.h"
#include "bus-error.h"
#include "dbus-unit.h"
#include "errno-util.h"
#include "log.h"
#include "load-fragment.h"
#include "manager.h"
#include "pager.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-file.h"
#include "unit-name.h"
#include "unit-serialize.h"
#include "utf8.h"

int verify_prepare_filename(const char *filename, const char *instance, char **ret) {
        _cleanup_free_ char *abspath = NULL, *name = NULL, *dir = NULL, *with_instance = NULL;
        char *c;
        int r;

        assert(filename);
        assert(ret);

        r = path_make_absolute_cwd(filename, &abspath);
        if (r < 0)
                return r;

        r = path_extract_filename(abspath, &name);
        if (r < 0)
                return r;

        if (!unit_name_is_valid(name, UNIT_NAME_ANY))
                return -EINVAL;

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                r = unit_name_replace_instance(name, instance, &with_instance);
                if (r < 0)
                        return r;
        }

        r = path_extract_directory(abspath, &dir);
        if (r < 0)
                return r;

        c = path_join(dir, with_instance ?: name);
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

static int find_unit_directory(const char *p, char **ret) {
        _cleanup_free_ char *a = NULL, *u = NULL, *t = NULL, *d = NULL;
        int r;

        assert(p);
        assert(ret);

        r = path_make_absolute_cwd(p, &a);
        if (r < 0)
                return r;

        if (access(a, F_OK) >= 0) {
                r = path_extract_directory(a, &d);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(d);
                return 0;
        }

        r = path_extract_filename(a, &u);
        if (r < 0)
                return r;

        if (!unit_name_is_valid(u, UNIT_NAME_INSTANCE))
                return -ENOENT;

        /* If the specified unit is an instance of a template unit, then let's try to find the template unit. */
        r = unit_name_template(u, &t);
        if (r < 0)
                return r;

        r = path_extract_directory(a, &d);
        if (r < 0)
                return r;

        free(a);
        a = path_join(d, t);
        if (!a)
                return -ENOMEM;

        if (access(a, F_OK) < 0)
                return -errno;

        *ret = TAKE_PTR(d);
        return 0;
}

int verify_build_unit_path(char * const *filenames, char **ret) {
        _cleanup_strv_free_ char **ans = NULL;
        _cleanup_free_ char *joined = NULL;
        const char *old;
        int r;

        assert(ret);

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *t = NULL;

                r = find_unit_directory(*filename, &t);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;

                r = strv_consume(&ans, TAKE_PTR(t));
                if (r < 0)
                        return r;
        }

        if (strv_isempty(ans)) {
                *ret = NULL;
                return 0;
        }

        joined = strv_join(strv_uniq(ans), ":");
        if (!joined)
                return -ENOMEM;

        /* First, prepend our directories. Second, if some path was specified, use that, and
         * otherwise use the defaults. Any duplicates will be filtered out in path-lookup.c.
         * Treat explicit empty path to mean that nothing should be appended. */
        old = getenv("SYSTEMD_UNIT_PATH");
        if (!path_is_valid_search_path(old))
                return -EINVAL;

        if (!streq_ptr(old, "") &&
            !strextend_with_separator(&joined, ":", streq_ptr(old, ":") ? "" : strempty(old)))
                return -ENOMEM;

        *ret = TAKE_PTR(joined);
        return 0;
}

static bool verify_error_is_fatal(int r) {
        return ERRNO_IS_NEG_RESOURCE(r) || r == -E2BIG;
}

static int verify_replace_lookup_path(char **search_path, const char *old_path, const char *new_path) {
        assert(old_path);

        if (!new_path || (!path_equal(old_path, new_path) && path_strv_contains(search_path, new_path))) {
                strv_remove(search_path, old_path);
                return 0;
        }

        if (path_equal(old_path, new_path))
                return 0;

        STRV_FOREACH(path, search_path)
                if (path_equal(*path, old_path))
                        return free_and_strdup(path, new_path);

        return 0;
}

static int verify_unit_name_set_put(Set **names, const char *name, size_t max_names) {
        int r;

        assert(names);
        assert(name);

        if (set_contains(*names, name))
                return 0;
        if (max_names > 0 && set_size(*names) >= max_names)
                return -E2BIG;

        r = set_put_strdup(names, name);
        if (r < 0)
                return r;

        return 1;
}

static bool verify_unit_name_may_be_fragmentless(Manager *manager, const char *name) {
        assert(manager);
        assert(name);

        return unit_name_is_valid(name, UNIT_NAME_PLAIN) &&
               (IN_SET(unit_name_to_type(name), UNIT_DEVICE, UNIT_SLICE) ||
                (MANAGER_IS_SYSTEM(manager) && unit_has_builtin_fragment(name)));
}

static int verify_unit_name_from_path_cache(Manager *manager, const char *path, char **ret) {
        _cleanup_free_ char *filename = NULL, *name = NULL;
        int r;

        assert(manager);
        assert(path);
        assert(ret);

        r = path_extract_filename(path, &filename);
        if (r < 0)
                return r;

        r = unit_file_parse_directory_name(filename, &name);
        if (r <= 0)
                return r;

        /* Plain and template drop-in directories can also be prefix-wide configuration. Concrete
         * instances always identify finite configurations. Slice and device units are also finite and
         * loadable without fragments, and system managers have built-in fallback fragments. Thus their
         * drop-in/dependency directories are effective on their own. */
        if (!unit_name_is_valid(name, UNIT_NAME_INSTANCE) &&
            !verify_unit_name_may_be_fragmentless(manager, name))
                return 0;

        *ret = TAKE_PTR(name);
        return 1;
}

static int verify_unit_name_has_fragment(Manager *manager, const char *name) {
        const char *fragment = NULL;
        int r;

        assert(manager);
        assert(name);

        if (manager_get_unit(manager, name))
                return true;

        r = unit_file_find_fragment(
                        manager->unit_id_map,
                        manager->unit_name_map,
                        name,
                        &fragment,
                        /* ret_names= */ NULL);
        if (verify_error_is_fatal(r))
                return r;
        if (r < 0 || !fragment)
                return false;

        r = null_or_empty_path(fragment);
        if (verify_error_is_fatal(r))
                return r;

        return r == 0;
}

static int verify_template_instance_try(
                Manager *manager,
                Set *names,
                const char *template,
                const char *instance,
                char **ret) {

        _cleanup_free_ char *instantiated = NULL;
        int r;

        assert(manager);
        assert(unit_name_is_valid(template, UNIT_NAME_TEMPLATE));
        assert(instance);
        assert(ret);

        r = unit_name_replace_instance(template, instance, &instantiated);
        if (r == -EINVAL)
                return false;
        if (r < 0)
                return r;

        if (set_contains(names, instantiated) || manager_get_unit(manager, instantiated))
                return false;

        *ret = TAKE_PTR(instantiated);
        return true;
}

static int verify_template_instance_candidate(size_t n, char **ret) {
        static const char single_char_instances[] = ALPHANUMERICAL ":-_.\\@";
        _cleanup_free_ char *instance = NULL;
        size_t encoded;

        assert(ret);

        /* Bijective base-K numbers enumerate all non-empty strings in shortlex order: every
         * single-character instance first, then every two-character instance, and so on. */
        if (!ADD_SAFE(&encoded, n, 1))
                return -E2BIG;

        size_t length = 0;
        for (size_t k = encoded; k > 0; k = (k - 1) / (ELEMENTSOF(single_char_instances) - 1))
                length++;

        instance = new(char, length + 1);
        if (!instance)
                return -ENOMEM;

        size_t k = encoded;
        for (size_t i = length; i > 0; i--) {
                k--;
                instance[i - 1] = single_char_instances[k % (ELEMENTSOF(single_char_instances) - 1)];
                k /= ELEMENTSOF(single_char_instances) - 1;
        }
        instance[length] = 0;

        *ret = TAKE_PTR(instance);
        return 0;
}

static int verify_pick_template_load_name(
                Manager *manager,
                Set *names,
                const char *template,
                const char *preferred_instance,
                char **ret) {

        size_t max_instance_length, n_attempts;
        int r;

        assert(manager);
        assert(unit_name_is_valid(template, UNIT_NAME_TEMPLATE));
        assert(ret);

        max_instance_length = UNIT_NAME_MAX - 1 - strlen(template);

        if (preferred_instance) {
                if (!unit_instance_is_valid(preferred_instance))
                        return -EINVAL;

                if (strlen(preferred_instance) <= max_instance_length) {
                        r = verify_template_instance_try(
                                        manager, names, template, preferred_instance, ret);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return 0;
                }
        }

        if (!ADD_SAFE(&n_attempts, set_size(names), hashmap_size(manager->units)) ||
            !ADD_SAFE(&n_attempts, n_attempts, 1))
                return -E2BIG;

        for (size_t n = 0, tried = 0; tried < n_attempts; n++) {
                _cleanup_free_ char *instance = NULL;

                r = verify_template_instance_candidate(n, &instance);
                if (r < 0)
                        return r;
                if (strlen(instance) > max_instance_length)
                        break;

                if (streq_ptr(instance, preferred_instance))
                        continue;

                tried++;
                r = verify_template_instance_try(manager, names, template, instance, ret);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                if (n == SIZE_MAX)
                        return -E2BIG;
        }

        /* Every usable instance is already occupied. Keep the template name so the ordinary load path
         * reports a per-unit problem without preventing unrelated templates from being checked. */
        *ret = strdup(template);
        return *ret ? 0 : -ENOMEM;
}

int verify_discover_unit_names(
                Manager *manager,
                const char *preferred_instance,
                size_t max_names,
                char ***ret) {

        _cleanup_set_free_ Set *names = NULL, *selected = NULL;
        _cleanup_strv_free_ char **unit_names = NULL;
        int r;

        assert(manager);
        assert(ret);

        r = unit_file_build_name_map_full(
                        &manager->lookup_paths,
                        &manager->unit_cache_timestamp_hash,
                        &manager->unit_id_map,
                        &manager->unit_name_map,
                        &manager->unit_path_cache,
                        max_names);
        if (r < 0)
                return r;

        const char *name, *path;
        HASHMAP_FOREACH_KEY(path, name, manager->unit_id_map) {
                r = verify_unit_name_set_put(&names, name, max_names);
                if (r < 0)
                        return r;
        }

        SET_FOREACH(path, manager->unit_path_cache) {
                _cleanup_free_ char *candidate = NULL;

                r = verify_unit_name_from_path_cache(manager, path, &candidate);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (!verify_unit_name_may_be_fragmentless(manager, candidate)) {
                        r = verify_unit_name_has_fragment(manager, candidate);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;
                }

                r = verify_unit_name_set_put(&names, candidate, max_names);
                if (r < 0)
                        return r;
        }

        SET_FOREACH(name, names) {
                _cleanup_free_ char *load_name = NULL;
                const char *fragment = NULL;

                r = unit_file_find_fragment(
                                manager->unit_id_map,
                                manager->unit_name_map,
                                name,
                                &fragment,
                                /* ret_names= */ NULL);
                if (verify_error_is_fatal(r))
                        return r;

                if (r >= 0 && fragment) {
                        r = null_or_empty_path(fragment);
                        if (verify_error_is_fatal(r))
                                return r;
                        if (r > 0)
                                continue;
                }

                if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE)) {
                        r = verify_pick_template_load_name(
                                        manager, names, name, preferred_instance, &load_name);
                        if (r < 0)
                                return r;
                } else {
                        load_name = strdup(name);
                        if (!load_name)
                                return -ENOMEM;
                }

                r = verify_unit_name_set_put(&selected, load_name, max_names);
                if (r < 0)
                        return r;
        }

        if (!set_isempty(selected)) {
                unit_names = set_to_strv(&selected);
                if (!unit_names)
                        return -ENOMEM;

                strv_sort(unit_names);
        }

        *ret = TAKE_PTR(unit_names);
        return 0;
}

void verify_diagnostic_done(VerifyDiagnostic *diagnostic) {
        if (!diagnostic)
                return;

        free(diagnostic->message);
        free(diagnostic->unit);
        free(diagnostic->configuration_file);
        free(diagnostic->message_id);

        *diagnostic = (VerifyDiagnostic) {};
}

void verify_diagnostics_done(VerifyDiagnostics *diagnostics) {
        if (!diagnostics)
                return;

        FOREACH_ARRAY(diagnostic, diagnostics->items, diagnostics->n_items)
                verify_diagnostic_done(diagnostic);

        free(diagnostics->items);
        *diagnostics = (VerifyDiagnostics) {};
}

void verify_units_result_done(VerifyUnitsResult *result) {
        if (!result)
                return;

        verify_diagnostics_done(&result->diagnostics);
        *result = (VerifyUnitsResult) {};
}

static bool verify_diagnostic_message_id_is_collected(const char *message_id) {
        return STR_IN_SET(message_id,
                          SD_MESSAGE_INVALID_CONFIGURATION_STR,
                          SD_MESSAGE_UNSAFE_USER_NAME_STR,
                          SD_MESSAGE_NOBODY_USER_UNSUITABLE_STR,
                          SD_MESSAGE_UNIT_ORDERING_CYCLE_STR,
                          SD_MESSAGE_DELETING_JOB_BECAUSE_ORDERING_CYCLE_STR,
                          SD_MESSAGE_CANT_BREAK_ORDERING_CYCLE_STR);
}

static bool verify_diagnostic_message_id_is_cycle(const char *message_id) {
        return STR_IN_SET(message_id,
                          SD_MESSAGE_UNIT_ORDERING_CYCLE_STR,
                          SD_MESSAGE_DELETING_JOB_BECAUSE_ORDERING_CYCLE_STR,
                          SD_MESSAGE_CANT_BREAK_ORDERING_CYCLE_STR);
}

static int verify_diagnostic_dup_field(const char *value, size_t size, char **ret) {
        char *copy;

        assert(value || size == 0);
        assert(ret);

        if (size == 0)
                value = "";

        if (memchr(value, 0, size))
                return 0;
        if (!utf8_is_valid_n(value, size))
                return 0;

        copy = memdup_suffix0(value, size);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 1;
}

static int verify_diagnostic_set_singleton(
                char **field,
                const char *value,
                size_t size,
                bool *conflict) {

        _cleanup_free_ char *copy = NULL;
        int r;

        assert(field);
        assert(conflict);

        r = verify_diagnostic_dup_field(value, size, &copy);
        if (r <= 0)
                return r;

        if (*conflict)
                return 0;
        if (!*field) {
                *field = TAKE_PTR(copy);
                return 1;
        }
        if (streq(*field, copy))
                return 0;

        *field = mfree(*field);
        *conflict = true;
        return 0;
}

static int verify_diagnostic_set_message_id(
                char **field,
                const char *value,
                size_t size,
                bool *conflict) {

        _cleanup_free_ char *copy = NULL, *canonical = NULL;
        sd_id128_t id;
        int r;

        assert(field);
        assert(conflict);

        r = verify_diagnostic_dup_field(value, size, &copy);
        if (r <= 0)
                return r;

        r = sd_id128_from_string(copy, &id);
        if (r < 0)
                return 0;

        canonical = strdup(SD_ID128_TO_STRING(id));
        if (!canonical)
                return -ENOMEM;

        if (*conflict)
                return 0;
        if (!*field) {
                *field = TAKE_PTR(canonical);
                return 1;
        }
        if (streq(*field, canonical))
                return 0;

        *field = mfree(*field);
        *conflict = true;
        return 0;
}

static int verify_diagnostic_size(const VerifyDiagnostic *diagnostic, size_t *ret) {
        size_t size = sizeof(*diagnostic);

        assert(diagnostic);
        assert(ret);

        const char *fields[] = {
                diagnostic->message,
                diagnostic->unit,
                diagnostic->configuration_file,
                diagnostic->message_id,
        };

        FOREACH_ELEMENT(field, fields) {
                size_t n;

                if (!*field)
                        continue;

                if (!ADD_SAFE(&n, strlen(*field), 1) || !ADD_SAFE(&size, size, n))
                        return -E2BIG;
        }

        *ret = size;
        return 0;
}

static int verify_diagnostics_append(VerifyDiagnostics *diagnostics, VerifyDiagnostic *diagnostic) {
        size_t diagnostic_size, n_bytes, n_items;
        int r;

        assert(diagnostics);
        assert(diagnostic);
        assert(diagnostic->message);

        r = verify_diagnostic_size(diagnostic, &diagnostic_size);
        if (r < 0)
                return r;

        if (!ADD_SAFE(&n_items, diagnostics->n_items, 1) ||
            !ADD_SAFE(&n_bytes, diagnostics->n_bytes, diagnostic_size))
                return -E2BIG;

        if ((diagnostics->items_max > 0 && n_items > diagnostics->items_max) ||
            (diagnostics->bytes_max > 0 && n_bytes > diagnostics->bytes_max))
                return -E2BIG;

        if (!GREEDY_REALLOC(diagnostics->items, n_items))
                return -ENOMEM;

        diagnostics->items[diagnostics->n_items] = TAKE_STRUCT(*diagnostic);
        diagnostics->n_items = n_items;
        diagnostics->n_bytes = n_bytes;
        return 1;
}

static int verify_diagnostics_add(
                VerifyDiagnostics *diagnostics,
                int priority,
                const char *message,
                const char *unit,
                const char *configuration_file,
                unsigned configuration_line,
                const char *message_id) {

        _cleanup_(verify_diagnostic_done) VerifyDiagnostic diagnostic = {
                .priority = priority,
                .configuration_line = configuration_line,
        };

        assert(message);

        diagnostic.message = strdup(message);
        if (!diagnostic.message)
                return -ENOMEM;

        if (unit) {
                diagnostic.unit = strdup(unit);
                if (!diagnostic.unit)
                        return -ENOMEM;
        }

        if (configuration_file) {
                diagnostic.configuration_file = strdup(configuration_file);
                if (!diagnostic.configuration_file)
                        return -ENOMEM;
        }

        if (message_id) {
                diagnostic.message_id = strdup(message_id);
                if (!diagnostic.message_id)
                        return -ENOMEM;
        }

        return verify_diagnostics_append(diagnostics, &diagnostic);
}

static int verify_diagnostics_add_plain_log_record(VerifyDiagnostics *diagnostics, const LogRecord *record) {
        _cleanup_(verify_diagnostic_done) VerifyDiagnostic diagnostic = {
                .priority = record->priority,
        };
        int r;

        if (!record->object_field ||
            !STR_IN_SET(record->object_field, "UNIT=", "USER_UNIT=") ||
            !record->object)
                return 0;

        r = verify_diagnostic_dup_field(record->message, record->message_size, &diagnostic.message);
        if (r <= 0)
                return r;

        diagnostic.unit = strdup(record->object);
        if (!diagnostic.unit)
                return -ENOMEM;

        return verify_diagnostics_append(diagnostics, &diagnostic);
}

static bool verify_diagnostic_field_name_is(const char *field, size_t size, const char *name) {
        return strlen(name) == size && memcmp(field, name, size) == 0;
}

typedef struct VerifyDiagnosticFieldState {
        VerifyDiagnostic *diagnostic;
        bool unit_conflict;
        bool message_conflict;
        bool configuration_file_conflict;
        bool configuration_line_conflict;
        bool message_id_conflict;
        bool have_configuration_line;
} VerifyDiagnosticFieldState;

static int verify_diagnostic_set_unit(
                VerifyDiagnosticFieldState *state,
                const char *value,
                size_t size) {

        _cleanup_free_ char *unit = NULL;
        int r;

        assert(state);
        assert(state->diagnostic);

        r = verify_diagnostic_dup_field(value, size, &unit);
        if (r <= 0)
                return r;
        if (!unit_name_is_valid(unit, UNIT_NAME_ANY))
                return 0;

        if (state->unit_conflict)
                return 0;

        if (!state->diagnostic->unit) {
                state->diagnostic->unit = TAKE_PTR(unit);
                return 1;
        }

        if (streq(state->diagnostic->unit, unit))
                return 0;

        state->diagnostic->unit = mfree(state->diagnostic->unit);
        state->unit_conflict = true;
        return 0;
}

static int verify_diagnostic_add_structured_field(
                VerifyDiagnosticFieldState *state,
                const char *field,
                size_t size,
                bool message_id_only) {

        const char *eq;
        size_t name_size, value_size;
        int r;

        assert(state);
        assert(state->diagnostic);
        assert(field || size == 0);

        if (size == 0)
                return 0;

        eq = memchr(field, '=', size);
        if (!eq)
                return 0;
        if (eq == field)
                return 0;

        name_size = eq - field;
        value_size = size - name_size - 1;

        if (verify_diagnostic_field_name_is(field, name_size, "MESSAGE_ID")) {
                if (!message_id_only)
                        return 0;

                r = verify_diagnostic_set_message_id(
                                &state->diagnostic->message_id,
                                eq + 1,
                                value_size,
                                &state->message_id_conflict);
                return r < 0 ? r : 0;
        }

        if (message_id_only)
                return 0;

        if (verify_diagnostic_field_name_is(field, name_size, "MESSAGE")) {
                r = verify_diagnostic_set_singleton(
                                &state->diagnostic->message,
                                eq + 1,
                                value_size,
                                &state->message_conflict);
                return r < 0 ? r : 0;
        }

        if (verify_diagnostic_field_name_is(field, name_size, "UNIT") ||
            verify_diagnostic_field_name_is(field, name_size, "USER_UNIT"))
                return verify_diagnostic_set_unit(state, eq + 1, value_size);

        if (verify_diagnostic_field_name_is(field, name_size, "CONFIG_FILE")) {
                r = verify_diagnostic_set_singleton(
                                &state->diagnostic->configuration_file,
                                eq + 1,
                                value_size,
                                &state->configuration_file_conflict);
                return r < 0 ? r : 0;
        }

        if (verify_diagnostic_field_name_is(field, name_size, "CONFIG_LINE")) {
                _cleanup_free_ char *line = NULL;
                unsigned n;

                r = verify_diagnostic_dup_field(eq + 1, value_size, &line);
                if (r <= 0)
                        return r;

                r = safe_atou(line, &n);
                if (r < 0)
                        return 0;

                if (state->configuration_line_conflict)
                        return 0;
                if (!state->have_configuration_line) {
                        state->diagnostic->configuration_line = n;
                        state->have_configuration_line = true;
                        return 0;
                }
                if (state->diagnostic->configuration_line == n)
                        return 0;

                state->diagnostic->configuration_line = 0;
                state->configuration_line_conflict = true;
                return 0;
        }

        return 0;
}

static bool verify_diagnostic_field_is_unit(const char *field, size_t size) {
        const char *eq;
        size_t name_size;

        assert(field || size == 0);

        if (size == 0)
                return false;

        eq = memchr(field, '=', size);
        if (!eq || eq == field)
                return false;

        name_size = eq - field;
        return verify_diagnostic_field_name_is(field, name_size, "UNIT") ||
                verify_diagnostic_field_name_is(field, name_size, "USER_UNIT");
}

static int verify_diagnostic_add_cycle_unit_iovec(
                VerifyDiagnosticFieldState *state,
                const struct iovec *iovec) {

        const char *p;
        size_t left;
        int r;

        assert(state);
        assert(iovec);

        p = iovec->iov_base;
        left = iovec->iov_len;

        if (left == 0)
                return 0;

        if (!memchr(p, '\n', left))
                return verify_diagnostic_add_structured_field(state, p, left, /* message_id_only= */ false);

        for (const char *q = p; q < p + left; ) {
                const char *newline = memchr(q, '\n', p + left - q);
                size_t size = newline ? (size_t) (newline - q) : (size_t) (p + left - q);

                if (size == 0 || !verify_diagnostic_field_is_unit(q, size))
                        return verify_diagnostic_add_structured_field(
                                        state, p, left, /* message_id_only= */ false);

                if (!newline)
                        break;

                q = newline + 1;
        }

        while (left > 0) {
                const char *newline = memchr(p, '\n', left);
                size_t size = newline ? (size_t) (newline - p) : left;

                r = verify_diagnostic_add_structured_field(state, p, size, /* message_id_only= */ false);
                if (r < 0)
                        return r;

                if (!newline)
                        return 0;

                left -= size + 1;
                p = newline + 1;
        }

        return 0;
}

static int verify_diagnostics_add_structured_log_record(
                VerifyDiagnostics *diagnostics,
                const LogRecord *record) {
        _cleanup_(verify_diagnostic_done) VerifyDiagnostic diagnostic = {
                .priority = record->priority,
        };
        VerifyDiagnosticFieldState state = {
                .diagnostic = &diagnostic,
        };
        int r;

        FOREACH_ARRAY(iovec, record->fields, record->n_fields) {
                r = verify_diagnostic_add_structured_field(
                                &state, iovec->iov_base, iovec->iov_len, /* message_id_only= */ true);
                if (r < 0)
                        return r;
        }

        if (!diagnostic.message_id || state.message_id_conflict)
                return 0;
        if (!verify_diagnostic_message_id_is_collected(diagnostic.message_id))
                return 0;

        FOREACH_ARRAY(iovec, record->fields, record->n_fields) {
                if (verify_diagnostic_message_id_is_cycle(diagnostic.message_id) &&
                    verify_diagnostic_field_is_unit(iovec->iov_base, iovec->iov_len))
                        r = verify_diagnostic_add_cycle_unit_iovec(&state, iovec);
                else
                        r = verify_diagnostic_add_structured_field(
                                        &state,
                                        iovec->iov_base,
                                        iovec->iov_len,
                                        /* message_id_only= */ false);
                if (r < 0)
                        return r;
        }

        if (!diagnostic.message || state.message_conflict)
                return 0;

        return verify_diagnostics_append(diagnostics, &diagnostic);
}

int verify_diagnostics_add_log_record(VerifyDiagnostics *diagnostics, const LogRecord *record) {
        assert(diagnostics);
        assert(record);

        if (record->priority > LOG_INFO)
                return 0;

        switch (record->type) {

        case LOG_RECORD_PLAIN:
                return verify_diagnostics_add_plain_log_record(diagnostics, record);

        case LOG_RECORD_STRUCTURED:
                return verify_diagnostics_add_structured_log_record(diagnostics, record);

        default:
                assert_not_reached();
        }
}

static bool verify_diagnostic_is_syntax_warning(const VerifyDiagnostic *diagnostic) {
        assert(diagnostic);

        return diagnostic->priority <= LOG_WARNING &&
                diagnostic->unit &&
                streq_ptr(diagnostic->message_id, SD_MESSAGE_INVALID_CONFIGURATION_STR);
}

static int verify_diagnostics_syntax_status(
                const VerifyDiagnostics *diagnostics,
                char * const *filenames,
                RecursiveErrors recursive_errors) {

        assert(diagnostics);

        if (recursive_errors == RECURSIVE_ERRORS_YES || recursive_errors == RECURSIVE_ERRORS_NO) {
                FOREACH_ARRAY(diagnostic, diagnostics->items, diagnostics->n_items)
                        if (verify_diagnostic_is_syntax_warning(diagnostic))
                                return -ENOTRECOVERABLE;

                return 0;
        }

        if (recursive_errors != RECURSIVE_ERRORS_ONE)
                return 0;

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *unit_file = NULL;
                int r;

                r = path_extract_filename(*filename, &unit_file);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", *filename);

                FOREACH_ARRAY(diagnostic, diagnostics->items, diagnostics->n_items)
                        if (verify_diagnostic_is_syntax_warning(diagnostic) &&
                            streq(diagnostic->unit, unit_file))
                                return -ENOTRECOVERABLE;
        }

        return 0;
}

static int verify_log_observer_callback(const LogRecord *record, void *userdata) {
        return verify_diagnostics_add_log_record(ASSERT_PTR(userdata), record);
}

static int verify_socket(Unit *u) {
        Unit *service;
        int r;

        assert(u);

        if (u->type != UNIT_SOCKET)
                return 0;

        r = socket_load_service_unit(SOCKET(u), -1, &service);
        if (r < 0)
                return log_unit_error_errno(u, r, "service unit for the socket cannot be loaded: %m");

        if (service->load_state != UNIT_LOADED)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOENT),
                                            "service %s not loaded, socket cannot be started.", service->id);

        log_unit_debug(u, "using service unit %s.", service->id);
        return 0;
}

int verify_executable(Unit *u, const ExecCommand *exec, const char *root) {
        int r;

        if (!exec)
                return 0;

        if (exec->flags & EXEC_COMMAND_IGNORE_FAILURE)
                return 0;

        r = find_executable_full(exec->path, root, NULL, false, NULL, NULL);
        if (r < 0)
                return log_unit_error_errno(u, r, "Command %s is not executable: %m", exec->path);

        return 0;
}

static int verify_executables(Unit *u, const char *root) {
        int r = 0, k;

        assert(u);

        if (u->type == UNIT_SERVICE)
                FOREACH_ELEMENT(i, SERVICE(u)->exec_command)
                        LIST_FOREACH(command, j, *i) {
                                k = verify_executable(u, j, root);
                                if (verify_error_is_fatal(k))
                                        return k;

                                RET_GATHER(r, k);
                        }

        if (u->type == UNIT_SOCKET)
                FOREACH_ELEMENT(i, SOCKET(u)->exec_command)
                        LIST_FOREACH(command, j, *i) {
                                k = verify_executable(u, j, root);
                                if (verify_error_is_fatal(k))
                                        return k;

                                RET_GATHER(r, k);
                        }

        return r;
}

static int verify_documentation(Unit *u, bool check_man) {
        int r = 0, k;

        STRV_FOREACH(p, u->documentation) {
                log_unit_debug(u, "Found documentation item: %s", *p);

                if (check_man && startswith(*p, "man:")) {
                        k = show_man_page(*p + 4, true);
                        if (k != 0) {
                                if (verify_error_is_fatal(k))
                                        return k;

                                if (k < 0)
                                        log_unit_error_errno(u, k, "Can't show %s: %m", *p + 4);
                                else {
                                        log_unit_error(u, "Command 'man %s' failed with code %d", *p + 4, k);
                                        k = -ENOEXEC;
                                }
                                if (r == 0)
                                        r = k;
                        }
                }
        }

        /* Check remote URLs? */

        return r;
}

static int verify_unit(Unit *u, bool check_man, const char *root, bool suppress_output) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, k;

        assert(u);

        if (!suppress_output && DEBUG_LOGGING)
                unit_dump(u, stdout, "\t");

        log_unit_debug(u, "Creating %s/start job", u->id);
        r = manager_add_job(u->manager, JOB_START, u, JOB_REPLACE, &error, /* ret= */ NULL);
        if (r < 0) {
                log_unit_error_errno(
                                u, r, "Failed to create %s/start: %s", u->id, bus_error_message(&error, r));
                if (verify_error_is_fatal(r))
                        return r;
        }

        k = verify_socket(u);
        if (verify_error_is_fatal(k))
                return k;
        RET_GATHER(r, k);

        k = verify_executables(u, root);
        if (verify_error_is_fatal(k))
                return k;
        RET_GATHER(r, k);

        k = verify_documentation(u, check_man);
        if (verify_error_is_fatal(k))
                return k;
        RET_GATHER(r, k);

        return r;
}

static int verify_find_unit_source_path(Manager *manager, const char *name, char **ret) {
        _cleanup_free_ char *template = NULL;
        int r;

        assert(manager);
        assert(name);
        assert(ret);

        if (unit_name_is_valid(name, UNIT_NAME_INSTANCE)) {
                r = unit_name_template(name, &template);
                if (r < 0)
                        return r;
        }

        for (unsigned candidate = 0; candidate < 2; candidate++) {
                const char *unit_name = candidate == 0 ? name : template;

                if (!unit_name)
                        continue;

                STRV_FOREACH(dir, manager->lookup_paths.search_path) {
                        _cleanup_free_ char *path = NULL;

                        path = path_join(*dir, unit_name);
                        if (!path)
                                return -ENOMEM;
                        if (!set_contains(manager->unit_path_cache, path))
                                continue;

                        *ret = TAKE_PTR(path);
                        return 1;
                }
        }

        *ret = NULL;
        return 0;
}

static int verify_load_startable_unit(
                Manager *m,
                const char *name,
                const char *path,
                const char *diagnostic_path,
                VerifyDiagnostics *diagnostics,
                Set **seen_units,
                Unit **ret,
                int *ret_status) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *unit_name = NULL;
        Unit *unit;
        int r, k;

        assert(m);
        assert(name || path);
        assert(diagnostics);
        assert(ret);
        assert(ret_status);

        if (name) {
                unit_name = strdup(name);
                if (!unit_name)
                        return -ENOMEM;
        } else {
                r = path_extract_filename(path, &unit_name);
                if (r < 0)
                        return r;
        }

        r = manager_load_unit(m, name, path, &error, &unit);
        if (r < 0) {
                if (verify_error_is_fatal(r))
                        return r;

                const char *message = bus_error_message(&error, r);

                if (path)
                        log_error_errno(r, "Failed to load unit file %s: %s", path, message);
                else
                        log_error_errno(r, "Failed to load unit %s: %s", name, message);

                k = verify_diagnostics_add(
                                diagnostics,
                                LOG_ERR,
                                message,
                                unit_name,
                                diagnostic_path ?: path,
                                0,
                                /* message_id= */ NULL);
                if (k < 0)
                        return k;

                *ret_status = r;
                return 0;
        }

        if (seen_units) {
                k = set_ensure_put(seen_units, &trivial_hash_ops, unit);
                if (k < 0)
                        return k;
                if (k == 0) {
                        *ret = NULL;
                        *ret_status = 0;
                        return 0;
                }
        }

        r = bus_unit_validate_load_state(unit, &error);
        if (r < 0) {
                if (verify_error_is_fatal(r))
                        return r;

                const char *message = bus_error_message(&error, r);

                log_error_errno(r, "%s", message);

                k = verify_diagnostics_add(
                                diagnostics,
                                LOG_ERR,
                                message,
                                unit->id,
                                unit->fragment_path ?: diagnostic_path ?: path,
                                0,
                                /* message_id= */ NULL);
                if (k < 0)
                        return k;

                *ret_status = r;
                return 0;
        }

        *ret = unit;
        *ret_status = 0;
        return 0;
}

static int verify_prepare_filename_and_report(
                const char *filename,
                const char *instance,
                VerifyDiagnostics *diagnostics,
                char **ret,
                int *ret_status) {

        _cleanup_free_ char *message = NULL;
        int r, k;

        assert(filename);
        assert(instance);
        assert(diagnostics);
        assert(ret);
        assert(ret_status);

        r = verify_prepare_filename(filename, instance, ret);
        if (r >= 0) {
                *ret_status = 0;
                return 0;
        }

        log_error_errno(r, "Failed to prepare filename %s: %m", filename);
        if (verify_error_is_fatal(r))
                return r;

        message = strjoin("Failed to prepare filename ", filename, ": ", STRERROR(r));
        if (!message)
                return -ENOMEM;

        k = verify_diagnostics_add(
                        diagnostics,
                        LOG_ERR,
                        message,
                        /* unit= */ NULL,
                        filename,
                        0,
                        /* message_id= */ NULL);
        if (k < 0)
                return k;

        *ret_status = r;
        return 0;
}

int verify_check_input_filenames(
                char * const *filenames,
                const VerifyUnitsLimits *limits,
                size_t *ret_n_filenames) {

        size_t n_bytes = 0, n_filenames = 0;

        assert(limits);
        assert(ret_n_filenames);

        STRV_FOREACH(filename, filenames) {
                size_t n;

                if (!ADD_SAFE(&n_filenames, n_filenames, 1) ||
                    !ADD_SAFE(&n, strlen(*filename), 1) ||
                    !ADD_SAFE(&n_bytes, n_bytes, n))
                        return -E2BIG;

                if ((limits->input_filenames_max > 0 &&
                     n_filenames > limits->input_filenames_max) ||
                    (limits->input_filename_bytes_max > 0 &&
                     n_bytes > limits->input_filename_bytes_max))
                        return -E2BIG;
        }

        *ret_n_filenames = n_filenames;
        return 0;
}

int verify_units(const VerifyUnitsParameters *parameters, VerifyUnitsResult *ret) {
        _cleanup_(lookup_paths_done) LookupPaths live_lookup_paths = {};
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(log_observer_freep) LogObserver *observer = NULL;
        _cleanup_set_free_ Set *loaded_units = NULL;
        _cleanup_strv_free_ char **discovered_names = NULL;
        _cleanup_free_ char *unit_path = NULL;
        _cleanup_free_ Unit **units = NULL;
        char * const *filenames;
        size_t n_filenames, count = 0;
        int r, k, status = 0;

        assert(parameters);
        assert(parameters->instance);
        assert(ret);

        filenames = parameters->filenames;
        result.diagnostics.items_max = parameters->limits.diagnostics_max;
        result.diagnostics.bytes_max = parameters->limits.diagnostic_bytes_max;

        r = verify_check_input_filenames(parameters->filenames, &parameters->limits, &n_filenames);
        if (r < 0)
                return r;

        const bool scan_all = n_filenames == 0;

        const ManagerTestRunFlags flags =
                MANAGER_TEST_RUN_MINIMAL |
                parameters->run_environment_generators * MANAGER_TEST_RUN_ENV_GENERATORS |
                MANAGER_TEST_DONT_OPEN_EXECUTOR |
                (parameters->recursive_errors == RECURSIVE_ERRORS_NO) *
                        MANAGER_TEST_RUN_IGNORE_DEPENDENCIES |
                parameters->run_unit_generators * MANAGER_TEST_RUN_GENERATORS;

        r = verify_build_unit_path(parameters->filenames, &unit_path);
        if (r < 0)
                return log_error_errno(r, "Failed to build unit load path: %m");

        r = manager_new(parameters->runtime_scope, flags, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        if (parameters->limits.unit_name_map_max > 0)
                manager_set_unit_name_map_limit(m, parameters->limits.unit_name_map_max);

        if (unit_path) {
                r = manager_set_unit_path_override(m, unit_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to set unit load path: %m");
        }

        log_debug("Starting manager...");

        r = manager_startup(
                        m,
                        /* serialization= */ NULL,
                        /* fds= */ NULL,
                        /* named_listen_fds= */ NULL,
                        parameters->root);
        if (r < 0)
                return r;

        manager_clear_jobs(m);

        if (scan_all) {
                r = lookup_paths_init_full(
                                &live_lookup_paths,
                                parameters->runtime_scope,
                                /* flags= */ 0,
                                parameters->root,
                                m->unit_path_override);
                if (r < 0)
                        return r;

                /* A test manager uses temporary generator and transient directories so startup and
                 * teardown cannot alter the live manager's files. Verification only reads unit files,
                 * hence change just the search path and leave the temporary output directories owned
                 * by the test manager. Preserve freshly generated units when they were requested, but
                 * always use the live transient directory. */
                if (!parameters->run_unit_generators)
                        strv_free_and_replace(m->lookup_paths.search_path, live_lookup_paths.search_path);
                else if (m->lookup_paths.transient) {
                        r = verify_replace_lookup_path(
                                        m->lookup_paths.search_path,
                                        m->lookup_paths.transient,
                                        live_lookup_paths.transient);
                        if (r < 0)
                                return r;
                }
        }

        /* Verification diagnostics and their effect on the result must not depend on the ambient log
         * level. When output is suppressed, observe through DEBUG so that no verification-phase log
         * record escapes. */
        observer = log_observer_new(
                        parameters->suppress_output ? LOG_DEBUG : LOG_INFO,
                        parameters->suppress_output ? LOG_OBSERVER_SUPPRESS : 0,
                        verify_log_observer_callback,
                        &result.diagnostics);
        if (!observer)
                return -ENOMEM;

        if (scan_all) {
                r = verify_discover_unit_names(
                                m,
                                parameters->instance,
                                parameters->limits.unit_name_map_max,
                                &discovered_names);
                if (r < 0)
                        return r;

                filenames = discovered_names;
                n_filenames = strv_length(filenames);
        }

        k = log_observer_get_error(observer);
        if (k < 0)
                return k;

        if (n_filenames == 0) {
                *ret = TAKE_STRUCT(result);
                return 0;
        }

        units = new(Unit*, n_filenames);
        if (!units)
                return -ENOMEM;

        log_debug("Loading %s units...", scan_all ? "discovered" : "requested");

        STRV_FOREACH(filename, filenames) {
                _cleanup_free_ char *prepared = NULL, *source_path = NULL;
                int finding_status;

                log_debug("Handling %s...", *filename);

                if (!scan_all) {
                        k = verify_prepare_filename_and_report(
                                        *filename,
                                        parameters->instance,
                                        &result.diagnostics,
                                        &prepared,
                                        &finding_status);
                        if (k < 0)
                                return k;

                        k = log_observer_get_error(observer);
                        if (k < 0)
                                return k;

                        if (finding_status < 0) {
                                RET_GATHER(status, finding_status);
                                continue;
                        }
                }

                if (scan_all) {
                        k = verify_find_unit_source_path(m, *filename, &source_path);
                        if (k < 0)
                                return k;
                }

                k = verify_load_startable_unit(
                                m,
                                /* name= */ scan_all ? *filename : NULL,
                                /* path= */ prepared,
                                /* diagnostic_path= */ scan_all ? source_path : prepared,
                                &result.diagnostics,
                                /* seen_units= */ scan_all ? &loaded_units : NULL,
                                &units[count],
                                &finding_status);
                if (k < 0)
                        return k;

                k = log_observer_get_error(observer);
                if (k < 0)
                        return k;

                if (finding_status < 0) {
                        RET_GATHER(status, finding_status);
                        continue;
                }

                if (!units[count])
                        continue;

                count++;
        }

        k = log_observer_get_error(observer);
        if (k < 0)
                return k;

        FOREACH_ARRAY(i, units, count) {
                k = verify_unit(
                                *i,
                                parameters->check_man,
                                parameters->root,
                                parameters->suppress_output);

                r = log_observer_get_error(observer);
                if (r < 0)
                        return r;

                if (k < 0) {
                        if (verify_error_is_fatal(k))
                                return k;

                        RET_GATHER(status, k);
                }
        }

        k = log_observer_get_error(observer);
        if (k < 0)
                return k;

        if (status == 0) {
                k = verify_diagnostics_syntax_status(
                                &result.diagnostics,
                                filenames,
                                parameters->recursive_errors);
                if (k < 0) {
                        if (verify_error_is_fatal(k))
                                return k;

                        status = k;
                }
        }

        result.legacy_status = status;
        *ret = TAKE_STRUCT(result);
        return 0;
}

static const char* const recursive_errors_table[_RECURSIVE_ERRORS_MAX] = {
        [RECURSIVE_ERRORS_NO]  = "no",
        [RECURSIVE_ERRORS_YES] = "yes",
        [RECURSIVE_ERRORS_ONE] = "one",
};

DEFINE_STRING_TABLE_LOOKUP(recursive_errors, RecursiveErrors);

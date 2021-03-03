/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-wait-for-jobs.h"
#include "def.h"
#include "dirent-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "os-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "spawn-polkit-agent.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_ask_password = true;
static bool arg_quiet = false;
static const char *arg_profile = "default";
static const char* arg_copy_mode = NULL;
static bool arg_runtime = false;
static bool arg_reload = true;
static bool arg_cat = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_enable = false;
static bool arg_now = false;
static bool arg_no_block = false;

static bool is_portable_managed(const char *unit) {
        return ENDSWITH_SET(unit, ".service", ".target", ".socket", ".path", ".timer");
}

static int determine_image(const char *image, bool permit_non_existing, char **ret) {
        int r;

        /* If the specified name is a valid image name, we pass it as-is to portabled, which will search for it in the
         * usual search directories. Otherwise we presume it's a path, and will normalize it on the client's side
         * (among other things, to make the path independent of the client's working directory) before passing it
         * over. */

        if (image_name_is_valid(image)) {
                char *c;

                if (!arg_quiet && laccess(image, F_OK) >= 0)
                        log_warning("Ambiguous invocation: current working directory contains file matching non-path argument '%s', ignoring. "
                                    "Prefix argument with './' to force reference to file in current working directory.", image);

                c = strdup(image);
                if (!c)
                        return log_oom();

                *ret = c;
                return 0;
        }

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Operations on images by path not supported when connecting to remote systems.");

        r = chase_symlinks(image, NULL, CHASE_TRAIL_SLASH | (permit_non_existing ? CHASE_NONEXISTENT : 0), ret, NULL);
        if (r < 0)
                return log_error_errno(r, "Cannot normalize specified image path '%s': %m", image);

        return 0;
}

static int extract_prefix(const char *path, char **ret) {
        _cleanup_free_ char *name = NULL;
        const char *bn, *underscore;
        size_t m;

        bn = basename(path);

        underscore = strchr(bn, '_');
        if (underscore)
                m = underscore - bn;
        else {
                const char *e;

                e = endswith(bn, ".raw");
                if (!e)
                        e = strchr(bn, 0);

                m = e - bn;
        }

        name = strndup(bn, m);
        if (!name)
                return -ENOMEM;

        /*  A slightly reduced version of what's permitted in unit names. With ':' and '\' are removed, as well as '_'
         *  which we use as delimiter for the second part of the image string, which we ignore for now. */
        if (!in_charset(name, DIGITS LETTERS "-."))
                return -EINVAL;

        if (!filename_is_valid(name))
                return -EINVAL;

        *ret = TAKE_PTR(name);

        return 0;
}

static int determine_matches(const char *image, char **l, bool allow_any, char ***ret) {
        _cleanup_strv_free_ char **k = NULL;
        int r;

        /* Determine the matches to apply. If the list is empty we derive the match from the image name. If the list
         * contains exactly the "-" we return a wildcard list (which is the empty list), but only if this is expressly
         * permitted. */

        if (strv_isempty(l)) {
                char *prefix;

                r = extract_prefix(image, &prefix);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract prefix of image name '%s': %m", image);

                if (!arg_quiet)
                        log_info("(Matching unit files with prefix '%s'.)", prefix);

                r = strv_consume(&k, prefix);
                if (r < 0)
                        return log_oom();

        } else if (strv_equal(l, STRV_MAKE("-"))) {

                if (!allow_any)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Refusing all unit file match.");

                if (!arg_quiet)
                        log_info("(Matching all unit files.)");
        } else {

                k = strv_copy(l);
                if (!k)
                        return log_oom();

                if (!arg_quiet) {
                        _cleanup_free_ char *joined = NULL;

                        joined = strv_join(k, "', '");
                        if (!joined)
                                return log_oom();

                        log_info("(Matching unit files with prefixes '%s'.)", joined);
                }
        }

        *ret = TAKE_PTR(k);

        return 0;
}

static int acquire_bus(sd_bus **bus) {
        int r;

        assert(bus);

        if (*bus)
                return 0;

        r = bus_connect_transport(arg_transport, arg_host, false, bus);
        if (r < 0)
                return bus_log_connect_error(r);

        (void) sd_bus_set_allow_interactive_authorization(*bus, arg_ask_password);

        return 0;
}

static int maybe_reload(sd_bus **bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        if (!arg_reload)
                return 0;

        r = acquire_bus(bus);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        *bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Reload");
        if (r < 0)
                return bus_log_create_error(r);

        /* Reloading the daemon may take long, hence set a longer timeout here */
        r = sd_bus_call(*bus, m, DEFAULT_TIMEOUT_USEC * 2, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload daemon: %s", bus_error_message(&error, r));

        return 0;
}

static int inspect_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **matches = NULL;
        _cleanup_free_ char *image = NULL;
        bool nl = false, header = false;
        const void *data;
        const char *path;
        size_t sz;
        int r;

        r = determine_image(argv[1], false, &image);
        if (r < 0)
                return r;

        r = determine_matches(argv[1], argv + 2, true, &matches);
        if (r < 0)
                return r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_message_new_method_call(bus, &m, bus_portable_mgr, "GetImageMetadata");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", image);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, matches);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect image metadata: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read_array(reply, 'y', &data, &sz);
        if (r < 0)
                return bus_log_parse_error(r);

        (void) pager_open(arg_pager_flags);

        if (arg_cat) {
                printf("%s-- OS Release: --%s\n", ansi_highlight(), ansi_normal());
                fwrite(data, sz, 1, stdout);
                fflush(stdout);
                nl = true;
        } else {
                _cleanup_free_ char *pretty_portable = NULL, *pretty_os = NULL;
                _cleanup_fclose_ FILE *f;

                f = fmemopen_unlocked((void*) data, sz, "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open /etc/os-release buffer: %m");

                r = parse_env_file(f, "/etc/os-release",
                                   "PORTABLE_PRETTY_NAME", &pretty_portable,
                                   "PRETTY_NAME", &pretty_os);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse /etc/os-release: %m");

                printf("Image:\n\t%s\n"
                       "Portable Service:\n\t%s\n"
                       "Operating System:\n\t%s\n",
                       path,
                       strna(pretty_portable),
                       strna(pretty_os));
        }

        r = sd_bus_message_enter_container(reply, 'a', "{say}");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *name;

                r = sd_bus_message_enter_container(reply, 'e', "say");
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = sd_bus_message_read(reply, "s", &name);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &data, &sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (arg_cat) {
                        if (nl)
                                fputc('\n', stdout);

                        printf("%s-- Unit file: %s --%s\n", ansi_highlight(), name, ansi_normal());
                        fwrite(data, sz, 1, stdout);
                        fflush(stdout);
                        nl = true;
                } else {
                        if (!header) {
                                fputs("Unit files:\n", stdout);
                                header = true;
                        }

                        fputc('\t', stdout);
                        fputs(name, stdout);
                        fputc('\n', stdout);
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int print_changes(sd_bus_message *m) {
        int r;

        if (arg_quiet)
                return 0;

        r = sd_bus_message_enter_container(m, 'a', "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *type, *path, *source;

                r = sd_bus_message_read(m, "(sss)", &type, &path, &source);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (streq(type, "symlink"))
                        log_info("Created symlink %s %s %s.", path, special_glyph(SPECIAL_GLYPH_ARROW), source);
                else if (streq(type, "copy")) {
                        if (isempty(source))
                                log_info("Copied %s.", path);
                        else
                                log_info("Copied %s %s %s.", source, special_glyph(SPECIAL_GLYPH_ARROW), path);
                } else if (streq(type, "unlink"))
                        log_info("Removed %s.", path);
                else if (streq(type, "write"))
                        log_info("Written %s.", path);
                else if (streq(type, "mkdir"))
                        log_info("Created directory %s.", path);
                else
                        log_error("Unexpected change: %s/%s/%s", type, path, source);
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int maybe_enable_disable(sd_bus *bus, const char *path, bool enable) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **names = NULL;
        UnitFileChange *changes = NULL;
        const uint64_t flags = UNIT_FILE_PORTABLE | (arg_runtime ? UNIT_FILE_RUNTIME : 0);
        size_t n_changes = 0;
        int r;

        if (!arg_enable)
                return 0;

        names = strv_new(path, NULL);
        if (!names)
                return log_oom();

        r = sd_bus_message_new_method_call(
                bus,
                &m,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                enable ? "EnableUnitFilesWithFlags" : "DisableUnitFilesWithFlags");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, names);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "t", flags);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to %s the portable service %s: %s",
                        enable ? "enable" : "disable", path, bus_error_message(&error, r));

        if (enable) {
                r = sd_bus_message_skip(reply, "b");
                if (r < 0)
                        return bus_log_parse_error(r);
        }
        (void) bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet, &changes, &n_changes);

        return 0;
}

static int maybe_start_stop_restart(sd_bus *bus, const char *path, const char *method, BusWaitForJobs *wait) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        char *name = (char *)basename(path), *job = NULL;
        int r;

        assert(STR_IN_SET(method, "StartUnit", "StopUnit", "RestartUnit"));

        if (!arg_now)
                return 0;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        method,
                        &error,
                        &reply,
                        "ss", name, "replace");
        if (r < 0)
                return log_error_errno(r, "Failed to call %s on the portable service %s: %s",
                                       method,
                                       path,
                                       bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &job);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!arg_quiet)
                log_info("Queued %s to call %s on portable service %s.", job, method, name);

        if (wait) {
                r = bus_wait_for_jobs_add(wait, job);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch %s job to call %s on %s: %m",
                                               job, method, name);
        }

        return 0;
}

static int maybe_enable_start(sd_bus *bus, sd_bus_message *reply) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *wait = NULL;
        int r;

        if (!arg_enable && !arg_now)
                return 0;

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &wait);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = sd_bus_message_rewind(reply, true);
        if (r < 0)
                return r;
        r = sd_bus_message_enter_container(reply, 'a', "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                char *type, *path, *source;

                r = sd_bus_message_read(reply, "(sss)", &type, &path, &source);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (STR_IN_SET(type, "symlink", "copy") && is_portable_managed(path)) {
                        (void) maybe_enable_disable(bus, path, true);
                        (void) maybe_start_stop_restart(bus, path, "StartUnit", wait);
                }
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        if (!arg_no_block) {
                r = bus_wait_for_jobs(wait, arg_quiet, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int maybe_stop_enable_restart(sd_bus *bus, sd_bus_message *reply) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *wait = NULL;
        int r;

        if (!arg_enable && !arg_now)
                return 0;

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &wait);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = sd_bus_message_rewind(reply, true);
        if (r < 0)
                return r;

        /* First we get a list of units that were definitely removed, not just re-attached,
         * so we can also stop them if the user asked us to. */
        r = sd_bus_message_enter_container(reply, 'a', "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                char *type, *path, *source;

                r = sd_bus_message_read(reply, "(sss)", &type, &path, &source);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (streq(type, "unlink") && is_portable_managed(path))
                        (void) maybe_start_stop_restart(bus, path, "StopUnit", wait);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        /* Then we get a list of units that were either added or changed, so that we can
         * enable them and/or restart them if the user asked us to. */
        r = sd_bus_message_enter_container(reply, 'a', "(sss)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                char *type, *path, *source;

                r = sd_bus_message_read(reply, "(sss)", &type, &path, &source);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                if (STR_IN_SET(type, "symlink", "copy") && is_portable_managed(path)) {
                        (void) maybe_enable_disable(bus, path, true);
                        (void) maybe_start_stop_restart(bus, path, "RestartUnit", wait);
                }
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        if (!arg_no_block) {
                r = bus_wait_for_jobs(wait, arg_quiet, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int maybe_stop_disable(sd_bus *bus, char *image, char *argv[]) {
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *wait = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_strv_free_ char **matches = NULL;
        int r;

        if (!arg_enable && !arg_now)
                return 0;

        r = determine_matches(argv[1], argv + 2, true, &matches);
        if (r < 0)
                return r;

        r = bus_wait_for_jobs_new(bus, &wait);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        r = bus_message_new_method_call(bus, &m, bus_portable_mgr, "GetImageMetadata");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", image);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, matches);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect image metadata: %s", bus_error_message(&error, r));

        r = sd_bus_message_skip(reply, "say");
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_enter_container(reply, 'a', "{say}");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *name;

                r = sd_bus_message_enter_container(reply, 'e', "say");
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = sd_bus_message_read(reply, "s", &name);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_skip(reply, "ay");
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                (void) maybe_start_stop_restart(bus, name, "StopUnit", wait);
                (void) maybe_enable_disable(bus, name, false);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        /* Stopping must always block or the detach will fail if the unit is still running */
        r = bus_wait_for_jobs(wait, arg_quiet, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int attach_reattach_image(int argc, char *argv[], const char *method) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **matches = NULL;
        _cleanup_free_ char *image = NULL;
        int r;

        assert(method);
        assert(STR_IN_SET(method, "AttachImage", "ReattachImage"));

        r = determine_image(argv[1], false, &image);
        if (r < 0)
                return r;

        r = determine_matches(argv[1], argv + 2, false, &matches);
        if (r < 0)
                return r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_message_new_method_call(bus, &m, bus_portable_mgr, method);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", image);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, matches);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "sbs", arg_profile, arg_runtime, arg_copy_mode);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "%s failed: %s", method, bus_error_message(&error, r));

        (void) maybe_reload(&bus);

        print_changes(reply);

        if (streq(method, "AttachImage"))
                (void) maybe_enable_start(bus, reply);
        else {
                /* ReattachImage returns 2 lists - removed units first, and changed/added second */
                print_changes(reply);
                (void) maybe_stop_enable_restart(bus, reply);
        }

        return 0;
}

static int attach_image(int argc, char *argv[], void *userdata) {
        return attach_reattach_image(argc, argv, "AttachImage");
}

static int reattach_image(int argc, char *argv[], void *userdata) {
        return attach_reattach_image(argc, argv, "ReattachImage");
}

static int detach_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *image = NULL;
        int r;

        r = determine_image(argv[1], true, &image);
        if (r < 0)
                return r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        (void) maybe_stop_disable(bus, image, argv);

        r = bus_call_method(bus, bus_portable_mgr, "DetachImage", &error, &reply, "sb", image, arg_runtime);
        if (r < 0)
                return log_error_errno(r, "Failed to detach image: %s", bus_error_message(&error, r));

        (void) maybe_reload(&bus);

        print_changes(reply);
        return 0;
}

static int list_images(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_portable_mgr, "ListImages", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list images: %s", bus_error_message(&error, r));

        table = table_new("name", "type", "ro", "crtime", "mtime", "usage", "state");
        if (!table)
                return log_oom();

        r = sd_bus_message_enter_container(reply, 'a', "(ssbtttso)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *name, *type, *state;
                uint64_t crtime, mtime, usage;
                int ro_int;

                r = sd_bus_message_read(reply, "(ssbtttso)", &name, &type, &ro_int, &crtime, &mtime, &usage, &state, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = table_add_many(table,
                                   TABLE_STRING, name,
                                   TABLE_STRING, type,
                                   TABLE_BOOLEAN, ro_int,
                                   TABLE_SET_COLOR, ro_int ? ansi_highlight_red() : NULL,
                                   TABLE_TIMESTAMP, crtime,
                                   TABLE_TIMESTAMP, mtime,
                                   TABLE_SIZE, usage,
                                   TABLE_STRING, state,
                                   TABLE_SET_COLOR, !streq(state, "detached") ? ansi_highlight_green() : NULL);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (table_get_rows(table) > 1) {
                r = table_set_sort(table, (size_t) 0);
                if (r < 0)
                        return table_log_sort_error(r);

                table_set_header(table, arg_legend);

                r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);
        }

        if (arg_legend) {
                if (table_get_rows(table) > 1)
                        printf("\n%zu images listed.\n", table_get_rows(table) - 1);
                else
                        printf("No images.\n");
        }

        return 0;
}

static int remove_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, i;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (i = 1; i < argc; i++) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_portable_mgr, "RemoveImage");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", argv[i]);
                if (r < 0)
                        return bus_log_create_error(r);

                /* This is a slow operation, hence turn off any method call timeouts */
                r = sd_bus_call(bus, m, USEC_INFINITY, &error, NULL);
                if (r < 0)
                        return log_error_errno(r, "Could not remove image: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int read_only_image(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int b = true, r;

        if (argc > 2) {
                b = parse_boolean(argv[2]);
                if (b < 0)
                        return log_error_errno(b, "Failed to parse boolean argument: %s", argv[2]);
        }

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_call_method(bus, bus_portable_mgr, "MarkImageReadOnly", &error, NULL, "sb", argv[1], b);
        if (r < 0)
                return log_error_errno(r, "Could not mark image read-only: %s", bus_error_message(&error, r));

        return 0;
}

static int set_limit(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        uint64_t limit;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (STR_IN_SET(argv[argc-1], "-", "none", "infinity"))
                limit = UINT64_MAX;
        else {
                r = parse_size(argv[argc-1], 1024, &limit);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse size: %s", argv[argc-1]);
        }

        if (argc > 2)
                /* With two arguments changes the quota limit of the specified image */
                r = bus_call_method(bus, bus_portable_mgr, "SetImageLimit", &error, NULL, "st", argv[1], limit);
        else
                /* With one argument changes the pool quota limit */
                r = bus_call_method(bus, bus_portable_mgr, "SetPoolLimit", &error, NULL, "t", limit);

        if (r < 0)
                return log_error_errno(r, "Could not set limit: %s", bus_error_message(&error, r));

        return 0;
}

static int is_image_attached(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *image = NULL;
        const char *state;
        int r;

        r = determine_image(argv[1], true, &image);
        if (r < 0)
                return r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_portable_mgr, "GetImageState", &error, &reply, "s", image);
        if (r < 0)
                return log_error_errno(r, "Failed to get image state: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &state);
        if (r < 0)
                return r;

        if (!arg_quiet)
                puts(state);

        return streq(state, "detached");
}

static int dump_profiles(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **l = NULL;
        char **i;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_get_property_strv(bus, bus_portable_mgr, "Profiles", &error, &l);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire list of profiles: %s", bus_error_message(&error, r));

        if (arg_legend)
                log_info("Available unit profiles:");

        STRV_FOREACH(i, l) {
                fputs(*i, stdout);
                fputc('\n', stdout);
        }

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        (void) pager_open(arg_pager_flags);

        r = terminal_urlify_man("portablectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sAttach or detach portable services from the local system.%s\n"
               "\nCommands:\n"
               "  list                        List available portable service images\n"
               "  attach NAME|PATH [PREFIX...]\n"
               "                              Attach the specified portable service image\n"
               "  detach NAME|PATH [PREFIX...]\n"
               "                              Detach the specified portable service image\n"
               "  reattach NAME|PATH [PREFIX...]\n"
               "                              Reattach the specified portable service image\n"
               "  inspect NAME|PATH [PREFIX...]\n"
               "                              Show details of specified portable service image\n"
               "  is-attached NAME|PATH       Query if portable service image is attached\n"
               "  read-only NAME|PATH [BOOL]  Mark or unmark portable service image read-only\n"
               "  remove NAME|PATH...         Remove a portable service image\n"
               "  set-limit [NAME|PATH]       Set image or pool size limit (disk quota)\n"
               "\nOptions:\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "     --no-ask-password        Do not ask for system passwords\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "  -q --quiet                  Suppress informational messages\n"
               "  -p --profile=PROFILE        Pick security profile for portable service\n"
               "     --copy=copy|auto|symlink Prefer copying or symlinks if possible\n"
               "     --runtime                Attach portable service until next reboot only\n"
               "     --no-reload              Don't reload the system and service manager\n"
               "     --cat                    When inspecting include unit and os-release file\n"
               "                              contents\n"
               "     --enable                 Immediately enable/disable the portable service\n"
               "                              after attach/detach\n"
               "     --now                    Immediately start/stop the portable service after\n"
               "                              attach/before detach\n"
               "     --no-block               Don't block waiting for attach --now to complete\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_NO_ASK_PASSWORD,
                ARG_COPY,
                ARG_RUNTIME,
                ARG_NO_RELOAD,
                ARG_CAT,
                ARG_ENABLE,
                ARG_NOW,
                ARG_NO_BLOCK,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "no-legend",       no_argument,       NULL, ARG_NO_LEGEND       },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "quiet",           no_argument,       NULL, 'q'                 },
                { "profile",         required_argument, NULL, 'p'                 },
                { "copy",            required_argument, NULL, ARG_COPY            },
                { "runtime",         no_argument,       NULL, ARG_RUNTIME         },
                { "no-reload",       no_argument,       NULL, ARG_NO_RELOAD       },
                { "cat",             no_argument,       NULL, ARG_CAT             },
                { "enable",          no_argument,       NULL, ARG_ENABLE          },
                { "now",             no_argument,       NULL, ARG_NOW             },
                { "no-block",        no_argument,       NULL, ARG_NO_BLOCK        },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        for (;;) {
                int c;

                c = getopt_long(argc, argv, "hH:M:qp:", options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case 'p':
                        if (streq(optarg, "help"))
                                return dump_profiles();

                        if (!filename_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unit profile name not valid: %s", optarg);

                        arg_profile = optarg;
                        break;

                case ARG_COPY:
                        if (streq(optarg, "auto"))
                                arg_copy_mode = NULL;
                        else if (STR_IN_SET(optarg, "copy", "symlink"))
                                arg_copy_mode = optarg;
                        else if (streq(optarg, "help")) {
                                puts("auto\n"
                                     "copy\n"
                                     "symlink");
                                return 0;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse --copy= argument: %s", optarg);

                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                case ARG_NO_RELOAD:
                        arg_reload = false;
                        break;

                case ARG_CAT:
                        arg_cat = true;
                        break;

                case ARG_ENABLE:
                        arg_enable = true;
                        break;

                case ARG_NOW:
                        arg_now = true;
                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,            help              },
                { "list",        VERB_ANY, 1,        VERB_DEFAULT, list_images       },
                { "attach",      2,        VERB_ANY, 0,            attach_image      },
                { "detach",      2,        VERB_ANY, 0,            detach_image      },
                { "inspect",     2,        VERB_ANY, 0,            inspect_image     },
                { "is-attached", 2,        2,        0,            is_image_attached },
                { "read-only",   2,        3,        0,            read_only_image   },
                { "remove",      2,        VERB_ANY, 0,            remove_image      },
                { "set-limit",   3,        3,        0,            set_limit         },
                { "reattach",    2,        VERB_ANY, 0,            reattach_image    },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);

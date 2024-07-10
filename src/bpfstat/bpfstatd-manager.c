/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/wait.h>

#include "sd-messages.h"

#include "bpf-dlopen.h"
#include "bpfstatd-conf.h"
#include "bpfstatd-manager.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "mkdir.h"
#include "parse-util.h"
#include "stdio-util.h"

static void btf_free(struct btf **btf) {
        assert(btf);

        sym_btf__free(*btf);
}

static void toggle_bpf_stats_enabled(bool enable) {
        int r;

        r = write_string_file("/proc/sys/kernel/bpf_stats_enabled", one_zero(enable), WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to write '%s' to /proc/sys/kernel/bpf_stats_enabled, ignoring: %m", one_zero(enable));
}

static int get_memlock_by_fd(int fd, uint64_t *ret_memlock) {
        _cleanup_free_ char *fdinfo = NULL;
        char *memlock_line;
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        int r;

        xsprintf(path, "/proc/self/fdinfo/%i", fd);
        r = read_full_virtual_file(path, &fdinfo, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read memlock from /proc/self/fdinfo/%i, ignoring: %m", fd);

        memlock_line = find_line_startswith(fdinfo, "memlock:");
        if (!memlock_line)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to read memlock from /proc/self/fdinfo/%i, ignoring: %m", fd);

        memlock_line += strspn(memlock_line, WHITESPACE);
        memlock_line[strcspn(memlock_line, WHITESPACE)] = 0;

        r = safe_atou64(memlock_line, ret_memlock);
        if (r < 0)
                return log_error_errno(r, "Failed to parse memlock value '%s', ignoring: %m", memlock_line);

        return 0;
}

static int fetch_bpf_maps(JsonVariant **ret) {
        uint32_t id = 0;
        _cleanup_(json_variant_unrefp) JsonVariant *map_list = NULL;
        int r;

        /* Iterate through all BPF maps to get map names, map types, and memlock */
        while (sym_bpf_map_get_next_id(id, &id) >= 0) {
                struct bpf_map_info map_info = {};
                uint32_t map_info_len = sizeof(map_info);
                _cleanup_close_ int fd = -EBADF;
                uint64_t memlock = 0;
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                /* Grab the FD using the ID*/
                fd = sym_bpf_map_get_fd_by_id(id);
                if (fd < 0) {
                        log_error_errno(errno, "Can't get fd for map id %u, ignoring: %m", id);
                        continue;
                }

                /* Fetch bpf_map_info using fd */
                r = sym_bpf_obj_get_info_by_fd(fd, &map_info, &map_info_len);
                if (r < 0) {
                        log_error_errno(errno, "Can't get bpf map info for fd %i, ignoring: %m", fd);
                        continue;
                }

                /* Fetch memlock from /proc/self/fdinfo using map fd */
                r = get_memlock_by_fd(fd, &memlock);
                if (r < 0)
                        continue;

                r = json_build(&v, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("name", map_info.name),
                                        JSON_BUILD_PAIR_UNSIGNED("type", map_info.type),
                                        JSON_BUILD_PAIR_UNSIGNED("memlock", memlock)));
                if (r < 0) {
                        log_error_errno(r, "Failed to build map JSON object, ignoring: %m");
                        continue;
                }

                r = json_variant_append_array(&map_list, v);
                if (r < 0) {
                        log_error_errno(r, "Failed to append to json variant array for map, ignoring: %m");
                        continue;
                }
        }

        *ret = TAKE_PTR(map_list);

        return 0;
}


static int fetch_bpf_programs(JsonVariant **ret) {
        _cleanup_hashmap_free_free_ Hashmap *map_name_by_id = NULL;
        uint32_t id = 0;
        JsonVariant *prog_list = NULL;
        int r;

        /* Iterate through all attached BPF progs*/
        while (sym_bpf_prog_get_next_id(id, &id) >= 0) {
                struct bpf_prog_info prog_info = {};
                uint32_t prog_info_len = sizeof(prog_info);
                uint32_t nr_map_ids = 0;
                uint64_t memlock = 0;
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *prog_name = NULL, *prog_tag = NULL;
                _cleanup_free_ uint32_t *prog_map_ids = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                _cleanup_strv_free_ char **prog_map_names = NULL;

                /* Grab the FDs using their IDs*/
                fd = sym_bpf_prog_get_fd_by_id(id);
                if (fd < 0) {
                        log_error_errno(errno, "Can't get fd for prog id %u, ignoring: %m", id);
                        continue;
                }

                /* Fetch bpf_prog_info using fd */
                r = sym_bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
                if (r < 0) {
                        log_error_errno(errno, "Can't get bpf prog info for fd %i, ignoring: %m", fd);
                        continue;
                }

                /* If there are maps associated with this prog, fetch bpf_prog_info again
                 * to get a list of map ids */
                nr_map_ids = prog_info.nr_map_ids;
                if (nr_map_ids > 0) {
                        prog_map_ids = new(uint32_t, nr_map_ids);
                        if (!prog_map_ids)
                                return log_oom();

                        prog_info = (struct bpf_prog_info) {
                                .nr_map_ids = nr_map_ids,
                                .map_ids = PTR_TO_UINT64(prog_map_ids),
                        };
                        r = sym_bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
                        if (r < 0) {
                                log_error_errno(errno, "Can't get bpf prog info for fd %i, ignoring: %m", fd);
                                continue;
                        }

                        /* For each map id, fetch the bpf_map_info so we can get the map name, unless it's
                         * already been cached in our hashmap. Append the map name to a strv. */
                        FOREACH_ARRAY(j, prog_map_ids, nr_map_ids) {
                                uint32_t map_id = *j;
                                char *map_name = NULL;
                                if (hashmap_contains(map_name_by_id, UINT32_TO_PTR(map_id))) {
                                        map_name = hashmap_get(map_name_by_id, UINT32_TO_PTR(map_id));
                                        if (!map_name) {
                                                log_error_errno(r, "Failed to hashmap_get with id %u, ignoring: %m", *j);
                                                continue;
                                        }
                                } else {
                                        _cleanup_close_ int map_fd = -EBADF;
                                        struct bpf_map_info map_info = {};
                                        uint32_t map_info_len = sizeof(map_info);

                                        /* Grab the FD using the ID*/
                                        map_fd = sym_bpf_map_get_fd_by_id(map_id);
                                        if (map_fd < 0) {
                                                log_error_errno(errno, "Can't get fd for map id %u, ignoring: %m", map_id);
                                                continue;
                                        }

                                        /* Fetch bpf_map_info using fd */
                                        r = sym_bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len);
                                        if (r < 0) {
                                                log_error_errno(errno, "Can't get bpf map info for fd %i, ignoring: %m", map_fd);
                                                continue;
                                        }

                                        map_name = strdup(map_info.name);
                                        if (!map_name)
                                                return log_oom();

                                        r = hashmap_ensure_put(&map_name_by_id, &trivial_hash_ops, UINT32_TO_PTR(map_id), map_name);
                                        if (r < 0) {
                                                log_error_errno(r, "Failed to hashmap_put map id to map name, ignoring: %m");
                                                continue;
                                        }

                                }

                                strv_extend(&prog_map_names, map_name);
                        }
                }

                /* Fetch memlock using fd from /proc/self/fdinfo */
                r = get_memlock_by_fd(fd, &memlock);
                if (r < 0)
                        continue;

                /* Format prog tag */
                prog_tag = hexmem(prog_info.tag, BPF_TAG_SIZE);
                if (!prog_tag)
                        return log_oom();

                /* Check if prog name is empty or might be truncated. If so, try to get full name from BTF */
                if (isempty(prog_info.name) || strlen(prog_info.name) >= BPF_OBJ_NAME_LEN - 1) {
                        struct bpf_func_info func_info = {};
                        uint32_t func_info_rec_size = 0;
                        const struct btf_type *t;
                        _cleanup_(btf_free) struct btf *btf = NULL;

                        if (prog_info.btf_id == 0) {
                                log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No valid btf for prog id %u, ignoring", id);
                                continue;
                        }

                        if (prog_info.nr_func_info == 0) {
                                log_error_errno(SYNTHETIC_ERRNO(EINVAL), "0 func infos found for prog id %u, ignoring", id);
                                continue;
                        }

                        /* Fetch bpf_prog_info again with the corresponding fields loaded to get
                         * func_infos. We only need the first one, which points to the program itself,
                         * so we can set nr_func_info to 1. */
                        func_info_rec_size = prog_info.func_info_rec_size;
                        prog_info = (struct bpf_prog_info) {
                                .nr_func_info = 1,
                                .func_info_rec_size = func_info_rec_size,
                                .func_info = PTR_TO_UINT64(&func_info),
                        };

                        r = sym_bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
                        if (r < 0) {
                                log_error_errno(errno, "Couldn't get func info for prog id %u, ignoring: %m", id);
                                continue;
                        }

                        /* Fetch the BTF, then fetch the type with the type_id from func_info.
                         * Finally, use name_off fetch the non-truncated name. */
                        btf = sym_btf__load_from_kernel_by_id(prog_info.btf_id);
                        if ((r = sym_libbpf_get_error(btf))) {
                                log_error_errno(r, "Failed to load btf for prog fd %i, ignoring: %m", fd);
                                continue;
                        }

                        t = sym_btf__type_by_id(btf, func_info.type_id);
                        if ((r = sym_libbpf_get_error(t))) {
                                log_error_errno(r, "btf %u doesn't have type %u, ignoring: %m", prog_info.btf_id, func_info.type_id);
                                continue;
                        }

                        prog_name = strdup(sym_btf__name_by_offset(btf, t->name_off));
                        if (!prog_name)
                                return log_oom();
                } else {
                        /* Prog name doesn't seem to be truncated. Just use the one from the prog_info */
                        prog_name = strdup(prog_info.name);
                        if (!prog_name)
                                return log_oom();
                }

                r = json_build(&v, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("name", prog_name),
                                        JSON_BUILD_PAIR_UNSIGNED("type", prog_info.type),
                                        JSON_BUILD_PAIR_UNSIGNED("memlock", memlock),
                                        JSON_BUILD_PAIR_STRING("tag", prog_tag),
                                        JSON_BUILD_PAIR_CONDITION(prog_map_names, "map_names", JSON_BUILD_STRV(prog_map_names)),
                                        JSON_BUILD_PAIR_UNSIGNED("run_time_ns", prog_info.run_time_ns),
                                        JSON_BUILD_PAIR_UNSIGNED("run_count", prog_info.run_cnt)));
                if (r < 0) {
                        log_error_errno(r, "Failed to build JSON object for program, ignoring: %m");
                        continue;
                }

                r = json_variant_append_array(&prog_list, v);
                if (r < 0) {
                        log_error_errno(r, "Failed to append to json variant array for program, ignoring: %m");
                        continue;
                }
        }

        *ret = TAKE_PTR(prog_list);

        return 0;
}

static int log_bpf_maps_and_progs(Manager *m) {
        JsonVariant *map_list = NULL, *prog_list = NULL;
        _cleanup_(erase_and_freep) char *maps_formatted = NULL, *progs_formatted = NULL;
        int r = 0;

        r = fetch_bpf_maps(&map_list);
        if (r < 0)
                return r;

        r = json_variant_format(map_list, JSON_FORMAT_NEWLINE, &maps_formatted);
        if (r < 0)
                log_error_errno(r, "Failed to format list of bpf maps, ignoring: %m");
        else
                log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_BPFSTATD_LOG_STR, "TYPE=map", "DATA=%s", maps_formatted);

        r = fetch_bpf_programs(&prog_list);
        if (r < 0)
                return r;

        r = json_variant_format(prog_list, JSON_FORMAT_NEWLINE, &progs_formatted);
        if (r < 0)
                log_error_errno(r, "Failed to format list of bpf programs, ignoring: %m");
        else
                log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_BPFSTATD_LOG_STR, "TYPE=prog", "DATA=%s", progs_formatted);

        return 0;
}

static int vl_method_describe_maps(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        JsonVariant *v = NULL, *map_list = NULL;
        size_t idx = 0, length = 0;
        int r = 0;

        r = fetch_bpf_maps(&map_list);
        if (r < 0)
                return r;

        length = json_variant_elements(map_list);
        JSON_VARIANT_ARRAY_FOREACH(v, map_list) {
                if (idx < length - 1) {
                        r = varlink_notify(link, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to varlink notify for map: %m");
                } else {
                        /* varlink reply on final element only */
                        r = varlink_reply(link, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to varlink reply for map: %m");
                }
                idx++;
        }

        return 0;
}

static int vl_method_describe_programs(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        JsonVariant *v = NULL, *prog_list = NULL;
        size_t idx = 0, length = 0;
        int r = 0;

        r = fetch_bpf_programs(&prog_list);
        if (r < 0)
                return r;

        length = json_variant_elements(prog_list);
        JSON_VARIANT_ARRAY_FOREACH(v, prog_list) {
                if (idx < length - 1) {
                        r = varlink_notify(link, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to varlink notify for program: %m");
                } else {
                        /* varlink reply on final element only */
                        r = varlink_reply(link, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to varlink reply for program: %m");
                }
                idx++;
        }

        return 0;
}

static int manager_bind_varlink(Manager *m) {
        int r;

        assert(m);
        assert(!m->varlink_server);

        r = varlink_server_new(&m->varlink_server, VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(m->varlink_server, m);

        r = varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.Bpf.DescribeMaps", vl_method_describe_maps,
                        "io.systemd.Bpf.DescribePrograms", vl_method_describe_programs
        );
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/bpf", 0755);

        r = varlink_server_listen_address(m->varlink_server, BPFSTATD_VARLINK_ADDRESS, 0600);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket %s: %m", BPFSTATD_VARLINK_ADDRESS);

        r = varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        return 0;
}

static int monitor_bpf_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(s);

        /* Collect BPF tax information */
        r = log_bpf_maps_and_progs(m);
        if (r < 0)
                return r;

        r = sd_event_source_set_time_relative(s, BPF_TIMER_INTERVAL_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set relative time for timer: %m");

        return 0;
}

static int monitor_bpf(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(m);
        assert(m->event);

        r = sd_event_add_time(m->event, &s, CLOCK_MONOTONIC, 0, 0, monitor_bpf_handler, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add bpf timer event source: %m");

        r = sd_event_source_set_exit_on_failure(s, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-failure logic: %m");

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to enable bpfstatd logging timer: %m");

        (void) sd_event_source_set_description(s, "bpfstatd-timer");

        m->bpf_timer_event_source = TAKE_PTR(s);
        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        m = new(Manager, 1);
        if (!m)
                return log_oom();

        *m = (Manager) {
                .enable_logging = true,
        };

        r = manager_parse_config_file(m);
        if (r < 0)
                log_warning_errno(r, "Failed to parse configuration file - using defaults: %m");

        r = sd_event_default(&m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        r = sd_event_set_watchdog(m->event, true);
        if (r < 0)
                log_error_errno(r, "Failed to enable watchdog handling, ignoring: %m");

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        sd_event_unref(m->event);
        varlink_server_unref(m->varlink_server);

        toggle_bpf_stats_enabled(/*enable=*/ false);

        return mfree(m);
}

int manager_start(Manager *m) {
        int r;

        r = dlopen_bpf();
        if (r < 0)
                return log_error_errno(r, "Couldn't dlopen_bpf: %m");

        toggle_bpf_stats_enabled(/*enable=*/ true);

        assert(m);
        assert(m->event);

        r = manager_bind_varlink(m);
        if (r < 0)
                return r;

        if (m->enable_logging) {
                r = monitor_bpf(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

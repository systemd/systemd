/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/wait.h>

#include "bpf-dlopen.h"
#include "fileio.h"
#include "sd-daemon.h"
#include "sd-messages.h"
#include "bpfd-manager.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "umask-util.h"

static int get_memlock_by_fd(int fd, char **memlock) {
        _cleanup_free_ char *fdinfo = NULL;
        char *memlock_line;
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        int r;

        xsprintf(path, "/proc/self/fdinfo/%i", fd);
        r = read_full_virtual_file(path, &fdinfo, NULL);
        if (r < 0)
                return r;

        memlock_line = find_line_startswith(fdinfo, "memlock:");
        if (!memlock_line)
                return -EOPNOTSUPP;

        memlock_line += strspn(memlock_line, WHITESPACE);
        memlock_line[strcspn(memlock_line, WHITESPACE)] = 0;

        *memlock = strdup(memlock_line);
        if (!*memlock)
                return -ENOMEM;

        return 0;
}

static int fetch_bpf_maps_and_progs(Varlink *link) {
        int i = 0;
        uint32_t id = 0;
        struct bpf_map_info map_info = {};
        uint32_t map_info_len = sizeof(map_info);
        struct bpf_prog_info prog_info = {};
        uint32_t prog_info_len = sizeof(prog_info);
        uint32_t nr_map_ids = 0;
        struct bpf_func_info func_info = {};
        uint32_t func_info_rec_size = 0;
        const struct btf_type *t;
        struct btf *btf = NULL;
        char prog_tag[BPF_TAG_SIZE * 2 + 1];
        _cleanup_hashmap_free_ Hashmap *map_name_by_id = NULL;
        int r;

        map_name_by_id = hashmap_new(NULL);
        if (!map_name_by_id)
                return -ENOMEM;
        /* Iterate through all BPF maps to get map names, map types, and memlock */
        while (sym_bpf_map_get_next_id(id, &id) >= 0) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *memlock = NULL;
                char *map_name = NULL;
                uint32_t map_id = id;
                JsonVariant *v;

                zero(map_info);
                /* Grab the FD using the ID*/
                fd = sym_bpf_map_get_fd_by_id(id);
                if (fd < 0) {
                        log_error("Can't get fd for map id: %u", id);
                        continue;
                }

                /* Fetch bpf_map_info using fd */
                r = sym_bpf_obj_get_info_by_fd(fd, &map_info, &map_info_len);
                if (r < 0) {
                        log_error("Can't get bpf map info for fd: %i", fd);
                        continue;
                }

                /* Store map names into hashmap for later lookup when iterating progs */
                map_name = strdup(map_info.name);
                if (!map_name)
                        return -ENOMEM;
                hashmap_put(map_name_by_id, UINT32_TO_PTR(map_id), map_name);

                /* Fetch memlock from /proc/self/fdinfo using map fd */
                r = get_memlock_by_fd(fd, &memlock);
                if (r < 0)
                        return log_error_errno(r, "Failed to read map memlock from /proc/self/fdinfo/%i", fd);

                if (link) {
                        r = json_build(&v, JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_STRING("TYPE", "MAP")));

                        r = json_variant_merge_objectb(&v, JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_OBJECT("DATA",
                                                JSON_BUILD_PAIR_STRING("NAME", map_info.name),
                                                JSON_BUILD_PAIR_UNSIGNED("TYPE", map_info.type),
                                                JSON_BUILD_PAIR_STRING("MEMLOCK", memlock))));

                        varlink_notify(link, v);
                } else {
                        log_struct(LOG_INFO,
                                LOG_MESSAGE("Logging info about BPF map: %s", map_info.name),
                                "MESSAGE_ID=" SD_MESSAGE_BPFD_LOG_STR,
                                "NAME=%s", map_info.name,
                                "TYPE=%u", map_info.type,
                                "MEMLOCK=%s", memlock);
                }
        }

        /* Iterate through all attached BPF progs*/
        id = 0;
        while (sym_bpf_prog_get_next_id(id, &id) >= 0) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *memlock = NULL;
                _cleanup_free_ uint32_t *prog_map_ids = NULL;
                _cleanup_free_ char *prog_name = NULL;
                _cleanup_free_ char *prog_map_names = NULL;
                JsonVariant *v = NULL;

                zero(prog_info);
                /* Grab the FDs using their IDs*/
                fd = sym_bpf_prog_get_fd_by_id(id);
                if (fd < 0) {
                        log_error("Can't get fd for prog id: %u", id);
                        continue;
                }

                /* Fetch bpf_prog_info using fd */
                r = sym_bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
                if (r < 0) {
                        log_error("Can't get bpf prog info for fd: %i", fd);
                }

                /* If there are maps associated with this prog, fetch bpf_prog_info again
                 * to get a list of map ids */
                nr_map_ids = prog_info.nr_map_ids;
                if (nr_map_ids > 0) {
                        prog_map_ids = malloc(nr_map_ids * sizeof(uint32_t));
                        if (!prog_map_ids)
                                return -ENOMEM;
                        prog_map_names = malloc(nr_map_ids * BPF_OBJ_NAME_LEN);
                        if (!prog_map_names)
                                return -ENOMEM;

                        zero(prog_info);
                        prog_info.nr_map_ids = nr_map_ids;
                        prog_info.map_ids = PTR_TO_UINT64(prog_map_ids);
                        r = sym_bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
                        if (r < 0) {
                                log_error("Can't get bpf prog info for fd: %i", fd);
                                continue;
                        }

                        /* For each map id, get the map name from the hashmap and concatenate them
                         * into one string, separated by colons. */
                        i = 0;
                        FOREACH_ARRAY(j, prog_map_ids, nr_map_ids) {
                                uint32_t map_id = *j;
                                char *map_name = hashmap_get(map_name_by_id, UINT32_TO_PTR(map_id));
                                if (map_name == NULL) {
                                        log_error("Can't find map in map_name_by_id: %u", map_id);
                                        continue;
                                }
                                strcpy(&prog_map_names[i], map_name);
                                i += strlen(map_name);
                                prog_map_names[i] = ':';
                                i++;
                        }
                        prog_map_names[i] = '\0';
                }

                /* Fetch memlock using fd from /proc/self/fdinfo */
                r = get_memlock_by_fd(fd, &memlock);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read memlock from /proc/self/fdinfo/%i", fd);

                /* Format prog tag */
                prog_tag[BPF_TAG_SIZE * 2] = '\0';
                for (size_t j = 0; j < BPF_TAG_SIZE; ++j) {
                        sprintf(&(prog_tag[2 * j]), "%02hhx", prog_info.tag[j]);
                }

                /* Check if prog name is empty or might be truncated. If so, try to get full name from BTF */
                if (strlen(prog_info.name) == 0 || strlen(prog_info.name) >= BPF_OBJ_NAME_LEN - 1) {
                        if (prog_info.btf_id == 0) {
                                log_error("No valid btf for prog id %u", id);
                                continue;
                        }

                        if (prog_info.nr_func_info == 0) {
                                log_error("0 fun infos found for prog id %u", id);
                                continue;
                        }

                        /* Fetch bpf_prog_info again with the corresponding fields loaded to get
                         * func_infos. We only need the first one, which points to the program itself,
                         * so we can set nr_func_info to 1. */
                        func_info_rec_size = prog_info.func_info_rec_size;
                        zero(prog_info);
                        prog_info.nr_func_info = 1;
                        prog_info.func_info_rec_size = func_info_rec_size;
                        prog_info.func_info = PTR_TO_UINT64(&func_info);

                        r = sym_bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
                        if (r < 0) {
                                log_error("Couldn't get func info for prog id %u", id);
                                continue;
                        }

                        /* Fetch the BTF, then fetch the type with the type_id from func_info.
                         * Finally, use name_off fetch the non-truncated name. */
                        btf = sym_btf__load_from_kernel_by_id(prog_info.btf_id);
                        if (sym_libbpf_get_error(btf)) {
                                log_error("Failed to load btf for prog fd %i", fd);
                        }

                        t = sym_btf__type_by_id(btf, func_info.type_id);
                        if (!t) {
                                log_error("btf %u doesn't have type %u", prog_info.btf_id, func_info.type_id);
                                continue;
                        }

                        prog_name = strdup(sym_btf__name_by_offset(btf, t->name_off));
                        if (!prog_name)
                                return -ENOMEM;
                        sym_btf__free(btf);
                } else {
                        /* Prog name doesn't seem to be truncated. Just use the one from the prog_info */
                        prog_name = strdup(prog_info.name);
                        if (!prog_name)
                                return -ENOMEM;
                }

                if (link) {
                        r = json_build(&v, JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_STRING("TYPE", "PROG")));

                        r = json_variant_merge_objectb(&v, JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_OBJECT("DATA",
                                                JSON_BUILD_PAIR_STRING("NAME", prog_name),
                                                JSON_BUILD_PAIR_UNSIGNED("TYPE", prog_info.type),
                                                JSON_BUILD_PAIR_STRING("MEMLOCK", memlock),
                                                JSON_BUILD_PAIR_STRING("TAG", prog_tag),
                                                JSON_BUILD_PAIR_CONDITION(prog_map_names, "MAP_NAMES", JSON_BUILD_STRING(prog_map_names)),
                                                JSON_BUILD_PAIR_UNSIGNED("RUN_TIME_NS", prog_info.run_time_ns),
                                                JSON_BUILD_PAIR_UNSIGNED("RUN_COUNT", prog_info.run_cnt))));
                        varlink_notify(link, v);
                } else {
                        log_struct(LOG_INFO,
                                LOG_MESSAGE("Logging info about BPF program: %s", prog_name),
                                "MESSAGE_ID=" SD_MESSAGE_BPFD_LOG_STR,
                                "NAME=%s", prog_name,
                                "TYPE=%u", prog_info.type,
                                "MEMLOCK=%s", memlock,
                                "TAG=%s", prog_tag,
                                "MAP_NAMES=%s", prog_map_names,
                                "RUN_TIME_NS=%llu", prog_info.run_time_ns,
                                "RUN_COUNT=%llu", prog_info.run_cnt);
                }
        }

        char *map_name;
        HASHMAP_FOREACH(map_name, map_name_by_id) {
                free(map_name);
        }
        return 0;
}

static int log_bpf_maps_and_progs(Manager *m) {
        int r = fetch_bpf_maps_and_progs(NULL);
        if (r < 0)
                return r;
        return 0;
}

static int vl_method_get_bpf_progs_and_maps(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        int r;

        r = fetch_bpf_maps_and_progs(link);
        if (r < 0)
                return r;

        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_BOOLEAN("done", true)));

        return 0;
}

static int manager_bind_varlink(Manager *m) {
        const char *socket_path;
        int r;

        assert(m);
        assert(!m->varlink_server);

        r = varlink_server_new(&m->varlink_server, VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(m->varlink_server, m);

        r = varlink_server_bind_method(
                        m->varlink_server,
                        "io.systemd.BpfProgsAndMaps.GetBpfProgsAndMaps", vl_method_get_bpf_progs_and_maps
        );
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/bpf", 0755);
        socket_path = "/run/systemd/bpf/io.systemd.Bpf";

        r = varlink_server_listen_address(m->varlink_server, socket_path, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        return 0;
}



static int monitor_bpf_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        usec_t usec_now;
        int r;

        assert(s);

        /* Collect BPF tax information */
        r = log_bpf_maps_and_progs(m);
        if (r < 0)
                return r;

        r = sd_event_now(sd_event_source_get_event(s), CLOCK_MONOTONIC, &usec_now);
        if (r < 0)
                return log_error_errno(r, "Failed to reset event timer: %m");

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
                return r;

        r = sd_event_source_set_exit_on_failure(s, true);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, "bpfd-timer");

        m->bpf_timer_event_source = TAKE_PTR(s);
        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_new(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_set_watchdog(m->event, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable watchdog handling, ignoring: %m");

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* manager_free(Manager *m) {
        int r;

        if (!m)
                return NULL;

        sd_event_unref(m->event);
        varlink_server_unref(m->varlink_server);

        r = write_string_file("/proc/sys/kernel/bpf_stats_enabled", "0", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to write '%s' to /proc/sys/kernel/bpf_stats_enabled, ignoring: %m", "0");


        return mfree(m);
}

int manager_start(Manager *m) {
        int r;

        r = dlopen_bpf();
        if (r < 0) {
                log_debug("Couldn't dlopen_bpf");
                return r;
        }

        r = write_string_file("/proc/sys/kernel/bpf_stats_enabled", "1", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to write '%s' to /proc/sys/kernel/bpf_stats_enabled, ignoring: %m", "1");

        assert(m);
        assert (m->event);

        r = manager_bind_varlink(m);
        if (r < 0)
                return r;

        r = monitor_bpf(m);
        if (r < 0)
                return r;

        return 0;
}

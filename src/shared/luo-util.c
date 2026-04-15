/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/liveupdate.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "json-util.h"
#include "log.h"
#include "luo-util.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"

/* Kernel API defined at https://docs.kernel.org/next/userspace-api/liveupdate.html The /dev/liveupdate is a
 * single-owner singleton, only a single process at any given time can open it. Callers can create named
 * "sessions", and then add FDs to them. The session name can be used to retrieve the session after reboot.
 * To identify an FD, a 64bit token (what we would call an 'index' in our codebase) is passed in, and the
 * caller is responsible for coming up with the token and tracking them. */

int luo_open_device(void) {
        return RET_NERRNO(open("/dev/liveupdate", O_RDWR|O_CLOEXEC));
}

int luo_create_session(int device_fd, const char *name) {
        struct liveupdate_ioctl_create_session args = {
                .size = sizeof(args),
        };
        int r;

        assert(device_fd >= 0);
        assert(name);

        if (strlen(name) >= LIVEUPDATE_SESSION_NAME_LENGTH)
                return -ENAMETOOLONG;

        strncpy_exact((char *) args.name, name, sizeof(args.name));

        if (ioctl(device_fd, LIVEUPDATE_IOCTL_CREATE_SESSION, &args) < 0)
                return -errno;

        /* The kernel struct does not have a flags field for O_CLOEXEC, set it manually. */
        r = fd_cloexec(args.fd, true);
        if (r < 0) {
                safe_close(args.fd);
                return r;
        }

        return args.fd;
}

int luo_retrieve_session(int device_fd, const char *name) {
        struct liveupdate_ioctl_retrieve_session args = {
                .size = sizeof(args),
        };
        int r;

        assert(device_fd >= 0);
        assert(name);

        if (strlen(name) >= LIVEUPDATE_SESSION_NAME_LENGTH)
                return -ENAMETOOLONG;

        strncpy_exact((char *) args.name, name, sizeof(args.name));

        if (ioctl(device_fd, LIVEUPDATE_IOCTL_RETRIEVE_SESSION, &args) < 0)
                return -errno;

        r = fd_cloexec(args.fd, true);
        if (r < 0) {
                safe_close(args.fd);
                return r;
        }

        return args.fd;
}

int luo_session_preserve_fd(int session_fd, int fd, uint64_t token) {
        struct liveupdate_session_preserve_fd args = {
                .size = sizeof(args),
                .fd = fd,
                .token = token,
        };

        assert(session_fd >= 0);
        assert(fd >= 0);

        return RET_NERRNO(ioctl(session_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &args));
}

int luo_session_retrieve_fd(int session_fd, uint64_t token) {
        struct liveupdate_session_retrieve_fd args = {
                .size = sizeof(args),
                .token = token,
        };
        int r;

        assert(session_fd >= 0);

        if (ioctl(session_fd, LIVEUPDATE_SESSION_RETRIEVE_FD, &args) < 0)
                return -errno;

        r = fd_cloexec(args.fd, true);
        if (r < 0) {
                safe_close(args.fd);
                return r;
        }

        return args.fd;
}

int luo_session_finish(int session_fd) {
        struct liveupdate_session_finish args = {
                .size = sizeof(args),
        };

        assert(session_fd >= 0);

        return RET_NERRNO(ioctl(session_fd, LIVEUPDATE_SESSION_FINISH, &args));
}

int luo_parse_serialization(sd_json_variant **ret, int **ret_fds, size_t *ret_n_fds) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *root = NULL;
        _cleanup_free_ int *fd_list = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t n_fds = 0;
        int serialize_fd = -EBADF, r;

        assert(ret);
        assert(ret_fds);
        assert(ret_n_fds);

        const char *luo_fd_str = getenv("SYSTEMD_LUO_SERIALIZE_FD");
        if (!luo_fd_str) {
                *ret = NULL;
                *ret_fds = NULL;
                *ret_n_fds = 0;
                return 0;
        }

        r = safe_atoi(luo_fd_str, &serialize_fd);
        if (r < 0 || serialize_fd < 0)
                return log_warning_errno(r < 0 ? r : SYNTHETIC_ERRNO(EBADF),
                                         "Failed to parse SYSTEMD_LUO_SERIALIZE_FD='%s', ignoring: %m", luo_fd_str);

        r = fdopen_independent(serialize_fd, "r", &f);
        if (r < 0)
                return log_warning_errno(r, "Failed to open LUO serialization fd %d: %m", serialize_fd);

        r = sd_json_parse_file(f, /* path= */ NULL, SD_JSON_PARSE_MUST_BE_OBJECT, &root, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse LUO serialization JSON: %m");

        /* Collect all fd numbers referenced in the JSON (plus the serialization fd itself)
         * so the caller can protect them from close_all_fds(). */
        const char *cgroup_path _unused_;
        sd_json_variant *unit_entries;

        JSON_VARIANT_OBJECT_FOREACH(cgroup_path, unit_entries, root) {
                sd_json_variant *entry;

                JSON_VARIANT_ARRAY_FOREACH(entry, unit_entries) {
                        sd_json_variant *fd_json = sd_json_variant_by_key(entry, "fd_index");
                        if (!fd_json || !sd_json_variant_is_integer(fd_json))
                                continue;

                        int fd = (int) sd_json_variant_integer(fd_json);
                        if (fd < 0)
                                continue;

                        if (!GREEDY_REALLOC(fd_list, n_fds + 1))
                                return log_oom();

                        fd_list[n_fds++] = fd;
                }
        }

        /* Also protect the serialization fd itself */
        if (!GREEDY_REALLOC(fd_list, n_fds + 1))
                return log_oom();
        fd_list[n_fds++] = serialize_fd;

        log_debug("Parsed LUO serialization with %zu fd(s) to preserve.", n_fds);

        *ret = TAKE_PTR(root);
        *ret_fds = TAKE_PTR(fd_list);
        *ret_n_fds = n_fds;
        return 0;
}

int luo_preserve_fd_stores(sd_json_variant *serialization, int *ret_session_fd) {
        _cleanup_close_ int device_fd = -EBADF, session_fd = -EBADF;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mapping = NULL;
        const char *cgroup_path;
        sd_json_variant *entries;
        uint64_t fd_index = LUO_MAPPING_INDEX + 1;
        int r;

        assert(ret_session_fd);

        if (!serialization) {
                *ret_session_fd = -EBADF;
                return 0; /* No LUO serialization, nothing to preserve */
        }

        device_fd = luo_open_device();
        if (device_fd == -ENOENT) {
                *ret_session_fd = -EBADF;
                return 0; /* LUO not supported, ignore */
        }
        if (device_fd < 0)
                return log_error_errno(device_fd, "Failed to open /dev/liveupdate: %m");

        session_fd = luo_create_session(device_fd, LUO_SESSION_NAME);
        if (session_fd < 0)
                return log_error_errno(session_fd, "Failed to create LUO session '%s': %m", LUO_SESSION_NAME);

        /* Build the mapping JSON for the new kernel's PID 1 and preserve each fd.
         * JSON format:   { "cgroup": [ {"type": "fd", "name": "...", "fd_index": N},
         *                              {"type": "luo_session", "name": "...", "session_name": "..."} ], ... }
         *
         * For regular fds: type=fd, preserved in the systemd session with the given fd_index.
         * For LUO session fds: type=luo_session, the session survives kexec independently, as it cannot be
         * nested. */
        JSON_VARIANT_OBJECT_FOREACH(cgroup_path, entries, serialization) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fd_list = NULL;
                sd_json_variant *entry;

                JSON_VARIANT_ARRAY_FOREACH(entry, entries) {
                        sd_json_variant *fd_json, *name_json, *type_json;
                        const char *type, *name;
                        int fd;

                        type_json = sd_json_variant_by_key(entry, "type");
                        name_json = sd_json_variant_by_key(entry, "name");
                        fd_json = sd_json_variant_by_key(entry, "fd_index");
                        if (!type_json || !sd_json_variant_is_string(type_json) ||
                            !name_json || !sd_json_variant_is_string(name_json) ||
                            !fd_json || !sd_json_variant_is_integer(fd_json))
                                continue;

                        type = sd_json_variant_string(type_json);
                        name = sd_json_variant_string(name_json);
                        fd = (int) sd_json_variant_integer(fd_json);
                        if (fd < 0) {
                                log_warning("LUO mapping for cgroup '%s' fd '%s': negative fd_index %i, skipping.", cgroup_path, name, fd);
                                continue;
                        }

                        if (streq(type, "fd")) {
                                /* Regular fd, preserve in the systemd session */
                                r = luo_session_preserve_fd(session_fd, fd, fd_index);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to preserve LUO fd %i (name '%s') with fd_index %" PRIu64 ", will be lost across kexec: %m", fd, name, fd_index);
                                        continue;
                                }

                                r = sd_json_variant_append_arraybo(
                                                &fd_list,
                                                SD_JSON_BUILD_PAIR_STRING("type", "fd"),
                                                SD_JSON_BUILD_PAIR_STRING("name", name),
                                                SD_JSON_BUILD_PAIR_UNSIGNED("fd_index", fd_index));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to build LUO mapping: %m");

                                ++fd_index;
                        } else if (streq(type, "luo_session")) {
                                sd_json_variant *sname_json = sd_json_variant_by_key(entry, "session_name");
                                if (!sname_json || !sd_json_variant_is_string(sname_json)) {
                                        log_warning("LUO mapping for cgroup '%s' fd '%s': missing or invalid session_name, skipping.", cgroup_path, name);
                                        continue;
                                }

                                /* Remember the FDStore name to session name mapping */
                                r = sd_json_variant_append_arraybo(
                                                &fd_list,
                                                SD_JSON_BUILD_PAIR_STRING("type", "luo_session"),
                                                SD_JSON_BUILD_PAIR_STRING("name", name),
                                                SD_JSON_BUILD_PAIR_STRING("session_name", sd_json_variant_string(sname_json)));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to build LUO mapping for session fd: %m");

                                log_debug("LUO session fd '%s' (session '%s') recorded in mapping.",
                                          name, sd_json_variant_string(sname_json));
                        } else
                                log_warning("Unknown fd type '%s' for cgroup '%s' fd '%s', skipping.", type, cgroup_path, name);
                }

                if (fd_list) {
                        r = sd_json_variant_set_field(&mapping, cgroup_path, fd_list);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add cgroup to LUO mapping: %m");
                }
        }

        if (!mapping) {
                log_debug("No fds were preserved in LUO session.");
                *ret_session_fd = -EBADF;
                return 0;
        }

        /* Store the mapping as a memfd at fd_index 0 */
        _cleanup_free_ char *mapping_text = NULL;

        r = sd_json_variant_format(mapping, /* flags= */ 0, &mapping_text);
        if (r < 0)
                return log_error_errno(r, "Failed to format LUO mapping JSON: %m");

        _cleanup_close_ int mapping_fd = -EBADF;

        mapping_fd = memfd_new_and_seal_string("luo-mapping", mapping_text);
        if (mapping_fd < 0)
                return log_error_errno(mapping_fd, "Failed to create LUO mapping memfd: %m");

        r = luo_session_preserve_fd(session_fd, mapping_fd, LUO_MAPPING_INDEX);
        if (r < 0)
                return log_error_errno(r, "Failed to preserve LUO mapping memfd: %m");

        log_info("Preserved fd stores in LUO session '%s' for kexec.", LUO_SESSION_NAME);

        /* Return the session fd to the caller as it must stay open until the kexec syscall,
         * otherwise the kernel discards the session. */
        *ret_session_fd = TAKE_FD(session_fd);
        return 1;
}

static int fd_get_luo_session_path(int fd, char **ret) {
        _cleanup_free_ char *path = NULL;
        struct statfs sfs;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        // TODO: switch to LUO specific inode magic once available
        if (!F_TYPE_EQUAL(sfs.f_type, ANON_INODE_FS_MAGIC))
                return -EMEDIUMTYPE;

        r = fd_get_path(fd, &path);
        if (r < 0)
                return r;

        if (!startswith(path, "anon_inode:[luo_session]"))
                return -EMEDIUMTYPE;

        *ret = TAKE_PTR(path);
        return 0;
}

int fd_is_luo_session(int fd) {
        _cleanup_free_ char *path = NULL;
        int r;

        r = fd_get_luo_session_path(fd, &path);
        if (r == -EMEDIUMTYPE)
                return false;
        if (r < 0)
                return r;

        return true;
}

int fd_get_luo_session_name(int fd, char **ret) {
        _cleanup_free_ char *path = NULL;
        const char *name;
        int r;

        assert(ret);

        r = fd_get_luo_session_path(fd, &path);
        if (r < 0)
                return r;

        /* Path is "anon_inode:[luo_session] <session_name>" */
        name = startswith(path, "anon_inode:[luo_session] ");
        if (!name)
                return -EMEDIUMTYPE; /* Has no session name suffix */

        return strdup_to(ret, name);
}

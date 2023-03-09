/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "argv-util.h"
#include "chase.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "main-func.h"
#include "missing_loop.h"
#include "namespace-util.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "user-util.h"
#include "varlink.h"
#include "varlink-io.systemd.MountFileSystem.h"

/* When we use F_GETFL to get file flags, this will likely contain O_LARGEFILE set, but glibc defines that to
 * 0 if we are compiling in _LARGEFILE64_SOURCE mode on archs that by default have a 32bit off_t. Let's hence
 * define our own macro for this, in this case */
#if O_LARGEFILE != 0
#define RAW_O_LARGEFILE O_LARGEFILE
#else
#define RAW_O_LARGEFILE 0100000
#endif

#define ITERATIONS_MAX 64U
#define RUNTIME_MAX_USEC (5 * USEC_PER_MINUTE)
#define PRESSURE_SLEEP_TIME_USEC (50 * USEC_PER_MSEC)
#define CONNECTION_IDLE_USEC (15 * USEC_PER_SEC)
#define LISTEN_IDLE_USEC (90 * USEC_PER_SEC)

static const ImagePolicy image_policy_untrusted = {
        .n_policies = 2,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

static int allowlist_mount(int userns_fd, int mount_fd) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        const char *error_id;
        int r, userns_fd_idx, mount_fd_idx;

        assert(userns_fd >= 0);
        assert(mount_fd >= 0);

        r = varlink_connect_address(&vl, "/run/systemd/userdb/io.systemd.UserRegistry");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to userdb registry: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable varlink fd passing for read: %m");

        userns_fd_idx = varlink_dup_fd(vl, userns_fd);
        if (userns_fd_idx < 0)
                return log_error_errno(userns_fd_idx, "Failed to push userns fd into varlink connection: %m");

        mount_fd_idx = varlink_dup_fd(vl, mount_fd);
        if (mount_fd_idx < 0)
                return log_error_errno(mount_fd_idx, "Failed to push mount fd into varlink connection: %m");

        r = varlink_callb(vl,
                          "io.systemd.UserRegistry.AddMountToUserNamespace",
                          NULL,
                          &error_id,
                          /* ret_flags= */ NULL,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("userNamespaceFileDescriptor", JSON_BUILD_UNSIGNED(userns_fd_idx)),
                                          JSON_BUILD_PAIR("mountFileDescriptor", JSON_BUILD_UNSIGNED(mount_fd_idx))));
        if (r < 0)
                return log_error_errno(r, "Failed to call AddMountToUserNamespace() varlink call.");
        if (streq_ptr(error_id, "io.systemd.UserRegistry.UserNamespaceNotRegistered")) {
                log_notice("User namespace has not been allocated via UserRegistry, not adding mount to registration.");
                return 0;
        }
        if (!isempty(error_id))
                return log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Failed to mount image: %s", error_id);

        return 1;
}

static int json_dispatch_image_policy(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        _cleanup_(image_policy_freep) ImagePolicy *q = NULL;
        ImagePolicy **p = ASSERT_PTR(userdata);
        int r;

        assert(p);

        if (json_variant_is_null(variant)) {
                *p = image_policy_free(*p);
                return 0;
        }

        if (!json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = image_policy_from_string(json_variant_string(variant), &q);
        if (r < 0)
                return json_log(variant, flags, r, "JSON field '%s' is not a valid image policy.", strna(name));

        image_policy_free(*p);
        *p = TAKE_PTR(q);
        return 0;
}

typedef struct MountImageParameters {
        unsigned image_fd_idx;
        unsigned userns_fd_idx;
        int read_only;
        int growfs;
        char *password;
        ImagePolicy *image_policy;
} MountImageParameters;

static void mount_image_parameters_done(MountImageParameters *p) {
        assert(p);

        erase_and_free(p->password);
        image_policy_free(p->image_policy);
}

static int verify_safe_image_fd(int fd, MountImageParameters *p) {
        int r, fl;

        assert(fd >= 0);
        assert(p);

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        fl = fcntl(fd, F_GETFL);
        if (fl < 0)
                return -errno;

        switch (fl & O_ACCMODE) {

        case O_RDONLY:
                p->read_only = true;
                break;

        case O_RDWR:
                break;

        default:
                return -EBADF;
        }

        /* Refuse fds with unexpected flags. In paticular we don't want to allow O_PATH fds, since with those
         * it's not guarantee the client actually has access to the file */
        if ((fl & ~(O_ACCMODE|RAW_O_LARGEFILE)) != 0)
                return -EBADF;

        return 0;
}

static int verify_trusted_image_fd_by_path(int fd) {
        _cleanup_free_ char *p = NULL;
        struct stat sta;
        int r;

        assert(fd >= 0);

        r = fd_get_path(fd, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to get path of passed image file descriptor: %m");
        if (fstat(fd, &sta) < 0)
                return log_debug_errno(errno, "Failed to stat() passed image file descriptor: %m");

        for (ImageClass c = 0; c < _IMAGE_CLASS_MAX; c++)
                NULSTR_FOREACH(s, image_search_path[c]) {
                        _cleanup_close_ int dir_fd = -EBADF, inode_fd = -EBADF;
                        _cleanup_free_ char *q = NULL;
                        struct stat stb;
                        const char *e;

                        r = chase(s, NULL, CHASE_SAFE, &q, &dir_fd);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0) {
                                log_warning_errno(r, "Failed to resolve search path '%s', ignoring: %m", s);
                                continue;
                        }

                        e = path_startswith(p, q);
                        if (isempty(e))
                                continue;

                        r = chaseat(dir_fd, e, CHASE_SAFE, NULL, &inode_fd);
                        if (r < 0)
                                return log_error_errno(r, "Couldn't verify that specified image '%s' is in search path '%s': %m", p, s);

                        if (fstat(inode_fd, &stb) < 0)
                                return log_error_errno(errno, "Failed to stat image file '%s/%s': %m", q, e);

                        if (stat_inode_same(&sta, &stb))
                                return true; /* Yay */
                }

        return false;
}

static int determine_image_policy(
                int image_fd,
                uid_t peer_uid,
                ImagePolicy *client_policy,
                ImagePolicy **ret) {

        _cleanup_(image_policy_freep) ImagePolicy *envvar_policy = NULL;
        const ImagePolicy *default_policy;
        const char *envvar, *e;
        bool trusted;
        int r;

        assert(image_fd >= 0);
        assert(ret);

        /* An image is considered "trusted" if client is root, or located in trusted path */
        if (peer_uid == 0)
                trusted = true;
        else {
                r = verify_trusted_image_fd_by_path(image_fd);
                if (r < 0)
                        return r;

                trusted = r;
        }

        if (trusted) {
                envvar = "SYSTEMD_IMAGE_POLICY_TRUSTED";
                default_policy = &image_policy_allow;
        } else {
                envvar = "SYSTEMD_IMAGE_POLICY_UNTRUSTED";
                default_policy = &image_policy_untrusted;
        }

        e = getenv(envvar);
        if (e) {
                r = image_policy_from_string(e, &envvar_policy);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse image policy supplied via $%s: %m", envvar);

                default_policy = envvar_policy;
        }

        return image_policy_intersect(default_policy, client_policy, ret);
}

static int vl_method_mount_image(
                Varlink *link,
                JsonVariant *parameters,
                VarlinkMethodFlags flags,
                void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "imageFileDescriptor",         JSON_VARIANT_UNSIGNED, json_dispatch_uint,         offsetof(MountImageParameters, image_fd_idx),  JSON_MANDATORY },
                { "userNamespaceFileDescriptor", JSON_VARIANT_UNSIGNED, json_dispatch_uint,         offsetof(MountImageParameters, userns_fd_idx), 0 },
                { "readOnly",                    JSON_VARIANT_BOOLEAN,  json_dispatch_tristate,     offsetof(MountImageParameters, read_only),     0 },
                { "growFileSystems",             JSON_VARIANT_BOOLEAN,  json_dispatch_tristate,     offsetof(MountImageParameters, growfs),        0 },
                { "password",                    JSON_VARIANT_STRING,   json_dispatch_string,       offsetof(MountImageParameters, password),      0 },
                { "imagePolicy",                 JSON_VARIANT_STRING,   json_dispatch_image_policy, offsetof(MountImageParameters, image_policy),  0 },
                {}
        };

        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        _cleanup_(mount_image_parameters_done) MountImageParameters p = {
                .image_fd_idx = UINT_MAX,
                .userns_fd_idx = UINT_MAX,
                .read_only = -1,
                .growfs = -1,
        };
        _cleanup_(dissected_image_unrefp) DissectedImage *di = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *aj = NULL;
        _cleanup_close_ int image_fd = -EBADF, userns_fd = -EBADF;
        _cleanup_(image_policy_freep) ImagePolicy *use_policy = NULL;
        _cleanup_free_ char *ps = NULL;
        uid_t peer_uid;
        int r;

        assert(link);
        assert(parameters);

        json_variant_sensitive(parameters); /* might contain passwords */

        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r < 0)
                return r;

        if (p.image_fd_idx != UINT_MAX) {
                image_fd = varlink_take_fd(link, p.image_fd_idx);
                if (image_fd < 0)
                        return image_fd;
        }

        if (p.userns_fd_idx != UINT_MAX) {
                userns_fd = varlink_take_fd(link, p.userns_fd_idx);
                if (userns_fd < 0)
                        return userns_fd;
        }

        r = verify_safe_image_fd(image_fd, &p);
        if (r < 0)
                return r;

        if (userns_fd >= 0) {
                r = fd_is_ns(userns_fd, CLONE_NEWUSER);
                if (r < 0)
                        return r;
                if (r == 0)
                        return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

                /* Our own host user namespace? Then close the fd, and handle it as if none was specified. */
                r = is_our_namespace(userns_fd, NAMESPACE_USER);
                if (r < 0)
                        return r;
                if (r > 0)
                        userns_fd = safe_close(userns_fd);
        }

        /* If this is the host userns, refuse mounting from unprivileged clients */
        if (userns_fd < 0 && peer_uid != 0)
                return varlink_error(link, VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = determine_image_policy(image_fd, peer_uid, p.image_policy, &use_policy);
        if (r < 0)
                return r;

        r = image_policy_to_string(use_policy, /* simplify= */ true, &ps);
        if (r < 0)
                return r;

        log_debug("Using image policy: %s", ps);

        DissectImageFlags dissect_flags =
                (p.read_only == 0 ? DISSECT_IMAGE_READ_ONLY : 0) |
                (p.growfs != 0 ? DISSECT_IMAGE_GROWFS : 0) |
                DISSECT_IMAGE_DISCARD_ANY |
                DISSECT_IMAGE_FSCK |
                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                DISSECT_IMAGE_PIN_PARTITION_DEVICES;

        r = loop_device_make(
                        image_fd,
                        p.read_only == 0 ? O_RDONLY : O_RDWR,
                        0,
                        UINT64_MAX,
                        UINT32_MAX,
                        LO_FLAGS_PARTSCAN,
                        LOCK_EX,
                        &loop);
        if (r < 0)
                return r;

        r = dissect_loop_device(
                        loop,
                        &verity,
                        /* mount_options= */ NULL,
                        use_policy,
                        dissect_flags,
                        &di);
        if (r == -ENOPKG)
                return varlink_error(link, "io.systemd.MountFileSystem.IncompatibleImage", NULL);
        if (r == -ENOTUNIQ)
                return varlink_error(link, "io.systemd.MountFileSystem.MultipleRootPartitionsFound", NULL);
        if (r == -ENXIO)
                return varlink_error(link, "io.systemd.MountFileSystem.RootPartitionNotFound", NULL);
        if (r == -ERFKILL)
                return varlink_error(link, "io.systemd.MountFileSystem.DeniedByImagePolicy", NULL);
        if (r < 0)
                return r;

        r = dissected_image_load_verity_sig_partition(
                        di,
                        loop->fd,
                        &verity);
        if (r < 0)
                return r;

        r = dissected_image_decrypt(
                        di,
                        p.password,
                        &verity,
                        dissect_flags);
        if (r < 0)
                return r;

        r = dissected_image_mount(
                        di,
                        /* where= */ NULL,
                        /* uid_shift= */ UID_INVALID,
                        /* uid_range= */ UID_INVALID,
                        userns_fd,
                        dissect_flags);
        if (r < 0)
                return r;

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                _cleanup_(json_variant_unrefp) JsonVariant *pj = NULL;
                DissectedPartition *pp = di->partitions + d;
                int fd_idx;

                if (!pp->found)
                        continue;

                if (pp->fsmount_fd < 0)
                        continue;

                if (userns_fd >= 0) {
                        r = allowlist_mount(userns_fd, pp->fsmount_fd);
                        if (r < 0)
                                return r;
                }

                fd_idx = varlink_push_fd(link, pp->fsmount_fd);
                if (fd_idx < 0)
                        return fd_idx;

                TAKE_FD(pp->fsmount_fd);

                r = json_build(&pj,
                               JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("designator", JSON_BUILD_STRING(partition_designator_to_string(d))),
                                               JSON_BUILD_PAIR("writable", JSON_BUILD_BOOLEAN(pp->rw)),
                                               JSON_BUILD_PAIR("growFileSystem", JSON_BUILD_BOOLEAN(pp->growfs)),
                                               JSON_BUILD_PAIR_CONDITION(pp->partno > 0, "partitionNumber", JSON_BUILD_INTEGER(pp->partno)),
                                               JSON_BUILD_PAIR_CONDITION(pp->architecture > 0, "architecture", JSON_BUILD_STRING(architecture_to_string(pp->architecture))),
                                               JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(pp->uuid), "partitionUuid", JSON_BUILD_UUID(pp->uuid)),
                                               JSON_BUILD_PAIR("fileSystemType", JSON_BUILD_STRING(dissected_partition_fstype(pp))),
                                               JSON_BUILD_PAIR_CONDITION(pp->label, "partitionLabel", JSON_BUILD_STRING(pp->label)),
                                               JSON_BUILD_PAIR("size", JSON_BUILD_INTEGER(pp->size)),
                                               JSON_BUILD_PAIR("offset", JSON_BUILD_INTEGER(pp->offset)),
                                               JSON_BUILD_PAIR("mountFileDescriptor", JSON_BUILD_INTEGER(fd_idx))));
                if (r < 0)
                        return r;

                r = json_variant_append_array(&aj, pj);
                if (r < 0)
                        return r;
        }

        loop_device_relinquish(loop);

        r = varlink_replyb(link, JSON_BUILD_OBJECT(
                                           JSON_BUILD_PAIR("partitions", JSON_BUILD_VARIANT(aj)),
                                           JSON_BUILD_PAIR("imagePolicy", JSON_BUILD_STRING(ps)),
                                           JSON_BUILD_PAIR("imageSize", JSON_BUILD_INTEGER(di->image_size)),
                                           JSON_BUILD_PAIR("sectorSize", JSON_BUILD_INTEGER(di->sector_size)),
                                           JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(di->image_uuid), "imageUuid", JSON_BUILD_UUID(di->image_uuid))));
        if (r < 0)
                return r;

        return r;
}

static int process_connection(VarlinkServer *server, int _fd) {
        _cleanup_close_ int fd = TAKE_FD(_fd); /* always take possesion */
        _cleanup_(varlink_close_unrefp) Varlink *vl = NULL;
        int r;

        r = varlink_server_add_connection(server, fd, &vl);
        if (r < 0)
                return log_error_errno(r, "Failed to add connection: %m");

        TAKE_FD(fd);
        vl = varlink_ref(vl);

        r = varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for read: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for write: %m");

        for (;;) {
                r = varlink_process(vl);
                if (r == -ENOTCONN) {
                        log_debug("Connection terminated.");
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to process connection: %m");
                if (r > 0)
                        continue;

                r = varlink_wait(vl, CONNECTION_IDLE_USEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for connection events: %m");
                if (r == 0)
                        break;
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        usec_t start_time, listen_idle_usec, last_busy_usec = USEC_INFINITY;
        _cleanup_(varlink_server_unrefp) VarlinkServer *server = NULL;
        _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;
        unsigned n_iterations = 0;
        int m, listen_fd, r;

        log_setup();

        m = sd_listen_fds(false);
        if (m < 0)
                return log_error_errno(m, "Failed to determine number of listening fds: %m");
        if (m == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No socket to listen on received.");
        if (m > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Worker can only listen on a single socket at a time.");

        listen_fd = SD_LISTEN_FDS_START;

        r = fd_nonblock(listen_fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to turn off non-blocking mode for listening socket: %m");

        r = varlink_server_new(&server, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate server: %m");

        r = varlink_server_add_interface(server, &vl_interface_io_systemd_MountFileSystem);
        if (r < 0)
                return log_error_errno(r, "Failed to add MountFileSystem interface to varlink server: %m");

        r = varlink_server_bind_method_many(
                        server,
                        "io.systemd.MountFileSystem.MountImage",vl_method_mount_image);
        if (r < 0)
                return log_error_errno(r, "Failed to bind methods: %m");

        r = getenv_bool("MNTFS_FIXED_WORKER");
        if (r < 0)
                return log_error_errno(r, "Failed to parse MNTFSD_FIXED_WORKER: %m");
        listen_idle_usec = r ? USEC_INFINITY : LISTEN_IDLE_USEC;

        r = pidref_set_parent(&parent);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire pidfd of parent process: %m");

        start_time = now(CLOCK_MONOTONIC);

        for (;;) {
                _cleanup_close_ int fd = -EBADF;
                usec_t n;

                /* Exit the worker in regular intervals, to flush out all memory use */
                if (n_iterations++ > ITERATIONS_MAX) {
                        log_debug("Exiting worker, processed %u iterations, that's enough.", n_iterations);
                        break;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= usec_add(start_time, RUNTIME_MAX_USEC)) {
                        log_debug("Exiting worker, ran for %s, that's enough.",
                                  FORMAT_TIMESPAN(usec_sub_unsigned(n, start_time), 0));
                        break;
                }

                if (last_busy_usec == USEC_INFINITY)
                        last_busy_usec = n;
                else if (listen_idle_usec != USEC_INFINITY && n >= usec_add(last_busy_usec, listen_idle_usec)) {
                        log_debug("Exiting worker, been idle for %s.",
                                  FORMAT_TIMESPAN(usec_sub_unsigned(n, last_busy_usec), 0));
                        break;
                }

                (void) rename_process("systemd-mntwork: waiting...");
                fd = RET_NERRNO(accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC));
                (void) rename_process("systemd-mntwork: processing...");

                if (fd == -EAGAIN)
                        continue; /* The listening socket has SO_RECVTIMEO set, hence a timeout is expected
                                   * after a while, let's check if it's time to exit though. */
                if (fd == -EINTR)
                        continue; /* Might be that somebody attached via strace, let's just continue in that
                                   * case */
                if (fd < 0)
                        return log_error_errno(fd, "Failed to accept() from listening socket: %m");

                if (now(CLOCK_MONOTONIC) <= usec_add(n, PRESSURE_SLEEP_TIME_USEC)) {
                        /* We only slept a very short time? If so, let's see if there are more sockets
                         * pending, and if so, let's ask our parent for more workers */

                        r = fd_wait_for_event(listen_fd, POLLIN, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test for POLLIN on listening socket: %m");

                        if (FLAGS_SET(r, POLLIN)) {
                                r = pidref_kill(&parent, SIGUSR2);
                                if (r == -ESRCH)
                                        return log_error_errno(r, "Parent already died?");
                                if (r < 0)
                                        return log_error_errno(r, "Failed to send SIGUSR2 signal to parent. %m");
                        }
                }

                (void) process_connection(server, TAKE_FD(fd));
                last_busy_usec = USEC_INFINITY;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);

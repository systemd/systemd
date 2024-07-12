/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-varlink.h"

#include "argv-util.h"
#include "bus-polkit.h"
#include "chase.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "json-util.h"
#include "main-func.h"
#include "missing_loop.h"
#include "namespace-util.h"
#include "nsresource.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "user-util.h"
#include "varlink-io.systemd.MountFileSystem.h"

#define ITERATIONS_MAX 64U
#define RUNTIME_MAX_USEC (5 * USEC_PER_MINUTE)
#define PRESSURE_SLEEP_TIME_USEC (50 * USEC_PER_MSEC)
#define LISTEN_IDLE_USEC (90 * USEC_PER_SEC)

static const ImagePolicy image_policy_untrusted = {
        .n_policies = 2,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

static int json_dispatch_image_policy(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        _cleanup_(image_policy_freep) ImagePolicy *q = NULL;
        ImagePolicy **p = ASSERT_PTR(userdata);
        int r;

        assert(p);

        if (sd_json_variant_is_null(variant)) {
                *p = image_policy_free(*p);
                return 0;
        }

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        r = image_policy_from_string(sd_json_variant_string(variant), &q);
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

        p->password = erase_and_free(p->password);
        p->image_policy = image_policy_free(p->image_policy);
}

static int validate_image_fd(int fd, MountImageParameters *p) {
        int r, fl;

        assert(fd >= 0);
        assert(p);

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        fl = fd_verify_safe_flags(fd);
        if (fl < 0)
                return log_debug_errno(fl, "Image file descriptor has unsafe flags set: %m");

        switch (fl & O_ACCMODE) {

        case O_RDONLY:
                p->read_only = true;
                break;

        case O_RDWR:
                break;

        default:
                return -EBADF;
        }

        return 0;
}

static int verify_trusted_image_fd_by_path(int fd) {
        _cleanup_free_ char *p = NULL;
        struct stat sta;
        int r;

        assert(fd >= 0);

        r = secure_getenv_bool("SYSTEMD_MOUNTFSD_TRUSTED_DIRECTORIES");
        if (r == -ENXIO)  {
                if (!DEFAULT_MOUNTFSD_TRUSTED_DIRECTORIES) {
                        log_debug("Trusted directory mechanism disabled at compile time.");
                        return false;
                }
        } else if (r < 0) {
                log_debug_errno(r, "Failed to parse $SYSTEMD_MOUNTFSD_TRUSTED_DIRECTORIES environment variable, not trusting any image.");
                return false;
        } else if (!r) {
                log_debug("Trusted directory mechanism disabled via $SYSTEMD_MOUNTFSD_TRUSTED_DIRECTORIES environment variable.");
                return false;
        }

        r = fd_get_path(fd, &p);
        if (r < 0)
                return log_debug_errno(r, "Failed to get path of passed image file descriptor: %m");
        if (fstat(fd, &sta) < 0)
                return log_debug_errno(errno, "Failed to stat() passed image file descriptor: %m");

        log_debug("Checking if image '%s' is in trusted directories.", p);

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

                        /* Check that the inode refers to a file immediately inside the image directory,
                         * i.e. not the image directory itself, and nothing further down the tree */
                        e = path_startswith(p, q);
                        if (isempty(e))
                                continue;

                        e += strspn(e, "/");
                        if (!filename_is_valid(e))
                                continue;

                        r = chaseat(dir_fd, e, CHASE_SAFE, NULL, &inode_fd);
                        if (r < 0)
                                return log_error_errno(r, "Couldn't verify that specified image '%s' is in search path '%s': %m", p, s);

                        if (fstat(inode_fd, &stb) < 0)
                                return log_error_errno(errno, "Failed to stat image file '%s/%s': %m", q, e);

                        if (stat_inode_same(&sta, &stb)) {
                                log_debug("Image '%s' is *in* trusted directories.", p);
                                return true; /* Yay */
                        }
                }

        log_debug("Image '%s' is *not* in trusted directories.", p);
        return false;
}

static int determine_image_policy(
                int image_fd,
                bool trusted,
                ImagePolicy *client_policy,
                ImagePolicy **ret) {

        _cleanup_(image_policy_freep) ImagePolicy *envvar_policy = NULL;
        const ImagePolicy *default_policy;
        const char *envvar, *e;
        int r;

        assert(image_fd >= 0);
        assert(ret);

        if (trusted) {
                envvar = "SYSTEMD_MOUNTFSD_IMAGE_POLICY_TRUSTED";
                default_policy = &image_policy_allow;
        } else {
                envvar = "SYSTEMD_MOUNTFSD_IMAGE_POLICY_UNTRUSTED";
                default_policy = &image_policy_untrusted;
        }

        e = secure_getenv(envvar);
        if (e) {
                r = image_policy_from_string(e, &envvar_policy);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse image policy supplied via $%s: %m", envvar);

                default_policy = envvar_policy;
        }

        return image_policy_intersect(default_policy, client_policy, ret);
}

static int validate_userns(sd_varlink *link, int *userns_fd) {
        int r;

        assert(link);
        assert(userns_fd);

        if (*userns_fd < 0)
                return 0;

        r = fd_verify_safe_flags(*userns_fd);
        if (r < 0)
                return log_debug_errno(r, "User namespace file descriptor has unsafe flags set: %m");

        r = fd_is_ns(*userns_fd, CLONE_NEWUSER);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        /* Our own host user namespace? Then close the fd, and handle it as if none was specified. */
        r = is_our_namespace(*userns_fd, NAMESPACE_USER);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if user namespace provided by client is our own.");
        if (r > 0) {
                log_debug("User namespace provided by client is our own.");
                *userns_fd = safe_close(*userns_fd);
        }

        return 0;
}

static int vl_method_mount_image(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "imageFileDescriptor",         SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,      offsetof(MountImageParameters, image_fd_idx),  SD_JSON_MANDATORY },
                { "userNamespaceFileDescriptor", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,      offsetof(MountImageParameters, userns_fd_idx), 0 },
                { "readOnly",                    SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_tristate,  offsetof(MountImageParameters, read_only),     0 },
                { "growFileSystems",             SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_tristate,  offsetof(MountImageParameters, growfs),        0 },
                { "password",                    SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,    offsetof(MountImageParameters, password),      0 },
                { "imagePolicy",                 SD_JSON_VARIANT_STRING,   json_dispatch_image_policy, offsetof(MountImageParameters, image_policy),  0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *aj = NULL;
        _cleanup_close_ int image_fd = -EBADF, userns_fd = -EBADF;
        _cleanup_(image_policy_freep) ImagePolicy *use_policy = NULL;
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        _cleanup_free_ char *ps = NULL;
        bool image_is_trusted = false;
        uid_t peer_uid;
        int r;

        assert(link);
        assert(parameters);

        sd_json_variant_sensitive(parameters); /* might contain passwords */

        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get client UID: %m");

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.image_fd_idx != UINT_MAX) {
                image_fd = sd_varlink_peek_dup_fd(link, p.image_fd_idx);
                if (image_fd < 0)
                        return log_debug_errno(image_fd, "Failed to peek image fd from client: %m");
        }

        if (p.userns_fd_idx != UINT_MAX) {
                userns_fd = sd_varlink_peek_dup_fd(link, p.userns_fd_idx);
                if (userns_fd < 0)
                        return log_debug_errno(userns_fd, "Failed to peek user namespace fd from client: %m");
        }

        r = validate_image_fd(image_fd, &p);
        if (r < 0)
                return r;

        r = validate_userns(link, &userns_fd);
        if (r != 0)
                return r;

        r = verify_trusted_image_fd_by_path(image_fd);
        if (r < 0)
                return r;
        image_is_trusted = r;

        const char *polkit_details[] = {
                "read_only", one_zero(p.read_only > 0),
                NULL,
        };

        const char *polkit_action, *polkit_untrusted_action;
        PolkitFlags polkit_flags;
        if (userns_fd < 0) {
                /* Mount into the host user namespace */
                polkit_action = "io.systemd.mount-file-system.mount-image";
                polkit_untrusted_action = "io.systemd.mount-file-system.mount-untrusted-image";
                polkit_flags = 0;
        } else {
                /* Mount into a private user namespace */
                polkit_action = "io.systemd.mount-file-system.mount-image-privately";
                polkit_untrusted_action = "io.systemd.mount-file-system.mount-untrusted-image-privately";

                /* If polkit is not around, let's allow mounting authenticated images by default */
                polkit_flags = POLKIT_DEFAULT_ALLOW;
        }

        /* Let's definitely acquire the regular action privilege, for mounting properly signed images */
        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        polkit_action,
                        polkit_details,
                        /* good_user= */ UID_INVALID,
                        polkit_flags,
                        polkit_registry);
        if (r <= 0)
                return r;

        /* Generate the common dissection directory here. We are not going to use it, but the clients might,
         * and they likely are unprivileged, hence cannot create it themselves. Hence let's just create it
         * here, if it is missing. */
        r = get_common_dissect_directory(NULL);
        if (r < 0)
                return r;

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

        DissectImageFlags dissect_flags =
                (p.read_only == 0 ? DISSECT_IMAGE_READ_ONLY : 0) |
                (p.growfs != 0 ? DISSECT_IMAGE_GROWFS : 0) |
                DISSECT_IMAGE_DISCARD_ANY |
                DISSECT_IMAGE_FSCK |
                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                DISSECT_IMAGE_PIN_PARTITION_DEVICES |
                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY;

        /* Let's see if we have acquired the privilege to mount untrusted images already */
        bool polkit_have_untrusted_action =
                varlink_has_polkit_action(link, polkit_untrusted_action, polkit_details, polkit_registry);

        for (;;) {
                use_policy = image_policy_free(use_policy);
                ps = mfree(ps);

                /* We use the image policy for trusted images if either the path is below a trusted
                 * directory, or if we have already acquired a PK authentication that tells us that untrusted
                 * images are OK */
                bool use_trusted_policy =
                        image_is_trusted ||
                        polkit_have_untrusted_action;

                r = determine_image_policy(
                                image_fd,
                                use_trusted_policy,
                                p.image_policy,
                                &use_policy);
                if (r < 0)
                        return r;

                r = image_policy_to_string(use_policy, /* simplify= */ true, &ps);
                if (r < 0)
                        return r;

                log_debug("Using image policy: %s", ps);

                r = dissect_loop_device(
                                loop,
                                &verity,
                                /* mount_options= */ NULL,
                                use_policy,
                                dissect_flags,
                                &di);
                if (r == -ENOPKG)
                        return sd_varlink_error(link, "io.systemd.MountFileSystem.IncompatibleImage", NULL);
                if (r == -ENOTUNIQ)
                        return sd_varlink_error(link, "io.systemd.MountFileSystem.MultipleRootPartitionsFound", NULL);
                if (r == -ENXIO)
                        return sd_varlink_error(link, "io.systemd.MountFileSystem.RootPartitionNotFound", NULL);
                if (r == -ERFKILL) {
                        /* The image policy refused this, let's retry after trying to get PolicyKit */

                        if (!polkit_have_untrusted_action) {
                                log_debug("Denied by image policy. Trying a stronger polkit authentication before continuing.");
                                r = varlink_verify_polkit_async_full(
                                                link,
                                                /* bus= */ NULL,
                                                polkit_untrusted_action,
                                                polkit_details,
                                                /* good_user= */ UID_INVALID,
                                                /* flags= */ 0,                   /* NB: the image cannot be authenticated, hence unless PK is around to allow this anyway, fail! */
                                                polkit_registry);
                                if (r <= 0 && !ERRNO_IS_NEG_PRIVILEGE(r))
                                        return r;
                                if (r > 0) {
                                        /* Try again, now that we know the client has enough privileges. */
                                        log_debug("Denied by image policy, retrying after polkit authentication.");
                                        polkit_have_untrusted_action = true;
                                        continue;
                                }
                        }

                        return sd_varlink_error(link, "io.systemd.MountFileSystem.DeniedByImagePolicy", NULL);
                }
                if (r < 0)
                        return r;

                /* Success */
                break;
        }

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
        if (r == -ENOKEY) /* new dm-verity userspace returns ENOKEY if the dm-verity signature key is not in
                           * key chain. That's great. */
                return sd_varlink_error(link, "io.systemd.MountFileSystem.KeyNotFound", NULL);
        if (r == -EBUSY) /* DM kernel subsystem is shit with returning useful errors hence we keep retrying
                          * under the assumption that some errors are transitional. Which the errors might
                          * not actually be. After all retries failed we return EBUSY. Let's turn that into a
                          * generic Verity error. It's not very helpful, could mean anything, but at least it
                          * gives client a clear idea that this has to do with Verity. */
                return sd_varlink_error(link, "io.systemd.MountFileSystem.VerityFailure", NULL);
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
                DissectedPartition *pp = di->partitions + d;
                int fd_idx;

                if (!pp->found)
                        continue;

                if (pp->fsmount_fd < 0)
                        continue;

                if (userns_fd >= 0) {
                        r = nsresource_add_mount(userns_fd, pp->fsmount_fd);
                        if (r < 0)
                                return r;
                }

                fd_idx = sd_varlink_push_fd(link, pp->fsmount_fd);
                if (fd_idx < 0)
                        return fd_idx;

                TAKE_FD(pp->fsmount_fd);

                r = sd_json_variant_append_arraybo(
                                &aj,
                                SD_JSON_BUILD_PAIR("designator", SD_JSON_BUILD_STRING(partition_designator_to_string(d))),
                                SD_JSON_BUILD_PAIR("writable", SD_JSON_BUILD_BOOLEAN(pp->rw)),
                                SD_JSON_BUILD_PAIR("growFileSystem", SD_JSON_BUILD_BOOLEAN(pp->growfs)),
                                SD_JSON_BUILD_PAIR_CONDITION(pp->partno > 0, "partitionNumber", SD_JSON_BUILD_INTEGER(pp->partno)),
                                SD_JSON_BUILD_PAIR_CONDITION(pp->architecture > 0, "architecture", SD_JSON_BUILD_STRING(architecture_to_string(pp->architecture))),
                                SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(pp->uuid), "partitionUuid", SD_JSON_BUILD_UUID(pp->uuid)),
                                SD_JSON_BUILD_PAIR("fileSystemType", SD_JSON_BUILD_STRING(dissected_partition_fstype(pp))),
                                SD_JSON_BUILD_PAIR_CONDITION(!!pp->label, "partitionLabel", SD_JSON_BUILD_STRING(pp->label)),
                                SD_JSON_BUILD_PAIR("size", SD_JSON_BUILD_INTEGER(pp->size)),
                                SD_JSON_BUILD_PAIR("offset", SD_JSON_BUILD_INTEGER(pp->offset)),
                                SD_JSON_BUILD_PAIR("mountFileDescriptor", SD_JSON_BUILD_INTEGER(fd_idx)));
                if (r < 0)
                        return r;
        }

        loop_device_relinquish(loop);

        r = sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR("partitions", SD_JSON_BUILD_VARIANT(aj)),
                        SD_JSON_BUILD_PAIR("imagePolicy", SD_JSON_BUILD_STRING(ps)),
                        SD_JSON_BUILD_PAIR("imageSize", SD_JSON_BUILD_INTEGER(di->image_size)),
                        SD_JSON_BUILD_PAIR("sectorSize", SD_JSON_BUILD_INTEGER(di->sector_size)),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(di->image_uuid), "imageUuid", SD_JSON_BUILD_UUID(di->image_uuid)));
        if (r < 0)
                return r;

        return r;
}

static int process_connection(sd_varlink_server *server, int _fd) {
        _cleanup_close_ int fd = TAKE_FD(_fd); /* always take possession */
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *vl = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        r = sd_event_new(&event);
        if (r < 0)
                return r;

        r = sd_varlink_server_attach_event(server, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        r = sd_varlink_server_add_connection(server, fd, &vl);
        if (r < 0)
                return log_error_errno(r, "Failed to add connection: %m");

        TAKE_FD(fd);
        vl = sd_varlink_ref(vl);

        r = sd_varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for read: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for write: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        r = sd_varlink_server_detach_event(server);
        if (r < 0)
                return log_error_errno(r, "Failed to detach Varlink server from event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        usec_t start_time, listen_idle_usec, last_busy_usec = USEC_INFINITY;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(hashmap_freep) Hashmap *polkit_registry = NULL;
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

        r = sd_varlink_server_new(&server, SD_VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate server: %m");

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_MountFileSystem);
        if (r < 0)
                return log_error_errno(r, "Failed to add MountFileSystem interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        server,
                        "io.systemd.MountFileSystem.MountImage", vl_method_mount_image);
        if (r < 0)
                return log_error_errno(r, "Failed to bind methods: %m");

        sd_varlink_server_set_userdata(server, &polkit_registry);

        r = sd_varlink_server_set_exit_on_idle(server, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-idle mode: %m");

        r = getenv_bool("MOUNTFS_FIXED_WORKER");
        if (r < 0)
                return log_error_errno(r, "Failed to parse MOUNTFSD_FIXED_WORKER: %m");
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

                (void) rename_process("systemd-mountwork: waiting...");
                fd = RET_NERRNO(accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC));
                (void) rename_process("systemd-mountwork: processing...");

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

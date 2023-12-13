/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "nsresource.h"
#include "varlink.h"
#include "namespace-util.h"

int nsresource_allocate_userns(const char *name, uint64_t size) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        _cleanup_close_ int userns_fd = -EBADF;
        const char *error_id;
        int r, userns_fd_idx;

        /* Allocate a new dynamic user namespace via the userdb registry logic */

        assert(name);

        if (size <= 0 || size > UINT64_C(0x100000000)) /* Note: the server actually only allows allocating 1 or 64K right now */
                return -EINVAL;

        r = varlink_connect_address(&vl, "/run/systemd/userdb/io.systemd.NamespaceResource");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to namespace resource manager: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for write: %m");

        userns_fd = userns_acquire_empty();
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to acquire empty user namespace: %m");

        userns_fd_idx = varlink_dup_fd(vl, userns_fd);
        if (userns_fd_idx < 0)
                return log_debug_errno(userns_fd_idx, "Failed to push userns fd into varlink connection: %m");

        r = varlink_callb(vl,
                          "io.systemd.NamespaceResource.AllocateUserRange",
                          /* ret_reply= */ NULL,
                          &error_id,
                          /* ret_flags= */ NULL,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("name", JSON_BUILD_STRING(name)),
                                          JSON_BUILD_PAIR("size", JSON_BUILD_UNSIGNED(size)),
                                          JSON_BUILD_PAIR("userNamespaceFileDescriptor", JSON_BUILD_UNSIGNED(userns_fd_idx))));
        if (r < 0)
                return log_debug_errno(r, "Failed to call AllocateUserRange() varlink call.");
        if (!isempty(error_id))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOANO), "Failed to allocate user namespace with %" PRIu64 " users: %s", size, error_id);

        return TAKE_FD(userns_fd);
}

int nsresource_register_userns(const char *name, int userns_fd) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        _cleanup_close_ int _userns_fd = -EBADF;
        const char *error_id;
        int r, userns_fd_idx;

        /* Register the specified user namespace with userbd. */

        assert(name);

        if (userns_fd < 0) {
                _userns_fd = namespace_open_by_type(NAMESPACE_USER);
                if (_userns_fd < 0)
                        return -errno;

                userns_fd = _userns_fd;
        }

        r = varlink_connect_address(&vl, "/run/systemd/userdb/io.systemd.NamespaceResource");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to namespace resource manager: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for write: %m");

        userns_fd_idx = varlink_dup_fd(vl, userns_fd);
        if (userns_fd_idx < 0)
                return log_debug_errno(userns_fd_idx, "Failed to push userns fd into varlink connection: %m");

        r = varlink_callb(vl,
                          "io.systemd.NamespaceResource.RegisterUserNamespace",
                          /* ret_reply= */ NULL,
                          &error_id,
                          /* ret_flags= */ NULL,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("name", JSON_BUILD_STRING(name)),
                                          JSON_BUILD_PAIR("userNamespaceFileDescriptor", JSON_BUILD_UNSIGNED(userns_fd_idx))));
        if (r < 0)
                return log_debug_errno(r, "Failed to call RegisterUserNamespace() varlink call.");
        if (!isempty(error_id))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOANO), "Failed to register user namespace: %s", error_id);

        return TAKE_FD(userns_fd);
}

int nsresource_add_cgroup(int userns_fd, int cgroup_fd) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        _cleanup_close_ int _userns_fd = -EBADF;
        int r, userns_fd_idx, cgroup_fd_idx;
        const char *error_id;

        assert(userns_fd >= 0);
        assert(cgroup_fd >= 0);

        if (userns_fd < 0) {
                _userns_fd = namespace_open_by_type(NAMESPACE_USER);
                if (_userns_fd < 0)
                        return -errno;

                userns_fd = _userns_fd;
        }

        r = varlink_connect_address(&vl, "/run/systemd/io.systemd.NamespaceResource");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to namespace resource manager: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable varlink fd passing for write: %m");

        userns_fd_idx = varlink_dup_fd(vl, userns_fd);
        if (userns_fd_idx < 0)
                return log_debug_errno(userns_fd_idx, "Failed to push userns fd into varlink connection: %m");

        cgroup_fd_idx = varlink_dup_fd(vl, cgroup_fd);
        if (cgroup_fd_idx < 0)
                return log_debug_errno(userns_fd_idx, "Failed to push cgroup fd into varlink connection: %m");

        r = varlink_callb(vl,
                          "io.systemd.NamespaceResource.AddControlGroupToUserNamespace",
                          /* ret_reply= */ NULL,
                          &error_id,
                          /* ret_flags= */ NULL,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("userNamespaceFileDescriptor", JSON_BUILD_UNSIGNED(userns_fd_idx)),
                                          JSON_BUILD_PAIR("controlGroupFileDescriptor", JSON_BUILD_UNSIGNED(cgroup_fd_idx))));
        if (r < 0)
                return log_debug_errno(r, "Failed to call AddControlGroupToUserNamespace() varlink call.");
        if (!isempty(error_id))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOANO), "Failed to add cgroup to user namepsace: %s", error_id);

        return TAKE_FD(userns_fd);
}

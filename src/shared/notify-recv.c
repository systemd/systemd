/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "async.h"
#include "fdset.h"
#include "log.h"
#include "notify-recv.h"
#include "pidref.h"
#include "socket-util.h"
#include "strv.h"

int notify_recv_with_fds(
                int fd,
                char **ret_text,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds) {

        _cleanup_free_ char *text = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        struct ucred ucred;
        _cleanup_free_ int *fds = NULL;
        size_t n_fds = 0;
        int r;

        r = notify_recv_with_fd_array(fd, ret_text ? &text : NULL, ret_ucred ? &ucred : NULL,
                                     ret_pidref ? &pidref : NULL, &fds, &n_fds);
        if (r < 0)
                return r;

        _cleanup_(fdset_free_asyncp) FDSet *set = NULL;
        if (n_fds > 0 && !ret_fds)
                asynchronous_close_many(fds, n_fds);
        else if (n_fds > 0) {
                r = fdset_new_array(&set, fds, n_fds);
                if (r < 0) {
                        asynchronous_close_many(fds, n_fds);
                        log_warning_errno(r, "Failed to collect fds from notification, ignoring message: %m");
                        return -EAGAIN;
                }
        }

        if (ret_text)
                *ret_text = TAKE_PTR(text);
        if (ret_ucred)
                *ret_ucred = ucred;
        if (ret_pidref)
                *ret_pidref = TAKE_PIDREF(pidref);
        if (ret_fds)
                *ret_fds = TAKE_PTR(set);
        return 0;
}

int notify_recv_with_fds_strv(
                int fd,
                char ***ret_list,
                struct ucred *ret_ucred,
                PidRef *ret_pidref,
                FDSet **ret_fds) {

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_(fdset_free_asyncp) FDSet *fds = NULL;
        struct ucred ucred = UCRED_INVALID;
        _cleanup_free_ char *text = NULL;
        int r;

        r = notify_recv_with_fds(
                        fd,
                        ret_list ? &text : NULL,
                        ret_ucred ? &ucred : NULL,
                        ret_pidref ? &pidref : NULL,
                        ret_fds ? &fds : NULL);
        if (r < 0)
                return r;

        if (ret_list) {
                char **l = strv_split_newlines(text);
                if (!l) {
                        log_oom_warning();
                        return -EAGAIN;
                }

                *ret_list = l;
        }

        if (ret_ucred)
                *ret_ucred = ucred;
        if (ret_pidref)
                *ret_pidref = TAKE_PIDREF(pidref);
        if (ret_fds)
                *ret_fds = TAKE_PTR(fds);

        return 0;
}

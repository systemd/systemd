/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.SecureLockBackend.h"

/*
 * This API is internal and subject to change!
 *
 * For the time being, it is separated from the userdb API because that API is read-only and
 * this API mutates the state of the user. However, in the future the userdb API may grow to
 * encompass mutating the user and notifying about changes to the user, making this API obsolete.
 *
 * Before using this, please look at & contribute your opinions to the following:
 *   - https://github.com/systemd/systemd/issues/16823
 *   - https://github.com/systemd/systemd/issues/32568
 * Depending on the outcome of those discussions, this API will either become stable &
 * documented, or it will be removed and added directly to the userdb API.
 */

static VARLINK_DEFINE_METHOD(
                Activate,
                VARLINK_DEFINE_INPUT(service, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(userName, VARLINK_STRING, 0));

static VARLINK_DEFINE_METHOD(
                Subscribe,
                VARLINK_DEFINE_INPUT(service, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(uid, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT(locked, VARLINK_BOOL, 0));

static VARLINK_DEFINE_ERROR(BadService);
static VARLINK_DEFINE_ERROR(NoSuchUser);
static VARLINK_DEFINE_ERROR(AlreadySubscribed);

VARLINK_DEFINE_INTERFACE(
                io_systemd_SecureLockBackend,
                "io.systemd.SecureLockBackend",
                &vl_method_Activate,
                &vl_method_Subscribe,
                &vl_error_BadService,
                &vl_error_NoSuchUser,
                &vl_error_AlreadySubscribed);

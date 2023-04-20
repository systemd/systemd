/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.NamespaceResource.h"

static VARLINK_DEFINE_METHOD(
                AllocateUserRange,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(size, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(target, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                RegisterUserNamespace,
                VARLINK_DEFINE_INPUT(name, VARLINK_STRING, 0),
                VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                AddMountToUserNamespace,
                VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(mountFileDescriptor, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(
                AddControlGroupToUserNamespace,
                VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(controlGroupFileDescriptor, VARLINK_INT, 0));

static VARLINK_DEFINE_ERROR(UserNamespaceInterfaceNotSupported);
static VARLINK_DEFINE_ERROR(NameExists);
static VARLINK_DEFINE_ERROR(UserNamespaceExists);
static VARLINK_DEFINE_ERROR(DynamicRangeUnavailable);
static VARLINK_DEFINE_ERROR(NoDynamicRange);
static VARLINK_DEFINE_ERROR(UserNamespaceNotRegistered);
static VARLINK_DEFINE_ERROR(UserNamespaceWithoutUserRange);
static VARLINK_DEFINE_ERROR(TooManyControlGroups);
static VARLINK_DEFINE_ERROR(ControlGroupAlreadyAdded);

VARLINK_DEFINE_INTERFACE(
                io_systemd_NamespaceResource,
                "io.systemd.NamespaceResource",
                &vl_method_AllocateUserRange,
                &vl_method_RegisterUserNamespace,
                &vl_method_AddMountToUserNamespace,
                &vl_method_AddControlGroupToUserNamespace,
                &vl_error_UserNamespaceInterfaceNotSupported,
                &vl_error_NameExists,
                &vl_error_UserNamespaceExists,
                &vl_error_DynamicRangeUnavailable,
                &vl_error_NoDynamicRange,
                &vl_error_UserNamespaceNotRegistered,
                &vl_error_UserNamespaceWithoutUserRange,
                &vl_error_TooManyControlGroups,
                &vl_error_ControlGroupAlreadyAdded);

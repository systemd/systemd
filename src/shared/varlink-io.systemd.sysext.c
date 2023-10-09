/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.sysext.h"

static VARLINK_DEFINE_ENUM_TYPE(
                ImageClass,
                VARLINK_DEFINE_ENUM_VALUE(sysext),
                VARLINK_DEFINE_ENUM_VALUE(confext));

static VARLINK_DEFINE_ENUM_TYPE(
                ImageType,
                VARLINK_DEFINE_ENUM_VALUE(directory),
                VARLINK_DEFINE_ENUM_VALUE(subvolume),
                VARLINK_DEFINE_ENUM_VALUE(raw),
                VARLINK_DEFINE_ENUM_VALUE(block));

static VARLINK_DEFINE_METHOD(
                Merge,
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(force, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(noReload, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(noexec, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                Unmerge,
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(noReload, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                Refresh,
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(force, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(noReload, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_INPUT(noexec, VARLINK_BOOL, VARLINK_NULLABLE));

static VARLINK_DEFINE_METHOD(
                List,
                VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(Class, ImageClass, 0),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(Type, ImageType, 0),
                VARLINK_DEFINE_OUTPUT(Name, VARLINK_STRING, 0),
                VARLINK_DEFINE_OUTPUT(Path, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(ReadOnly, VARLINK_BOOL, 0),
                VARLINK_DEFINE_OUTPUT(CreationTimestamp, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(ModificationTimestamp, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(Usage, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(UsageExclusive, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(Limit, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(LimitExclusive, VARLINK_INT, VARLINK_NULLABLE));

static VARLINK_DEFINE_ERROR(NoImagesFound);

static VARLINK_DEFINE_ERROR(
                AlreadyMerged,
                VARLINK_DEFINE_FIELD(hierarchy, VARLINK_STRING, 0));

VARLINK_DEFINE_INTERFACE(
                io_systemd_sysext,
                "io.systemd.sysext",
                &vl_type_ImageClass,
                &vl_type_ImageType,
                &vl_method_Merge,
                &vl_method_Unmerge,
                &vl_method_Refresh,
                &vl_method_List,
                &vl_error_NoImagesFound,
                &vl_error_AlreadyMerged);

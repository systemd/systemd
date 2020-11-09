/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "user-record.h"

typedef struct GroupRecord {
        unsigned n_ref;
        UserRecordMask mask;
        bool incomplete;

        char *group_name;
        char *realm;
        char *group_name_and_realm_auto;

        char *description;

        UserDisposition disposition;
        uint64_t last_change_usec;

        gid_t gid;

        char **members;

        char *service;

        /* The following exist mostly so that we can cover the full /etc/gshadow set of fields, we currently
         * do not actually make use of these */
        char **administrators;  /* maps to 'struct sgrp' .sg_adm field */
        char **hashed_password; /* maps to 'struct sgrp' .sg_passwd field */

        JsonVariant *json;
} GroupRecord;

GroupRecord* group_record_new(void);
GroupRecord* group_record_ref(GroupRecord *g);
GroupRecord* group_record_unref(GroupRecord *g);

DEFINE_TRIVIAL_CLEANUP_FUNC(GroupRecord*, group_record_unref);

int group_record_load(GroupRecord *h, JsonVariant *v, UserRecordLoadFlags flags);
int group_record_build(GroupRecord **ret, ...);
int group_record_clone(GroupRecord *g, UserRecordLoadFlags flags, GroupRecord **ret);

const char *group_record_group_name_and_realm(GroupRecord *h);
UserDisposition group_record_disposition(GroupRecord *h);

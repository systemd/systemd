/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machine-util.h"
#include "tests.h"

TEST(bind_volume_parse_minimal) {
        _cleanup_(bind_volume_freep) BindVolume *v = NULL;

        ASSERT_OK(bind_volume_parse("block:/dev/sda", &v));
        ASSERT_STREQ(v->provider, "block");
        ASSERT_STREQ(v->volume, "/dev/sda");
        ASSERT_NULL(v->config);
        ASSERT_NULL(v->template);
        ASSERT_EQ(v->create_mode, _CREATE_MODE_INVALID);
        ASSERT_EQ(v->request_as, _VOLUME_TYPE_INVALID);
        ASSERT_EQ(v->read_only, -1);
        ASSERT_EQ(v->create_size_bytes, UINT64_MAX);
}

TEST(bind_volume_parse_with_config) {
        _cleanup_(bind_volume_freep) BindVolume *v = NULL;

        ASSERT_OK(bind_volume_parse("block:/dev/sda:virtio-scsi", &v));
        ASSERT_STREQ(v->provider, "block");
        ASSERT_STREQ(v->volume, "/dev/sda");
        ASSERT_STREQ(v->config, "virtio-scsi");
}

TEST(bind_volume_parse_empty_config) {
        _cleanup_(bind_volume_freep) BindVolume *v = NULL;

        ASSERT_OK(bind_volume_parse("fs:vol-1::create=new,size=64M,template=sparse-file", &v));
        ASSERT_STREQ(v->provider, "fs");
        ASSERT_STREQ(v->volume, "vol-1");
        ASSERT_NULL(v->config);
        ASSERT_EQ(v->create_mode, CREATE_NEW);
        ASSERT_STREQ(v->template, "sparse-file");
        ASSERT_EQ(v->create_size_bytes, UINT64_C(64) * 1024 * 1024);
}

TEST(bind_volume_parse_full) {
        _cleanup_(bind_volume_freep) BindVolume *v = NULL;

        ASSERT_OK(bind_volume_parse(
                          "fs:vol-2:nvme:create=any,template=allocated-file,size=128M,ro=auto,request-as=blk",
                          &v));
        ASSERT_STREQ(v->provider, "fs");
        ASSERT_STREQ(v->volume, "vol-2");
        ASSERT_STREQ(v->config, "nvme");
        ASSERT_EQ(v->create_mode, CREATE_ANY);
        ASSERT_STREQ(v->template, "allocated-file");
        ASSERT_EQ(v->request_as, VOLUME_BLK);
        ASSERT_EQ(v->create_size_bytes, UINT64_C(128) * 1024 * 1024);
        ASSERT_EQ(v->read_only, -ENODATA);
}

TEST(bind_volume_parse_read_only) {
        _cleanup_(bind_volume_freep) BindVolume *v = NULL;

        ASSERT_OK(bind_volume_parse("block:/dev/sdb:scsi-cd:read-only=yes", &v));
        ASSERT_EQ(v->read_only, 1);

        v = bind_volume_free(v);
        ASSERT_OK(bind_volume_parse("block:/dev/sdb:scsi-cd:ro=no", &v));
        ASSERT_EQ(v->read_only, 0);
}

TEST(bind_volume_parse_invalid) {
        BindVolume *v = NULL;

        /* Missing provider */
        ASSERT_ERROR(bind_volume_parse(":vol", &v), EINVAL);
        ASSERT_NULL(v);

        /* Missing volume */
        ASSERT_ERROR(bind_volume_parse("block:", &v), EINVAL);
        ASSERT_NULL(v);

        /* Provider with control char */
        ASSERT_ERROR(bind_volume_parse("bl\x01ock:vol", &v), EINVAL);
        ASSERT_NULL(v);

        /* Config with control char */
        ASSERT_ERROR(bind_volume_parse("block:vol:nv\x01me", &v), EINVAL);
        ASSERT_NULL(v);

        /* Unknown extras key */
        ASSERT_ERROR(bind_volume_parse("block:vol::bogus=foo", &v), EINVAL);
        ASSERT_NULL(v);

        /* Bogus create mode */
        ASSERT_ERROR(bind_volume_parse("block:vol::create=bogus", &v), EINVAL);
        ASSERT_NULL(v);

        /* Bogus request-as */
        ASSERT_ERROR(bind_volume_parse("block:vol::request-as=bogus", &v), EINVAL);
        ASSERT_NULL(v);

        /* Extras entry without '=' */
        ASSERT_ERROR(bind_volume_parse("block:vol::nokey", &v), EINVAL);
        ASSERT_NULL(v);

        /* Empty key (=value with no key) */
        ASSERT_ERROR(bind_volume_parse("block:vol::=value", &v), EINVAL);
        ASSERT_NULL(v);

        /* Duplicate key */
        ASSERT_ERROR(bind_volume_parse("block:vol::create=new,create=any", &v), EINVAL);
        ASSERT_NULL(v);

        /* Aliased duplicate (size / create-size) */
        ASSERT_ERROR(bind_volume_parse("block:vol::size=64M,create-size=128M", &v), EINVAL);
        ASSERT_NULL(v);

        /* Zero-byte size */
        ASSERT_ERROR(bind_volume_parse("block:vol::size=0", &v), EINVAL);
        ASSERT_NULL(v);

        /* Duplicate read-only (including across explicit auto) */
        ASSERT_ERROR(bind_volume_parse("block:vol::read-only=yes,read-only=no", &v), EINVAL);
        ASSERT_NULL(v);
        ASSERT_ERROR(bind_volume_parse("block:vol::read-only=auto,ro=yes", &v), EINVAL);
        ASSERT_NULL(v);
}

TEST(machine_storage_name_split) {
        _cleanup_free_ char *p = NULL, *v = NULL;

        ASSERT_OK(machine_storage_name_split("block:/dev/sda", &p, &v));
        ASSERT_STREQ(p, "block");
        ASSERT_STREQ(v, "/dev/sda");

        /* NULL outputs — validate-only mode */
        ASSERT_OK(machine_storage_name_split("fs:vol-1", NULL, NULL));

        ASSERT_ERROR(machine_storage_name_split(NULL, NULL, NULL), EINVAL);
        ASSERT_ERROR(machine_storage_name_split("", NULL, NULL), EINVAL);
        ASSERT_ERROR(machine_storage_name_split("no-colon", NULL, NULL), EINVAL);
        ASSERT_ERROR(machine_storage_name_split(":vol", NULL, NULL), EINVAL);
        ASSERT_ERROR(machine_storage_name_split("block:", NULL, NULL), EINVAL);
        ASSERT_ERROR(machine_storage_name_split("bl\x01ock:vol", NULL, NULL), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);

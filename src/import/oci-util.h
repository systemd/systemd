/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool oci_image_is_valid(const char *n);
int oci_registry_is_valid(const char *n);
bool oci_tag_is_valid(const char *n);

int oci_ref_parse(const char *ref, char **ret_registry, char **ret_image, char **ret_tag);

static inline int oci_ref_valid(const char *ref) {
        int r;
        r = oci_ref_parse(ref, NULL, NULL, NULL);
        if (r == -EINVAL)
                return false;
        if (r < 0)
                return r;
        return true;
}

int oci_ref_normalize(char **protocol, char **registry, char **image, char **tag);

char* oci_digest_string(const struct iovec *iovec);

#define OCI_MEDIA_TYPES_INDEX                                           \
        "application/vnd.oci.image.index.v1+json",                      \
        "application/vnd.docker.distribution.manifest.list.v2+json"

#define OCI_MEDIA_TYPES_MANIFEST                                        \
        "application/vnd.oci.image.manifest.v1+json",                   \
        "application/vnd.docker.distribution.manifest.v2+json"

#define OCI_MEDIA_TYPES_CONFIG                                          \
        "application/vnd.oci.image.config.v1+json",                     \
        "application/vnd.docker.container.image.v1+json"

/* Docker's "foreign" layers are intentionally not included here */
#define OCI_MEDIA_TYPES_LAYER                                           \
        "application/vnd.oci.image.layer.v1.tar",                       \
        "application/vnd.oci.image.layer.v1.tar+gzip",                  \
        "application/vnd.oci.image.layer.v1.tar+zstd",                  \
        "application/vnd.docker.image.rootfs.diff.tar.gzip"

bool oci_media_type_is_index(const char *t);
bool oci_media_type_is_manifest(const char *t);
bool oci_media_type_is_config(const char *t);
bool oci_media_type_is_layer(const char *t);

int oci_make_manifest_url(const char *protocol, const char *repository, const char *image, const char *tag, char **ret);
int oci_make_blob_url(const char *protocol, const char *repository, const char *image, const struct iovec *digest, char **ret);

Architecture go_arch_from_string(const char *s);

char* urlescape(const char *s);

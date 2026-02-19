/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

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

int oci_make_manifest_url(const char *protocol, const char *repository, const char *image, const char *tag, char **ret);
int oci_make_blob_url(const char *protocol, const char *repository, const char *image, const struct iovec *digest, char **ret);

Architecture go_arch_from_string(const char *s);

char* urlescape(const char *s);

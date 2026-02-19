/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "architecture.h"
#include "constants.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "oci-util.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"

bool oci_image_is_valid(const char *n) {
        bool slash = true;

        /* The OCI spec suggests validating this regex:
         *
         * [a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*
         *
         * We implement a generalization of this, i.e. do not insist on the single ".", "_", "__", "-", "+"
         * separator, but allow any number of them. And we refuse leading dots, since if used in the fs this
         * would make the files hidden, and we probably don't want that.
         */

        for (const char *p = n; *p; p++) {
                if (*p == '/') {
                        if (slash)
                                return false;

                        slash = true;
                        continue;
                }

                if (!strchr(slash ? LOWERCASE_LETTERS DIGITS "_-+" :
                                    "." LOWERCASE_LETTERS DIGITS "_-+", *p))
                        return false;

                slash = false;
        }

        return !slash;
}

int oci_registry_is_valid(const char *n) {
        int r;

        if (!n)
                return false;

        const char *colon = strchr(n, ':');
        if (!colon)
                return dns_name_is_valid(n);

        _cleanup_free_ char *s = strndup(n, colon - n);
        if (!s)
                return -ENOMEM;

        r = dns_name_is_valid(s);
        if (r <= 0)
                return r;

        uint16_t port;
        return safe_atou16(s, &port) >= 0 && port != 0;
}

bool oci_tag_is_valid(const char *n) {
        if (!n)
                return false;

        /* As per https://github.com/opencontainers/distribution-spec/blob/main/spec.md, accept the following regex:
         *
         * [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}
         */

        if (!strchr(LETTERS DIGITS "_", n[0]))
                return false;

        size_t l = strspn(n + 1, LETTERS DIGITS "._-");
        if (l > 126)
                return false;
        if (n[1+l] != 0)
                return false;

        return true;
}

int oci_ref_parse(
                const char *ref,
                char **ret_registry,
                char **ret_image,
                char **ret_tag) {

        int r;

        assert(ref);

        _cleanup_free_ char *without_tag = NULL, *tag = NULL;
        const char *t = strrchr(ref, ':');
        if (t) {
                tag = strdup(t + 1);
                if (!tag)
                        return -ENOMEM;
                if (!oci_tag_is_valid(tag))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "OCI tag specification '%s' is not valid.", tag);

                without_tag = strndup(ref, t - ref);
                if (!without_tag)
                        return -ENOMEM;

                ref = without_tag;
        }

        _cleanup_free_ char *image = NULL, *registry = NULL;
        t = strchr(ref, '/');
        if (t) {
                registry = strndup(ref, t - ref);
                if (!registry)
                        return -ENOMEM;

                r = oci_registry_is_valid(registry);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "OCI registry specification '%s' is not valid.", registry);

                image = strdup(t + 1);
        } else
                image = strdup(ref);
        if (!image)
                return -ENOMEM;
        if (!oci_image_is_valid(image))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "OCI image specification '%s' is not valid.", registry);

        if (ret_registry)
                *ret_registry = TAKE_PTR(registry);
        if (ret_image)
                *ret_image = TAKE_PTR(image);
        if (ret_tag)
                *ret_tag = TAKE_PTR(tag);

        return 0;
}

int oci_ref_normalize(char **protocol, char **registry, char **image, char **tag) {
        int r;

        assert(protocol);
        assert(registry);
        assert(image && *image);
        assert(tag);

        /* OCI container reference are supposed to have the form <registry>/<name>:<tag>. Except that it's
         * all super messy, and for some registries the server name differs from the name people use in the
         * references, and there are special rules for "short" container names (i.e. those which do not
         * contain a "/"), and more. To deal with this, we devise a relatively simple scheme, to normalize
         * such names. Specifically:
         *
         * If a registry is specified we look for
         * /usr/lib/systemd/oci-registry/registry.<registry>.oci-registry for registry-specific rules, to
         * enforce on the reference. If no registry is specified, we look for an
         * /usr/lib/systemd/oci-registry/image.<name>.oci-registry file, which contains image-specific rules
         * instead. If this is not found we load /usr/lib/systemd/oci-registry/default.oci-registry
         * instead. The files are encoded in JSON.
         *
         * The rules we apply are relatively simple:
         *
         * • defaultProtocol controls which protocol to use if none is known. This should always be https
         *   (since OCI images are authenticated purely via HTTPS), but for testing purposes "file" might be
         *   useful too.
         *
         * • overrideRegistry encodes which registry server to actually use, overriding what might have been
         *   specified.
         *
         * • overrideImage encodes which image name to actually use, overriding what might have been specified.
         *
         * • shortImagePrefix encodes a name prefix to prepend to "short" container names. This has no effect
         *   if overrideImage is set too.
         *
         * • defaultTag contains a tag to use as default, if none is specified. If not configured this
         *   defaults to "latest".
         */

        _cleanup_free_ char *fn = NULL;
        if (*registry) {
                /* If a registry is specified, we'll always respect it, and use it as only search key */
                _cleanup_free_ char *e = urlescape(*registry);
                if (!e)
                        return -ENOMEM;

                fn = strjoin("registry.", e, ".oci-registry");
        } else {
                /* If no registry is specified, let's go by image name */
                _cleanup_free_ char *e = urlescape(*image);
                if (!e)
                        return -ENOMEM;

                fn = strjoin("image.", e, ".oci-registry");
        }
        if (!fn)
                return -ENOMEM;

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *path = NULL;
        r = search_and_fopen_nulstr(fn, "re", /* root= */ NULL, CONF_PATHS_NULSTR("systemd/oci-registry"), &f, &path);
        if (r == -ENOENT)
                r = search_and_fopen_nulstr("default.oci-registry", "re", /* root= */ NULL, CONF_PATHS_NULSTR("systemd/oci-registry"), &f, &path);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to find suitable OCI registry file: %m");

        /* if ENOENT is seen, we use the defaults below! */

        struct {
                const char *default_protocol;
                const char *override_registry;
                const char *default_registry;
                const char *override_image;
                const char *short_image_prefix;
                const char *default_tag;
        } data = {
                .default_protocol = "https",
                .default_tag = "latest",
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (f) {
                unsigned line = 0, column = 0;
                r = sd_json_parse_file(f, path, /* flags= */ 0, &v, &line, &column);
                if (r < 0)
                        return log_debug_errno(r, "Parse failure at %s:%u:%u: %m", path, line, column);

                static const sd_json_dispatch_field table[] = {
                        { "defaultProtocol",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(data, default_protocol),   0 },
                        { "overrideRegistry", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(data, override_registry),  0 },
                        { "defaultRegistry",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(data, default_registry),   0 },
                        { "overrideImage",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(data, override_image),     0 },
                        { "shortImagePrefix", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(data, short_image_prefix), 0 },
                        { "defaultTag",       SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(data, default_tag),        0 },
                        {},
                };
                r = sd_json_dispatch(v, table, SD_JSON_ALLOW_EXTENSIONS, &data);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *new_protocol = NULL;
        if (data.default_protocol && isempty(*protocol)) {
                new_protocol = strdup(data.default_protocol);
                if (!new_protocol)
                        return -ENOMEM;
        }

        _cleanup_free_ char *new_registry = NULL;
        if (data.override_registry) {
                if (!isempty(*registry))
                        log_debug("Overriding registry to '%s' (was '%s') based on OCI registry database.", data.override_registry, *registry);

                new_registry = strdup(data.override_registry);
                if (!new_registry)
                        return -ENOMEM;
        } else if (data.default_registry && isempty(*registry)) {
                new_registry = strdup(data.default_registry);
                if (!new_registry)
                        return -ENOMEM;
        }

        _cleanup_free_ char *new_image = NULL;
        if (data.override_image) {
                log_debug("Overriding image to '%s' (was '%s') based on OCI registry database.", data.override_registry, *image);

                new_image = strdup(data.override_image);
                if (!new_image)
                        return -ENOMEM;
        } else if (data.short_image_prefix && !strchr(*image, '/')) {
                new_image = strjoin(data.short_image_prefix, *image);
                if (!new_image)
                        return -ENOMEM;
        }

        _cleanup_free_ char *new_tag = NULL;
        if (data.default_tag && isempty(*tag)) {
                new_tag = strdup(data.default_tag);
                if (!new_tag)
                        return -ENOMEM;
        }

        if (!new_registry && isempty(*registry))
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "No suitable registry found.");

        if (new_protocol)
                free_and_replace(*protocol, new_protocol);
        if (new_registry)
                free_and_replace(*registry, new_registry);
        if (new_image)
                free_and_replace(*image, new_image);
        if (new_tag)
                free_and_replace(*tag, new_tag);

        return 0;
}

char* oci_digest_string(const struct iovec *iovec) {
        assert(iovec);

        _cleanup_free_ char *h = hexmem(iovec->iov_base, iovec->iov_len);
        if (!h)
                return NULL;

        return strjoin("sha256:", h);
}

int oci_make_manifest_url(
                const char *protocol,
                const char *repository,
                const char *image,
                const char *tag,
                char **ret) {

        assert(protocol);
        assert(repository);
        assert(image);
        assert(tag);
        assert(ret);

        _cleanup_free_ char *url = strjoin(protocol, "://", repository, "/v2/", image, "/manifests/", tag);
        if (!url)
                return -ENOMEM;

        *ret = TAKE_PTR(url);
        return 0;
}

int oci_make_blob_url(
                const char *protocol,
                const char *repository,
                const char *image,
                const struct iovec *digest,
                char **ret) {

        assert(protocol);
        assert(repository);
        assert(image);
        assert(digest);
        assert(ret);

        _cleanup_free_ char *d = oci_digest_string(digest);
        if (!d)
                return -ENOMEM;

        _cleanup_free_ char *url = strjoin(protocol, "://", repository, "/v2/", image, "/blobs/", d);
        if (!url)
                return -ENOMEM;

        *ret = TAKE_PTR(url);
        return 0;
}

/* OCI uses the Go architecture IDs */
static const char *const go_arch_table[_ARCHITECTURE_MAX] = {
        [ARCHITECTURE_ARM]       = "arm",
        [ARCHITECTURE_ARM64]     = "arm64",
        [ARCHITECTURE_MIPS]      = "mips",
        [ARCHITECTURE_MIPS64]    = "mips64",
        [ARCHITECTURE_MIPS64_LE] = "mips64le",
        [ARCHITECTURE_MIPS_LE]   = "mipsle",
        [ARCHITECTURE_PPC64]     = "ppc64",
        [ARCHITECTURE_PPC64_LE]  = "ppc64le",
        [ARCHITECTURE_S390X]     = "s390x",
        [ARCHITECTURE_X86]       = "386",
        [ARCHITECTURE_X86_64]    = "amd64",
};

DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(go_arch, Architecture);

char* urlescape(const char *s) {
        size_t l = strlen_ptr(s);

        _cleanup_free_ char *t = new(char, l * 3 + 1);
        if (!t)
                return NULL;

        char *p = t;
        for (; s && *s; s++) {
                if (strchr(LETTERS DIGITS ".-_", *s))
                        *(p++) = *s;
                else {
                        *(p++) = '%';
                        *(p++) = hexchar((uint8_t) *s >> 4);
                        *(p++) = hexchar((uint8_t) *s & 15);
                }
        }

        *p = 0;
        return TAKE_PTR(t);
}

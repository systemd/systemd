/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

struct iovec_wrapper {
        struct iovec *iovec;
        size_t count;
};

struct iovec_wrapper *iovw_new(void);
struct iovec_wrapper *iovw_free(struct iovec_wrapper *iovw);
struct iovec_wrapper *iovw_free_free(struct iovec_wrapper *iovw);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct iovec_wrapper*, iovw_free_free);

void iovw_done_free(struct iovec_wrapper *iovw);
void iovw_done(struct iovec_wrapper *iovw);

int iovw_put(struct iovec_wrapper *iovw, void *data, size_t len);
static inline int iovw_consume(struct iovec_wrapper *iovw, void *data, size_t len) {
        /* Move data into iovw or free on error */
        int r;

        r = iovw_put(iovw, data, len);
        if (r < 0)
                free(data);

        return r;
}

static inline bool iovw_isempty(const struct iovec_wrapper *iovw) {
        return !iovw || iovw->count == 0;
}

int iovw_put_string_field_full(struct iovec_wrapper *iovw, bool replace, const char *field, const char *value);
static inline int iovw_put_string_field(struct iovec_wrapper *iovw, const char *field, const char *value) {
        return iovw_put_string_field_full(iovw, false, field, value);
}
static inline int iovw_replace_string_field(struct iovec_wrapper *iovw, const char *field, const char *value) {
        return iovw_put_string_field_full(iovw, true, field, value);
}
int iovw_put_string_fieldf_full(struct iovec_wrapper *iovw, bool replace, const char *field, const char *format, ...) _printf_(4, 5);
#define iovw_put_string_fieldf(iovw, ...)     iovw_put_string_fieldf_full(iovw, false, __VA_ARGS__)
#define iovw_replace_string_fieldf(iovw, ...) iovw_put_string_fieldf_full(iovw, true, __VA_ARGS__)
int iovw_put_string_field_free(struct iovec_wrapper *iovw, const char *field, char *value);
void iovw_rebase(struct iovec_wrapper *iovw, void *old, void *new);
size_t iovw_size(const struct iovec_wrapper *iovw);
int iovw_append(struct iovec_wrapper *target, const struct iovec_wrapper *source);

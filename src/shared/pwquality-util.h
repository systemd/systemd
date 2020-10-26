/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

#if HAVE_PWQUALITY
/* pwquality.h uses size_t but doesn't include sys/types.h on its own */
#include <sys/types.h>
#include <pwquality.h>

#include "pwquality-wrapper.h"

extern wrap_type_pwquality_check sym_pwquality_check;
extern wrap_type_pwquality_default_settings sym_pwquality_default_settings;
extern wrap_type_pwquality_free_settings sym_pwquality_free_settings;
extern wrap_type_pwquality_generate sym_pwquality_generate;
extern wrap_type_pwquality_get_str_value sym_pwquality_get_str_value;
extern wrap_type_pwquality_read_config sym_pwquality_read_config;
extern wrap_type_pwquality_set_int_value sym_pwquality_set_int_value;
extern wrap_type_pwquality_strerror sym_pwquality_strerror;

int dlopen_pwquality(void);

DEFINE_TRIVIAL_CLEANUP_FUNC(pwquality_settings_t*, sym_pwquality_free_settings);

void pwq_maybe_disable_dictionary(pwquality_settings_t *pwq);
int pwq_allocate_context(pwquality_settings_t **ret);
int suggest_passwords(void);
int quality_check_password(const char *password, const char *username, char **ret_error);

#else

static inline int suggest_passwords(void) {
        return 0;
}

static inline int quality_check_password(const char *password, const char *username, char **ret_error) {
        if (ret_error)
                *ret_error = NULL;
        return 1; /* all good */
}

#endif

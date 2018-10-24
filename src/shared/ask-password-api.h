/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "time-util.h"

typedef enum AskPasswordFlags {
        ASK_PASSWORD_ACCEPT_CACHED = 1 << 0,
        ASK_PASSWORD_PUSH_CACHE    = 1 << 1,
        ASK_PASSWORD_ECHO          = 1 << 2, /* show the password literally while reading, instead of "*" */
        ASK_PASSWORD_SILENT        = 1 << 3, /* do no show any password at all while reading */
        ASK_PASSWORD_NO_TTY        = 1 << 4,
        ASK_PASSWORD_NO_AGENT      = 1 << 5,
        ASK_PASSWORD_CONSOLE_COLOR = 1 << 6, /* Use color if /dev/console points to a console that supports color */
} AskPasswordFlags;

int ask_password_tty(int tty_fd, const char *message, const char *keyname, usec_t until, AskPasswordFlags flags, const char *flag_file, char ***ret);
int ask_password_agent(const char *message, const char *icon, const char *id, const char *keyname, usec_t until, AskPasswordFlags flag, char ***ret);
int ask_password_keyring(const char *keyname, AskPasswordFlags flags, char ***ret);
int ask_password_auto(const char *message, const char *icon, const char *id, const char *keyname, usec_t until, AskPasswordFlags flag, char ***ret);

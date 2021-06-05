/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

char *replace_var(const char *text, char *(*lookup)(const char *variable, void *userdata), void *userdata);

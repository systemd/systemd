/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink.h"

int verb_status(int argc, char *argv[], void *userdata);
int verb_list(int argc, char *argv[], void *userdata);
int verb_unlink(int argc, char *argv[], void *userdata);

int vl_method_list_boot_entries(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata);

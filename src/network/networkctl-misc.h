/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int link_up_down(int argc, char *argv[], void *userdata);
int link_delete(int argc, char *argv[], void *userdata);
int link_renew(int argc, char *argv[], void *userdata);
int link_force_renew(int argc, char *argv[], void *userdata);
int verb_reload(int argc, char *argv[], void *userdata);
int verb_reconfigure(int argc, char *argv[], void *userdata);
int verb_persistent_storage(int argc, char *argv[], void *userdata);

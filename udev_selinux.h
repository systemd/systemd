#ifndef UDEV_SELINUX_H
#define UDEV_SELINUX_H

#ifdef USE_SELINUX
extern void selinux_add_node(char *filename);
#else
static void selinux_add_node(char *filename) { }
#endif

#endif

/*
 * umount.c
 *
 * Single-argument form of umount
 */

#include <sys/mount.h>

int umount(const char *dir)
{
  return umount2(dir, 0);
}

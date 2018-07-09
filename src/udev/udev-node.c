/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "device-nodes.h"
#include "dirent-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "lockfile-util.h"
#include "udev.h"

static int node_symlink(struct udev_device *dev, const char *node, const char *slink) {
        struct stat stats;
        char target[UTIL_PATH_SIZE];
        char *s;
        size_t l;
        char slink_tmp[UTIL_PATH_SIZE + 32];
        int i = 0;
        int tail = 0;
        int err = 0;

        /* use relative link */
        target[0] = '\0';
        while (node[i] && (node[i] == slink[i])) {
                if (node[i] == '/')
                        tail = i+1;
                i++;
        }
        s = target;
        l = sizeof(target);
        while (slink[i] != '\0') {
                if (slink[i] == '/')
                        l = strpcpy(&s, l, "../");
                i++;
        }
        l = strscpy(s, l, &node[tail]);
        if (l == 0) {
                err = -EINVAL;
                goto exit;
        }

        /* preserve link with correct target, do not replace node of other device */
        if (lstat(slink, &stats) == 0) {
                if (S_ISBLK(stats.st_mode) || S_ISCHR(stats.st_mode)) {
                        log_error("conflicting device node '%s' found, link to '%s' will not be created", slink, node);
                        goto exit;
                } else if (S_ISLNK(stats.st_mode)) {
                        char buf[UTIL_PATH_SIZE];
                        int len;

                        len = readlink(slink, buf, sizeof(buf));
                        if (len > 0 && len < (int)sizeof(buf)) {
                                buf[len] = '\0';
                                if (streq(target, buf)) {
                                        log_debug("preserve already existing symlink '%s' to '%s'", slink, target);
                                        (void) label_fix(slink, LABEL_IGNORE_ENOENT);
                                        utimensat(AT_FDCWD, slink, NULL, AT_SYMLINK_NOFOLLOW);
                                        goto exit;
                                }
                        }
                }
        } else {
                log_debug("creating symlink '%s' to '%s'", slink, target);
                do {
                        err = mkdir_parents_label(slink, 0755);
                        if (!IN_SET(err, 0, -ENOENT))
                                break;
                        mac_selinux_create_file_prepare(slink, S_IFLNK);
                        err = symlink(target, slink);
                        if (err != 0)
                                err = -errno;
                        mac_selinux_create_file_clear();
                } while (err == -ENOENT);
                if (err == 0)
                        goto exit;
        }

        log_debug("atomically replace '%s'", slink);
        strscpyl(slink_tmp, sizeof(slink_tmp), slink, ".tmp-", udev_device_get_id_filename(dev), NULL);
        unlink(slink_tmp);
        do {
                err = mkdir_parents_label(slink_tmp, 0755);
                if (!IN_SET(err, 0, -ENOENT))
                        break;
                mac_selinux_create_file_prepare(slink_tmp, S_IFLNK);
                err = symlink(target, slink_tmp);
                if (err != 0)
                        err = -errno;
                mac_selinux_create_file_clear();
        } while (err == -ENOENT);
        if (err != 0) {
                log_error_errno(errno, "symlink '%s' '%s' failed: %m", target, slink_tmp);
                goto exit;
        }
        err = rename(slink_tmp, slink);
        if (err != 0) {
                log_error_errno(errno, "rename '%s' '%s' failed: %m", slink_tmp, slink);
                unlink(slink_tmp);
        }
exit:
        return err;
}

static const char links_dirname[] = "/run/udev/links/";
#define PRIONAME_SIZE 32
static const char prio_prefix[] = "L:";

static int make_prio_name(int prio, char *buf, size_t buflen)
{
        return snprintf(buf, buflen, "%s%d", prio_prefix, prio);
}

static bool is_prio_name(const char *name, int *priority)
{
        int len = sizeof(prio_prefix) - 1;
        long prio;
        char *e;

        if (name == NULL ||
            strncmp(name, prio_prefix, len) || name[len] == '\0')
                return false;

        prio = strtol(name + len, &e, 10);
        if (*e != '\0' || prio < INT_MIN || prio >INT_MAX)
                return false;

        *priority = prio;
        return true;
}

static bool is_prio_dirent(DIR *dir, struct dirent *de, int *priority)
{
        int prio;

        if (!is_prio_name(de->d_name, &prio))
                return  false;

        dirent_ensure_type(dir, de);
        if (de->d_type != DT_DIR)
                return false;

        *priority = prio;
        return true;
}

enum {
        NO_TARGET_FOUND,
        TARGET_FOUND,
        TARGET_NEEDS_CLEANUP,
};

/* find device node of device with highest priority */
static int link_find_prioritized(struct udev_device *dev, bool add, int dfd,
                                 DIR *dir, char *buf, size_t bufsize,
                                 const char *slink) {
        struct udev *udev = udev_device_get_udev(dev);
        int ret, priority;
        struct dirent *de;

        if (add) {
                priority = udev_device_get_devlink_priority(dev);
                strscpy(buf, bufsize, udev_device_get_devnode(dev));
                ret = TARGET_FOUND;
        } else {
                priority = INT_MIN;
                buf[0] = '\0';
                ret = NO_TARGET_FOUND;
        }

        rewinddir(dir);
        FOREACH_DIRENT_ALL(de, dir, break) {
                const char *name = de->d_name;
                int prio = INT_MIN;

                if (name[0] == '\0')
                        break;
                if (dot_or_dot_dot(name))
                        continue;

                if (!is_prio_dirent(dir, de, &prio)) {
                        ret = TARGET_NEEDS_CLEANUP;
                        break;
                }

                if (prio > priority) {
                        int priofd;
                        DIR *pdir;
                        struct dirent *dent;
                        const char *devnode;
                        struct udev_device *dev_db;

                        priofd = openat(dfd, name, O_RDONLY|O_DIRECTORY);
                        /* May race with another remove */
                        if (priofd == -1)
                                continue;
                        pdir = fdopendir(priofd);
                        if (pdir == NULL)
                                continue;

                        dent = readdir_no_dot(pdir);

                        if (dent == NULL)
                                continue;
                        dev_db = udev_device_new_from_device_id(udev,
                                                                dent->d_name);
                        if (dev_db == NULL)
                                continue;
                        devnode = udev_device_get_devnode(dev_db);
                        if (devnode != NULL) {
                                strscpy(buf, bufsize, devnode);
                                priority = prio;
                                ret = TARGET_FOUND;
                                log_debug("'%s' claims priority %i for '%s'",
                                          udev_device_get_syspath(dev_db), prio,
                                          slink);
                        }
                        udev_device_unref(dev_db);
                        closedir(pdir);
                }
        }

        return ret;
}

static int create_target_entry(int dirfd, const char *prioname,
                               const char *filename, const char *slink)
{
        int priofd;
        int ret = 0;

        mkdirat(dirfd, prioname, 0755);
        priofd = openat(dirfd, prioname, O_RDONLY|O_DIRECTORY);
        if (priofd == -1) {
                ret = -1;
                goto out;
        }

        if (symlinkat(".", priofd, filename) != 0)
                log_debug("added target %s/%s for %s",
                          prioname, filename, slink);
        else if (errno != EEXIST)
                ret = -1;
        close(priofd);

out:
        if (ret  == -1)
                log_error_errno(-errno,
                                "failed to add target %s/%s for %s",
                                prioname, filename, filename);
        return ret;
}

static int delete_target_entry(int dirfd, const char *prioname,
                               const char *filename, const char *slink)
{
        int priofd;
        int ret = 0, r;

        unlinkat(dirfd, filename, 0);

        priofd = openat(dirfd, prioname, O_RDONLY|O_DIRECTORY);
        if (priofd == -1) {
                if (errno == ENOENT)
                        return 0;
                else {
                        ret = -1;
                        goto out;
                }
        }

        r = unlinkat(priofd, filename, 0);
        if (r ==  0)
                log_debug("removed target %s/%s for %s",
                          prioname, filename, slink);
        else if (errno != ENOENT)
                ret = -1;

        r = unlinkat(dirfd, prioname, AT_REMOVEDIR);
        if (r == 0)
                log_debug("removed last target for %s in %s",
                          slink, prioname);
        else if (errno != ENOTEMPTY && errno != ENOENT)
                log_warning_errno(-errno, "failed to rmdir %s for %s",
                                  prioname, slink);
        close(priofd);
out:
        if (ret == -1)
                log_error("failed to remove target %s/%s for %s",
                          prioname, filename, slink);
        return ret;
}

static int cleanup_filter(const struct dirent *de)
{
        /*
         * can't use  is_prio_dirent() here, because it needs to call
         * dirent_ensure_type()
         */
        return !dot_or_dot_dot(de->d_name);
}

static void cleanup_old_targets(const char *dirname, struct udev_device *dev)
{
        struct udev *udev = udev_device_get_udev(dev);
        struct dirent **darr;
        int n;
        int dfd = -1;
        DIR *dir;

        log_info("migrating symlink targets in %s", dirname);

        /* Use scandir here to avoid races with deleting entries */
        n = scandir(dirname, &darr, cleanup_filter, alphasort);
        if (n < 0) {
                log_error_errno(-errno, "error scanning %s", dirname);
                return;
        }
        if (n == 0)
                return;

        dir = opendir(dirname);
        if (dir != NULL)
                dfd = dirfd(dir);
        if (dfd == -1) {
                log_error_errno(-errno, "error opening %s", dirname);
                return;
        }

        while (n--) {
                struct dirent *de = darr[n];
                struct udev_device *ud;
                int prio, r;
                char prioname[PRIONAME_SIZE];

                if (is_prio_dirent(dir, de, &prio))
                        continue;
                /* is_prio_dirent() called dirent_ensure_type() */
                r = unlinkat(dfd, de->d_name,
                             de->d_type == DT_DIR ? AT_REMOVEDIR : 0);
                if (r == 0)
                        log_debug("removed %s/%s", dirname, de->d_name);
                else
                        log_error_errno(-errno, "failed to remove %s/%s",
                                        dirname, de->d_name);

                ud = udev_device_new_from_device_id(udev, de->d_name);
                if (ud == NULL)
                        continue;

                prio = udev_device_get_devlink_priority(ud);
                udev_device_unref(ud);

                make_prio_name(prio, prioname, sizeof(prioname));
                create_target_entry(dfd, prioname, de->d_name, dirname);
        }

        closedir(dir);
        free(darr);
}

/* manage "stack of names" with possibly specified device priorities */
static void link_update(struct udev_device *dev, const char *slink, bool add) {
        char name_enc[UTIL_PATH_SIZE];
        char dirname[UTIL_PATH_SIZE];
        char buf[UTIL_PATH_SIZE];
        char prioname[PRIONAME_SIZE];
        const char *filename;
        LockFile lf;
        int r, links_fd, dfd, priority;
        DIR *dir = NULL;

        mkdir_p(links_dirname, 0755);
        links_fd = open(links_dirname, O_RDONLY|O_DIRECTORY);
        if (links_fd == -1) {
                log_error_errno(-errno, "failed to open %s", dirname);
                return;
        }

        util_path_encode(slink + STRLEN("/dev"), name_enc, sizeof(name_enc));
        strscpyl(dirname, sizeof(dirname), links_dirname, "/", name_enc, NULL);
        priority = udev_device_get_devlink_priority(dev);
        make_prio_name(priority, prioname, sizeof(prioname));
        filename = udev_device_get_id_filename(dev);

        if (add) {
                mkdirat(links_fd, name_enc, 0755);
                dfd = openat(links_fd, name_enc, O_RDONLY|O_DIRECTORY);
                if (dfd == -1) {
                        log_error_errno(-errno, "failed to open %s", dirname);
                        goto out;
                }
                create_target_entry(dfd, prioname, filename, slink);
        } else {
                dfd = openat(links_fd, name_enc, O_RDONLY|O_DIRECTORY);
                if (dfd == -1 && errno != ENOENT) {
                        log_error_errno(-errno, "failed to open %s", dirname);
                        goto out;
                }
                delete_target_entry(dfd, prioname, filename, slink);
        }

        dir = fdopendir(dfd);
        if (dir == NULL) {
                close(dfd);
                goto out;
        }

        r = make_lock_file_for(dirname, LOCK_EX, &lf);
        if (r < 0) {
                log_warning_errno(r, "failed to lock %s", dirname);
                goto out_dir;
        }

        r = link_find_prioritized(dev, add, dfd, dir,
                                  buf, sizeof(buf), slink);
        if (r == TARGET_NEEDS_CLEANUP) {
                cleanup_old_targets(dirname, dev);
                r = link_find_prioritized(dev, add, dfd, dir,
                                          buf, sizeof(buf), slink);
                /* A single cleanup must be enough */
                assert(r != TARGET_NEEDS_CLEANUP);
        }
        if (r == NO_TARGET_FOUND) {
                log_debug("no reference left, remove '%s'", slink);
                if (unlink(slink) == 0)
                        rmdir_parents(slink, "/");
        } else {
                log_debug("creating link '%s' to '%s'", slink, buf);
                mkdir_parents(slink, 0755);
                node_symlink(dev, buf, slink);
        }

        release_lock_file(&lf);

out_dir:
        closedir(dir);
out:
        close(links_fd);
}

void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old) {
        struct udev_list_entry *list_entry;

        /* update possible left-over symlinks */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev_old)) {
                const char *name = udev_list_entry_get_name(list_entry);
                struct udev_list_entry *list_entry_current;
                int found;

                /* check if old link name still belongs to this device */
                found = 0;
                udev_list_entry_foreach(list_entry_current, udev_device_get_devlinks_list_entry(dev)) {
                        const char *name_current = udev_list_entry_get_name(list_entry_current);

                        if (streq(name, name_current)) {
                                found = 1;
                                break;
                        }
                }
                if (found)
                        continue;

                log_debug("update old name, '%s' no longer belonging to '%s'",
                     name, udev_device_get_devpath(dev));
                link_update(dev, name, false);
        }
}

static int node_permissions_apply(struct udev_device *dev, bool apply,
                                  mode_t mode, uid_t uid, gid_t gid,
                                  struct udev_list *seclabel_list) {
        const char *devnode = udev_device_get_devnode(dev);
        dev_t devnum = udev_device_get_devnum(dev);
        struct stat stats;
        struct udev_list_entry *entry;
        int err = 0;

        if (streq(udev_device_get_subsystem(dev), "block"))
                mode |= S_IFBLK;
        else
                mode |= S_IFCHR;

        if (lstat(devnode, &stats) != 0) {
                err = log_debug_errno(errno, "cannot stat() node '%s' (%m)", devnode);
                goto out;
        }

        if (((stats.st_mode & S_IFMT) != (mode & S_IFMT)) || (stats.st_rdev != devnum)) {
                err = -EEXIST;
                log_debug("found node '%s' with non-matching devnum %s, skip handling",
                          udev_device_get_devnode(dev), udev_device_get_id_filename(dev));
                goto out;
        }

        if (apply) {
                bool selinux = false;
                bool smack = false;

                if ((stats.st_mode & 0777) != (mode & 0777) || stats.st_uid != uid || stats.st_gid != gid) {
                        log_debug("set permissions %s, %#o, uid=%u, gid=%u", devnode, mode, uid, gid);
                        err = chmod(devnode, mode);
                        if (err < 0)
                                log_warning_errno(errno, "setting mode of %s to %#o failed: %m", devnode, mode);
                        err = chown(devnode, uid, gid);
                        if (err < 0)
                                log_warning_errno(errno, "setting owner of %s to uid=%u, gid=%u failed: %m", devnode, uid, gid);
                } else {
                        log_debug("preserve permissions %s, %#o, uid=%u, gid=%u", devnode, mode, uid, gid);
                }

                /* apply SECLABEL{$module}=$label */
                udev_list_entry_foreach(entry, udev_list_get_entry(seclabel_list)) {
                        const char *name, *label;
                        int r;

                        name = udev_list_entry_get_name(entry);
                        label = udev_list_entry_get_value(entry);

                        if (streq(name, "selinux")) {
                                selinux = true;

                                r = mac_selinux_apply(devnode, label);
                                if (r < 0)
                                        log_error_errno(r, "SECLABEL: failed to set SELinux label '%s': %m", label);
                                else
                                        log_debug("SECLABEL: set SELinux label '%s'", label);

                        } else if (streq(name, "smack")) {
                                smack = true;

                                r = mac_smack_apply(devnode, SMACK_ATTR_ACCESS, label);
                                if (r < 0)
                                        log_error_errno(r, "SECLABEL: failed to set SMACK label '%s': %m", label);
                                else
                                        log_debug("SECLABEL: set SMACK label '%s'", label);

                        } else
                                log_error("SECLABEL: unknown subsystem, ignoring '%s'='%s'", name, label);
                }

                /* set the defaults */
                if (!selinux)
                        (void) mac_selinux_fix(devnode, LABEL_IGNORE_ENOENT);
                if (!smack)
                        mac_smack_apply(devnode, SMACK_ATTR_ACCESS, NULL);
        }

        /* always update timestamp when we re-use the node, like on media change events */
        utimensat(AT_FDCWD, devnode, NULL, 0);
out:
        return err;
}

void udev_node_add(struct udev_device *dev, bool apply,
                   mode_t mode, uid_t uid, gid_t gid,
                   struct udev_list *seclabel_list) {
        char filename[DEV_NUM_PATH_MAX];
        struct udev_list_entry *list_entry;

        log_debug("handling device node '%s', devnum=%s, mode=%#o, uid="UID_FMT", gid="GID_FMT,
                  udev_device_get_devnode(dev), udev_device_get_id_filename(dev), mode, uid, gid);

        if (node_permissions_apply(dev, apply, mode, uid, gid, seclabel_list) < 0)
                return;

        /* always add /dev/{block,char}/$major:$minor */
        xsprintf_dev_num_path(filename,
                              streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                              udev_device_get_devnum(dev));
        node_symlink(dev, udev_device_get_devnode(dev), filename);

        /* create/update symlinks, add symlinks to name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev))
                        link_update(dev, udev_list_entry_get_name(list_entry), true);
}

void udev_node_remove(struct udev_device *dev) {
        struct udev_list_entry *list_entry;
        char filename[DEV_NUM_PATH_MAX];

        /* remove/update symlinks, remove symlinks from name index */
        udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(dev))
                link_update(dev, udev_list_entry_get_name(list_entry), false);

        /* remove /dev/{block,char}/$major:$minor */
        xsprintf_dev_num_path(filename,
                              streq(udev_device_get_subsystem(dev), "block") ? "block" : "char",
                              udev_device_get_devnum(dev));
        unlink(filename);
}

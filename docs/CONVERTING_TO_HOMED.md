---
title: Converting Existing Users to systemd-homed
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Converting Existing Users to systemd-homed managed Users

Traditionally on most Linux distributions, regular (human) users are managed
via entries in `/etc/passwd`, `/etc/shadow`, `/etc/group` and
`/etc/gshadow`. With the advent of
[`systemd-homed`](https://www.freedesktop.org/software/systemd/man/systemd-homed.service.html)
it might be desirable to convert an existing, traditional user account to a
`systemd-homed` managed one. Below is a brief guide how to do that.

Before continuing, please read up on these basic concepts:

* [Home Directories](HOME_DIRECTORY.md)
* [JSON User Records](USER_RECORD.md)
* [JSON Group Records](GROUP_RECORD.md)
* [User/Group Record Lookup API via Varlink](USER_GROUP_API.md)

## Caveat

This is a manual process, and possibly a bit fragile. Hence, do this at your
own risk, read up beforehand, and make a backup first. You know what's at
stake: your own home directory, i.e. all your personal data.

## Step-By-Step

Here's the step-by-step guide:

0. Preparations: make sure you run a distribution that has `systemd-homed`
   enabled and properly set up, including the necessary PAM and NSS
   configuration updates. Make sure you have enough disk space in `/home/` for
   a (temporary) second copy of your home directory. Make sure to backup your
   home directory. Make sure to log out of your user account fully. Then log in
   as root on the console.

1. Rename your existing home directory to something safe. Let's say your user
   ID is `foobar`. Then do:

    ```
    mv /home/foobar /home/foobar.saved
    ```

2. Have a look at your existing user record, as stored in `/etc/passwd` and
   related files. We want to use the same data for the new record, hence it's good
   looking at the old data. Use commands such as:

    ```
    getent passwd foobar
    getent shadow foobar
    ```

   This will tell you the `/etc/passwd` and `/etc/shadow` entries for your
   user. For details about the fields, see the respective man pages
   [passwd(5)](https://man7.org/linux/man-pages/man5/passwd.5.html) and
   [shadow(5)](https://man7.org/linux/man-pages/man5/shadow.5.html).

   The fourth field in the `getent passwd foobar` output tells you the GID of
   your user's main group. Depending on your distribution it's a group private
   to the user, or a group shared by most local, regular users. Let's say the
   GID reported is 1000, let's then query its details:

    ```
    getent group 1000
    ```

   This will tell you the name of that group. If the name is the same as your
   user name your distribution apparently provided you with a private group for
   your user. If it doesn't match (and is something like `users`) it apparently
   didn't. Note that `systemd-homed` will always manage a private group for
   each user under the same name, hence if your distribution is one of the
   latter kind, then there's a (minor) mismatch in structure when converting.

   Save the information reported by these three commands somewhere, for later
   reference.

3. Now edit your `/etc/passwd` file and remove your existing record
   (i.e. delete a single line, the one of your user's account, leaving all
   other lines unmodified). Similar for `/etc/shadow`, `/etc/group` (in case
   you have a private group for your user) and `/etc/gshadow`. Most
   distributions provide you with a tool for that, that adds safe
   synchronization for these changes: `vipw`, `vipw -s`, `vigr` and `vigr -s`.

4. At this point the old user account vanished, while the home directory still
   exists safely under the `/home/foobar.saved` name. Let's now create a new
   account with `systemd-homed`, using the same username and UID as before:

    ```
    homectl create foobar --uid=$UID --real-name=$GECOS
    ```

   In this command line, replace `$UID` by the UID you previously used,
   i.e. the third field of the `getent passwd foobar` output above. Similar,
   replace `$GECOS` by the GECOS field of your old account, i.e the fifth field
   of the old output. If your distribution traditionally does not assign a
   private group to regular user groups, then consider adding `--member-of=`
   with the group name to get a modicum of compatibility with the status quo
   ante: this way your new user account will still not have the old primary
   group as new primary group, but will have it as auxiliary group.

   Consider reading through the
   [homectl(1)](https://www.freedesktop.org/software/systemd/man/homectl.html)
   manual page at this point, maybe there are a couple of other settings you
   want to set for your new account. In particular, look at `--storage=` and
   `--disk-size=`, in order to change how your home directory shall be stored
   (the default `luks` storage is recommended).

5. Your new user account exists now, but it has an empty home directory. Let's
   now migrate your old home directory into it. For that let's mount the new
   home directory temporarily and copy the data in.

    ```
    homectl with foobar -- rsync -aHAXv --remove-source-files /home/foobar.saved/ .
    ```

   This mounts the home directory of the user, and then runs the specified
   `rsync` command which copies the contents of the old home directory into the
   new. The new home directory is the working directory of the invoked `rsync`
   process. We are invoking this command as root, hence the `rsync` runs as
   root too. When the `rsync` command completes the home directory is
   automatically unmounted again. Since we used `--remove-source-files` all files
   copied are removed from the old home directory as the copy progresses. After
   the command completes the old home directory should be empty. Let's remove
   it hence:

    ```
    rmdir /home/foobar.saved
    ```

And that's it, we are done already. You can log out now and should be able to
log in under your user account as usual, but now with `systemd-homed` managing
your home directory.

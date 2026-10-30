/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Aggregator header consumed by bindgen to generate the systemd_shared_sys crate. It lists the headers Rust
 * code uses; a wrapper that needs another one adds it here. The libc constants come by family, see the
 * allowlist in meson.build. Same-named headers exist in src/basic/ and src/shared/ (tmpfile-util.h): the
 * src/shared/ one is found first and includes its src/basic/ namesake, so both are bound. */

/* The libc and kernel surface systemd code sees: the headers behind the constant families the allowlist in
 * meson.build picks, and what the allocator, the panic handler and print!() call. Listed here so that it does
 * not depend on what the headers below happen to include. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "sd-dlopen.h"
#include "sd-id128.h"
#include "sd-json.h"

#include "build.h"
#include "chase.h"
#include "conf-files.h"
#include "creds-util.h"
#include "crypto-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "forward.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "keyring-util.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "module-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "verbs.h"
#include "voa-util.h"

/* Object-like macros with casts are not constant expressions to bindgen. These give it something it can
 * evaluate, the crate root renames them; values that do not fit a long (USEC_INFINITY, NSEC_INFINITY) are
 * written by hand there instead. */
const uid_t RUST_CONST_HELPER_UID_INVALID = UID_INVALID;
const gid_t RUST_CONST_HELPER_GID_INVALID = GID_INVALID;
const mode_t RUST_CONST_HELPER_MODE_INVALID = MODE_INVALID;
const usec_t RUST_CONST_HELPER_USEC_PER_MSEC = USEC_PER_MSEC;
const usec_t RUST_CONST_HELPER_USEC_PER_SEC = USEC_PER_SEC;
const usec_t RUST_CONST_HELPER_USEC_PER_MINUTE = USEC_PER_MINUTE;
const usec_t RUST_CONST_HELPER_USEC_PER_HOUR = USEC_PER_HOUR;
const usec_t RUST_CONST_HELPER_USEC_PER_DAY = USEC_PER_DAY;
const usec_t RUST_CONST_HELPER_USEC_PER_WEEK = USEC_PER_WEEK;
const nsec_t RUST_CONST_HELPER_NSEC_PER_USEC = NSEC_PER_USEC;
const nsec_t RUST_CONST_HELPER_NSEC_PER_MSEC = NSEC_PER_MSEC;
const nsec_t RUST_CONST_HELPER_NSEC_PER_SEC = NSEC_PER_SEC;
const unsigned RUST_CONST_HELPER_VERB_ANY = VERB_ANY;
const uint32_t RUST_CONST_HELPER_SD_ELF_NOTE_DLOPEN_TYPE = SD_ELF_NOTE_DLOPEN_TYPE;

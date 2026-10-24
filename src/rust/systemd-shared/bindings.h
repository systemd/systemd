/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Aggregator header consumed by bindgen to generate the systemd_shared_sys crate. It lists the headers Rust
 * code uses; a wrapper that needs another one adds it here. The libc constants come by family, see the
 * allowlist in meson.build. */

/* The libc and kernel surface systemd code sees. Most of it arrives through the headers below, these add
 * what they do not pull in. */
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <sys/prctl.h>
#include <sysexits.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "build.h"
#include "errno-list.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "process-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "user-util.h"
#include "verbs.h"

/* Object-like macros with casts are not constant expressions to bindgen. These give it something it can
 * evaluate, the crate root renames them; values that do not fit a long (USEC_INFINITY, NSEC_INFINITY) are
 * written by hand there instead. */
const uid_t RUST_CONST_HELPER_UID_INVALID = UID_INVALID;
const gid_t RUST_CONST_HELPER_GID_INVALID = GID_INVALID;
const uid_t RUST_CONST_HELPER_UID_NOBODY = UID_NOBODY;
const gid_t RUST_CONST_HELPER_GID_NOBODY = GID_NOBODY;
const mode_t RUST_CONST_HELPER_MODE_INVALID = MODE_INVALID;
const pid_t RUST_CONST_HELPER_PID_AUTOMATIC = PID_AUTOMATIC;
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

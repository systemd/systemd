/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/capability.h>

/* 3a101b8de0d39403b2c7e5c23fd0b005668acf48 (3.16) */
#ifndef CAP_AUDIT_READ
#  define CAP_AUDIT_READ 37
#endif

/* 980737282232b752bb14dab96d77665c15889c36 (5.8) */
#ifndef CAP_PERFMON
#  define CAP_PERFMON 38
#endif

/* a17b53c4a4b55ec322c132b6670743612229ee9c (5.8) */
#ifndef CAP_BPF
#  define CAP_BPF 39
#endif

/* 124ea650d3072b005457faed69909221c2905a1f (5.9) */
#ifndef CAP_CHECKPOINT_RESTORE
#  define CAP_CHECKPOINT_RESTORE 40
#endif

#define SYSTEMD_CAP_LAST_CAP CAP_CHECKPOINT_RESTORE

#ifdef CAP_LAST_CAP
#  if CAP_LAST_CAP > SYSTEMD_CAP_LAST_CAP
#    if BUILD_MODE_DEVELOPER && defined(TEST_CAPABILITY_C)
#      warning "The capability list here is outdated"
#    endif
#  else
#    undef CAP_LAST_CAP
#  endif
#endif
#ifndef CAP_LAST_CAP
#  define CAP_LAST_CAP SYSTEMD_CAP_LAST_CAP
#endif

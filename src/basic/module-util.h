/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <libkmod.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_ctx*, kmod_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_module*, kmod_module_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_list*, kmod_module_unref_list);

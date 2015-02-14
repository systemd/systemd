/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014  Tom Gundersen <teg@jklm.no>
    Copyright 2014  Susant Sahani

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


#include "networkd-netdev-bridge.h"
#include "missing.h"

const NetDevVTable bridge_vtable = {
        .object_size = sizeof(Bridge),
        .sections = "Match\0NetDev\0",
        .create_type = NETDEV_CREATE_MASTER,
};

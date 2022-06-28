/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

/* the current version of this struct is defined in sd-bus-vtable.h, but we need to list here the historical versions
   to make sure the calling code is compatible with one of these */
struct sd_bus_vtable_221 {
        uint8_t type:8;
        uint64_t flags:56;
        union {
                struct {
                        size_t element_size;
                } start;
                struct {
                        const char *member;
                        const char *signature;
                        const char *result;
                        sd_bus_message_handler_t handler;
                        size_t offset;
                } method;
                struct {
                        const char *member;
                        const char *signature;
                } signal;
                struct {
                        const char *member;
                        const char *signature;
                        sd_bus_property_get_t get;
                        sd_bus_property_set_t set;
                        size_t offset;
                } property;
        } x;
};
/* Structure size up to v241 */
#define VTABLE_ELEMENT_SIZE_221 sizeof(struct sd_bus_vtable_221)

/* Size of the structure when "features" field was added. If the structure definition is augmented, a copy of
 * the structure definition will need to be made (similarly to the sd_bus_vtable_221 above), and this
 * definition updated to refer to it. */
#define VTABLE_ELEMENT_SIZE_242 sizeof(struct sd_bus_vtable)

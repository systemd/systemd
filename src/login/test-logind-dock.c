/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "logind.h"
#include "strv.h"
#include "tests.h"

/* The connector type is what decides whether a display can plausibly belong to a docking setup */
TEST(drm_connector_is_external) {
        FOREACH_STRING(sysname,
                       "card0-Component-1",
                       "card0-Composite-1",
                       "card0-DIN-1",
                       "card0-DP-1",
                       "card0-DVI-A-1",
                       "card0-DVI-D-1",
                       "card0-DVI-I-1",
                       "card0-HDMI-A-1",
                       "card0-HDMI-B-1",
                       "card0-SVIDEO-1",
                       "card0-TV-1",
                       "card0-VGA-1")
                ASSERT_TRUE(drm_connector_is_external(sysname));

        /* Panels wired into the chassis, plus the writeback connector. */
        FOREACH_STRING(sysname,
                       "card0-DSI-1",
                       "card0-LVDS-1",
                       "card0-Writeback-1",
                       "card0-eDP-1")
                ASSERT_FALSE(drm_connector_is_external(sysname));

        /* Names that do not carry a connector type at all. */
        FOREACH_STRING(sysname, "card0", "", "-", "card0-")
                ASSERT_FALSE(drm_connector_is_external(sysname));
}

/* 'enabled' reports whether a DRM master currently drives the connector. Note
 * that this is false when the output is put to sleep via DPMS. We use it
 * nevertheless because it is the only thing that can disambiguate connectors
 * whose hotplug detection reports "unknown". */
TEST(drm_connector_is_active) {
        ASSERT_TRUE(drm_connector_is_active("connected", "enabled"));

        /* VGA and some DVI connectors cannot detect whether anything is attached. Trust the modeset. */
        ASSERT_TRUE(drm_connector_is_active("unknown", "enabled"));

        /* A monitor that is attached but asleep, i.e. https://github.com/systemd/systemd/issues/41898. */
        ASSERT_FALSE(drm_connector_is_active("connected", "disabled"));

        ASSERT_FALSE(drm_connector_is_active("disconnected", "enabled"));

        /* A missing attribute tells us nothing, so it shouldn't be interpreted as a display being
         * present. */
        ASSERT_FALSE(drm_connector_is_active(/* status= */ NULL, "enabled"));
        ASSERT_FALSE(drm_connector_is_active("connected", /* enabled= */ NULL));
        ASSERT_FALSE(drm_connector_is_active(/* status= */ NULL, /* enabled= */ NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);

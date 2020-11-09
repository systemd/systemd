# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TIMEDATED') == 1
        install_data('org.freedesktop.timedate1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.timedate1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.timedate1.policy',
                     install_dir : polkitpolicydir)
endif

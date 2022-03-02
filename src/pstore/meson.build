# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_pstore_sources = files('pstore.c')

if conf.get('ENABLE_PSTORE') == 1 and install_sysconfdir_samples
        install_data('pstore.conf',
                     install_dir : pkgsysconfdir)
endif

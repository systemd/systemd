# SPDX-License-Identifier: LGPL-2.1+

install_data('kernel-install',
             install_mode : 'rwxr-xr-x',
             install_dir : bindir)

install_data('00-entry-directory.install',
             '50-depmod.install',
             '90-loaderentry.install',
             install_mode : 'rwxr-xr-x',
             install_dir : kernelinstalldir)

meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(sysconfdir, 'kernel/install.d')))

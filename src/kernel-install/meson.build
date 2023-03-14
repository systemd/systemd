# SPDX-License-Identifier: LGPL-2.1-or-later

loaderentry_install_in = files('90-loaderentry.install.in')

loaderentry_install = custom_target(
        '90-loaderentry.install',
        input : loaderentry_install_in,
        output : '90-loaderentry.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

kernel_install_files = files(
        '50-depmod.install',
        '90-uki-copy.install',
)

if want_kernel_install
        install_data(kernel_install_files,
                     install_mode : 'rwxr-xr-x',
                     install_dir : kernelinstalldir)

        install_data('install.conf',
                     install_dir : kerneldir)

        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'kernel/install.d'))
        endif

        test_kernel_install_sh = find_program('test-kernel-install.sh')
endif

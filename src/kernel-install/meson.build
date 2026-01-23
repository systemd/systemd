# SPDX-License-Identifier: LGPL-2.1-or-later

want_kernel_install = conf.get('ENABLE_KERNEL_INSTALL') == 1

executables += [
        executable_template + {
                'name' : 'kernel-install',
                'public' : true,
                'conditions' : ['ENABLE_KERNEL_INSTALL'],
                'sources' : files('kernel-install.c'),
        },
]

ukify_install = custom_target(
        input : '60-ukify.install.in',
        output : '60-ukify.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install and want_ukify,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

loaderentry_install = custom_target(
        input : '90-loaderentry.install.in',
        output : '90-loaderentry.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

uki_copy_install = custom_target(
        input : '90-uki-copy.install.in',
        output : '90-uki-copy.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

custom_target(
        input : '50-depmod.install.in',
        output : '50-depmod.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

if want_kernel_install
        install_data('install.conf',
                     install_dir : kerneldir)

        if want_ukify
                install_data('uki.conf',
                             install_dir : kerneldir)
        endif

        if install_sysconfdir
                install_emptydir(sysconfdir / 'kernel/install.d')
        endif
endif

test_kernel_install_sh = files('test-kernel-install.sh')

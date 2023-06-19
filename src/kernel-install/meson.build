# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_KERNEL_INSTALL') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'kernel-install',
                'public' : true,
                'sources' : files('kernel-install.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]

ukify_install = custom_target(
        '60-ukify.install',
        input : '60-ukify.install.in',
        output : '60-ukify.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_ukify,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

loaderentry_install = custom_target(
        '90-loaderentry.install',
        input : '90-loaderentry.install.in',
        output : '90-loaderentry.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : true,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

uki_copy_install = files('90-uki-copy.install')

kernel_install_files = uki_copy_install + files(
        '50-depmod.install',
)

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

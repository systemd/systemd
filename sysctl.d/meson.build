# SPDX-License-Identifier: LGPL-2.1-or-later

install_data(
        'README',
        '50-default.conf',
        install_dir : sysctldir)

# Kernel determines PID_MAX_LIMIT by
# #define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
#         (sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))
if cc.sizeof('long') > 4
        install_data('50-pid-max.conf', install_dir : sysctldir)
endif

custom_target(
        input : '50-coredump.conf.in',
        output : '50-coredump.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_COREDUMP') == 1,
        install_dir : sysctldir)

if install_sysconfdir
        install_emptydir(sysconfdir / 'sysctl.d')
endif

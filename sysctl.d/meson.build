# SPDX-License-Identifier: LGPL-2.1+

install_data(
        '50-default.conf',
        install_dir : sysctldir)

in_files = []

# Kernel determines PID_MAX_LIMIT by
# #define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
#         (sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))
if cc.sizeof('long') > 4
        install_data('50-pid-max.conf', install_dir : sysctldir)
endif

if conf.get('ENABLE_COREDUMP') == 1
        in_files += ['50-coredump.conf']
endif

foreach file : in_files
        gen = configure_file(
                input : file + '.in',
                output : file,
                configuration : substs)
        install_data(gen,
                     install_dir : sysctldir)
endforeach

meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(sysconfdir, 'sysctl.d')))
